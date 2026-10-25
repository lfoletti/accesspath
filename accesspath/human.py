"""Politique humain-in-the-loop pour le warmup des profils Chrome.

INTERACTIVE : un humain est là (TTY détecté), on lui propose de warmer.
UNATTENDED  : lancé par launchd/cron, pas de prompt possible. Le CLI
              signale needs_warmup via exit code 2 et STATUS.md.
"""

from __future__ import annotations

import asyncio
import json
import os
import signal
import sys
from enum import StrEnum

from playwright.async_api import async_playwright

from . import config, gestures
from .browser import cdp as cdp_mod
from .browser import profile as profile_mod


class HumanPolicy(StrEnum):
    INTERACTIVE = "interactive"
    UNATTENDED = "unattended"


def detect_policy() -> HumanPolicy:
    """Interactive si stdin est un TTY, unattended sinon (launchd, CI)."""
    if sys.stdin.isatty() and sys.stdout.isatty():
        return HumanPolicy.INTERACTIVE
    return HumanPolicy.UNATTENDED


async def warmup(site: object, at: str | None = None) -> bool:
    """Lance Chrome headed sur la 1re URL du site (ou `at`), attend l'humain.

    Si `site.needs_login=True`, tente d'exécuter `site.login_flow` avec les
    credentials depuis `data/credentials.json`. Si login échoue ou creds absents,
    fallback sur le mode manuel (l'utilisateur se connecte lui-même puis Entrée).

    Sinon : l'utilisateur accepte cookies / résolve captcha, puis Entrée.

    Retourne True si le profil a été marqué warm, False sinon.
    """
    return await warmup_at(site.name, at or _home_url(site), site=site)


async def warmup_at(name: str, url: str, *, site: object | None = None) -> bool:
    """Warmup d'un profil par son nom, sur une URL donnée : marche aussi pour
    un site qui n'a pas encore de collecteur (audit puis geste). Ferme le
    ticket de la file de gestes quand le profil est marqué warm."""
    if detect_policy() == HumanPolicy.UNATTENDED:
        print(f"  ✗ [{name}] warmup impossible en mode unattended")
        return False

    print(f"\n  🔥 [{name}] warmup")
    print(f"     profil  : {profile_mod.profile_dir(name)}")
    print(f"     page    : {url}")
    if site is not None and site.needs_login:
        print("     login   : requis (auto si credentials.json, sinon manuel)")
    else:
        print("     action  : accepte les cookies / passe le défi / connecte-toi, puis Entrée\n")

    await _open_and_wait(name, url, site)
    profile_mod.mark_warm(name)
    gestures.resolve(name)
    print(f"  ✅ [{name}] profil marqué warm")
    return True


async def _open_and_wait(name: str, url: str, site: object | None = None) -> None:
    """Chrome visible sur le profil du site, jusqu'à ce que l'humain tape Entrée."""
    chrome = await cdp_mod.launch_chrome(profile_mod.profile_dir(name), headless=False)
    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.connect_over_cdp(cdp_mod.cdp_url(chrome.cdp_port))
            ctx = browser.contexts[0] if browser.contexts else await browser.new_context()
            page = ctx.pages[0] if ctx.pages else await ctx.new_page()
            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=30_000)
            except Exception as e:
                print(f"     (navigation a échoué: {e} — continue quand même)")

            if site is not None and site.needs_login:
                await _try_auto_login(site, page)

            await asyncio.get_running_loop().run_in_executor(
                None, lambda: input("\n     appuie sur Entrée quand c'est prêt… ")
            )
            await browser.close()
    finally:
        chrome.terminate()
        await asyncio.sleep(1)


def _home_url(site: object) -> str:
    """URL de home pour le warmup : 1re catégorie OU URL de seed OU guess."""
    if site.categories:
        return site.categories[0].url_template.format(1)
    # Les sites à URL de départ (seed) n'ont pas de categories — hack : on utilise
    # l'URL de base du domaine, l'utilisateur finira la navigation.

    try:
        mod = config.site_module(site.name)
        if hasattr(mod, "SEASON_INDEX_URL"):
            return mod.SEASON_INDEX_URL
    except ImportError:
        pass
    return f"https://www.{site.name}.com"


async def _try_auto_login(site: object, page) -> bool:
    """Tente le login auto si credentials présents et module expose login_flow."""
    from . import credentials

    creds = credentials.load(site.name)
    if not creds or "email" not in creds or "password" not in creds:
        print("     ℹ️  pas de credentials.json — login manuel attendu")
        return False

    try:
        mod = config.site_module(site.name)
    except ImportError:
        return False
    login_flow = getattr(mod, "login_flow", None)
    if login_flow is None:
        print(f"     ℹ️  {site.name} n'expose pas login_flow — login manuel attendu")
        return False

    print("     🤖 tentative de login auto…")
    try:
        ok = await login_flow(page, creds["email"], creds["password"])
    except Exception as e:
        print(f"     ✗ login_flow a levé: {e}")
        return False
    return bool(ok)


# ── Geste piloté depuis la conversation ─────────────────────────────────────
# Chaque étape est une commande qui rend la main : ouvrir laisse Chrome ouvert sur le
# profil du site (la personne y accède par le partage d'écran quand elle est en SSH),
# puis verifier, passer ou ecarter selon sa réponse. L'état de la fenêtre ouverte vit
# dans le profil du site.
OPEN_WINDOW = "geste_ouvert.json"


def _state_path(name: str):
    return profile_mod.profile_dir(name) / OPEN_WINDOW


def _window_alive(st: dict) -> bool:
    try:
        os.kill(int(st["pid"]), 0)
    except (ProcessLookupError, PermissionError, ValueError, KeyError):
        return False
    return True


def open_window(name: str) -> dict | None:
    """Fenêtre de geste ouverte pour ce site, ou None (jamais ouverte, ou fermée depuis)."""
    path = _state_path(name)
    try:
        st = json.loads(path.read_text())
    except (OSError, ValueError):
        return None
    if not _window_alive(st):
        path.unlink(missing_ok=True)
        return None
    return st


def _has_gui_session() -> bool:
    """Session graphique ouverte par l'utilisateur courant. Sur l'écran de connexion
    (/dev/console à root), un Chrome avec fenêtre meurt au lancement."""
    try:
        return os.stat("/dev/console").st_uid == os.getuid()
    except OSError:
        return True


async def _launch_detached(name: str, url: str) -> dict:
    """Chrome avec fenêtre si une session graphique est ouverte, sinon sans fenêtre :
    DevTools (tunnel SSH, chrome://inspect) montre alors la page et on y clique."""
    headless = not _has_gui_session()
    size = {"window_size": "1440,900"} if headless else {}  # 800 × 600 par défaut : version mobile
    chrome = await cdp_mod.launch_chrome(
        profile_mod.profile_dir(name), headless=headless, url=url, detached=True, **size
    )
    return {"pid": chrome.pid, "port": chrome.cdp_port}


# Bandeau de consentement affiché : présent dans le DOM ne suffit pas, un bandeau accepté y
# reste souvent, masqué. Gestionnaires courants, puis motifs génériques de l'audit.
CONSENT_VISIBLE_JS = """() => {
  const sel = '#onetrust-banner-sdk, #didomi-notice, #CybotCookiebotDialog, [id^="sp_message_container"],'
    + ' #usercentrics-root, .fc-consent-root, #qc-cmp2-ui, .cmp-banner, [class*="cookie-consent" i],'
    + ' [id*="cookie-banner" i], [class*="cookie-banner" i], [aria-modal="true"][aria-label*="cookie" i]';
  const shown = (el) => {
    const r = el.getBoundingClientRect();
    const st = getComputedStyle(el);
    return r.width * r.height > 2000 && st.visibility !== 'hidden' && st.display !== 'none' && +st.opacity > 0.05;
  };
  return [...document.querySelectorAll(sel)].some(shown);
}"""


async def _read_open_page(port: int) -> dict:
    """Titre, texte et adresse de la page affichée, bandeau de consentement affiché ou non ;
    la connexion se coupe, Chrome reste."""
    async with async_playwright() as pw:
        browser = await pw.chromium.connect_over_cdp(cdp_mod.cdp_url(port))
        pages = [pg for ctx in browser.contexts for pg in ctx.pages if pg.url.startswith("http")]
        if not pages:
            return {"title": "", "body": "", "final_url": ""}
        page = pages[-1]
        body = await page.evaluate("() => document.body ? document.body.innerText : ''")
        consent = await page.evaluate(CONSENT_VISIBLE_JS)
        return {"title": await page.title(), "body": body, "final_url": page.url, "consent_visible": bool(consent)}


async def _close_chrome(port: int, pid: int) -> None:
    """Fermeture propre (Browser.close : les cookies sont écrits dans le profil), sinon SIGTERM."""
    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.connect_over_cdp(cdp_mod.cdp_url(port))
            session = await browser.new_browser_cdp_session()
            await session.send("Browser.close")
    except Exception:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass


async def _close_window(name: str, st: dict) -> None:
    await _close_chrome(st["port"], st["pid"])
    _state_path(name).unlink(missing_ok=True)


async def open_gesture(g: gestures.Gesture) -> tuple[dict, bool]:
    """Chrome visible sur le profil du site, à l'adresse du ticket ; (état, lancé maintenant)."""
    st = open_window(g.site)
    if st:
        return st, False
    st = {**await _launch_detached(g.site, g.open_url), "url": g.open_url}
    _state_path(g.site).write_text(json.dumps(st))
    return st, True


async def check_gesture(name: str) -> tuple[bool, str] | None:
    """Relit la page ouverte. Servie : profil marqué, ticket fermé, fenêtre fermée.
    Défi, refus net ou page vide : tout reste en place. None sans fenêtre ouverte."""
    from .sap_inspect import classify_page

    st = open_window(name)
    if st is None:
        return None
    page = await _read_open_page(st["port"])
    reach = classify_page(page["title"], page["body"], st["url"], page["final_url"])
    if reach.hard_block:
        return False, f"refus net : {page['title']!r}"
    if reach.status == "challenge":
        return False, f"défi encore affiché : {page['title']!r}"
    if reach.status != "OK":
        return False, f"page vide ({reach.status})"
    ticket = next((g for g in gestures.pending() if g.site == name), None)
    if ticket and ticket.kind == "consent" and page.get("consent_visible"):
        return False, "bandeau de consentement encore affiché"
    profile_mod.mark_warm(name)
    gestures.resolve(name, why="fait")
    await _close_window(name, st)
    return True, f"page servie : {page['title']!r}"


async def pass_gesture(name: str) -> bool:
    """Ferme la fenêtre, garde le ticket ; False s'il n'y avait pas de fenêtre."""
    st = open_window(name)
    if st:
        await _close_window(name, st)
    return st is not None


async def drop_gesture(name: str, motif: str = "") -> None:
    """Geste inutile : fenêtre fermée, ticket fermé avec son motif, profil non marqué."""
    st = open_window(name)
    if st:
        await _close_window(name, st)
    gestures.resolve(name, why="inutile" + (f" : {motif}" if motif else ""))
