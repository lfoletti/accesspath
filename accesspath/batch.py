"""Audit de masse : une liste de sites, auditée en parallèle (`sap batch`).

- Liste : un fichier texte (une URL par ligne, `#` pour commenter) ou un CSV avec une
  colonne `url` (et `name` facultatif ; les autres colonnes suivent dans les résultats).
  URL normalisées et dédoublonnées, noms validés, lignes refusées consignées.
- Mode `probe` : la sonde HTTP, dans ce processus ; chaque sonde a sa propre échéance.
- Mode `inspect` : un processus par site, dans son propre groupe ; au délai, le groupe
  entier est tué (Chrome compris). `asyncio.wait_for` n'arrête pas nodriver bloqué dans
  un appel natif ; seul le système le fait.
- Sortie : `data/batch/<lot>/results.jsonl`, une ligne par site écrite dès qu'il est fini
  (reprise par `--resume`), et `summary.md`, la synthèse.
"""

from __future__ import annotations

import asyncio
import csv
import io
import ipaddress
import json
import os
import re
import shutil
import signal
import socket
import sys
import time
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from ._safe import (
    DATA_BEGIN,
    DATA_END,
    UnsafeInput,
    name_from_url,
    neutralize,
    normalize_target_url,
    validate_site_name,
)
from .config import DATA_DIR

BATCH_DIR = DATA_DIR / "batch"
PROBES_DIR = DATA_DIR / "probes"
# history : deux requêtes à la fois au plus par lot, par égard pour la Wayback Machine.
DEFAULT_CONCURRENCY = {"probe": 8, "inspect": 4, "history": 2, "contents": 8}
MAX_CONCURRENCY = {"probe": 32, "inspect": 8, "history": 4, "contents": 16}
SITE_DEADLINE_S = {"probe": 180.0, "inspect": 90.0, "history": 900.0, "contents": 150.0}
clock = time.monotonic  # durée du passage (remplaçable en test)

# Configurations d'inspect, essayées dans l'ordre jusqu'à un rapport complet.
INSPECT_CONFIGS: dict[str, dict] = {
    "headless-30": {"headless": True, "capture_s": 30},
    "headless-12": {"headless": True, "capture_s": 12},  # site lent qui ne finit pas de charger
    "visible-30": {"headless": False, "capture_s": 30},  # fenêtre : passe mieux certains anti-bots
}
DEFAULT_ROTATION = ("headless-30", "headless-12")
# Silence toléré au-delà de la capture (pendant la capture, inspect n'écrit rien).
STALL_GRACE_S = 25.0
# Sites d'un même bloc d'adresses (hébergeur mutualisé) visités à la fois : au-delà, un
# hébergeur comme Strato coupe les connexions de notre adresse pendant le lot.
PER_HOST_BLOCK = 1


# ── Liste ────────────────────────────────────────────────────────────────
def batch_name(path: str | Path) -> str:
    stem = re.sub(r"[^a-z0-9]+", "_", Path(path).stem.lower()).strip("_")[:64]
    return validate_site_name(stem)


def _rows(text: str) -> list[dict]:
    lines = [x for x in text.splitlines() if x.strip() and not x.lstrip().startswith("#")]
    if lines and "url" in [c.strip().lower() for c in lines[0].split(",")]:
        reader = csv.DictReader(io.StringIO("\n".join(lines)))
        return [
            {
                "line": ",".join(r.get(k) or "" for k in reader.fieldnames or []),
                **{k.strip().lower(): (v or "").strip() for k, v in r.items() if k},
            }
            for r in reader
        ]
    return [{"line": x.strip(), "url": x.strip()} for x in lines]


def read_targets(path: str | Path) -> tuple[list[dict], list[dict]]:
    """(cibles, lignes refusées). Cible : {name, url, extra}."""
    targets: list[dict] = []
    invalid: list[dict] = []
    urls: set[str] = set()
    names: Counter = Counter()
    for r in _rows(Path(path).read_text(encoding="utf-8", errors="replace")):
        try:
            url = normalize_target_url(r.get("url", ""))
            parts = urlsplit(url)
            if not parts.path:  # https://a.ch et https://a.ch/ : un seul site
                url = urlunsplit(parts._replace(path="/"))
            name = validate_site_name(r["name"]) if r.get("name") else name_from_url(url)
        except UnsafeInput as e:
            invalid.append({"line": r["line"], "error": str(e)})
            continue
        if url in urls:
            continue
        urls.add(url)
        names[name] += 1
        if names[name] > 1:
            name = validate_site_name(f"{name[:60]}_{names[name]}")
        extra = {k: v for k, v in r.items() if k not in ("line", "url", "name")}
        targets.append({"name": name, "url": url, "extra": extra})
    return targets, invalid


# ── Exécution ────────────────────────────────────────────────────────────
def _done_urls(results: Path) -> set[str]:
    if not results.exists():
        return set()
    done = set()
    for line in results.read_text(encoding="utf-8").splitlines():
        try:
            row = json.loads(line)
            if not row.get("retry"):  # ligne à refaire : la reprise la relance
                done.add(row["url"])
        except (ValueError, KeyError, TypeError):
            continue
    return done


def read_results(results: Path) -> list[dict]:
    """Lignes du lot, la dernière de chaque site : une reprise remplace la ligne à refaire."""
    rows: dict[str, dict] = {}
    for line in results.read_text(encoding="utf-8").splitlines():
        if line.strip():
            row = json.loads(line)
            rows[row["url"]] = row
    return list(rows.values())


def _prepare(out_dir: Path, resume: bool) -> tuple[Path, set[str]]:
    out_dir.mkdir(parents=True, exist_ok=True)
    results = out_dir / "results.jsonl"
    done = _done_urls(results) if resume else set()
    results.touch()
    return results, done


def _append(results: Path, row: dict) -> None:
    with results.open("a", encoding="utf-8") as f:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")


async def _resolve(host: str) -> str:
    infos = await asyncio.get_running_loop().getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    return infos[0][4][0]


async def host_block(url: str, resolve=None) -> str:
    """Bloc d'adresses d'un site (IPv4 /24, IPv6 /48) ; l'hôte lui-même s'il ne se résout pas."""
    host = urlsplit(url).hostname or url
    try:
        address = ipaddress.ip_address(await (resolve or _resolve)(host))
    except (OSError, ValueError):
        return host
    prefix = 24 if address.version == 4 else 48
    return str(ipaddress.ip_network(f"{address}/{prefix}", strict=False))


async def run_batch(
    targets: list[dict],
    *,
    runner,
    concurrency: int,
    out_dir: Path,
    resume: bool = False,
    per_block: int | None = None,
    resolve=None,
) -> list[dict]:
    """Lance `runner(cible)` sur chaque cible, `concurrency` à la fois ; chaque résultat est
    ajouté à `results.jsonl` dès qu'il arrive. Une exception reste propre à son site.

    `per_block` : sites d'un même bloc d'adresses à la fois (None : pas de limite). Un site
    qui attend son bloc ne prend pas de place dans `concurrency`."""
    results, done = await asyncio.to_thread(_prepare, out_dir, resume)
    sem = asyncio.Semaphore(concurrency)
    lock = asyncio.Lock()
    rows: list[dict] = []
    blocks: dict[str, asyncio.Semaphore] = {}

    async def one(t: dict) -> None:
        if per_block is None:
            await visit(t, {})
            return
        block = await host_block(t["url"], resolve)
        async with blocks.setdefault(block, asyncio.Semaphore(per_block)):
            await visit(t, {"host_block": block})

    async def visit(t: dict, more: dict) -> None:
        async with sem:
            t0 = time.monotonic()
            try:
                found = await runner(t)
            except Exception as e:  # un site ne fait pas tomber le lot
                found = {"status": "error", "error": f"{type(e).__name__}: {e}"[:300]}
            row = {
                "name": t["name"],
                "url": t["url"],
                **t.get("extra", {}),
                **found,
                **more,
                "duration_s": round(time.monotonic() - t0, 2),
            }
            async with lock:
                rows.append(row)
                await asyncio.to_thread(_append, results, row)

    await asyncio.gather(*(one(t) for t in targets if t["url"] not in done))
    return rows


# ── Mode probe ───────────────────────────────────────────────────────────
def probe_row(report) -> dict:
    t1 = report.tier1
    return {
        "status": "ok",
        # Un site injoignable n'a pas de tier : rien ne dit comment il se lirait.
        "tier": None if report.tls.get("verdict") == "injoignable" else report.chosen_tier,
        "rationale": report.rationale[:200],
        "platform": t1.get("platform"),
        "rss": len(t1.get("rss_feeds", [])),
        "api": len(t1.get("api_endpoints", [])),
        "sitemap": bool(t1.get("sitemap")),
        "robots_skipped": len(t1.get("skipped_by_robots", [])),
        "tls": report.tls.get("verdict"),
        **usage_columns(getattr(report, "usage", None) or {}),
        "known_platform": [f["platform"] for f in getattr(report, "known_platforms", None) or []],
        "generator": (getattr(report, "fingerprint", None) or {}).get("generator"),
        "asset_hosts": (getattr(report, "fingerprint", None) or {}).get("asset_hosts", []),
    }


def _reserved(value) -> bool:
    return str(value).strip() == "1"


def usage_columns(u: dict) -> dict:
    """Préférences d'usage d'une sonde, réduites à des colonnes comparables."""
    bots = u.get("ai_crawlers") or {}
    prefs = dict(u.get("content_usage_header") or {})
    for rule in u.get("robots_content_usage") or []:
        if rule.get("path") == "/":
            prefs = {**rule.get("prefs", {}), **prefs}
    tdm = u.get("tdmrep") or {}
    declared = [*(tdm.get("header") or {}).items(), *(tdm.get("html") or {}).items()]
    reserved = any(k == "tdm-reservation" and _reserved(v) for k, v in declared) or any(
        isinstance(e, dict) and _reserved(e.get("tdm-reservation")) for e in tdm.get("well_known") or []
    )
    return {
        "ai_blocked": sorted(b for b, v in bots.items() if v == "bloqué"),
        "ai_partial": sorted(b for b, v in bots.items() if v == "partiel"),
        "content_usage": prefs,
        "tdm_reservation": reserved,
        "llms_txt": bool((u.get("llms_txt") or {}).get("present")),
        "pay_per_crawl": bool(u.get("pay_per_crawl")),
    }


def probe_runner(*, deadline: float, copies: bool):
    from . import probe as probe_mod

    async def run(t: dict) -> dict:
        try:
            report = await probe_mod.probe(t["url"], deadline=deadline, copies=copies)
        except TimeoutError as e:
            return {"status": "timeout", "error": str(e)[:200]}
        return probe_row(report)

    return run


# ── Mode history ─────────────────────────────────────────────────────────
# L'archive qui refuse la connexion a fermé la porte pour un moment : une pause, un
# nouvel essai, puis le lot s'arrête ; les sites restants sont à reprendre (--resume).
ARCHIVE_COOLDOWN_S = 900.0


async def _cooldown_sleep(seconds: float) -> None:
    await asyncio.sleep(seconds)


def history_runner(*, deadline: float):
    from . import robots_history as rh

    closed = False

    async def once(netloc: str) -> dict:
        return await asyncio.wait_for(rh.robots_history(netloc), deadline)

    async def run(t: dict) -> dict:
        nonlocal closed
        if closed:
            return {"status": "archive_indisponible", "retry": True, "error": "non tenté : archive fermée"}
        netloc = urlsplit(t["url"]).netloc
        try:
            h = await once(netloc)
            if h.get("unavailable"):
                await _cooldown_sleep(ARCHIVE_COOLDOWN_S)
                h = await once(netloc)
        except TimeoutError:
            return {"status": "timeout", "error": f"échéance de {deadline:.0f} s"}
        if h.get("unavailable"):
            closed = True
            return {"status": "archive_indisponible", "retry": True, "error": str(h.get("error"))[:200]}
        return rh.history_row(h)

    return run


# ── Mode contents ────────────────────────────────────────────────────────
# Collecte déjà faite, facultative : <racine>/<site>/projects/*.json (écart en ligne / disque).
# La racine vient de `ACCESSPATH_CONTENTS_ROOT` ; sans elle, pas de comparaison au disque.
CONTENTS_DISK_ROOT = None


def contents_runner(*, deadline: float):
    from .acquisition import contents as pp

    env = os.environ.get("ACCESSPATH_CONTENTS_ROOT")
    root = CONTENTS_DISK_ROOT or (Path(env) if env else None)

    async def run(t: dict) -> dict:
        try:
            p = await asyncio.wait_for(
                pp.profile_contents(t["url"], disk_contents=pp.disk_contents(root, t["name"]) if root else None),
                deadline,
            )
        except TimeoutError:
            return {"status": "timeout", "error": f"échéance de {deadline:.0f} s"}
        return pp.contents_row(p)

    return run


# ── Mode inspect ─────────────────────────────────────────────────────────
async def run_subprocess(cmd: list[str], *, timeout: float, stall: float | None = None) -> str:
    """Lance `cmd` dans son propre groupe de processus. Rend « ok », « exit=N »,
    « timeout_killed » (échéance dépassée) ou « stalled » (rien écrit sur la sortie
    d'erreur pendant `stall` secondes : Chrome n'avance plus). Dans les deux derniers
    cas, le groupe entier reçoit SIGKILL."""
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.PIPE if stall else asyncio.subprocess.DEVNULL,
        start_new_session=True,
    )
    end = time.monotonic() + timeout
    outcome = None
    try:
        if stall:
            while True:
                try:
                    line = await asyncio.wait_for(proc.stderr.readline(), max(min(stall, end - time.monotonic()), 0))
                except TimeoutError:
                    outcome = "timeout_killed" if time.monotonic() >= end else "stalled"
                    break
                if not line:  # sortie fermée : le processus se termine
                    await asyncio.wait_for(proc.wait(), max(end - time.monotonic(), 0.1))
                    break
        else:
            await asyncio.wait_for(proc.wait(), timeout)
    except TimeoutError:
        outcome = "timeout_killed"
    if outcome:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        await proc.wait()
        return outcome
    return "ok" if proc.returncode == 0 else f"exit={proc.returncode}"


def _newest_report(probes_dir: Path, name: str, started: float) -> tuple[Path, dict] | None:
    found = [p for p in Path(probes_dir).glob(f"{name}_inspect_*.json") if p.stat().st_mtime >= started]
    for p in sorted(found, key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            return p, json.loads(p.read_text(encoding="utf-8"))
        except ValueError:
            continue
    return None


def find_inspect_report(probes_dir: Path, name: str, started: float) -> dict | None:
    """Le rapport JSON d'`inspect` le plus récent écrit depuis `started`, ou None."""
    hit = _newest_report(probes_dir, name, started)
    return hit[1] if hit else None


def _keep_profile(path: Path, profiles_dir: Path) -> None:
    """Copie le rapport JSON et son markdown dans le dossier de profils de l'étude."""
    profiles_dir.mkdir(parents=True, exist_ok=True)
    for p in (path, path.with_suffix(".md")):
        if p.exists():
            shutil.copy2(p, profiles_dir / p.name)


def inspect_row(report: dict) -> dict:
    detected = lambda d: [k for k, v in (d or {}).items() if isinstance(v, dict) and v.get("detected")]  # noqa: E731
    tr = report.get("trackers") or {}
    return {
        "regies": list(tr.get("regies") or []),
        "trackers": sorted(tr.get("vendors") or {}),
        "tracker_categories": sorted(tr.get("categories") or {}),
        "consent": list(tr.get("consent_manager") or []),
        "third_party": len(tr.get("third_party_domains") or []),
        "unclassified": list(tr.get("unclassified") or []),
        "browser": bool(report.get("browser_ran")),
        "tier": (report.get("tier_recommendation") or {}).get("primary"),
        "anti_bot": detected(report.get("anti_bot_stack")),
        "reachability": (report.get("reachability") or {}).get("status"),
        "redirected_to": (report.get("reachability") or {}).get("redirected_to") or None,
        "human_gate": (report.get("human_gate") or {}).get("kind"),
        "difficulty": report.get("scraping_difficulty"),
        "sitemap_urls": (report.get("sitemap") or {}).get("n_urls", 0),
        "frameworks": detected(report.get("frameworks")),
    }


def refresh_trackers(out_dir: Path) -> int:
    """Reclasse les traceurs d'un lot inspecté depuis ses profils, avec la table du
    moment ; rend le nombre de sites reclassés. Sans profil, la ligne reste telle quelle."""
    from . import trackers

    results = Path(out_dir) / "results.jsonl"
    rows = read_results(results)
    n = 0
    for row in rows:
        found = sorted((Path(out_dir) / "profils").glob(f"{row['name']}_inspect_*.json"))
        if not found:
            continue
        report = json.loads(found[-1].read_text(encoding="utf-8"))
        report["trackers"] = trackers.reclassify(report.get("trackers") or {})
        row.update({k: v for k, v in inspect_row(report).items() if k in TRACKER_COLUMNS})
        n += 1
    results.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows), encoding="utf-8")
    return n


TRACKER_COLUMNS = ("regies", "trackers", "tracker_categories", "consent", "third_party", "unclassified")


def _attempt_start() -> float:
    return time.time() - 1


def inspect_cmd(t: dict, config: str, *, allow_private: bool, browser: bool) -> list[str]:
    c = INSPECT_CONFIGS[config]
    cmd = [sys.executable, "-m", "accesspath", "sap", "inspect", t["url"], "--save", "--name", t["name"]]
    cmd += ["--timeout", str(c["capture_s"]), "--purpose", "research"]
    if c["headless"]:
        cmd.append("--headless")
    if allow_private:
        cmd.append("--allow-private")
    if browser:
        cmd.append("--browser")
    return cmd


def inspect_runner(
    *,
    deadline: float,
    allow_private: bool = False,
    browser: bool = False,
    profiles_dir: Path | None = None,
    configs: list[str] | tuple[str, ...] = DEFAULT_ROTATION,
):
    async def attempt(t: dict, config: str) -> dict:
        started = _attempt_start()
        cmd = inspect_cmd(t, config, allow_private=allow_private, browser=browser)
        stall = INSPECT_CONFIGS[config]["capture_s"] + STALL_GRACE_S
        outcome = await run_subprocess(cmd, timeout=deadline, stall=stall)
        hit = await asyncio.to_thread(_newest_report, PROBES_DIR, t["name"], started)
        if hit is None:
            status = "timeout" if outcome in ("timeout_killed", "stalled") else "error"
            return {"status": status, "error": f"{outcome}, aucun rapport"}
        if profiles_dir is not None:
            await asyncio.to_thread(_keep_profile, hit[0], profiles_dir)
        row = inspect_row(hit[1])
        # Rapport de repli : processus tué ou en échec, ou Chrome demandé sans avoir tourné.
        partial = outcome != "ok" or (browser and not row["browser"])
        return {"status": "partial" if partial else "ok", "outcome": outcome, **row}

    async def run(t: dict) -> dict:
        result: dict = {}
        tried = 0
        for config in configs:
            tried += 1
            result = {**await attempt(t, config), "config": config}
            if result["status"] == "ok":
                break
        return {**result, "attempts": tried}

    return run


# ── Synthèse ─────────────────────────────────────────────────────────────
def _table(title: str, counts: Counter, head: str) -> list[str]:
    if not counts:
        return []
    out = ["", f"## {title}", "", f"| {head} | Sites |", "|---|---:|"]
    out += [f"| {neutralize(k, 60)} | {n} |" for k, n in counts.most_common()]
    return out


def _duration(s: float) -> str:
    s = round(s)
    return f"{s // 60} min {s % 60} s" if s >= 60 else f"{s} s"


def summarize(name: str, rows: list[dict], *, invalid: list[dict] | None = None, elapsed_s: float | None = None) -> str:
    ok = [r for r in rows if r.get("status") == "ok"]
    light = sum(1 for r in ok if r.get("tier") in (1, 2))
    timing = []
    if elapsed_s is not None:
        spent = sum(r.get("duration_s") or 0 for r in rows)
        timing = [
            f"- Durée du passage : {_duration(elapsed_s)}",
            f"- Temps d'audit cumulé : {_duration(spent)} ({spent / max(len(rows), 1):.1f} s par site)",
        ]
    lines = [
        f"# Batch {neutralize(name, 64)}",
        "",
        f"- Sites : {len(rows)} ; audits réussis : {len(ok)}",
        *timing,
        *(
            [
                f"- Sans navigateur (tiers 1 et 2) : {light} sur {len(ok)}",
                f"- Sans accès machine (tier 5) : {sum(1 for r in ok if r.get('tier') == 5)}",
            ]
            if any("tier" in r for r in ok)
            else []
        ),
        *(
            [f"- Sites avec une régie : {sum(1 for r in ok if r.get('regies'))} sur {len(ok)}"]
            if any("regies" in r for r in ok)
            else []
        ),
        *(
            [
                f"- Sites qui bloquent au moins un robot d'IA : {sum(1 for r in ok if r.get('ai_blocked'))} sur {len(ok)}",
                f"- llms.txt : {sum(1 for r in ok if r.get('llms_txt'))} ; "
                f"Content-Usage : {sum(1 for r in ok if r.get('content_usage'))} ; "
                f"réservation TDM : {sum(1 for r in ok if r.get('tdm_reservation'))}",
            ]
            if any("ai_blocked" in r for r in ok)
            else []
        ),
        *(
            [f"- Sites injoignables : {sum(1 for r in ok if r.get('tls') == 'injoignable')}"]
            if any(r.get("tls") == "injoignable" for r in ok)
            else []
        ),
        *(
            [
                f"- Gestes humains annoncés : {sum(1 for r in ok if r.get('human_gate'))}"
                " — python -m accesspath gestes --faire"
            ]
            if any(r.get("human_gate") for r in ok)
            else []
        ),
        *(
            [f"- Redirigés vers un autre site : {sum(1 for r in ok if r.get('redirected_to'))}"]
            if any(r.get("redirected_to") for r in ok)
            else []
        ),
        f"- Lignes invalides : {len(invalid or [])}",
        "",
        DATA_BEGIN,
    ]
    if any("content_source" in r for r in ok):
        online = sum(r.get("contents") or 0 for r in ok)
        missing = sum(1 for r in ok if "content_source" in r and not r.get("content_source"))
        lines[-2:-2] = [f"- Contenus en ligne : {online} ; sites sans contenu trouvé : {missing}"]
    lines += _table("Statut", Counter(r.get("status") for r in rows), "Statut")
    lines += _table("Tier", Counter(r["tier"] for r in ok if r.get("tier") is not None), "Tier")
    lines += _table("Plateforme", Counter(r["platform"] for r in ok if r.get("platform")), "Plateforme")
    lines += _table(
        "Redirigés vers un autre site", Counter(r["redirected_to"] for r in ok if r.get("redirected_to")), "Hôte"
    )
    lines += _table("Empreinte TLS", Counter(r["tls"] for r in ok if r.get("tls")), "Verdict")
    lines += _table("Anti-bot", Counter(v for r in ok for v in r.get("anti_bot") or []), "Fournisseur")
    lines += _table("Robots d'IA bloqués", Counter(v for r in ok for v in r.get("ai_blocked") or []), "Robot")
    lines += _table("Régies", Counter(v for r in ok for v in r.get("regies") or []), "Régie")
    lines += _table("Traceurs tiers", Counter(v for r in ok for v in r.get("trackers") or []), "Fournisseur")
    lines += _table(
        "Catégories de traceurs", Counter(v for r in ok for v in r.get("tracker_categories") or []), "Catégorie"
    )
    lines += _table(
        "Domaines tiers non classés", Counter(v for r in ok for v in r.get("unclassified") or []), "Domaine"
    )
    first = Counter(d[:7] for r in ok for d in (r.get("first_blocked") or {}).values() if not d.startswith("≤"))
    lines += _table("Premiers blocages par mois", Counter(dict(sorted(first.items()))), "Mois")
    lines += _table("Réouvertures", Counter(b for r in ok for b in r.get("reopened") or {}), "Robot")
    lines += _table(
        "Source des contenus", Counter(r["content_source"] for r in ok if r.get("content_source")), "Source"
    )
    lines += _table("Accueil illisible", Counter(r["home_error"] for r in ok if r.get("home_error")), "Motif")
    lines += _table("Images des contenus", Counter(r["image_mode"] for r in ok if r.get("image_mode")), "Mode")
    hosts = Counter(h for r in ok for h in r.get("image_hosts") or [])
    lines += _table("Hôtes d'images partagés", Counter({h: n for h, n in hosts.items() if n > 1}), "Hôte")
    doors = Counter()
    for r in ok:
        doors.update(k for k in ("rss", "api", "sitemap") if r.get(k))
    lines += _table("Portes", doors, "Porte")
    lines += ["", DATA_END, ""]
    return "\n".join(lines)
