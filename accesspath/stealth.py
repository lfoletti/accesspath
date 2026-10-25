"""En-têtes HTTP de navigateur, cohérents entre eux.

Un client Python envoie par défaut des en-têtes que beaucoup de serveurs refusent ou
traitent à part ; l'audit veut voir le site comme un visiteur ordinaire. Chaque requête
reprend donc un profil de navigateur réel, entier. Un set = (UA, Accept, Accept-Language,
Accept-Encoding, Sec-Fetch-*, sec-ch-ua) qui matchent un vrai navigateur.

Accept-Encoding n'annonce que gzip, deflate et br : ce sont les seuls encodages
que le moteur décode (avec une limite de taille, cf. accesspath/_http.py). Annoncer
zstd sans le décoder rendait des corps illisibles.

Attention : ne pas mixer les headers (ex: Chrome UA avec Firefox-style Accept)
— les fingerprinters sérieux détectent ça. On rotationne par PROFIL ENTIER.

Usage :
    from .stealth import random_headers
    headers = random_headers(accept="application/rss+xml")
    headers = random_headers(extra={"Referer": "..."})
"""

from __future__ import annotations

import random

try:  # br n'est annoncé que s'il peut être décodé (cf. accesspath/_http.py)
    import brotli  # type: ignore  # noqa: F401

    _HAS_BROTLI = True
except ImportError:
    _HAS_BROTLI = False


# ── Profils browser réels (cohérents en interne) ───────────────────────────
# Sources : sniffés sur browsers actuels macOS + Linux. À refresh périodiquement.

BROWSER_PROFILES = [
    {
        "_name": "chrome_macos_131",
        "User-Agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
        ),
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,"
            "image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
        ),
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "sec-ch-ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"macOS"',
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
    },
    {
        "_name": "chrome_macos_130",
        "User-Agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
        ),
        "Accept": ("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"),
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "sec-ch-ua": '"Chromium";v="130", "Google Chrome";v="130", "Not?A_Brand";v="99"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"macOS"',
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Upgrade-Insecure-Requests": "1",
    },
    {
        "_name": "firefox_macos_131",
        "User-Agent": ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:131.0) Gecko/20100101 Firefox/131.0"),
        "Accept": ("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"),
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "DNT": "1",
        "Sec-GPC": "1",
        "Upgrade-Insecure-Requests": "1",
    },
    {
        "_name": "safari_macos_18",
        "User-Agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
            "(KHTML, like Gecko) Version/18.1 Safari/605.1.15"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
    },
    {
        "_name": "chrome_linux_131",
        "User-Agent": (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
        ),
        "Accept": ("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"),
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "sec-ch-ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Linux"',
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Upgrade-Insecure-Requests": "1",
    },
    {
        "_name": "firefox_linux_131",
        "User-Agent": ("Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0"),
        "Accept": ("text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"),
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br",
        "DNT": "1",
    },
]


# ── Variations Accept-Language ───────────────────────────────────────────
ACCEPT_LANGUAGES = [
    "en-US,en;q=0.9",
    "en-US,en;q=0.5",
    "en-GB,en;q=0.9",
    "en,en-US;q=0.9",
    "fr-FR,fr;q=0.9,en;q=0.7",
    "en-US,en;q=0.9,fr;q=0.5",
]


def random_profile() -> dict:
    """Retourne une copie d'un profil browser aléatoire (sans la clé _name)."""
    p = random.choice(BROWSER_PROFILES).copy()
    p.pop("_name", None)
    # Petite variation : 30% du temps on remplace Accept-Language
    if random.random() < 0.3:
        p["Accept-Language"] = random.choice(ACCEPT_LANGUAGES)
    return p


def random_headers(
    *,
    accept: str | None = None,
    referer: str | None = None,
    extra: dict | None = None,
    force_chrome_ch: bool = False,
) -> dict:
    """Génère un set de headers prêt à l'emploi.

    Args :
      accept           : override le header Accept (ex: 'application/json' pour API).
      referer          : ajoute un header Referer (ex: page de listing pour un détail).
      extra            : merge des headers custom à la fin.
      force_chrome_ch  : restreint la sélection aux profils Chrome qui incluent
                         les Client Hints (Sec-CH-UA*). Indispensable pour les sites
                         CF Bot Management qui rejettent (429 + cf-mitigated:challenge)
                         les requêtes sans `Sec-CH-UA` headers (ex: cabanamagazine.com).
    """
    if force_chrome_ch:
        chrome_profiles = [p for p in BROWSER_PROFILES if p.get("_name", "").startswith("chrome_")]
        h = random.choice(chrome_profiles).copy()
        h.pop("_name", None)
        if random.random() < 0.3:
            h["Accept-Language"] = random.choice(ACCEPT_LANGUAGES)
    else:
        h = random_profile()
    if not _HAS_BROTLI:
        h["Accept-Encoding"] = ", ".join(e.strip() for e in h["Accept-Encoding"].split(",") if e.strip() != "br")
    if accept:
        h["Accept"] = accept
    if referer:
        h["Referer"] = referer
    if extra:
        h.update(extra)
    return h


def profile_names() -> list[str]:
    """Liste les profils browser disponibles (pour audit/SAP doc)."""
    return [p["_name"] for p in BROWSER_PROFILES]
