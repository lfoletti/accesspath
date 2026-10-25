"""Traceurs tiers d'une page : qui est appelé, et pour quoi.

Deux sources : les adresses appelées par la page (capture réseau d'`inspect`, ou
`src`/`href` lus dans le HTML) et quelques signatures dans le HTML, pour les outils
hébergés chez le site lui-même (Matomo). Les hôtes du site ne comptent pas. Un domaine
de la table vaut pour lui-même et ses sous-domaines, jamais pour un nom qui le contient
seulement (« evil-doubleclick.net »).

Catégories : régie (publicité, enchères, vérification), audience (mesure de
fréquentation), enregistrement (session rejouée, cartes de clics), réseau social
(pixels), balises (gestionnaires de balises), consentement (bannières), profilage
(plateformes de données et identifiants publicitaires), intégration (vidéo, carte,
polices, chargées depuis un tiers).

La table grandit avec les domaines non classés des études (`unclassified`) ;
`reclassify` rejoue un résultat enregistré avec la table du moment.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

# domaine → (fournisseur, catégorie)
TRACKERS: dict[str, tuple[str, str]] = {
    # régies
    "doubleclick.net": ("Google Ad Manager", "régie"),
    "googlesyndication.com": ("Google AdSense", "régie"),
    "googleadservices.com": ("Google Ads", "régie"),
    "adservice.google.com": ("Google Ads", "régie"),
    "amazon-adsystem.com": ("Amazon Ads", "régie"),
    "criteo.com": ("Criteo", "régie"),
    "criteo.net": ("Criteo", "régie"),
    "taboola.com": ("Taboola", "régie"),
    "outbrain.com": ("Outbrain", "régie"),
    "adnxs.com": ("Xandr", "régie"),
    "smartadserver.com": ("Equativ", "régie"),
    "teads.tv": ("Teads", "régie"),
    "pubmatic.com": ("PubMatic", "régie"),
    "rubiconproject.com": ("Magnite", "régie"),
    "openx.net": ("OpenX", "régie"),
    "casalemedia.com": ("Index Exchange", "régie"),
    "adform.net": ("Adform", "régie"),
    "yieldlab.net": ("Yieldlab", "régie"),
    "360yield.com": ("Improve Digital", "régie"),
    "adition.com": ("Adition", "régie"),
    "goldbach.com": ("Goldbach", "régie"),
    "seedtag.com": ("Seedtag", "régie"),
    "quantserve.com": ("Quantcast", "régie"),
    "bat.bing.com": ("Microsoft Ads", "régie"),
    "adsrvr.org": ("The Trade Desk", "régie"),
    "mathtag.com": ("MediaMath", "régie"),
    "doubleverify.com": ("DoubleVerify", "régie"),
    "adsafeprotected.com": ("Integral Ad Science", "régie"),
    "id5-sync.com": ("ID5", "régie"),
    "eu-1-id5-sync.com": ("ID5", "régie"),
    "googletagservices.com": ("Google Ad Manager", "régie"),
    "adtrafficquality.google": ("Google Ads", "régie"),
    "adnxs-simple.com": ("Xandr", "régie"),
    "indexww.com": ("Index Exchange", "régie"),
    "gbads.net": ("Goldbach", "régie"),
    "gbadtech.io": ("Goldbach", "régie"),
    "nexx360.io": ("Nexx360", "régie"),
    "connectad.io": ("ConnectAd", "régie"),
    "ay.delivery": ("Assertive Yield", "régie"),
    "pbstck.com": ("Pubstack", "régie"),
    "brandmetrics.com": ("Brand Metrics", "régie"),
    "insurads.com": ("InsurAds", "régie"),
    "wemass.com": ("WeMass", "régie"),
    # profilage : plateformes de données, identifiants publicitaires
    "permutive.app": ("Permutive", "profilage"),
    "permutive.com": ("Permutive", "profilage"),
    "cxense.com": ("Piano (Cxense)", "profilage"),
    "demdex.net": ("Adobe Audience Manager", "profilage"),
    "rlcdn.com": ("LiveRamp", "profilage"),
    # audience
    "google-analytics.com": ("Google Analytics", "audience"),
    "analytics.google.com": ("Google Analytics", "audience"),
    "matomo.cloud": ("Matomo Cloud", "audience"),
    "innocraft.cloud": ("Matomo Cloud", "audience"),
    "siteimprove.com": ("Siteimprove", "audience"),
    "siteimproveanalytics.com": ("Siteimprove", "audience"),
    "siteimproveanalytics.io": ("Siteimprove", "audience"),
    "plausible.io": ("Plausible", "audience"),
    "etracker.com": ("etracker", "audience"),
    "etracker.de": ("etracker", "audience"),
    "statcounter.com": ("StatCounter", "audience"),
    "wemfbox.ch": ("WEMF / Mediapulse", "audience"),
    "ioam.de": ("INFOnline", "audience"),
    "mc.yandex.ru": ("Yandex Metrica", "audience"),
    "piwik.pro": ("Piwik PRO", "audience"),
    "wt-safetag.com": ("Mapp", "audience"),
    "cloudflareinsights.com": ("Cloudflare Web Analytics", "audience"),
    "simpleanalyticscdn.com": ("Simple Analytics", "audience"),
    "usefathom.com": ("Fathom", "audience"),
    "scorecardresearch.com": ("Comscore", "audience"),
    "chartbeat.com": ("Chartbeat", "audience"),
    "chartbeat.net": ("Chartbeat", "audience"),
    "parsely.com": ("Parse.ly", "audience"),
    "imrworldwide.com": ("Nielsen", "audience"),
    "dotmetrics.net": ("Dotmetrics", "audience"),
    "sensic.net": ("GfK", "audience"),
    "k5a.io": ("Kilkaya", "audience"),
    "omtrdc.net": ("Adobe Analytics", "audience"),
    "visualwebsiteoptimizer.com": ("VWO", "audience"),
    "kameleoon.eu": ("Kameleoon", "audience"),
    "mrf.io": ("Marfeel", "audience"),
    "piano.io": ("Piano", "audience"),
    "tinypass.com": ("Piano", "audience"),
    # enregistrement de session
    "hotjar.com": ("Hotjar", "enregistrement"),
    "hotjar.io": ("Hotjar", "enregistrement"),
    "clarity.ms": ("Microsoft Clarity", "enregistrement"),
    "mouseflow.com": ("Mouseflow", "enregistrement"),
    "fullstory.com": ("FullStory", "enregistrement"),
    "smartlook.com": ("Smartlook", "enregistrement"),
    "smartlook.cloud": ("Smartlook", "enregistrement"),
    "luckyorange.com": ("Lucky Orange", "enregistrement"),
    # pixels de réseaux sociaux
    "connect.facebook.net": ("Meta Pixel", "réseau social"),
    "snap.licdn.com": ("LinkedIn Insight", "réseau social"),
    "px.ads.linkedin.com": ("LinkedIn Insight", "réseau social"),
    "analytics.tiktok.com": ("TikTok Pixel", "réseau social"),
    "ct.pinterest.com": ("Pinterest Tag", "réseau social"),
    "static.ads-twitter.com": ("X Ads", "réseau social"),
    "sc-static.net": ("Snap Pixel", "réseau social"),
    # gestionnaires de balises
    "googletagmanager.com": ("Google Tag Manager", "balises"),
    "tags.tiqcdn.com": ("Tealium", "balises"),
    "cdn.segment.com": ("Segment", "balises"),
    "assets.adobedtm.com": ("Adobe Launch", "balises"),
    # consentement
    "cookiebot.com": ("Cookiebot", "consentement"),
    "cookiebot.eu": ("Cookiebot", "consentement"),
    "cookielaw.org": ("OneTrust", "consentement"),
    "onetrust.com": ("OneTrust", "consentement"),
    "usercentrics.eu": ("Usercentrics", "consentement"),
    "didomi.io": ("Didomi", "consentement"),
    "iubenda.com": ("iubenda", "consentement"),
    "cookieyes.com": ("CookieYes", "consentement"),
    "consentmanager.net": ("consentmanager", "consentement"),
    "cookiefirst.com": ("CookieFirst", "consentement"),
    "termly.io": ("Termly", "consentement"),
    "privacy-center.org": ("Didomi", "consentement"),
    "privacy-mgmt.com": ("Sourcepoint", "consentement"),
    "sp-prod.net": ("Sourcepoint", "consentement"),
    "privacymanager.io": ("LiveRamp Privacy Manager", "consentement"),
    "consensu.org": ("CMP (IAB TCF)", "consentement"),
    "trustarc.com": ("TrustArc", "consentement"),
    "truste.com": ("TrustArc", "consentement"),
    "axept.io": ("Axeptio", "consentement"),
    "consentframework.com": ("Sirdata", "consentement"),
    # intégrations
    "youtube.com": ("YouTube", "intégration"),
    "youtube-nocookie.com": ("YouTube", "intégration"),
    "ytimg.com": ("YouTube", "intégration"),
    "vimeo.com": ("Vimeo", "intégration"),
    "vimeocdn.com": ("Vimeo", "intégration"),
    "maps.googleapis.com": ("Google Maps", "intégration"),
    "maps.gstatic.com": ("Google Maps", "intégration"),
    "fonts.googleapis.com": ("Google Fonts", "intégration"),
    "fonts.gstatic.com": ("Google Fonts", "intégration"),
    "recaptcha.net": ("reCAPTCHA", "intégration"),
    "platform.twitter.com": ("X", "intégration"),
    "instagram.com": ("Instagram", "intégration"),
    "facebook.com": ("Facebook", "intégration"),
    "issuu.com": ("Issuu", "intégration"),
    "typekit.net": ("Adobe Fonts", "intégration"),
    "jwplayer.com": ("JW Player", "intégration"),
    "jwpsrv.com": ("JW Player", "intégration"),
    "jwpcdn.com": ("JW Player", "intégration"),
    "gigya.com": ("SAP Customer Data Cloud", "intégration"),
}

# (domaine, début de chemin) → (fournisseur, catégorie) : services servis depuis un
# domaine généraliste, reconnus par leur chemin.
PATH_TRACKERS: dict[tuple[str, str], tuple[str, str]] = {
    ("google.com", "/recaptcha/"): ("reCAPTCHA", "intégration"),
    ("gstatic.com", "/recaptcha/"): ("reCAPTCHA", "intégration"),
}

# Signatures dans le HTML : outils servis par le site lui-même.
HTML_SIGNATURES: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"_paq\.push\("), "Matomo (auto-hébergé)", "audience"),
    (re.compile(r"\bfbq\(\s*['\"]init"), "Meta Pixel", "réseau social"),
    (re.compile(r"_hjSettings"), "Hotjar", "enregistrement"),
    # API du cadre TCF de l'IAB : tout gestionnaire de consentement conforme l'expose
    (re.compile(r"__tcfapi"), "CMP (IAB TCF)", "consentement"),
]

# Deuxième niveau des domaines nationaux à deux labels (bbc.co.uk).
_SECOND_LEVEL = {"co", "com", "gov", "ac", "org", "net", "edu"}
# Balises qui chargent une ressource ; un lien <a> ne charge rien et n'est pas un traceur.
_LOADING_TAG = re.compile(r"<(script|iframe|img|embed|source|link)\b([^>]*)>", re.I)
_TAG_URL = re.compile(r"""\b(?:src|href)\s*=\s*["']((?:https?:)?//[^"'\s>]+)""", re.I)
_LINK_LOADS = re.compile(
    r"""\brel\s*=\s*["'][^"']*\b(stylesheet|preload|modulepreload|preconnect|dns-prefetch|icon)\b""", re.I
)


def _loaded_urls(html: str) -> list[str]:
    out = []
    for tag, attrs in _LOADING_TAG.findall(html or ""):
        if tag.lower() == "link" and not _LINK_LOADS.search(attrs):
            continue
        out += [u if u.startswith("http") else f"https:{u}" for u in _TAG_URL.findall(attrs)]
    return out


def _host(url: str) -> str:
    try:
        return (urlsplit(url if "//" in url else f"//{url}").hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def site_domain(url_or_host: str) -> str:
    """Domaine enregistrable approché : les deux derniers labels, trois pour `co.uk`."""
    labels = _host(url_or_host).split(".")
    n = 3 if len(labels) >= 3 and labels[-2] in _SECOND_LEVEL else 2
    return ".".join(labels[-n:])


def _match(host: str, path: str = "") -> tuple[str, str] | None:
    labels = host.split(".")
    for i in range(len(labels)):
        suffix = ".".join(labels[i:])
        hit = TRACKERS.get(suffix)
        if hit:
            return hit
        for (domain, prefix), vendor in PATH_TRACKERS.items():
            if suffix == domain and path.startswith(prefix):
                return vendor
    return None


def detect_trackers(urls: list[str], html: str, site_url: str) -> dict:
    """Fournisseurs tiers vus dans `urls` (réseau) et dans `html` (scripts, signatures)."""
    own = site_domain(site_url)
    found: dict[str, dict] = {}
    third: set[str] = set()
    named: set[str] = set()

    def note(vendor: str, category: str, source: str, host: str | None) -> None:
        v = found.setdefault(vendor, {"category": category, "source": source, "hosts": []})
        if host and host not in v["hosts"]:
            v["hosts"].append(host)

    html_urls = _loaded_urls(html)
    for source, batch in (("réseau", urls), ("html", html_urls)):
        for u in batch:
            if not u.lower().startswith(("http://", "https://")):  # data:, blob:, about:…
                continue
            host = _host(u)
            if not host or site_domain(host) == own:
                continue
            third.add(site_domain(host))
            hit = _match(host, urlsplit(u).path)
            if hit:
                named.add(site_domain(host))
                note(hit[0], hit[1], source, host)

    for pattern, vendor, category in HTML_SIGNATURES:
        if vendor == "Matomo (auto-hébergé)" and "Matomo Cloud" in found:
            continue
        if vendor not in found and pattern.search(html or ""):
            note(vendor, category, "html", None)

    for v in found.values():
        v["hosts"].sort()
    return _result(found, third, named)


def _result(found: dict, third: set[str], named: set[str]) -> dict:
    vendors = dict(sorted(found.items()))
    categories: dict[str, int] = {}
    for v in vendors.values():
        categories[v["category"]] = categories.get(v["category"], 0) + 1
    return {
        "vendors": vendors,
        "categories": dict(sorted(categories.items())),
        "regies": [k for k, v in vendors.items() if v["category"] == "régie"],
        "consent_manager": [k for k, v in vendors.items() if v["category"] == "consentement"],
        "third_party_domains": sorted(third),
        "unclassified": sorted(third - named),
    }


def reclassify(saved: dict) -> dict:
    """Résultat enregistré → même résultat avec la table du moment. Les fournisseurs déjà
    trouvés restent (signatures HTML comprises) ; les domaines tiers non classés sont
    relus, au niveau du domaine (les hôtes précis ne sont pas conservés)."""
    found = {k: dict(v) for k, v in (saved.get("vendors") or {}).items()}
    third = set(saved.get("third_party_domains") or [])
    named = third - set(saved.get("unclassified") or [])
    for domain in sorted(saved.get("unclassified") or []):
        hit = _match(domain)
        if hit:
            named.add(domain)
            v = found.setdefault(hit[0], {"category": hit[1], "source": "reclassement", "hosts": []})
            if domain not in v["hosts"]:
                v["hosts"].append(domain)
    return _result(found, third, named)
