"""SAP Inspect — analyse rapide et fiable de la mécanique interne d'un site.

Usage : `python -m accesspath sap inspect <url> [--name X] [--timeout 30]`

6 phases séquentielles fail-fast :
  A. Reachability check     — page charge / throttle / challenge / error
  B. Anti-bot stack         — Cloudflare / Akamai / PerimeterX / DataDome / etc.
  C. Framework markers      — Next.js / Apollo / Algolia / React/Vue / data islands
  D. Endpoint capture       — XHR/fetch (graphql, api, search) avec bodies
  E. Inline JSON islands    — script[type=application/...] keys + previews
  F. Tier recommendation    — heuristique sur les findings → suggestion + rationale

Outputs (sauvés sous data/probes/) :
  <name>_inspect_<date>.json    — structuré, merge-able dans SAP entry
  <name>_inspect_<date>.md      — rapport humain

Driver : nodriver. Un ralentissement lié à l'adresse IP est signalé dans le rapport.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import re
import shutil
import tempfile
import time
import xml.etree.ElementTree as _ET
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from urllib.parse import urlparse

from . import _http
from ._safe import (
    DATA_BEGIN,
    DATA_END,
    neutralize,
    safe_path,
    safe_write_text,
    validate_site_name,
)
from .browser.cdp import CHROME_PATH
from .config import DATA_DIR
from .human_gate import LOGIN_PAGE_MAX_LINKS, HumanGate, predict_human_gate
from .trackers import detect_trackers

PROBES_DIR = DATA_DIR / "probes"
log = logging.getLogger(__name__)

# ── Patterns de filtrage statique + ad-tech ───────────────────────────────
STATIC_EXTS = (
    ".png",
    ".jpg",
    ".jpeg",
    ".webp",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".otf",
    ".eot",
    ".css",
    ".css.map",
    ".js.map",
)
AD_TECH_HOSTS = (
    "googletagmanager.com",
    "google-analytics.com",
    "googleadservices.com",
    "doubleclick.net",
    "googlesyndication.com",
    "facebook.net",
    "facebook.com/tr",
    "hotjar.com",
    "criteo.com",
    "adsystem.com",
    "adnxs.com",
    "adsrvr.org",
    "usercentrics.eu",
    "consensu.org",
    "trustarc.com",
    "onetrust.com",
    "sentry-cdn.com",
    "bugsnag.com",
    "newrelic.com",
    "datadog.com",
    "snowplowanalytics.com",
    "segment.io",
    "mixpanel.com",
    "amplitude.com",
)
TELEMETRY_PATH_PATTERNS = ("/api/t/", "/telemetry/", "/beacon/", "/log/", "/track/")


# ── Anti-bot signatures ───────────────────────────────────────────────────
# Format : nom → list[(detector_kind, pattern)] où detector_kind ∈ {"header_key", "header_value_substr", "url_substr", "html_substr", "title_substr"}
ANTI_BOT_SIGS = {
    "cloudflare": [
        ("header_key", "cf-ray"),
        ("title_substr", "Just a Moment"),
        ("title_substr", "Attention Required"),
        ("html_substr", "_cf_chl_opt"),
        ("html_substr", "challenge-platform"),
    ],
    "akamai": [
        # Bot Manager : paths obfusqués servent des sensor scripts JS
        ("url_substr", "/akam/"),
        ("html_substr", "/akamai/sensor"),
        ("header_value_substr", "AkamaiGHost"),
        ("header_key", "akamai-cache-status"),
    ],
    "perimeterx": [
        ("url_substr", "/_pxhd/"),
        ("url_substr", "client.perimeterx.net"),
        ("header_value_substr", "px-block"),
        ("html_substr", "_pxhd"),
    ],
    "datadome": [
        ("header_key", "x-datadome"),
        ("url_substr", "datadome.co"),
        ("html_substr", "dd_cookie_test"),
    ],
    "kasada": [
        ("html_substr", "kpsdk-ct"),
        ("url_substr", "ips-invite.io"),
        ("header_key", "x-kpsdk-ct"),
    ],
    "imperva": [
        ("html_substr", "Incapsula"),
        ("url_substr", "incapsula.com"),
        ("header_key", "x-iinfo"),
    ],
    "fortiadc": [
        # Pare-feu Fortinet : 302 vers une page CAPTCHA servie en 200 (registres chregister, 10.2026)
        ("url_substr", "/fortiadc_captcha/"),
        ("html_substr", "fortiadc_captcha_iframe"),
    ],
}

# Page CAPTCHA de FortiADC : elle répond 200, seule son adresse la trahit.
FORTIADC_CAPTCHA_PATH = "/fortiadc_captcha/"


# ── Endpoint categorisation ──────────────────────────────────────────────
def _categorize_url(url: str) -> str:
    u = url.lower()
    if any(u.endswith(ext) for ext in STATIC_EXTS):
        return "static"
    if "/static/" in u or "/_next/static/" in u or "/dist/" in u:
        return "static"
    if any(host in u for host in AD_TECH_HOSTS):
        return "ad-tech"
    if "/graphql" in u:
        return "graphql"
    if any(p in u for p in TELEMETRY_PATH_PATTERNS):
        return "telemetry"
    if "algolianet.com" in u or "/search/" in u and "/queries" in u:
        return "search"
    if "/api/" in u or "/wp-json/" in u or "/v1/" in u or "/v2/" in u:
        return "api-rest"
    if u.endswith(".xml") or "/sitemap" in u or "/feed" in u or "/rss" in u:
        return "sitemap-feed"
    return "other"


# ── Dataclasses ──────────────────────────────────────────────────────────
@dataclass
class Reachability:
    status: str  # "OK" | "throttled" | "challenge" | "blocked" | "error"
    page_status: int = 0
    body_length: int = 0
    title: str = ""
    final_url: str = ""
    evidence: str = ""
    hard_block: bool = False  # page de blocage explicite : refus net, pas un défi à passer
    redirected_to: str = ""  # hôte d'un autre site vers lequel l'accueil redirige


# Pages de blocage explicites : le site refuse cette adresse, il n'y a pas de défi à passer.
BLOCK_PAGE_MARKERS = (
    "sorry, you have been blocked",
    "why have i been blocked",
    "used cloudflare to restrict access",
)


def _site_host(url: str) -> str:
    host = (urlparse(url).hostname or "").lower()
    return host[4:] if host.startswith("www.") else host


def foreign_redirect(target_url: str, final_url: str) -> str:
    """Hôte final quand l'accueil redirige vers un autre site ; "" pour le même site
    (avec ou sans www, ou un de ses sous-domaines)."""
    if not final_url:
        return ""
    a, b = _site_host(target_url), _site_host(final_url)
    if not a or not b or a == b or b.endswith("." + a) or a.endswith("." + b):
        return ""
    return (urlparse(final_url).hostname or "").lower()


def classify_page(title: str, body_text: str, target_url: str, final_url: str) -> Reachability:
    """Joignabilité d'une page lue par Chrome : servie, vide, défi, ou refus net."""
    body_len = len(body_text) if isinstance(body_text, str) else 0
    text = f"{title}\n{body_text if isinstance(body_text, str) else ''}".casefold()
    common = {"title": title, "body_length": body_len, "final_url": final_url}
    if body_len == 0 and not title:
        reach = Reachability(
            status="throttled", evidence="page returned empty (body=0 + title=''). IP throttle suspected.", **common
        )
    elif any(m in text for m in BLOCK_PAGE_MARKERS):
        reach = Reachability(
            status="blocked",
            hard_block=True,
            evidence=f"page de blocage explicite : {title!r}",
            **common,
        )
    elif FORTIADC_CAPTCHA_PATH in (final_url or ""):
        reach = Reachability(status="challenge", evidence=f"CAPTCHA FortiADC : {final_url}", **common)
    elif any(m in title.casefold() for m in ("just a moment", "attention required")):
        reach = Reachability(
            status="challenge", evidence=f"page title indicates anti-bot challenge: {title!r}", **common
        )
    else:
        reach = Reachability(status="OK", evidence=f"page loaded, body={body_len} chars", **common)
    reach.redirected_to = foreign_redirect(target_url, final_url)
    return reach


@dataclass
class AntiBotDetection:
    detected: bool
    evidence: list[str] = field(default_factory=list)


@dataclass
class FrameworkDetection:
    detected: bool
    detail: str = ""


@dataclass
class EndpointSummary:
    url: str
    method: str
    status: int
    content_type: str
    category: str
    occurrences: int = 1


@dataclass
class GraphQLCall:
    url: str
    operation_name: str | None
    query_preview: str
    variables: dict
    response_preview: str = ""


@dataclass
class DataIsland:
    selector: str
    size: int
    keys: list[str]
    preview: str


@dataclass
class LinkCluster:
    pattern: str
    count: int
    samples: list[str]
    cluster_type: str  # "items" | "listings" | "pagination" | "navigation" | "other"


@dataclass
class PaginationPattern:
    kind: str  # ex: "query:page", "path:/page/N/"
    max_observed: int | None
    sample_url: str


@dataclass
class LinkArchitecture:
    total_anchors: int
    same_domain_count: int
    external_domains: list[str]
    clusters: list[LinkCluster]
    pagination_patterns: list[PaginationPattern]
    nav_anchors_count: int
    suggested_seeds: list[str]


@dataclass
class RobotsAnalysis:
    """Phase I — robots.txt parsing per RFC 9309."""

    fetched: bool
    status: int = 0
    user_agent_groups: dict[str, dict] = field(default_factory=dict)
    sitemaps: list[str] = field(default_factory=list)
    has_specific_ua_rules: bool = False
    flagged_paths_count: int = 0
    crawl_delay: float | None = None
    ai_bots_blocked: list[str] = field(default_factory=list)
    notes: str = ""


@dataclass
class SitemapAnalysis:
    """Phase I — Sitemap.xml parsing per Sitemaps.org protocol."""

    fetched: bool
    url: str = ""
    is_index: bool = False
    n_urls: int = 0
    n_sitemaps: int = 0
    sub_sitemaps: list[str] = field(default_factory=list)
    sample_urls: list[str] = field(default_factory=list)
    has_extensions: list[str] = field(default_factory=list)
    earliest_lastmod: str | None = None
    latest_lastmod: str | None = None


@dataclass
class StructuralFeatures:
    """Phase H — Lindemann/Thapa-style HOMEPAGE structural features."""

    n_internal_links: int = 0
    n_external_links: int = 0
    internal_external_ratio: float = 0.0
    n_forms: int = 0
    has_login_form: bool = False
    has_search_form: bool = False
    has_signup_form: bool = False
    has_cart_form: bool = False
    has_comment_form: bool = False
    has_contact_form: bool = False
    n_imgs: int = 0
    n_articles: int = 0
    n_h1: int = 0
    n_h2_h3: int = 0
    n_paragraphs: int = 0
    n_tables: int = 0
    n_iframes: int = 0
    schema_types: list[str] = field(default_factory=list)
    structured_data_formats: list[str] = field(default_factory=list)  # ["json-ld", "microdata", "rdfa", "opengraph"]
    has_paywall_marker: bool = False
    has_consent_wall: bool = False
    has_login_link: bool = False


@dataclass
class EthicsCheck:
    """Phase J — Khoury/Krotov-style legal+ethics flags."""

    robots_allows_root: bool = True
    ai_bots_blocked: list[str] = field(default_factory=list)
    crawl_delay: float | None = None
    tos_link_found: str | None = None
    privacy_link_found: str | None = None
    has_consent_wall: bool = False
    has_paywall_marker: bool = False
    requires_login_marker: bool = False
    is_eu_geo_targeting: bool = False
    user_profile_pages_detected: bool = False
    estimated_legal_risk: str = "low"  # low | medium | high
    notes: list[str] = field(default_factory=list)


@dataclass
class CategoryPrediction:
    """Phase K — Lindemann-inspired category prediction."""

    category: str = "unknown"
    subcategory: str = "unknown"
    confidence: float = 0.0
    reasoning: list[str] = field(default_factory=list)


@dataclass
class TierRecommendation:
    primary: int
    rationale: str
    fallbacks: list[int] = field(default_factory=list)


@dataclass
class InspectReport:
    target_url: str
    name: str
    timestamp: str
    duration_s: float
    reachability: Reachability
    anti_bot_stack: dict[str, AntiBotDetection]
    frameworks: dict[str, FrameworkDetection]
    endpoints: list[EndpointSummary]
    graphql_calls: list[GraphQLCall]
    inline_data_islands: list[DataIsland]
    link_architecture: LinkArchitecture | None
    # New v2 fields (post-knowledge synthesis)
    robots: RobotsAnalysis | None = None
    sitemap: SitemapAnalysis | None = None
    structural_features: StructuralFeatures | None = None
    ethics_check: EthicsCheck | None = None
    category_prediction: CategoryPrediction | None = None
    scraping_difficulty: int | None = None  # 1-5 scale (Mitchell)
    tier_recommendation: TierRecommendation | None = None
    # v3 (post-reprioritization)
    purpose: str = "research"
    skipped_browser_stage2: bool = False  # True si Stage 1 cheap suffit
    knn_prior: KNNPrior | None = None
    human_gate: HumanGate | None = None  # geste humain prévu (human_gate.py)
    trackers: dict = field(default_factory=dict)  # traceurs tiers (trackers.py)
    browser_ran: bool = False  # Chrome a chargé la page (étape 2 complète)


# ── Anti-bot detection helpers ───────────────────────────────────────────
def _detect_anti_bot(
    *,
    title: str,
    html: str,
    captured_urls: list[str],
    captured_headers: list[dict],
) -> dict[str, AntiBotDetection]:
    """Itère sur les signatures connues, retourne {nom: AntiBotDetection}."""
    out: dict[str, AntiBotDetection] = {}
    title_lower = title.lower()
    html_lower = html.lower() if html else ""

    for name, sigs in ANTI_BOT_SIGS.items():
        evidence: list[str] = []
        for kind, pat in sigs:
            pat_lower = pat.lower()
            if kind == "url_substr":
                hits = [u for u in captured_urls if pat_lower in u.lower()]
                if hits:
                    evidence.append(f"url contains {pat!r} ({len(hits)} hits, e.g. {hits[0][:80]!r})")
            elif kind == "header_key":
                for h in captured_headers:
                    if any(k.lower() == pat_lower for k in h):
                        evidence.append(f"response header {pat!r} present")
                        break
            elif kind == "header_value_substr":
                for h in captured_headers:
                    for k, v in h.items():
                        if isinstance(v, str) and pat_lower in v.lower():
                            evidence.append(f"header value contains {pat!r} ({k}={v[:60]!r})")
                            break
            elif kind == "html_substr":
                if pat_lower in html_lower:
                    evidence.append(f"html contains {pat!r}")
            elif kind == "title_substr":
                if pat_lower in title_lower:
                    evidence.append(f"page title contains {pat!r}")
        out[name] = AntiBotDetection(detected=bool(evidence), evidence=evidence)
    return out


# ── Framework detection ──────────────────────────────────────────────────
async def _detect_frameworks(tab) -> dict[str, FrameworkDetection]:
    """Probe DOM markers via tab.evaluate.

    Algolia detection : on cible des composants WIDGET spécifiques (Hits, MenuSelect,
    RefinementList, SearchBox, InfiniteHits) plutôt que `[class*="ais-"]` générique
    qui matche aussi des classes utilitaires CSS (ais-toolbar, ais-button) sans
    rapport avec un widget actif. Validé 2026-04-25 : sur dezeen, l'ancienne regex
    flaggait Algolia (false positive), la nouvelle ne le fait pas.
    """
    js = """
    (() => {
        const result = {};
        const nextEl = document.querySelector('script#__NEXT_DATA__');
        result.nextjs = {detected: !!nextEl, size: nextEl ? nextEl.textContent.length : 0};
        result.apollo = {detected: !!window.__APOLLO_STATE__};
        result.initial_state = {detected: !!(window.__INITIAL_STATE__ || window.__PRELOADED_STATE__)};
        // Algolia : cible composants widget spécifiques (pas [class*="ais-"] générique)
        const aisSelectors = [
            '.ais-Hits-item', '.ais-Hits-list',
            '.ais-InfiniteHits-item', '.ais-InfiniteHits-list',
            '.ais-MenuSelect', '.ais-MenuSelect-select',
            '.ais-RefinementList', '.ais-SearchBox',
            '.ais-Pagination', '.ais-Stats',
        ];
        const aisHits = aisSelectors.reduce((acc, sel) => acc + document.querySelectorAll(sel).length, 0);
        result.algolia_instantsearch = {
            detected: aisHits > 0,
            ais_count: aisHits,
            generic_class_count: document.querySelectorAll('[class*="ais-"]').length,
        };
        result.react = {detected: !!document.querySelector('[data-reactroot], [data-reactid]') || !!window.React};
        result.vue = {detected: !!document.querySelector('[data-v-app], [v-cloak]') || !!window.Vue};
        // Inline JSON islands
        const islands = Array.from(document.querySelectorAll('script[type^="application/"]'));
        result.json_islands_count = islands.length;
        return JSON.stringify(result);
    })()
    """
    try:
        raw = await tab.evaluate(js)
        data = json.loads(raw) if isinstance(raw, str) else raw
    except Exception as e:
        return {"_error": FrameworkDetection(False, f"evaluate failed: {e}")}

    out: dict[str, FrameworkDetection] = {}
    out["nextjs"] = FrameworkDetection(
        detected=data["nextjs"]["detected"],
        detail=f"__NEXT_DATA__ size={data['nextjs']['size']:,}" if data["nextjs"]["detected"] else "no __NEXT_DATA__",
    )
    out["apollo"] = FrameworkDetection(
        detected=data["apollo"]["detected"],
        detail="window.__APOLLO_STATE__" if data["apollo"]["detected"] else "absent",
    )
    out["initial_state"] = FrameworkDetection(
        detected=data["initial_state"]["detected"],
        detail="__INITIAL_STATE__ or __PRELOADED_STATE__" if data["initial_state"]["detected"] else "absent",
    )
    ais_count = data["algolia_instantsearch"]["ais_count"]
    ais_generic = data["algolia_instantsearch"]["generic_class_count"]
    if ais_count > 0:
        detail = f"{ais_count} widget components (.ais-Hits-item, .ais-MenuSelect, etc.)"
    elif ais_generic > 0:
        detail = f"{ais_generic} generic ais-* classes (likely CSS-only, no widget)"
    else:
        detail = "no Algolia markers"
    out["algolia_instantsearch"] = FrameworkDetection(
        detected=ais_count > 0,
        detail=detail,
    )
    out["react"] = FrameworkDetection(
        detected=data["react"]["detected"],
        detail="data-react* or window.React" if data["react"]["detected"] else "no obvious markers",
    )
    out["vue"] = FrameworkDetection(
        detected=data["vue"]["detected"],
        detail="data-v-app or window.Vue" if data["vue"]["detected"] else "absent",
    )
    out["_json_islands_count"] = FrameworkDetection(
        detected=data["json_islands_count"] > 0,
        detail=f"{data['json_islands_count']} script[type=application/...] tags",
    )
    return out


# ── Link architecture extraction (Phase G) ──────────────────────────────
async def _extract_anchors(tab) -> list[dict]:
    """Extrait tous les <a href> de la page chargée + leur position structurelle.

    Pour chaque anchor : href, text (truncated), ancestor_section
    (header/footer/nav/main/aside/other).
    """
    js = """
    (() => {
        const anchors = Array.from(document.querySelectorAll('a[href]')).slice(0, 800);
        const out = [];
        for (const a of anchors) {
            const href = a.getAttribute('href');
            if (!href) continue;
            // Ancestor section detection
            let section = 'body';
            let el = a;
            while (el && el !== document.body) {
                const tag = (el.tagName || '').toLowerCase();
                if (tag === 'header') { section = 'header'; break; }
                if (tag === 'footer') { section = 'footer'; break; }
                if (tag === 'nav') { section = 'nav'; break; }
                if (tag === 'aside') { section = 'aside'; break; }
                if (tag === 'main') { section = 'main'; break; }
                el = el.parentElement;
            }
            out.push({
                href: href,
                text: (a.textContent || '').trim().slice(0, 80),
                section: section,
            });
        }
        return JSON.stringify(out);
    })()
    """
    try:
        raw = await tab.evaluate(js)
        return json.loads(raw) if isinstance(raw, str) else raw
    except Exception:
        return []


def _normalize_path_pattern(path: str) -> str:
    """Convertit un path concret en un pattern abstrait :
    /article/the-title-of-the-piece → /article/<slug>
    /products/12345 → /products/<N>
    /2026/04/article → /<YYYY>/<N>/<slug>
    /galeries/photos/Diane-Legrand,75417.html → /galeries/photos/<slug>,<N>.html

    NB : on évite le placeholder `<MM>` (trop ambigu vs `<N>` court). YYYY
    seul pour les 4-digit-years. Sinon `<N>` pour tout digit-only segment.
    """
    parts = path.split("/")
    out = []
    for p in parts:
        if not p:
            out.append(p)
            continue
        # Pure digits
        if p.isdigit():
            if len(p) == 4 and 1990 <= int(p) <= 2100:
                out.append("<YYYY>")
            else:
                out.append("<N>")
            continue
        # Year-Month combo (2026-04)
        if re.match(r"^\d{4}-\d{2}$", p):
            out.append("<YYYY-MM>")
            continue
        # Slug,N.ext (ex: Diane-Legrand,75417.html — pattern fashionnetwork)
        m = re.match(r"^([a-z0-9-]+),(\d+)\.(html|htm|php|asp|aspx)$", p, re.I)
        if m:
            out.append(f"<slug>,<N>.{m.group(3).lower()}")
            continue
        # Slug,N (sans extension)
        m = re.match(r"^([a-z0-9-]+),(\d+)$", p, re.I)
        if m:
            out.append("<slug>,<N>")
            continue
        # Slug-N.ext (ex: article-name-123.html)
        m = re.match(r"^([a-z0-9-]+)-(\d{3,})\.(html|htm|php|asp|aspx)$", p, re.I)
        if m:
            out.append(f"<slug>-<N>.{m.group(3).lower()}")
            continue
        # Slug-N (article-name-123)
        m = re.match(r"^([a-z0-9-]+)-(\d{4,})$", p, re.I)
        if m:
            out.append("<slug>-<N>")
            continue
        # Slug.ext seul
        m = re.match(r"^([a-z0-9-]+)\.(html|htm|php|asp|aspx)$", p, re.I)
        if m:
            seg = m.group(1)
            ext = m.group(2).lower()
            if "-" in seg or len(seg) > 12:
                out.append(f"<slug>.{ext}")
            else:
                out.append(p)
            continue
        # Slug pur (alphanumeric + hyphens, has hyphen ou > 12 chars)
        if re.match(r"^[a-z0-9-]+$", p, re.I) and ("-" in p or len(p) > 12):
            out.append("<slug>")
            continue
        out.append(p)
    return "/".join(out)


def _normalize_query_pattern(query: str) -> str:
    """?page=5&order=date → ?page=<N>&order=date"""
    if not query:
        return ""
    parts = []
    for kv in query.split("&"):
        if "=" not in kv:
            parts.append(kv)
            continue
        k, v = kv.split("=", 1)
        if v.isdigit():
            parts.append(f"{k}=<N>")
        else:
            parts.append(kv)
    return "?" + "&".join(parts)


def _classify_cluster(pattern: str, count: int) -> str:
    """Heuristique pour étiqueter le type d'un cluster d'URLs."""
    p = pattern.lower()
    if "<n>" in p and ("page" in p or "/p/" in p or "?p=" in p or "offset" in p):
        return "pagination"
    if "<slug>" in p and "<n>" in p:
        return "items"  # ex: /article/<slug>-<N>
    if "<slug>" in p and count >= 5:
        return "items"
    if pattern.endswith("/") and count <= 5:
        return "navigation"
    if count == 1 and "<" not in pattern:
        return "navigation"
    if count >= 3 and "<" not in pattern:
        return "listings"
    return "other"


def _analyze_link_architecture(anchors: list[dict], base_url: str) -> LinkArchitecture:
    """Analyse les anchors capturés. Filtre external domains, cluster les
    same-domain URLs, détecte pagination, identifie nav links.
    """
    from urllib.parse import urlparse

    parsed_base = urlparse(base_url)
    base_host = parsed_base.netloc
    # Same-domain = même host OU sous-domaines proches (ex: img01.boutique.ch pour
    # www.boutique.ch — même eTLD+1 simple). Heuristique : on garde les domaines
    # se terminant par le eTLD+1 (split sur dot, dernier 2-3 segments).
    base_etld = ".".join(base_host.split(".")[-2:])

    same_domain_anchors: list[dict] = []
    external_domains_set: set[str] = set()

    for a in anchors:
        href = a["href"]
        if href.startswith(("javascript:", "mailto:", "tel:", "#")):
            continue
        if href.startswith("//"):
            href = parsed_base.scheme + ":" + href
        if href.startswith("/"):
            # relative → same-domain implicite
            same_domain_anchors.append(
                {
                    "url": f"{parsed_base.scheme}://{base_host}{href}",
                    "text": a["text"],
                    "section": a["section"],
                }
            )
            continue
        if not href.startswith(("http://", "https://")):
            # Relative weird — skip
            continue
        try:
            p = urlparse(href)
        except Exception:
            continue
        host = p.netloc
        if host == base_host or host.endswith("." + base_etld) or base_etld in host:
            same_domain_anchors.append(
                {
                    "url": href,
                    "text": a["text"],
                    "section": a["section"],
                }
            )
        else:
            # Domaine externe — on note mais on filtre out
            if host:
                external_domains_set.add(host)

    # Cluster same-domain URLs by pattern
    from collections import defaultdict

    pattern_groups: dict[str, list[dict]] = defaultdict(list)
    for a in same_domain_anchors:
        try:
            p = urlparse(a["url"])
            path_pattern = _normalize_path_pattern(p.path)
            query_pattern = _normalize_query_pattern(p.query)
            pattern = path_pattern + query_pattern
        except Exception:
            pattern = a["url"]
        pattern_groups[pattern].append(a)

    clusters_list: list[LinkCluster] = []
    for pattern, items in pattern_groups.items():
        cluster_type = _classify_cluster(pattern, len(items))
        samples = [it["url"] for it in items[:3]]
        clusters_list.append(
            LinkCluster(
                pattern=pattern,
                count=len(items),
                samples=samples,
                cluster_type=cluster_type,
            )
        )
    clusters_list.sort(key=lambda c: -c.count)

    # Pagination patterns detection — extract numeric values for ?page= and similar
    pagination: list[PaginationPattern] = []
    pag_kinds: dict[str, list[int]] = defaultdict(list)
    pag_samples: dict[str, str] = {}
    for a in same_domain_anchors:
        url = a["url"]
        # query-style
        for m in re.finditer(r"[?&](page|p|offset|start)=(\d+)", url, re.I):
            kind = f"query:{m.group(1).lower()}"
            pag_kinds[kind].append(int(m.group(2)))
            pag_samples.setdefault(kind, url)
        # path-style /page/N/
        for m in re.finditer(r"/(?:page|p)/(\d+)/?", url, re.I):
            kind = "path:/page/N/"
            pag_kinds[kind].append(int(m.group(1)))
            pag_samples.setdefault(kind, url)
    for kind, vals in pag_kinds.items():
        pagination.append(
            PaginationPattern(
                kind=kind,
                max_observed=max(vals) if vals else None,
                sample_url=pag_samples[kind][:160],
            )
        )

    nav_count = sum(1 for a in same_domain_anchors if a["section"] in ("nav", "header"))

    # Suggested seeds : top "listings" + "items" patterns + pagination
    suggested: list[str] = []
    listing_clusters = [c for c in clusters_list if c.cluster_type == "listings"][:3]
    item_clusters = [c for c in clusters_list if c.cluster_type == "items"][:2]
    for c in listing_clusters:
        suggested.append(f"{c.pattern}  ({c.count} liens — listings cluster)")
    for c in item_clusters:
        suggested.append(f"{c.pattern}  ({c.count} liens — items cluster)")
    for p in pagination[:2]:
        m = f", max=p={p.max_observed}" if p.max_observed else ""
        suggested.append(f"pagination via {p.kind}{m} (sample: {p.sample_url})")

    return LinkArchitecture(
        total_anchors=len(anchors),
        same_domain_count=len(same_domain_anchors),
        external_domains=sorted(external_domains_set)[:15],
        clusters=clusters_list[:30],  # cap pour éviter explosion JSON
        pagination_patterns=pagination,
        nav_anchors_count=nav_count,
        suggested_seeds=suggested,
    )


# ── Inline data islands extraction ──────────────────────────────────────
async def _extract_data_islands(tab, max_islands: int = 5) -> list[DataIsland]:
    """Pour chaque <script type="application/..."> dans le DOM, extrait
    selector + size + keys + preview."""
    js = f"""
    (() => {{
        const out = [];
        const scripts = Array.from(document.querySelectorAll('script[type^="application/"]')).slice(0, {max_islands});
        for (const s of scripts) {{
            const id = s.id ? `#${{s.id}}` : '';
            const type = s.type;
            const selector = `script[type="${{type}}"]${{id}}`;
            const text = s.textContent || '';
            let keys = [];
            try {{
                const parsed = JSON.parse(text);
                if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {{
                    keys = Object.keys(parsed).slice(0, 20);
                }}
            }} catch(e) {{}}
            out.push({{selector, size: text.length, keys, preview: text.slice(0, 200)}});
        }}
        return JSON.stringify(out);
    }})()
    """
    try:
        raw = await tab.evaluate(js)
        items = json.loads(raw) if isinstance(raw, str) else raw
    except Exception:
        return []
    return [DataIsland(**it) for it in items]


# ── Tier recommendation heuristic ────────────────────────────────────────
def _recommend_tier(*, reachability: Reachability, **kwargs) -> TierRecommendation:
    """Tier recommandé ; la raison dit d'abord si l'accueil redirige vers un autre site."""
    rec = _recommend_tier_core(reachability=reachability, **kwargs)
    if reachability.redirected_to:
        rec.rationale = (
            f"Le domaine redirige vers {reachability.redirected_to} : l'audit porte sur ce site-là, "
            f"pas sur un site propre. {rec.rationale}"
        )
    return rec


def _recommend_tier_core(
    *,
    reachability: Reachability,
    anti_bot: dict[str, AntiBotDetection],
    frameworks: dict[str, FrameworkDetection],
    endpoints: list[EndpointSummary],
    graphql_calls: list[GraphQLCall],
    requires_login: bool = False,
    robots_disallows_root: bool = False,
    browser: bool = False,
) -> TierRecommendation:
    """Heuristique simple — sera affinée à mesure qu'on couvre plus de sites.

    `browser` : la joignabilité vient d'un vrai Chrome (étape 2). Seul ce cas peut
    conclure au tier 5 : Chrome lui-même reste sur une page de défi."""
    has_cf = anti_bot.get("cloudflare", AntiBotDetection(False)).detected
    has_akamai = anti_bot.get("akamai", AntiBotDetection(False)).detected
    has_other_bot = any(v.detected for k, v in anti_bot.items() if k not in ("cloudflare", "akamai"))
    # "Anti-bot fort" = stacks qui rejettent activement les clients programmatic
    # (Akamai/PerimeterX/DataDome/Kasada/Imperva). CF est plus permissif.
    has_strong_antibot = has_akamai or has_other_bot
    has_nextjs = frameworks.get("nextjs", FrameworkDetection(False)).detected
    has_apollo = frameworks.get("apollo", FrameworkDetection(False)).detected
    has_algolia = frameworks.get("algolia_instantsearch", FrameworkDetection(False)).detected
    has_vue = frameworks.get("vue", FrameworkDetection(False)).detected

    has_graphql = any(e.category == "graphql" for e in endpoints)
    has_api_rest = any(e.category == "api-rest" for e in endpoints)
    has_sitemap = any(e.category == "sitemap-feed" for e in endpoints)
    has_search_xhr = any(e.category == "search" for e in endpoints)
    # T1 = public API confirmed (WP-JSON returning JSON, GraphQL with introspection,
    # or REST API that responds to anonymous GET). For now, only the api-rest category
    # qualifies as "verified public" since we probe wp-json. graphql calls observed during
    # Stage 2 don't qualify (they may require auth).
    has_public_api = has_api_rest

    # SPA "réel" = framework détecté ET activité XHR cohérente avec un client-side
    # rendering (graphql / search-api / api-rest non-trivial). Évite les faux-positifs
    # où Algolia est juste chargé en CSS sans firing.
    is_real_spa = (
        has_nextjs or has_apollo or (has_algolia and has_search_xhr) or (has_vue and (has_graphql or has_api_rest))
    )
    # SPA "potentiel" = juste les markers framework, sans XHR activité confirmée
    is_potential_spa = has_nextjs or has_apollo or has_algolia or has_vue

    if browser and reachability.hard_block:
        return TierRecommendation(
            primary=5,
            rationale=f"Chrome lui-même reçoit une page de blocage — {reachability.evidence}. "
            "Tier 5 : refus net de cette adresse, sans défi à passer ; un geste à la main n'y change rien. "
            "Voies : copie tierce (probe --copies), abonnement, demande à l'éditeur, autre réseau.",
            fallbacks=[],
        )

    if browser and reachability.status == "challenge":
        return TierRecommendation(
            primary=5,
            rationale=f"Chrome lui-même reste sur une page de défi — {reachability.evidence}. "
            "Tier 5 : pas d'accès machine. Voies : geste humain (warmup) puis session rejouée "
            "(ghost), copie tierce (probe --copies), abonnement, demande à l'éditeur. "
            "Tier 4 de repli une fois le défi passé à la main.",
            fallbacks=[4],
        )

    if reachability.status != "OK":
        return TierRecommendation(
            primary=4,
            rationale=f"Page non chargeable ({reachability.status}) — {reachability.evidence}. "
            "Tier 4 marionnette nodriver le plus probable, sinon proxy résidentiel requis.",
            fallbacks=[],
        )

    # Tier 1 — Public API vérifiée + pas d'anti-bot fort → JSON direct.
    # Ex : WordPress /wp-json répondant 200 JSON sans auth.
    if has_public_api and not has_strong_antibot:
        return TierRecommendation(
            primary=1,
            rationale="Public API détectée et vérifiée (JSON 200 sans auth) — "
            "Tier 1 fetch direct via httpx, parser JSON. "
            "Tier 2 fallback si l'endpoint plafonne sur certains champs.",
            fallbacks=[2, 3],
        )

    # Auth wall — Tier 3 (HTTP loggé via session warmed)
    # `requires_login` seul suffit comme signal (login form OU login link sur home).
    # `robots_disallows_root` est un renforcement (le site interdit explicitement le crawl
    # public) mais pas une exigence : un site peut avoir disallow / + requires_login,
    # un autre requires_login sans robots Disallow — les deux justifient T3.
    if requires_login:
        rationale = "Auth wall détecté (requires_login marker)"
        if robots_disallows_root:
            rationale += " + robots Disallow / for *"
        rationale += " — Tier 3 HTTP loggé via session cookies warmed (warmup interactif requis). Tier 4 fallback marionnette si replay direct bloqué."
        return TierRecommendation(primary=3, rationale=rationale, fallbacks=[4])

    # Anti-bot fort (Akamai/PerimeterX/DataDome/Kasada/Imperva) → Tier 4 quoi qu'il
    # arrive (ces stacks rejettent les clients programmatic, même replay HTTP avec
    # cookies de session). Marionnette = seule voie fiable.
    if has_strong_antibot:
        return TierRecommendation(
            primary=4,
            rationale="Anti-bot fort détecté (Akamai/PerimeterX/DataDome/Kasada/Imperva) — "
            "Tier 4 marionnette nodriver requise. Tier 3 replay direct typiquement "
            "rejeté même avec cookies de session.",
            fallbacks=[3] if has_graphql or has_api_rest else [],
        )

    # Cloudflare + SPA RÉEL (framework + XHR activity) → marionnette (pattern fashionnetwork)
    if has_cf and is_real_spa:
        return TierRecommendation(
            primary=4,
            rationale="Cloudflare Bot Manager + SPA confirmé (framework + activité XHR) — "
            "Tier 4 marionnette nodriver. "
            "Tier 3 possible si replay direct fonctionne avec session cookies.",
            fallbacks=[3] if has_graphql or has_api_rest else [],
        )

    # GraphQL/REST + pas d'anti-bot fort → Tier 3 replay direct
    if (has_graphql or has_api_rest or has_search_xhr) and not has_strong_antibot:
        return TierRecommendation(
            primary=3,
            rationale="Endpoint API détecté (graphql/rest/search) + anti-bot léger ou absent — "
            "Tier 3 replay direct via httpx avec headers tournés. "
            "Tier 4 fallback si replay bloqué.",
            fallbacks=[4],
        )

    # CF + framework potentiel SANS XHR confirmée → Tier 2 par défaut, T3 fallback
    # (cas dezeen : Algolia présent en CSS mais pas de query firing → SSR HTML marche)
    if has_cf and is_potential_spa and not is_real_spa:
        return TierRecommendation(
            primary=2,
            rationale="Cloudflare + framework markers présents mais sans activité XHR "
            "confirmée — SPA présumé décoratif (CSS-only ou widget non-actif). "
            "Tier 2 SSR HTML probable. T4 fallback si scrape échoue en pratique.",
            fallbacks=[3, 4],
        )

    # Sitemap + SSR → Tier 2 classique
    if has_sitemap or not is_potential_spa:
        return TierRecommendation(
            primary=2,
            rationale="SSR HTML détecté ou sitemap dispo — Tier 2 fetch + BeautifulSoup. "
            "Tier 1 possible si sitemap structuré.",
            fallbacks=[1, 3],
        )

    return TierRecommendation(
        primary=4,
        rationale="Pas de signal clair — démarrer en Tier 4 marionnette nodriver "
        "pour observer en live, raffiner ensuite.",
        fallbacks=[3, 2],
    )


# ── Corpus 307 sites — kNN memory-of-prior-examples (rules-based + memory) ──
_CORPUS_CACHE: list[dict] | None = None


def _load_corpus() -> list[dict]:
    """Lazy-load training corpus (307 expert-annotated sites)."""
    global _CORPUS_CACHE
    if _CORPUS_CACHE is not None:
        return _CORPUS_CACHE
    from . import config

    path = config.CORPUS_FILE
    if not path.exists():
        log.info("corpus SAP absent (%s) : pas de prior kNN", path)
        _CORPUS_CACHE = []
        return _CORPUS_CACHE
    try:
        data = json.loads(path.read_text())
        _CORPUS_CACHE = data.get("sites", [])
    except Exception as e:
        log.warning(
            "corpus SAP illisible (%s) : %s: %s — prior kNN désactivé",
            path,
            type(e).__name__,
            e,
        )
        _CORPUS_CACHE = []
    return _CORPUS_CACHE


def _site_similarity(target_url: str, target_signals: dict, corpus_site: dict) -> float:
    """Compute similarity score [0..1] between target and a corpus entry."""
    from urllib.parse import urlparse

    tp = urlparse(target_url)
    cp = urlparse(corpus_site.get("url", ""))
    score = 0.0
    # Exact host match (rare, very high signal)
    if tp.netloc == cp.netloc:
        return 1.0
    # Same eTLD+1
    target_etld = ".".join(tp.netloc.split(".")[-2:])
    corpus_etld = ".".join(cp.netloc.split(".")[-2:])
    if target_etld == corpus_etld:
        score += 0.4
    elif tp.netloc.split(".")[-1] == cp.netloc.split(".")[-1]:  # same TLD
        score += 0.1
    # Same anti-bot detected
    target_ab = set(target_signals.get("anti_bot", []))
    corpus_ab = set(corpus_site.get("anti_bot", []) or [])
    common_ab = target_ab & corpus_ab
    if common_ab:
        score += 0.2 * len(common_ab) / max(len(target_ab | corpus_ab), 1)
    # Same Schema.org dominant type
    target_schema = set(target_signals.get("schema_types", []))
    if target_schema:
        corpus_sd_types = set()
        for sd in corpus_site.get("structured_data") or []:
            if isinstance(sd, str) and sd.startswith("schema.org/"):
                corpus_sd_types.add(sd[len("schema.org/") :])
        if target_schema & corpus_sd_types:
            score += 0.2
    # Same CMS hint
    target_cms = set(target_signals.get("cms_hints", []))
    corpus_stack = set(s.lower() for s in (corpus_site.get("stack_hints") or []))
    if target_cms and any(c in s for c in target_cms for s in corpus_stack):
        score += 0.2
    return min(1.0, score)


@dataclass
class KNNPrior:
    """Knn-based prior pulled from expert-annotated corpus."""

    top_k_sites: list[dict] = field(default_factory=list)  # list of (site_dict, score)
    consensus_category: str | None = None
    consensus_subcategory: str | None = None
    consensus_difficulty: int | None = None
    consensus_rendering: str | None = None
    consensus_anti_bot: list[str] = field(default_factory=list)
    consensus_public_api: str | bool | None = None
    notes: list[str] = field(default_factory=list)


def _knn_corpus_lookup(target_url: str, target_signals: dict, k: int = 5, min_score: float = 0.4) -> KNNPrior:
    """Find K most similar sites in corpus, aggregate consensus annotations.

    `min_score` plancher : si meilleur match < min_score, retourne empty pour
    éviter du bruit sur sites trop différents du corpus.
    """
    corpus = _load_corpus()
    if not corpus:
        return KNNPrior(notes=["corpus not loaded"])

    scored = []
    for site in corpus:
        s = _site_similarity(target_url, target_signals, site)
        if s >= min_score:
            scored.append((s, site))
    scored.sort(key=lambda x: -x[0])
    top = scored[:k]
    if not top:
        return KNNPrior(notes=[f"no corpus site reached min similarity {min_score}"])

    # Consensus by majority vote
    from collections import Counter

    cats = Counter(t[1]["category"] for t in top)
    subcats = Counter(t[1].get("subcategory", "") for t in top)
    diffs = [t[1].get("scraping_difficulty", 3) for t in top]
    rends = Counter(t[1].get("rendering", "") for t in top if t[1].get("rendering"))
    pub_apis = Counter(str(t[1].get("public_api")) for t in top)
    ab_all = Counter()
    for _, s in top:
        for a in s.get("anti_bot") or []:
            ab_all[a] += 1

    return KNNPrior(
        top_k_sites=[
            {
                "url": s.get("url"),
                "category": s.get("category"),
                "score": round(sc, 2),
                "difficulty": s.get("scraping_difficulty"),
                "stack_hints": s.get("stack_hints", []),
            }
            for sc, s in top
        ],
        consensus_category=cats.most_common(1)[0][0] if cats else None,
        consensus_subcategory=subcats.most_common(1)[0][0] if subcats else None,
        consensus_difficulty=int(round(sum(diffs) / len(diffs))) if diffs else None,
        consensus_rendering=rends.most_common(1)[0][0] if rends else None,
        consensus_public_api=pub_apis.most_common(1)[0][0] if pub_apis else None,
        consensus_anti_bot=[a for a, c in ab_all.most_common() if c >= 2],
        notes=[f"top similarity: {top[0][0]:.2f} → {top[0][1].get('url')}"],
    )


# ── Stage 1 — Cheap HTTP probe (PRITES Plan-first prior to browser) ────
@dataclass
class Stage1Findings:
    """Findings from cheap HTTP probes (no browser). Decides if Stage 2 needed."""

    homepage_status: int = 0
    homepage_body_length: int = 0
    homepage_html_first_kb: str = ""
    homepage_response_headers: dict = field(default_factory=dict)
    homepage_set_cookies: list[str] = field(default_factory=list)
    homepage_fetch_error: str = ""
    homepage_final_url: str = ""
    # Robots + sitemap (déjà avec dataclasses dédiées)
    robots: RobotsAnalysis | None = None
    sitemap: SitemapAnalysis | None = None
    # Anti-bot signals from cheap probe
    cf_detected: bool = False
    akamai_detected: bool = False
    datadome_detected: bool = False
    perimeterx_detected: bool = False
    other_strong_antibot_detected: bool = False
    fortiadc_detected: bool = False
    # CDN signals (not anti-bot per se, but useful stack identification)
    fastly_detected: bool = False
    cloudfront_detected: bool = False
    wpvip_detected: bool = False  # WordPress VIP / Automattic hosting
    # Stack signals from cheap probe
    server_header: str = ""
    x_powered_by: str = ""
    generator: str = ""
    cms_hints: list[str] = field(default_factory=list)  # ["wordpress", "drupal", ...]
    # Schema.org found in homepage HTML
    schema_types_found: list[str] = field(default_factory=list)
    structured_data_formats: list[str] = field(default_factory=list)
    # Framework markers from homepage HTML body (cheap regex/string scan)
    fw_nextjs: bool = False  # __NEXT_DATA__ inline state
    fw_react: bool = False  # data-reactroot, __REACT_DEVTOOLS__
    fw_vue: bool = False  # __VUE__, data-v-, v-app
    fw_apollo: bool = False  # __APOLLO_STATE__
    fw_algolia: bool = False  # ais- classes, algoliasearch.com
    fw_initial_state: bool = False  # window.__INITIAL_STATE__ pattern
    # Public API probe (when CMS suggests it)
    wp_json_status: int = 0  # 0 = not probed, 200 = T1 candidate
    wp_json_count: int | None = None
    # Decision
    needs_browser: bool = True
    decision_rationale: str = ""


# Cookie name → tech detection table (OWASP + Wappalyzer-lite)
_COOKIE_FINGERPRINTS = {
    # Anti-bot
    "__cf_bm": "cloudflare",
    "cf_clearance": "cloudflare",
    "__cfduid": "cloudflare",
    "_pxhd": "perimeterx",
    "_pxff": "perimeterx",
    "_px3": "perimeterx",
    "datadome": "datadome",
    "kpsdk-ct": "kasada",
    "incap_ses_": "imperva",
    "visid_incap_": "imperva",  # prefix match
    "akacd_": "akamai",  # prefix
    # CMS / Frameworks
    "wp-settings-": "wordpress",
    "wordpress_logged_in_": "wordpress",
    "drupal.tableDrag.showWeight": "drupal",
    "_session_id": "rails",
    "_csrf_token": "rails",
    "csrftoken": "django",
    "sessionid": "django",
    "JSESSIONID": "java_ee",
    "ASP.NET_SessionId": "aspnet",
    "PHPSESSID": "php_generic",
    "laravel_session": "laravel",
    "ci_session": "codeigniter",
    "shopify_y": "shopify",
    "_shopify_y": "shopify",
    "X-Magento-Vary": "magento",
}


def _match_cookies(cookie_names: list[str]) -> list[str]:
    """Match cookie names to technologies. Returns list of detected tech keys."""
    detected: list[str] = []
    for cn in cookie_names:
        cn_lower = cn.lower()
        for pattern, tech in _COOKIE_FINGERPRINTS.items():
            pat_lower = pattern.lower()
            if cn_lower == pat_lower or cn_lower.startswith(pat_lower):
                if tech not in detected:
                    detected.append(tech)
    return detected


STAGE1_DEADLINE_S = 60.0


async def _stage1_cheap_probe(url: str, *, timeout: float = 6.0, deadline: float = STAGE1_DEADLINE_S) -> Stage1Findings:
    """Cheap HTTP probes (no browser), sous une échéance globale `deadline`.

    Si l'échéance tombe, retourne des findings vides marqués en erreur
    (needs_browser=True) plutôt que de bloquer l'inspection.
    """
    try:
        return await asyncio.wait_for(_stage1_cheap_probe_impl(url, timeout=timeout), deadline)
    except TimeoutError:
        msg = f"échéance globale de l'étape 1 dépassée ({deadline:g} s)"
        return Stage1Findings(homepage_fetch_error=msg, needs_browser=True, decision_rationale=msg)


async def _stage1_cheap_probe_impl(url: str, *, timeout: float = 6.0) -> Stage1Findings:
    """Cheap HTTP probes (no browser). Run robots/sitemap in parallel with homepage GET.

    Returns Stage1Findings. Decision `needs_browser` set based on signals.
    """
    from urllib.parse import urlparse

    from .stealth import random_headers

    f = Stage1Findings()

    # Run in parallel: homepage, robots, sitemap-discovery
    p = urlparse(url)
    base = f"{p.scheme}://{p.netloc}"
    rb_url = f"{base}/robots.txt"

    async def _fetch_home():
        try:
            async with _http.async_client(timeout=timeout) as client:
                r = await _http.aget(client, url, headers=random_headers())
            return r
        except Exception as e:
            return e

    async def _fetch_robots_text():
        try:
            async with _http.async_client(timeout=timeout) as client:
                r = await _http.aget(client, rb_url, headers=random_headers(accept="text/plain"))
            return r
        except Exception as e:
            return e

    home_resp, robots_resp = await asyncio.gather(_fetch_home(), _fetch_robots_text())

    # Parse homepage
    if isinstance(home_resp, Exception):
        f.homepage_fetch_error = f"{type(home_resp).__name__}: {str(home_resp)[:80]}"
    else:
        f.homepage_status = home_resp.status_code
        f.homepage_final_url = str(home_resp.url)
        body = home_resp.text or ""
        f.homepage_body_length = len(body)
        f.homepage_html_first_kb = body[:50000]
        # Headers
        for k, v in home_resp.headers.items():
            kl = k.lower()
            f.homepage_response_headers[kl] = v[:200]
        # Capture set-cookie names
        sc = home_resp.headers.get_list("set-cookie") if hasattr(home_resp.headers, "get_list") else []
        if not sc:
            sc_raw = home_resp.headers.get("set-cookie", "")
            if sc_raw:
                sc = [sc_raw]
        # Multi-cookie: parse names
        for cookie_str in sc:
            name = cookie_str.split("=", 1)[0].strip()
            if name:
                f.homepage_set_cookies.append(name)
        # Anti-bot via headers + cookies + BODY content (Fix 3 : recall accru)
        body_first_30k = body[:30000].lower()
        f.cf_detected = (
            "cf-ray" in f.homepage_response_headers
            or any(c.lower() in ("__cf_bm", "cf_clearance", "__cfduid") for c in f.homepage_set_cookies)
            or "challenge-platform" in body_first_30k
            or "_cf_chl_opt" in body_first_30k
            or "just a moment" in body_first_30k
            or "attention required" in body_first_30k.title().lower()
        )
        f.akamai_detected = (
            "akamai-cache-status" in f.homepage_response_headers
            or "x-akamai-transformed" in f.homepage_response_headers
            or "akamaighost" in str(f.homepage_response_headers.get("server", "")).lower()
            or any(c.lower().startswith("akacd_") for c in f.homepage_set_cookies)
            or "/akam/" in body_first_30k
            or "akamaihd.net" in body_first_30k
        )
        f.datadome_detected = (
            "x-datadome" in f.homepage_response_headers
            or any(c.lower() == "datadome" for c in f.homepage_set_cookies)
            or "datadome.co" in body_first_30k
        )
        f.perimeterx_detected = (
            any(c.lower().startswith("_px") for c in f.homepage_set_cookies)
            or "perimeterx.net" in body_first_30k
            or "_pxhd" in body_first_30k
        )
        f.fortiadc_detected = (
            FORTIADC_CAPTCHA_PATH in f.homepage_final_url or "fortiadc_captcha_iframe" in body_first_30k
        )
        f.other_strong_antibot_detected = any(
            [
                "x-iinfo" in f.homepage_response_headers,
                "x-kpsdk-ct" in f.homepage_response_headers,
                any(c.lower().startswith("incap_ses_") for c in f.homepage_set_cookies),
                any(c.lower() == "kpsdk-ct" for c in f.homepage_set_cookies),
                "kpsdk-ct" in body_first_30k,
                "incapsula" in body_first_30k,
            ]
        )
        # CDN identification (not anti-bot, just stack signals)
        served_by = str(f.homepage_response_headers.get("x-served-by", "")).lower()
        f.fastly_detected = (
            "fastly" in str(f.homepage_response_headers.get("via", "")).lower()
            or "varnish" in str(f.homepage_response_headers.get("via", "")).lower()
            or "fastly" in served_by
            or any(k.startswith("x-fastly-") for k in f.homepage_response_headers)
            or "fastly" in str(f.homepage_response_headers.get("req-svc-chain", "")).lower()
            or (served_by.startswith("cache-") and any(c.isdigit() for c in served_by))
        )
        f.cloudfront_detected = (
            "cloudfront" in str(f.homepage_response_headers.get("server", "")).lower()
            or "x-amz-cf-id" in f.homepage_response_headers
            or "x-amz-cf-pop" in f.homepage_response_headers
        )
        f.wpvip_detected = (
            "wordpress vip" in f.x_powered_by.lower()
            or "a8c.com" in str(f.homepage_response_headers.get("x-hacker", "")).lower()
            or "wpvip" in str(f.homepage_response_headers.get("x-powered-by", "")).lower()
            or str(f.homepage_response_headers.get("x-rq", "")).startswith("mxp")
        )
        # Stack hints from headers
        f.server_header = f.homepage_response_headers.get("server", "")[:80]
        f.x_powered_by = f.homepage_response_headers.get("x-powered-by", "")[:80]
        f.generator = f.homepage_response_headers.get("x-generator", "")[:80]
        # CMS hints from HTML body
        body_lower = body[:50000].lower()
        if "wp-content/" in body_lower or "wp-includes/" in body_lower:
            f.cms_hints.append("wordpress")
        if "drupal-selector" in body_lower or "/sites/default/files/" in body_lower:
            f.cms_hints.append("drupal")
        if "cdn.shopify.com" in body_lower or '"shop":' in body_lower:
            f.cms_hints.append("shopify")
        if "magento" in body_lower or "/skin/frontend/" in body_lower:
            f.cms_hints.append("magento")
        m = re.search(
            r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']+)',
            body[:30000],
            re.I,
        )
        if m and not f.generator:
            f.generator = m.group(1)[:80]
        # Schema.org from JSON-LD in homepage HTML
        for script in re.findall(
            r'<script[^>]*type=["\']application/ld\+json["\'][^>]*>(.+?)</script>',
            body,
            re.S | re.I,
        ):
            try:
                data = json.loads(script.strip())
                items = (
                    data if isinstance(data, list) else (data.get("@graph", [data]) if isinstance(data, dict) else [])
                )
                for it in items:
                    if isinstance(it, dict):
                        t = it.get("@type")
                        if isinstance(t, list):
                            for tt in t:
                                if isinstance(tt, str) and tt not in f.schema_types_found:
                                    f.schema_types_found.append(tt)
                        elif isinstance(t, str) and t not in f.schema_types_found:
                            f.schema_types_found.append(t)
            except Exception:
                pass
        if f.schema_types_found:
            f.structured_data_formats.append("json-ld")
        if 'itemtype="https://schema.org/' in body or 'itemtype="http://schema.org/' in body:
            f.structured_data_formats.append("microdata")
        if 'vocab="http://schema.org/"' in body or 'vocab="https://schema.org/"' in body or 'typeof="schema:' in body:
            f.structured_data_formats.append("rdfa")
        if 'property="og:type"' in body or "property='og:type'" in body:
            f.structured_data_formats.append("opengraph")
        # Framework markers (cheap string scan over homepage HTML)
        f.fw_nextjs = "__NEXT_DATA__" in body or "/_next/static/" in body
        f.fw_react = "data-reactroot" in body or "data-react-helmet" in body or "__REACT_DEVTOOLS_GLOBAL_HOOK__" in body
        f.fw_vue = "__VUE__" in body or "data-v-" in body[:100000] or 'id="__nuxt"' in body or "__NUXT__" in body
        f.fw_apollo = "__APOLLO_STATE__" in body or "apollo-client" in body_lower
        f.fw_algolia = (
            "algoliasearch" in body_lower
            or "algolianet.com" in body_lower
            or 'class="ais-' in body
            or "class='ais-" in body
        )
        f.fw_initial_state = (
            "window.__INITIAL_STATE__" in body or "__PRELOADED_STATE__" in body or "__INITIAL_DATA__" in body
        )

    # Parse robots
    if isinstance(robots_resp, Exception):
        f.robots = RobotsAnalysis(fetched=False, notes=f"{type(robots_resp).__name__}")
    elif robots_resp.status_code != 200:
        f.robots = RobotsAnalysis(fetched=False, status=robots_resp.status_code)
    else:
        f.robots = _parse_robots(robots_resp.text)

    # Discover + fetch sitemap (if robots has any, prefer those)
    sitemap_urls = f.robots.sitemaps if f.robots and f.robots.fetched else []
    f.sitemap = await _fetch_sitemap(url, sitemap_urls)

    # WP-JSON probe (cheap T1-candidate signal) when WordPress detected
    if "wordpress" in f.cms_hints:
        try:
            async with _http.async_client(timeout=4.0) as client:
                wp_url = f"{base}/wp-json/wp/v2/posts?per_page=1"
                r = await _http.aget(client, wp_url, headers=random_headers(accept="application/json"))
                f.wp_json_status = r.status_code
                if r.status_code == 200 and "application/json" in r.headers.get("content-type", ""):
                    try:
                        data = r.json()
                        f.wp_json_count = len(data) if isinstance(data, list) else None
                    except Exception:
                        pass
        except Exception:
            pass

    # === Decision: Stage 2 (browser) needed ? ===
    needs = False
    reasons = []

    if f.fortiadc_detected:
        # Chrome sans fenêtre fige sur cette page (100 % du processeur) : rien à apprendre de plus.
        reasons.append(f"CAPTCHA FortiADC ({f.homepage_final_url}) : geste humain, pas d'audit en navigateur")
    elif f.homepage_fetch_error:
        needs = True
        reasons.append(f"home fetch error: {f.homepage_fetch_error}")
    elif f.homepage_status != 200:
        # 403/503 → maybe anti-bot active, browser needed for cf_clearance
        needs = True
        reasons.append(f"home status {f.homepage_status}")
    elif f.akamai_detected or f.datadome_detected or f.perimeterx_detected or f.other_strong_antibot_detected:
        needs = True
        reasons.append("strong anti-bot detected via cheap probe")
    elif f.homepage_body_length < 2000 and not f.cms_hints and not f.schema_types_found:
        # Body trop court + pas de signal CMS → soit JS-rendered SPA, soit blocage
        needs = True
        reasons.append("homepage body too short + no CMS/Schema signal (probably JS-rendered)")
    else:
        reasons.append(
            f"sufficient stage1 signal (body={f.homepage_body_length}, schema={len(f.schema_types_found)}, cms={f.cms_hints or 'none'})"
        )

    f.needs_browser = needs
    f.decision_rationale = "; ".join(reasons)
    return f


# ── Phase I — robots.txt + sitemap fetcher (RFC 9309 + Sitemaps.org) ────

_AI_BOT_NAMES = (
    "gptbot",
    "claudebot",
    "ccbot",
    "anthropic-ai",
    "perplexitybot",
    "bytespider",
    "google-extended",
    "amazonbot",
    "applebot",
    "diffbot",
    "semrushbot",
    "ahrefsbot",
)


async def _fetch_robots(base_url: str) -> RobotsAnalysis:
    """Fetch + parse robots.txt per RFC 9309. Pure HTTP via httpx, no browser."""
    from urllib.parse import urlparse

    from .stealth import random_headers

    p = urlparse(base_url)
    rb_url = f"{p.scheme}://{p.netloc}/robots.txt"
    try:
        async with _http.async_client(timeout=8) as client:
            r = await _http.aget(client, rb_url, headers=random_headers(accept="text/plain"))
    except Exception as e:
        return RobotsAnalysis(fetched=False, notes=f"fetch error: {type(e).__name__}: {str(e)[:80]}")
    if r.status_code != 200:
        return RobotsAnalysis(fetched=False, status=r.status_code)
    return _parse_robots(r.text)


def _parse_robots(text: str) -> RobotsAnalysis:
    """Parse robots.txt content. Returns structured analysis."""
    groups: dict[str, dict] = {}
    current_uas: list[str] = []
    sitemaps: list[str] = []
    crawl_delay: float | None = None

    for raw_line in text[:500_000].split("\n"):  # 500 KiB cap per RFC 9309
        line = raw_line.split("#", 1)[0].strip()
        if not line or ":" not in line:
            if not line:
                current_uas = []
            continue
        key, _, val = line.partition(":")
        key = key.strip().lower()
        val = val.strip()
        if key == "user-agent":
            ua = val.lower()
            if not current_uas or current_uas[-1] != ua:
                current_uas.append(ua)
            groups.setdefault(ua, {"allow": [], "disallow": []})
        elif key in ("allow", "disallow") and current_uas:
            for ua in current_uas:
                groups.setdefault(ua, {"allow": [], "disallow": []})
                groups[ua][key].append(val)
        elif key == "sitemap":
            if val:
                sitemaps.append(val)
        elif key == "crawl-delay" and current_uas:
            try:
                crawl_delay = float(val)
            except ValueError:
                pass

    ai_blocked = []
    for ua_name in groups:
        if any(bot in ua_name for bot in _AI_BOT_NAMES):
            disallows = groups[ua_name].get("disallow", [])
            if any(d == "/" or d == "" for d in disallows):
                ai_blocked.append(ua_name)

    return RobotsAnalysis(
        fetched=True,
        status=200,
        user_agent_groups=groups,
        sitemaps=sitemaps,
        has_specific_ua_rules=len(groups) > 1,
        flagged_paths_count=len(groups.get("*", {}).get("disallow", [])),
        crawl_delay=crawl_delay,
        ai_bots_blocked=ai_blocked,
        notes=f"AI bots blocked: {ai_blocked}" if ai_blocked else "",
    )


async def _fetch_sitemap(base_url: str, robots_sitemaps: list[str]) -> SitemapAnalysis:
    """Discover + parse sitemap. Try robots-listed URLs first, fallback to conventions."""
    from urllib.parse import urlparse

    from .stealth import random_headers

    p = urlparse(base_url)
    # Lignes Sitemap de robots.txt : http(s) seulement ; la destination est en
    # plus contrôlée requête par requête par le client gardé (_http).
    robots_sitemaps = [u for u in robots_sitemaps if urlparse(u).scheme in ("http", "https") and urlparse(u).hostname]
    candidates = list(robots_sitemaps) + [
        f"{p.scheme}://{p.netloc}/sitemap.xml",
        f"{p.scheme}://{p.netloc}/sitemap_index.xml",
        f"{p.scheme}://{p.netloc}/wp-sitemap.xml",
    ]
    # Dedup preserving order
    seen, candidates_d = set(), []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            candidates_d.append(c)

    async with _http.async_client(timeout=8) as client:
        for url in candidates_d:
            try:
                r = await _http.aget(
                    client,
                    url,
                    headers=random_headers(accept="application/xml,text/xml"),
                )
            except Exception:
                continue
            if r.status_code != 200:
                continue
            ct = r.headers.get("content-type", "")
            if "xml" not in ct and not r.text.lstrip().startswith("<?xml"):
                continue
            return _parse_sitemap(r.text, url)

    return SitemapAnalysis(fetched=False)


def _parse_sitemap(text: str, url: str) -> SitemapAnalysis:
    """Parse sitemap XML — supports both <urlset> and <sitemapindex>."""
    NS = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
    try:
        root = _ET.fromstring(text[:5_000_000])  # cap 5MB
    except _ET.ParseError:
        return SitemapAnalysis(fetched=False, url=url)

    is_index = root.tag.endswith("sitemapindex")
    extensions = []
    for k in root.attrib:
        if k.startswith("xmlns:"):
            ns_name = k.split(":", 1)[1]
            if ns_name not in ("sm",):
                extensions.append(ns_name)

    if is_index:
        sitemap_locs = root.findall("sm:sitemap/sm:loc", NS)
        sub = [s.text for s in sitemap_locs[:5] if s.text]
        return SitemapAnalysis(
            fetched=True,
            url=url,
            is_index=True,
            n_sitemaps=len(sitemap_locs),
            sub_sitemaps=sub,
            has_extensions=extensions,
        )

    # <urlset>
    urls = root.findall("sm:url", NS)
    sample = []
    lastmods = []
    for u in urls[:50]:  # only sample first 50 for stats
        loc = u.find("sm:loc", NS)
        if loc is not None and loc.text and len(sample) < 10:
            sample.append(loc.text)
        lm = u.findtext("sm:lastmod", default="", namespaces=NS)
        if lm:
            lastmods.append(lm)
    return SitemapAnalysis(
        fetched=True,
        url=url,
        is_index=False,
        n_urls=len(urls),
        sample_urls=sample,
        has_extensions=extensions,
        earliest_lastmod=min(lastmods) if lastmods else None,
        latest_lastmod=max(lastmods) if lastmods else None,
    )


# ── Phase H — Structural features (Lindemann/Thapa) ────────────────────
def login_wall(struct: StructuralFeatures | None) -> bool:
    """Mur de connexion : accueil réduit à un formulaire de connexion. Un lien
    « Connexion » sur un site public ne suffit pas (même règle que human_gate)."""
    return bool(struct and struct.has_login_form and struct.n_internal_links < LOGIN_PAGE_MAX_LINKS)


async def _extract_structural_features(tab) -> StructuralFeatures:
    """Extract HOMEPAGE_FEATURES via single tab.evaluate."""
    js = """
    (() => {
        const sel = (q) => document.querySelectorAll(q);
        const has = (q) => document.querySelector(q) !== null;
        const links = Array.from(sel('a[href]'));
        const host = window.location.hostname;
        let internal = 0, external = 0;
        for (const a of links) {
            const href = a.getAttribute('href') || '';
            if (href.startsWith('javascript:') || href.startsWith('mailto:') || href.startsWith('tel:') || href.startsWith('#')) continue;
            try {
                const u = new URL(href, window.location.href);
                if (u.hostname === host || u.hostname.endsWith('.' + host.split('.').slice(-2).join('.'))) internal++;
                else external++;
            } catch(e) {}
        }
        // Form types
        const forms = sel('form');
        const has_pwd = has('input[type="password"]');
        const has_search = has('input[type="search"], input[placeholder*="search" i], input[name*="search" i], input[name="q"]');
        const has_signup = !!Array.from(forms).find(f => /(register|signup|sign-up|create.account)/i.test(f.action || '') || /(register|signup|sign up)/i.test(f.textContent || ''));
        const has_cart = has('[class*="cart" i], [id*="cart" i], button[class*="add-to" i], [class*="checkout" i]');
        const has_comment = has('[id*="comment" i], [class*="comment-form" i], textarea[name*="comment" i]');
        const has_contact = !!Array.from(forms).find(f => /(contact|inquiry|enquiry)/i.test(f.action || '') || /(contact us|get in touch)/i.test(f.textContent || ''));
        // Login link
        const login_link = !!Array.from(sel('a')).find(a => /(sign in|log in|login|connexion|se connecter)/i.test(a.textContent || ''));
        // Paywall markers
        const paywall = has('[class*="paywall" i], [class*="subscriber-only" i], [class*="premium-content" i]');
        // Consent wall (cookie banners)
        const consent_wall = has('[id*="cookie" i] button, [class*="cookie-consent" i], [class*="cmp-banner" i], [id="onetrust-banner-sdk"]');
        // Schema.org types
        const ldjson = Array.from(sel('script[type="application/ld+json"]'));
        const types = new Set();
        for (const s of ldjson) {
            try {
                const d = JSON.parse(s.textContent);
                const items = Array.isArray(d) ? d : (d['@graph'] || [d]);
                for (const it of items) {
                    if (!it || typeof it !== 'object') continue;
                    const t = it['@type'];
                    if (Array.isArray(t)) for (const tt of t) types.add(tt);
                    else if (typeof t === 'string') types.add(t);
                }
            } catch(e) {}
        }
        // Detect structured data formats
        const html = document.documentElement.outerHTML.slice(0, 200000);
        const formats = [];
        if (ldjson.length > 0) formats.push('json-ld');
        if (/itemtype="https?:\\/\\/schema\\.org\\//.test(html)) formats.push('microdata');
        if (/vocab="https?:\\/\\/schema\\.org\\//.test(html) || /typeof="schema:/.test(html)) formats.push('rdfa');
        if (/property="og:type"/.test(html)) formats.push('opengraph');
        return JSON.stringify({
            n_internal_links: internal,
            n_external_links: external,
            n_forms: forms.length,
            has_login: has_pwd,
            has_search: has_search,
            has_signup: has_signup,
            has_cart: has_cart,
            has_comment: has_comment,
            has_contact: has_contact,
            n_imgs: sel('img').length,
            n_articles: sel('article').length,
            n_h1: sel('h1').length,
            n_h2_h3: sel('h2,h3').length,
            n_p: sel('p').length,
            n_tables: sel('table').length,
            n_iframes: sel('iframe').length,
            schema_types: Array.from(types),
            structured_data_formats: formats,
            has_paywall: paywall,
            has_consent_wall: consent_wall,
            has_login_link: login_link,
        });
    })()
    """
    try:
        raw = await tab.evaluate(js)
        d = json.loads(raw) if isinstance(raw, str) else raw
    except Exception:
        return StructuralFeatures()
    n_int = d.get("n_internal_links", 0)
    n_ext = d.get("n_external_links", 0)
    return StructuralFeatures(
        n_internal_links=n_int,
        n_external_links=n_ext,
        internal_external_ratio=(n_int / max(n_ext, 1)),
        n_forms=d.get("n_forms", 0),
        has_login_form=d.get("has_login", False),
        has_search_form=d.get("has_search", False),
        has_signup_form=d.get("has_signup", False),
        has_cart_form=d.get("has_cart", False),
        has_comment_form=d.get("has_comment", False),
        has_contact_form=d.get("has_contact", False),
        n_imgs=d.get("n_imgs", 0),
        n_articles=d.get("n_articles", 0),
        n_h1=d.get("n_h1", 0),
        n_h2_h3=d.get("n_h2_h3", 0),
        n_paragraphs=d.get("n_p", 0),
        n_tables=d.get("n_tables", 0),
        n_iframes=d.get("n_iframes", 0),
        schema_types=d.get("schema_types", []),
        structured_data_formats=d.get("structured_data_formats", []),
        has_paywall_marker=d.get("has_paywall", False),
        has_consent_wall=d.get("has_consent_wall", False),
        has_login_link=d.get("has_login_link", False),
    )


# ── Phase J — Ethics check (Khoury + Krotov synthesis) ─────────────────
async def _ethics_check(
    tab,
    robots: RobotsAnalysis | None,
    struct: StructuralFeatures | None,
) -> EthicsCheck:
    """Combine robots-derived signals + DOM markers for ethics/legal preliminary score."""
    notes: list[str] = []
    ai_blocked = robots.ai_bots_blocked if robots else []
    crawl_delay = robots.crawl_delay if robots else None
    robots_allows_root = True
    if robots and robots.fetched:
        star = robots.user_agent_groups.get("*", {})
        if any(d == "/" for d in star.get("disallow", [])):
            robots_allows_root = False
            notes.append("robots.txt forbids root for *")

    # DOM-based ToS / Privacy detection
    js = """
    (() => {
        const links = Array.from(document.querySelectorAll('a[href]'));
        let tos = null, privacy = null;
        for (const a of links) {
            const href = a.getAttribute('href') || '';
            const text = (a.textContent || '').toLowerCase().trim();
            if (!tos && (/(terms|tos|conditions|legal)/i.test(href) || /(terms|tos|conditions of (use|service)|legal)/i.test(text))) {
                tos = href;
            }
            if (!privacy && (/privacy/i.test(href) || /(privacy|données.personnelles|gdpr)/i.test(text))) {
                privacy = href;
            }
            if (tos && privacy) break;
        }
        // GDPR signals
        const html = document.documentElement.outerHTML.slice(0, 100000);
        const has_gdpr = /(GDPR|RGPD|EU.cookie|ePrivacy|consent.management)/i.test(html);
        const has_eu_lang = !!document.querySelector('link[hreflang^="fr"], link[hreflang^="de"], link[hreflang^="it"], link[hreflang^="es"], link[hreflang^="nl"]');
        const has_user_paths = !!document.querySelector('a[href*="/user/" i], a[href*="/users/" i], a[href*="/profile/" i], a[href^="/@"]');
        return JSON.stringify({tos, privacy, has_gdpr, has_eu_lang, has_user_paths});
    })()
    """
    try:
        raw = await tab.evaluate(js)
        dom = json.loads(raw) if isinstance(raw, str) else raw
    except Exception:
        dom = {}

    is_eu = bool(dom.get("has_gdpr") or dom.get("has_eu_lang"))
    user_pages = bool(dom.get("has_user_paths"))
    consent_wall = struct.has_consent_wall if struct else False
    paywall = struct.has_paywall_marker if struct else False
    requires_login = login_wall(struct)

    # Risk scoring
    risk = 0
    if not robots_allows_root:
        risk += 2
        notes.append("legal risk: robots Disallow / for *")
    if ai_blocked:
        risk += 1
        notes.append(f"ethics flag: AI bots blocked ({', '.join(ai_blocked[:3])})")
    if requires_login:
        risk += 2
        notes.append("legal risk: login wall detected")
    if paywall:
        risk += 2
        notes.append("legal risk: paywall content")
    if user_pages:
        risk += 1
        notes.append("ethics flag: user profile pages (PII)")
    if is_eu:
        risk += 1
        notes.append("legal note: EU/GDPR markers detected")
    legal_risk = "high" if risk >= 5 else ("medium" if risk >= 2 else "low")

    return EthicsCheck(
        robots_allows_root=robots_allows_root,
        ai_bots_blocked=ai_blocked,
        crawl_delay=crawl_delay,
        tos_link_found=dom.get("tos"),
        privacy_link_found=dom.get("privacy"),
        has_consent_wall=consent_wall,
        has_paywall_marker=paywall,
        requires_login_marker=requires_login,
        is_eu_geo_targeting=is_eu,
        user_profile_pages_detected=user_pages,
        estimated_legal_risk=legal_risk,
        notes=notes,
    )


# ── Phase K — Category prediction (Lindemann + Schema.org) ─────────────
_ARCH_DESIGN_TITLE_RE = re.compile(
    r"\b(architect(ure|s|ural)?|design\s*(magazine|news|studio)?|interior(s)?|industrial design|graphic design|product design|d[ée]coration?|am[ée]nag(ement|ements)?)\b",
    re.I,
)
_ARCH_DESIGN_DOMAIN_HINTS = (
    "archdaily",
    "dezeen",
    "designboom",
    "architizer",
    "wallpaper",
    "architectmagazine",
    "interiordesign",
    "domusweb",
    "azuremagazine",
    "frame",
    "icon-magazine",
    "designmilk",
    # Indie / niche architecture-design publishers
    "pinupmagazine",
    "apartamentomagazine",
    "cabinetmagazine",
    "real-review",
    "frieze",
    "the-modernist",
    "032c",
    "032cmagazine",
)

# Fashion / luxury / mode media — magazines, fashion industry news, runway sites
# (NB: fashion e-commerce sites with Schema.org Product hit the ecommerce rule first;
# this rule is for fashion media outlets that publish editorial content)
_FASHION_LUXURY_TITLE_RE = re.compile(
    r"\b(fashion\s+(magazine|news|industry|media|professionnels?)|"
    r"(la\s+)?mode\s+(et|du|professionnels?)|"
    r"luxury\s+(brand|magazine|fashion)|"
    r"luxe\s+(et|du|professionnels?)|"
    r"haute\s+couture|"
    r"pr[êe]t.?[àa].?porter|"
    r"runway\s+(shows?|reports?|coverage)|"
    r"fashion\s+(week|show))\b",
    re.I,
)
_FASHION_LUXURY_DOMAIN_HINTS = (
    "fashionnetwork",
    "vogue",
    "businessoffashion",
    "wwd",
    "fashionunited",
    "elle",
    "harpersbazaar",
    "marieclaire",
    "glamour",
    "instyle",
    "vanityfair",
    "voguebusiness",
    "lofficiel",
    "numero",
    "highsnobiety",
    "hypebeast",
    "graziadaily",
    "graziamagazine",
    "purplemagazine",
    "anothermag",
    "system-magazine",
    "10magazine",
    "modemonline",
    "fashionmagazine",
)

# Fashion / luxury e-commerce — for sites where homepage doesn't expose Schema.org
# Product (carousel-only) but the domain is a known fashion-luxury retailer.
# SaaS / B2B software — for sites with Schema.org SoftwareApplication or
# title patterns indicating a software/platform product (not a media outlet)
_SAAS_TITLE_RE = re.compile(
    r"\b(platform|software|saas|api|sdk|dashboard|workspace|all-in-one|crm|"
    r"erp|cms|fp\&a|tool(set|s)?\s+for|automation|integration)\b",
    re.I,
)
_SAAS_DOMAIN_HINTS = (
    "figma",
    "canva",
    "airtable",
    "notion",
    "linear",
    "asana",
    "monday",
    "trello",
    "atlassian",
    "jira",
    "slack",
    "zoom",
    "webex",
    "miro",
    "loom",
    "calendly",
    "hubspot",
    "salesforce",
    "intercom",
    "zendesk",
    "stripe",
    "twilio",
    "segment",
    "amplitude",
    "mixpanel",
    "datadog",
    "newrelic",
    "sentry",
    "pagerduty",
    "vercel",
    "netlify",
    "fly",
    "render",
    "supabase",
    "planetscale",
    "neon",
)


_FASHION_ECOMMERCE_DOMAIN_HINTS = (
    "mytheresa",
    "farfetch",
    "zalando",
    "net-a-porter",
    "ssense",
    "matchesfashion",
    "lyst",
    "harveynichols",
    "harrods",
    "selfridges",
    "saksfifthavenue",
    "neimanmarcus",
    "bergdorfgoodman",
    "barneys",
    "browns",
    "mr-porter",
    "yoox",
    "luisaviaroma",
    # Major luxury houses with direct DTC sites
    "balenciaga",
    "gucci",
    "prada",
    "dior",
    "chanel",
    "hermes",
    "louisvuitton",
    "burberry",
    "fendi",
    "celine",
    "givenchy",
    "valentino",
    "saintlaurent",
    "loewe",
    "bottegaveneta",
)


def _predict_category(
    struct: StructuralFeatures,
    *,
    title: str = "",
    url: str = "",
) -> CategoryPrediction:
    """Rules-based category prediction using Schema.org types + structural signals.

    `title` and `url` are optional — when provided, they enable domain-specific
    subcategory refinement (e.g., distinguishing architecture/design media from
    general news media).
    """
    schema = set(struct.schema_types or [])
    reasons: list[str] = []
    url_low = (url or "").lower()

    def add(reason):
        reasons.append(reason)

    def _media_subcategory_refine(default_sub: str) -> str:
        """Refine media subcategory based on title/url hints."""
        if any(hint in url_low for hint in _ARCH_DESIGN_DOMAIN_HINTS):
            return "architecture_design"
        if any(hint in url_low for hint in _FASHION_LUXURY_DOMAIN_HINTS):
            return "fashion_luxury"
        if title and _ARCH_DESIGN_TITLE_RE.search(title):
            return "architecture_design"
        if title and _FASHION_LUXURY_TITLE_RE.search(title):
            return "fashion_luxury"
        return default_sub

    # ECOMMERCE — Schema Product/Offer is unambiguous, fires first.
    if "Product" in schema or "Offer" in schema or "AggregateOffer" in schema:
        add("Schema.org Product/Offer type")
        return CategoryPrediction("ecommerce", "products_listing", 0.95, reasons)

    # Cart-form detection — but check first if this is actually a magazine with a
    # secondary shop (apartamento, dezeen-with-store, etc.). Magazines often have
    # a small e-commerce surface (back issues, books) but their PRIMARY content
    # is editorial. A title regex `magazine|publisher|journal` + arch/design domain
    # = override to media.
    is_arch_design_magazine = any(hint in url_low for hint in _ARCH_DESIGN_DOMAIN_HINTS) or (
        title and _ARCH_DESIGN_TITLE_RE.search(title)
    )
    is_fashion_media = any(hint in url_low for hint in _FASHION_LUXURY_DOMAIN_HINTS) or (
        title and _FASHION_LUXURY_TITLE_RE.search(title)
    )
    has_magazine_in_title = bool(
        title
        and re.search(
            r"\b(magazine|publisher|journal|review|paper|gazette)\b",
            title,
            re.I,
        )
    )
    if struct.has_cart_form:
        # Magazine with secondary shop : keep media classification
        if is_arch_design_magazine and has_magazine_in_title:
            add("magazine title + arch/design domain + cart (secondary shop) → media")
            return CategoryPrediction("media", "architecture_design", 0.8, reasons)
        if is_fashion_media and has_magazine_in_title:
            add("magazine title + fashion domain + cart (secondary shop) → media")
            return CategoryPrediction("media", "fashion_luxury", 0.8, reasons)
        # Real e-commerce
        sub = "fashion_luxury" if any(h in url_low for h in _FASHION_ECOMMERCE_DOMAIN_HINTS) else "shop"
        add("cart-related elements detected in DOM")
        return CategoryPrediction("ecommerce", sub, 0.85, reasons)

    # Curated fashion-luxury e-commerce domain hints fallback (for homepages that
    # don't expose Schema Product / cart elements, e.g. a carousel-only home of a large fashion retailer).
    if any(h in url_low for h in _FASHION_ECOMMERCE_DOMAIN_HINTS):
        add(f"curated fashion/luxury e-commerce domain match ({url_low})")
        return CategoryPrediction("ecommerce", "fashion_luxury", 0.7, reasons)

    # JOBS
    if "JobPosting" in schema:
        return CategoryPrediction("jobs", "job_board", 0.95, ["Schema JobPosting"])

    # EVENTS
    if "Event" in schema:
        return CategoryPrediction("events", "event_listing", 0.9, ["Schema Event"])

    # REAL ESTATE
    if "RealEstateListing" in schema or "Residence" in schema:
        return CategoryPrediction("real_estate", "listings", 0.9, ["Schema RealEstate*"])

    # OPEN DATA
    if "Dataset" in schema or "DataCatalog" in schema:
        return CategoryPrediction("open_data", "data_portal", 0.9, ["Schema Dataset"])

    # MEDIA / publishing
    article_types = schema & {
        "NewsArticle",
        "Article",
        "BlogPosting",
        "Recipe",
        "Review",
    }
    if article_types:
        sub = (
            "blog"
            if "BlogPosting" in schema
            else ("recipe" if "Recipe" in schema else ("news" if "NewsArticle" in schema else "general"))
        )
        sub = _media_subcategory_refine(sub)
        add(f"Schema {article_types}, subcategory={sub}")
        if struct.has_comment_form:
            add("comment form present")
            return CategoryPrediction("media", f"{sub}_with_comments", 0.85, reasons)
        return CategoryPrediction("media", sub, 0.8, reasons)
    # MEDIA fallback : CollectionPage/WebSite + architecture/design domain hints
    # (catches sites like dezeen where homepage doesn't expose Article schema directly
    # but title/URL clearly identifies an architecture/design media)
    if {"CollectionPage", "WebSite", "WebPage"} & schema:
        if any(hint in url_low for hint in _ARCH_DESIGN_DOMAIN_HINTS) or (
            title and _ARCH_DESIGN_TITLE_RE.search(title)
        ):
            add("CollectionPage/WebSite schema + architecture/design domain hint")
            return CategoryPrediction("media", "architecture_design", 0.75, reasons)
        if any(hint in url_low for hint in _FASHION_LUXURY_DOMAIN_HINTS) or (
            title and _FASHION_LUXURY_TITLE_RE.search(title)
        ):
            add("CollectionPage/WebSite schema + fashion/luxury domain hint")
            return CategoryPrediction("media", "fashion_luxury", 0.75, reasons)

    # COMMUNITY
    if struct.has_login_form and (struct.has_comment_form or "DiscussionForumPosting" in schema):
        add("login + comments → community")
        return CategoryPrediction("community", "forum", 0.85, reasons)

    # DOCUMENTATION (high confidence : Schema TechArticle/APIReference seulement)
    if "TechArticle" in schema or "APIReference" in schema:
        return CategoryPrediction("documentation", "technical_docs", 0.9, ["Schema TechArticle/APIReference"])
    # Documentation structural fallback DEMOTED à confidence 0.35 (kNN prend le relais
    # si rules-based < 0.5). Rule plus stricte : tables élevées strict, pas
    # tables+h2_h3 (qui matchait tout article long).
    if struct.n_tables > 8 and struct.n_forms <= 1 and struct.internal_external_ratio > 5:
        add(f"high tables ({struct.n_tables}), low forms, internal-heavy → maybe docs")
        return CategoryPrediction("documentation", "guide", 0.35, reasons)

    # FAQ
    if "FAQPage" in schema:
        return CategoryPrediction("documentation", "faq", 0.85, ["Schema FAQPage"])

    # CORPORATE
    if "Organization" in schema and struct.has_contact_form:
        add("Organization schema + contact form")
        return CategoryPrediction("corporate", "company_homepage", 0.75, reasons)

    # REFERENCE_WIKI
    if struct.n_tables > 5 and struct.n_h2_h3 > 10 and struct.n_forms <= 1:
        return CategoryPrediction(
            "reference_wiki",
            "wiki_or_encyclopedia",
            0.7,
            ["high tables+headings, low forms"],
        )

    # SOCIAL
    if "Person" in schema and struct.has_login_form:
        return CategoryPrediction("social", "social_network", 0.75, ["Person schema + login"])

    # MEDIA_LIB (image/video heavy)
    if "ImageObject" in schema or "VideoObject" in schema:
        if struct.n_imgs > 30:
            return CategoryPrediction("media_lib", "image_video_lib", 0.8, ["Schema Image/Video + img-heavy"])

    # SAAS / B2B software — Schema SoftwareApplication is a strong signal
    if "SoftwareApplication" in schema:
        return CategoryPrediction("saas", "software_product", 0.9, ["Schema.org SoftwareApplication"])
    # Curated SaaS domain match → strong fallback
    if any(h in url_low for h in _SAAS_DOMAIN_HINTS):
        add(f"curated saas domain match ({url_low})")
        return CategoryPrediction("saas", "software_product", 0.7, reasons)
    # Title regex SaaS patterns (require login form to avoid FP on docs/blog sites)
    if title and _SAAS_TITLE_RE.search(title) and (struct.has_login_form or struct.has_login_link):
        add("title regex saas pattern + login form")
        return CategoryPrediction("saas", "software_product", 0.6, reasons)

    # Last-resort title/URL-only architecture/design / fashion-luxury media detection
    # (catches sites without any Schema.org markup, like designboom + architizer + fashionnetwork).
    # Curated domain hints are very specific → no further content check needed.
    # Title regex only is more permissive → require some content density.
    arch_domain_match = any(hint in url_low for hint in _ARCH_DESIGN_DOMAIN_HINTS)
    arch_title_match = bool(title and _ARCH_DESIGN_TITLE_RE.search(title))
    fashion_domain_match = any(hint in url_low for hint in _FASHION_LUXURY_DOMAIN_HINTS)
    fashion_title_match = bool(title and _FASHION_LUXURY_TITLE_RE.search(title))
    if arch_domain_match:
        add(f"curated arch/design domain match ({url_low})")
        return CategoryPrediction("media", "architecture_design", 0.7, reasons)
    if fashion_domain_match:
        add(f"curated fashion/luxury domain match ({url_low})")
        return CategoryPrediction("media", "fashion_luxury", 0.7, reasons)
    if arch_title_match and (struct.n_imgs > 5 or struct.n_h2_h3 > 3):
        add("title regex arch/design + content density")
        return CategoryPrediction("media", "architecture_design", 0.55, reasons)
    if fashion_title_match and (struct.n_imgs > 5 or struct.n_h2_h3 > 3):
        add("title regex fashion/luxury + content density")
        return CategoryPrediction("media", "fashion_luxury", 0.55, reasons)

    return CategoryPrediction("unknown", "unknown", 0.0, ["no strong signal"])


# ── Phase L — Scraping difficulty score (Mitchell + PRITES) ────────────
def _estimate_difficulty(
    reach: Reachability,
    anti_bot: dict[str, AntiBotDetection],
    frameworks: dict[str, FrameworkDetection],
    ethics: EthicsCheck | None,
    struct: StructuralFeatures | None,
) -> int:
    """1=trivial → 5=expert. Synthèse multi-axes."""
    if reach.status != "OK":
        return 5
    score = 1
    # Anti-bot weight
    strong_ab = ["akamai", "perimeterx", "datadome", "kasada", "imperva"]
    if any(anti_bot.get(s, AntiBotDetection(False)).detected for s in strong_ab):
        score += 3
    elif anti_bot.get("cloudflare", AntiBotDetection(False)).detected:
        score += 1
    # Framework / SPA weight
    spa_fw = ["nextjs", "apollo", "algolia_instantsearch"]
    if any(frameworks.get(f, FrameworkDetection(False)).detected for f in spa_fw):
        score += 1
    # Auth wall
    if struct and (struct.has_login_form or struct.has_login_link):
        if ethics and ethics.requires_login_marker:
            score += 2
    # Paywall
    if struct and struct.has_paywall_marker:
        score += 1
    # Ethics-derived
    if ethics:
        if ethics.estimated_legal_risk == "high":
            score += 1
    return min(5, score)


# ── Stage 1 → Report builder (skip browser path) ──────────────────────
def _build_report_from_stage1(s1: Stage1Findings, url: str, name: str, t0: float) -> InspectReport:
    """Build a complete InspectReport using only Stage 1 cheap probe signals.
    No browser involved. ~3-5s total."""
    # Reachability
    if s1.fortiadc_detected:
        reach = Reachability(
            status="challenge",
            page_status=s1.homepage_status,
            body_length=s1.homepage_body_length,
            title="Captcha verify",
            final_url=s1.homepage_final_url,
            evidence=f"CAPTCHA FortiADC : {s1.homepage_final_url}",
        )
    elif s1.homepage_fetch_error:
        reach = Reachability(status="error", evidence=s1.homepage_fetch_error)
    elif s1.homepage_status != 200:
        reach = Reachability(
            status="blocked" if s1.homepage_status in (403, 401, 451) else "error",
            page_status=s1.homepage_status,
            body_length=s1.homepage_body_length,
            evidence=f"HTTP {s1.homepage_status}",
        )
    else:
        # Try to extract title from HTML
        m = re.search(r"<title[^>]*>([^<]+)</title>", s1.homepage_html_first_kb, re.I)
        title = m.group(1).strip()[:100] if m else ""
        reach = Reachability(
            status="OK",
            page_status=200,
            body_length=s1.homepage_body_length,
            title=title,
            final_url=url,
            evidence=f"stage1 cheap probe OK, body={s1.homepage_body_length}",
        )

    # Anti-bot stack (synthèse stage1)
    anti_bot = {
        "cloudflare": AntiBotDetection(
            detected=s1.cf_detected,
            evidence=["header/cookie signal"] if s1.cf_detected else [],
        ),
        "akamai": AntiBotDetection(
            detected=s1.akamai_detected,
            evidence=["header/cookie"] if s1.akamai_detected else [],
        ),
        "datadome": AntiBotDetection(
            detected=s1.datadome_detected,
            evidence=["header/cookie"] if s1.datadome_detected else [],
        ),
        "perimeterx": AntiBotDetection(
            detected=s1.perimeterx_detected,
            evidence=["cookie _px*"] if s1.perimeterx_detected else [],
        ),
        "kasada": AntiBotDetection(detected=False),
        "imperva": AntiBotDetection(detected=False),
        "fortiadc": AntiBotDetection(
            detected=s1.fortiadc_detected,
            evidence=[f"redirection vers {s1.homepage_final_url}"] if s1.fortiadc_detected else [],
        ),
    }

    # Frameworks — depuis markers HTML stage1 (cheap regex scan)
    frameworks = {
        "nextjs": FrameworkDetection(
            detected=s1.fw_nextjs,
            detail="__NEXT_DATA__ or /_next/static/ in homepage HTML" if s1.fw_nextjs else "not detected",
        ),
        "apollo": FrameworkDetection(
            detected=s1.fw_apollo,
            detail="__APOLLO_STATE__ or apollo-client in HTML" if s1.fw_apollo else "not detected",
        ),
        "algolia_instantsearch": FrameworkDetection(
            detected=s1.fw_algolia,
            detail="algoliasearch / ais- markers in HTML" if s1.fw_algolia else "not detected",
        ),
        "react": FrameworkDetection(
            detected=s1.fw_react,
            detail="React markers in HTML" if s1.fw_react else "not detected",
        ),
        "vue": FrameworkDetection(
            detected=s1.fw_vue,
            detail="Vue/Nuxt markers in HTML" if s1.fw_vue else "not detected",
        ),
        "initial_state": FrameworkDetection(
            detected=s1.fw_initial_state,
            detail="window.__INITIAL_STATE__ pattern" if s1.fw_initial_state else "not detected",
        ),
    }

    # Endpoints (stage1 = robots/sitemap + wp-json si WordPress)
    endpoints = []
    if s1.sitemap and s1.sitemap.fetched:
        endpoints.append(
            EndpointSummary(
                url=s1.sitemap.url,
                method="GET",
                status=200,
                content_type="application/xml",
                category="sitemap-feed",
            )
        )
    if s1.robots and s1.robots.fetched:
        from urllib.parse import urlparse

        p = urlparse(url)
        endpoints.append(
            EndpointSummary(
                url=f"{p.scheme}://{p.netloc}/robots.txt",
                method="GET",
                status=200,
                content_type="text/plain",
                category="other",
            )
        )
    if s1.wp_json_status == 200 and s1.wp_json_count is not None:
        from urllib.parse import urlparse

        p = urlparse(url)
        endpoints.append(
            EndpointSummary(
                url=f"{p.scheme}://{p.netloc}/wp-json/wp/v2/posts",
                method="GET",
                status=200,
                content_type="application/json",
                category="api-rest",
            )
        )

    # StructuralFeatures depuis HTML brut stage1 (limité)
    body = s1.homepage_html_first_kb
    struct = StructuralFeatures(
        n_internal_links=0,  # not parsed in stage1
        n_external_links=0,
        internal_external_ratio=0.0,
        n_forms=len(re.findall(r"<form[^>]*>", body, re.I)),
        has_login_form=bool(re.search(r'input[^>]*type="password"', body, re.I)),
        has_search_form=bool(
            re.search(
                r'(input[^>]*type="search"|input[^>]*name="q"|placeholder="search)',
                body,
                re.I,
            )
        ),
        has_cart_form=bool(re.search(r'(class="[^"]*cart[^"]*"|add-to-cart|class="[^"]*checkout)', body, re.I)),
        has_comment_form=bool(re.search(r'name="comment"|id="comment', body, re.I)),
        has_contact_form=bool(re.search(r'class="[^"]*contact-form|action="[^"]*contact', body, re.I)),
        n_imgs=len(re.findall(r"<img\b", body, re.I)),
        n_articles=len(re.findall(r"<article\b", body, re.I)),
        n_h1=len(re.findall(r"<h1\b", body, re.I)),
        n_h2_h3=len(re.findall(r"<h[23]\b", body, re.I)),
        n_paragraphs=len(re.findall(r"<p\b", body, re.I)),
        n_tables=len(re.findall(r"<table\b", body, re.I)),
        n_iframes=len(re.findall(r"<iframe\b", body, re.I)),
        schema_types=s1.schema_types_found,
        structured_data_formats=s1.structured_data_formats,
        has_paywall_marker=bool(re.search(r"paywall|subscriber-only|premium-content", body, re.I)),
        has_consent_wall=bool(re.search(r"cookie-consent|cmp-banner|onetrust-banner", body, re.I)),
        has_login_link=bool(re.search(r">(\s*)(sign in|log in|login|connexion)", body, re.I)),
    )

    # Ethics
    ai_blocked = s1.robots.ai_bots_blocked if (s1.robots and s1.robots.fetched) else []
    crawl_delay = s1.robots.crawl_delay if (s1.robots and s1.robots.fetched) else None
    robots_allows_root = True
    if s1.robots and s1.robots.fetched:
        star = s1.robots.user_agent_groups.get("*", {})
        if any(d == "/" for d in star.get("disallow", [])):
            robots_allows_root = False
    risk = 0
    notes = []
    if not robots_allows_root:
        risk += 2
        notes.append("robots Disallow / for *")
    if ai_blocked:
        risk += 1
        notes.append(f"AI bots blocked: {ai_blocked[:3]}")
    if struct.has_paywall_marker:
        risk += 2
        notes.append("paywall detected")
    legal_risk = "high" if risk >= 4 else ("medium" if risk >= 2 else "low")
    ethics = EthicsCheck(
        robots_allows_root=robots_allows_root,
        ai_bots_blocked=ai_blocked,
        crawl_delay=crawl_delay,
        has_paywall_marker=struct.has_paywall_marker,
        has_consent_wall=struct.has_consent_wall,
        requires_login_marker=struct.has_login_link,
        estimated_legal_risk=legal_risk,
        notes=notes,
    )

    # Category prediction (uses title from reachability + url for domain hints)
    category_pred = _predict_category(struct, title=reach.title or "", url=url)

    # Difficulty
    difficulty = _estimate_difficulty(reach, anti_bot, frameworks, ethics, struct)

    # Tier recommendation (Stage 1 path : pass auth wall signals)
    rec = _recommend_tier(
        reachability=reach,
        anti_bot=anti_bot,
        frameworks=frameworks,
        endpoints=endpoints,
        graphql_calls=[],
        requires_login=login_wall(struct),
        robots_disallows_root=not (ethics.robots_allows_root if ethics else True),
    )

    duration = time.monotonic() - t0
    report = InspectReport(
        target_url=url,
        name=name,
        timestamp=datetime.now(UTC).isoformat(),
        duration_s=round(duration, 1),
        reachability=reach,
        anti_bot_stack=anti_bot,
        frameworks=frameworks,
        endpoints=endpoints,
        graphql_calls=[],
        inline_data_islands=[],
        link_architecture=None,
        robots=s1.robots,
        sitemap=s1.sitemap,
        structural_features=struct,
        ethics_check=ethics,
        category_prediction=category_pred,
        scraping_difficulty=difficulty,
        tier_recommendation=rec,
    )
    report.trackers = detect_trackers([], s1.homepage_html_first_kb, url)
    report.human_gate = predict_human_gate(report)
    return report


# ── Main inspect function ────────────────────────────────────────────────
async def inspect(
    url: str,
    name: str,
    *,
    headless: bool = False,
    timeout: float = 40.0,
    purpose: str = "research",
    save_partial: bool = False,
    force_browser: bool = False,
) -> InspectReport:
    """Inspecte un site cible, retourne un InspectReport."""
    # Garde de destination avant tout : ni requête HTTP ni navigateur vers une
    # adresse interne (le navigateur, lui, n'a pas de crochet par requête).
    await _http.assert_public_async(url)

    import nodriver as nd

    t0 = time.monotonic()
    log.info(f"  🔎 [sap inspect] {url}")

    # Stage 1 — Cheap HTTP probe (no browser, ~3-5s)
    log.info("  📡 [stage 1] cheap HTTP probe…")
    s1 = await _stage1_cheap_probe(url)
    log.info(
        f"  📡 [stage 1] home={s1.homepage_status} body={s1.homepage_body_length}b "
        f"cookies={len(s1.homepage_set_cookies)} cf={s1.cf_detected} ak={s1.akamai_detected} "
        f"schema={len(s1.schema_types_found)} cms={s1.cms_hints or 'none'}"
    )
    log.info(f"  📡 [stage 1] decision: needs_browser={s1.needs_browser} ({s1.decision_rationale})")

    if not s1.needs_browser and force_browser:
        log.info("  📡 [stage 1] --browser : Chrome ouvert quand même (traceurs chargés en JavaScript)")
    if not s1.needs_browser and not force_browser:
        # Stage 1 sufficient → skip browser entirely. Build report from cheap signals only.
        report = _build_report_from_stage1(s1, url, name, t0)
        report.purpose = purpose
        report.skipped_browser_stage2 = True
        # kNN prior with cheap signals
        target_signals = {
            "anti_bot": [k for k, v in report.anti_bot_stack.items() if v.detected],
            "schema_types": s1.schema_types_found,
            "cms_hints": s1.cms_hints,
        }
        report.knn_prior = _knn_corpus_lookup(url, target_signals, k=5)
        # Bridge kNN → category only when consensus is robust :
        #   - rules-based confidence < 0.5 (uncertain)
        #   - at least 2 voting neighbors (avoid single-neighbor extrapolation)
        #   - top neighbor score ≥ 0.6 (avoid weak matches)
        knn = report.knn_prior
        if (
            knn.consensus_category
            and report.category_prediction.confidence < 0.5
            and len(knn.top_k_sites) >= 2
            and (knn.top_k_sites[0].get("score", 0) if knn.top_k_sites else 0) >= 0.6
        ):
            report.category_prediction = CategoryPrediction(
                category=knn.consensus_category,
                subcategory=knn.consensus_subcategory or "from_knn",
                confidence=0.6,
                reasoning=[
                    f"kNN consensus from {len(knn.top_k_sites)} corpus sites "
                    f"(top score {knn.top_k_sites[0].get('score', 0):.2f})"
                ],
            )
        # Bridge kNN → difficulty when rules-based is in {1, 2} (low-confidence floor)
        # OR when no anti-bot signal but kNN sees one in similar sites.
        if (
            report.knn_prior.consensus_difficulty is not None
            and report.scraping_difficulty is not None
            and report.scraping_difficulty <= 2
            and report.knn_prior.consensus_difficulty > report.scraping_difficulty
        ):
            report.scraping_difficulty = report.knn_prior.consensus_difficulty
        if save_partial:
            try:
                save_report(report)
            except Exception:
                pass
        return report

    # === Stage 2 needed → save Stage 1 fallback BEFORE attempting browser ===
    # Critical for graceful degradation : if Stage 2 hangs/timeouts, we already
    # have a baseline report on disk built from Stage 1 + kNN.
    if save_partial:
        fallback = _build_report_from_stage1(s1, url, name, t0)
        fallback.purpose = purpose
        fallback.skipped_browser_stage2 = False  # browser WAS attempted
        # kNN with cheap signals
        target_signals = {
            "anti_bot": [k for k, v in fallback.anti_bot_stack.items() if v.detected],
            "schema_types": s1.schema_types_found,
            "cms_hints": s1.cms_hints,
        }
        fallback.knn_prior = _knn_corpus_lookup(url, target_signals, k=5)
        # Bridge kNN → category only when consensus is robust (≥2 voters, top score ≥0.6)
        knn = fallback.knn_prior
        rules_uncertain = fallback.category_prediction is None or fallback.category_prediction.confidence < 0.5
        if (
            knn.consensus_category
            and rules_uncertain
            and len(knn.top_k_sites) >= 2
            and (knn.top_k_sites[0].get("score", 0) if knn.top_k_sites else 0) >= 0.6
        ):
            fallback.category_prediction = CategoryPrediction(
                category=knn.consensus_category,
                subcategory=knn.consensus_subcategory or "from_knn",
                confidence=0.6,
                reasoning=[
                    f"kNN consensus from {len(knn.top_k_sites)} corpus sites "
                    f"(rules-based uncertain because Stage 2 unreachable)",
                ],
            )
        # Difficulty: prefer kNN consensus if available (more accurate than blanket "5"),
        # else use rules-based floor of 4 (anti-bot strong since Stage 2 was needed).
        rules_diff = fallback.scraping_difficulty or 1
        knn_diff = fallback.knn_prior.consensus_difficulty
        if knn_diff is not None:
            # Take max of kNN and rules-floor (4) — Stage 2 was needed, so it's at least
            # 4-territory, but kNN may indicate 5 for sites with stronger anti-bot.
            fallback.scraping_difficulty = max(knn_diff, 4)
        else:
            fallback.scraping_difficulty = max(rules_diff, 4)
        fallback.tier_recommendation = TierRecommendation(
            primary=4,
            rationale="Stage 1 cheap probe indicated anti-bot strong (browser needed, marionnette likely required).",
            fallbacks=[3],
        )
        try:
            save_report(fallback)
            # Emit YAML shards too — so even if Stage 2 hangs and gets killed externally
            # before emit_yaml_shards is called by CLI, the shards reflect the partial state.
            try:
                emit_yaml_shards(fallback)
            except Exception as ye:
                log.info(f"  ⚠️ fallback yaml emit err: {ye}")
            log.info("  💾 Stage 1 fallback persisted (in case Stage 2 timeouts)")
        except Exception as e:
            log.info(f"  ⚠️ fallback save err: {e}")

    captured_responses: list[dict] = []  # {url, status, headers, ct, method, request_id}
    pending_bodies: dict[str, str] = {}  # request_id → category
    bodies: dict[str, str] = {}  # request_id → body string
    request_post_data: dict[str, str] = {}  # request_id → post_data
    request_methods: dict[str, str] = {}  # request_id → méthode HTTP
    request_urls: list[str] = []  # toutes les requêtes, traceurs compris
    html = ""
    set_cookies_seen: set[str] = set()  # cookies posés au cours de la session (set-cookie headers)

    browser_args = [
        "--disable-blink-features=AutomationControlled",
        "--window-size=1280,900",
    ]
    # Profil jetable à nous : sert de marqueur exact pour arrêter le seul
    # navigateur lancé ici, et il est effacé à la fin.
    profile_dir = tempfile.mkdtemp(prefix="sap_inspect_")
    browser = None
    try:
        # Hard ceiling for browser startup + initial nav. Akamai/CF can hang nodriver
        # indefinitely on first navigation despite internal timeouts. Wrap with wait_for
        # so we bail out cleanly to the Stage 1 partial fallback (already saved on disk).
        try:
            browser = await asyncio.wait_for(
                nd.start(
                    _browser_config(
                        nd,
                        headless=headless,
                        profile_dir=profile_dir,
                        browser_args=browser_args,
                    )
                ),
                timeout=15.0,
            )
            tab = await asyncio.wait_for(browser.get(url), timeout=15.0)
            await asyncio.wait_for(tab.send(nd.cdp.network.enable()), timeout=5.0)
        except (TimeoutError, Exception) as e:
            msg = (
                "Stage 2 browser startup hang/error"
                if isinstance(e, asyncio.TimeoutError)
                else f"Stage 2 startup err: {type(e).__name__}"
            )
            log.warning("  ⚠️ %s (%s) — fallback to Stage 1 partial", msg, neutralize(e, 160))
            # Arrêt du seul navigateur lancé ici (repéré par son profil), s'il a démarré.
            _kill_browser_processes(f"--user-data-dir={profile_dir}")
            # Return Stage 1 partial report (built fresh — the on-disk save_partial may
            # not have run if save_partial=False)
            partial = _build_report_from_stage1(s1, url, name, t0)
            partial.purpose = purpose
            partial.skipped_browser_stage2 = False  # browser was attempted
            target_signals = {
                "anti_bot": [k for k, v in partial.anti_bot_stack.items() if v.detected],
                "schema_types": s1.schema_types_found,
                "cms_hints": s1.cms_hints,
            }
            partial.knn_prior = _knn_corpus_lookup(url, target_signals, k=5)
            partial.scraping_difficulty = max(partial.scraping_difficulty or 1, 4)
            partial.tier_recommendation = TierRecommendation(
                primary=4,
                rationale=f"{msg} → fallback Stage 1 + Tier 4 marionnette nodriver requise.",
                fallbacks=[3],
            )
            return partial

        async def on_req(event):
            _request_seen(event, request_methods, request_post_data)
            request_urls.append(event.request.url)

        async def on_resp(event):
            u = event.response.url
            entry = _response_entry(event, request_methods)
            headers = entry["headers"]
            captured_responses.append(entry)
            # Capture set-cookie names via CDP response events (Fix 3)
            for k, v in headers.items():
                if k.lower() == "set-cookie":
                    # v is a string with possibly multiple cookies separated by \n in some impls
                    for line in str(v).split("\n"):
                        name = line.split("=", 1)[0].strip()
                        if name:
                            set_cookies_seen.add(name)
            cat = _categorize_url(u)
            # Schedule body fetch for graphql + json-typed api-rest + search
            if cat in ("graphql", "search") and event.response.status == 200:
                pending_bodies[str(event.request_id)] = cat
            elif (
                cat == "api-rest"
                and event.response.status == 200
                and "json" in (event.response.headers.get("content-type", "") if event.response.headers else "")
            ):
                pending_bodies[str(event.request_id)] = cat

        async def on_loaded(event):
            rid = str(event.request_id)
            if rid not in pending_bodies:
                return
            pending_bodies.pop(rid)
            try:
                body, b64 = await tab.send(nd.cdp.network.get_response_body(event.request_id))
                if b64:
                    body = base64.b64decode(body).decode("utf-8", errors="replace")
                bodies[rid] = body
            except Exception:
                pass

        tab.add_handler(nd.cdp.network.RequestWillBeSent, on_req)
        tab.add_handler(nd.cdp.network.ResponseReceived, on_resp)
        tab.add_handler(nd.cdp.network.LoadingFinished, on_loaded)

        # Wait for activity (timeout window)
        log.info(f"  ⏳ collecting events for {timeout}s...")
        await asyncio.sleep(timeout)

        # Capture cookies post-load (CDP Network.getCookies — OWASP fingerprinting)
        # + Aggrège les set-cookies vus pendant la session (Fix 3 : recall accru)
        cookies_detected_tech: list[str] = []
        cookie_names: list[str] = list(set_cookies_seen)
        try:
            cookies_resp = await tab.send(nd.cdp.network.get_cookies())
            cookie_names_post = [c.name for c in (cookies_resp or [])]
            for cn in cookie_names_post:
                if cn not in set_cookies_seen:
                    cookie_names.append(cn)
        except Exception as e:
            log.info(f"  🍪 cookies fetch err: {type(e).__name__}: {str(e)[:60]}")
        cookies_detected_tech = _match_cookies(cookie_names)
        if cookies_detected_tech:
            log.info(f"  🍪 cookies detected: {cookies_detected_tech} (from {len(cookie_names)} cookies)")

        # Phase A — Reachability
        try:
            title = await tab.evaluate("document.title") or ""
            body_text = await tab.evaluate("document.body ? document.body.innerText : ''") or ""
            final_url = await tab.evaluate("window.location.href") or url
            html = await tab.get_content()
        except Exception:
            title = ""
            body_text = ""
            final_url = url
            html = ""

        reach = classify_page(title, body_text, url, final_url)
        log.info(f"  📍 reachability: {reach.status} (title={neutralize(reach.title, 80)}, body={reach.body_length})")

        # Phase B — Anti-bot detection (incluant signaux cookies)
        captured_urls = [r["url"] for r in captured_responses]
        captured_headers = [r["headers"] for r in captured_responses]
        anti_bot = _detect_anti_bot(
            title=title,
            html=html,
            captured_urls=captured_urls,
            captured_headers=captured_headers,
        )
        # Augment anti-bot with cookies detection (cookies are the most reliable per OWASP)
        cookie_to_antibot = {
            "cloudflare": "cloudflare",
            "perimeterx": "perimeterx",
            "datadome": "datadome",
            "kasada": "kasada",
            "imperva": "imperva",
            "akamai": "akamai",
        }
        for tech in cookies_detected_tech:
            ab_key = cookie_to_antibot.get(tech)
            if ab_key and ab_key in anti_bot:
                if not anti_bot[ab_key].detected:
                    anti_bot[ab_key] = AntiBotDetection(detected=True, evidence=[f"cookie signature ({tech})"])
                else:
                    anti_bot[ab_key].evidence.append(f"cookie signature ({tech})")
        detected_stacks = [k for k, v in anti_bot.items() if v.detected]
        log.info(f"  🛡  anti-bot stack: {detected_stacks or 'none detected'}")

        # Phase C — Frameworks
        frameworks = await _detect_frameworks(tab)
        detected_fwks = [k for k, v in frameworks.items() if v.detected and not k.startswith("_")]
        log.info(f"  🧰 frameworks: {detected_fwks or 'none'}")

        # Phase E — Data islands
        islands = await _extract_data_islands(tab)
        log.info(f"  📦 inline data islands: {len(islands)}")

        # Phase G — Link architecture
        anchors = await _extract_anchors(tab)
        link_arch = _analyze_link_architecture(anchors, url)
        log.info(
            f"  🔗 links: {link_arch.same_domain_count}/{link_arch.total_anchors} same-domain, "
            f"{len(link_arch.clusters)} clusters, {len(link_arch.pagination_patterns)} pagination patterns"
        )

        # Phase H — Structural features (Lindemann/Thapa)
        struct = await _extract_structural_features(tab)
        log.info(
            f"  📐 struct: forms={struct.n_forms} schema={len(struct.schema_types)} "
            f"links={struct.n_internal_links}/{struct.n_external_links} tables={struct.n_tables}"
        )

        # Phase I — robots.txt + sitemap (parallel-safe)
        robots = await _fetch_robots(url)
        log.info(
            f"  🤖 robots: fetched={robots.fetched} ai_blocked={len(robots.ai_bots_blocked)} sitemaps={len(robots.sitemaps)}"
        )
        sitemap_a = await _fetch_sitemap(url, robots.sitemaps if robots.fetched else [])
        if sitemap_a.fetched:
            kind = "index" if sitemap_a.is_index else "urlset"
            n = sitemap_a.n_sitemaps if sitemap_a.is_index else sitemap_a.n_urls
            log.info(f"  🗺  sitemap: {kind}, n={n}, ext={sitemap_a.has_extensions}")
        else:
            log.info("  🗺  sitemap: not found")

        # Phase J — Ethics check
        ethics = await _ethics_check(tab, robots, struct)
        log.info(
            f"  ⚖  ethics: legal_risk={ethics.estimated_legal_risk} ai_blocked={ethics.ai_bots_blocked or 'none'} paywall={ethics.has_paywall_marker}"
        )

        # Phase K — Category prediction (with title + url for domain-specific subcategory)
        category_pred = _predict_category(struct, title=reach.title or "", url=url)
        log.info(
            f"  🏷  category: {category_pred.category}/{category_pred.subcategory} (conf {category_pred.confidence:.2f})"
        )

        # Phase D — Endpoint summary (group by URL with categorize, count occurrences)
        endpoint_map: dict[str, EndpointSummary] = {}
        for r in captured_responses:
            cat = _categorize_url(r["url"])
            if cat in ("static", "ad-tech"):
                continue
            # Normalize URL for grouping (strip query)
            from urllib.parse import urlparse

            parsed = urlparse(r["url"])
            key_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            key = (key_url, r.get("method", "GET"))
            if key in endpoint_map:
                endpoint_map[key].occurrences += 1
            else:
                endpoint_map[key] = EndpointSummary(
                    url=key_url,
                    method=r.get("method", "GET"),
                    status=r["status"],
                    content_type=(r["content_type"] or "")[:60],
                    category=cat,
                    occurrences=1,
                )
        endpoints = sorted(
            endpoint_map.values(),
            key=lambda e: (
                {
                    "graphql": 0,
                    "search": 1,
                    "api-rest": 2,
                    "sitemap-feed": 3,
                    "telemetry": 4,
                    "other": 5,
                }.get(e.category, 9),
                -e.occurrences,
            ),
        )
        log.info(f"  🔗 endpoints captured: {len(endpoints)} (filtered out static/ad-tech)")

        # GraphQL bodies — extract operationName + query + variables + response
        graphql_calls: list[GraphQLCall] = []
        for r in captured_responses:
            if _categorize_url(r["url"]) != "graphql":
                continue
            rid = r["request_id"]
            post = request_post_data.get(rid)
            body = bodies.get(rid, "")
            op_name, query_preview, variables = None, "", {}
            if post:
                try:
                    d = json.loads(post)
                    if isinstance(d, list):
                        # batched
                        for q in d:
                            if isinstance(q, dict):
                                graphql_calls.append(
                                    GraphQLCall(
                                        url=r["url"],
                                        operation_name=q.get("operationName"),
                                        query_preview=(q.get("query", "") or "")[:300],
                                        variables=q.get("variables", {}) or {},
                                        response_preview=(body or "")[:500],
                                    )
                                )
                        continue
                    elif isinstance(d, dict):
                        op_name = d.get("operationName")
                        query_preview = (d.get("query", "") or "")[:300]
                        variables = d.get("variables", {}) or {}
                except Exception:
                    pass
            graphql_calls.append(
                GraphQLCall(
                    url=r["url"],
                    operation_name=op_name,
                    query_preview=query_preview,
                    variables=variables if isinstance(variables, dict) else {},
                    response_preview=(body or "")[:500],
                )
            )
        # dedup by (operation_name, str(variables))
        seen_keys = set()
        unique_calls: list[GraphQLCall] = []
        for c in graphql_calls:
            key = (c.operation_name, json.dumps(c.variables, sort_keys=True)[:200])
            if key in seen_keys:
                continue
            seen_keys.add(key)
            unique_calls.append(c)
        graphql_calls = unique_calls
        log.info(f"  📡 graphql calls (unique by op+vars): {len(graphql_calls)}")

        # Phase L — Scraping difficulty (Mitchell)
        difficulty = _estimate_difficulty(reach, anti_bot, frameworks, ethics, struct)
        log.info(f"  📊 scraping_difficulty: {difficulty}/5")

        # Phase F — Tier recommendation (Stage 2 path : pass auth wall signals)
        rec = _recommend_tier(
            browser=True,
            reachability=reach,
            anti_bot=anti_bot,
            frameworks=frameworks,
            endpoints=endpoints,
            graphql_calls=graphql_calls,
            requires_login=login_wall(struct),
            robots_disallows_root=not (ethics.robots_allows_root if ethics else True),
        )
        log.info(f"  💡 tier recommendation: Tier {rec.primary} (fallbacks: {rec.fallbacks or 'none'})")

    finally:
        # Arrêt garanti, même si une phase de l'étape 2 a levé une exception.
        if browser is not None:
            proc = getattr(browser, "_process", None)
            try:
                browser.stop()
                if proc is not None:  # laisser Chrome finir d'écrire son profil avant de l'effacer
                    await asyncio.wait_for(proc.wait(), timeout=5.0)
            except Exception:
                _kill_browser_processes(f"--user-data-dir={profile_dir}")
        shutil.rmtree(profile_dir, ignore_errors=True)

    duration = time.monotonic() - t0
    # kNN prior with all available signals
    target_signals = {
        "anti_bot": [k for k, v in anti_bot.items() if v.detected],
        "schema_types": (struct.schema_types if struct else []) or [],
        "cms_hints": s1.cms_hints if s1 else [],
    }
    knn_prior = _knn_corpus_lookup(url, target_signals, k=5)
    if knn_prior.consensus_category and category_pred.confidence < 0.5:
        category_pred = CategoryPrediction(
            category=knn_prior.consensus_category,
            subcategory=knn_prior.consensus_subcategory or "from_knn",
            confidence=0.6,
            reasoning=[f"kNN consensus from {len(knn_prior.top_k_sites)} similar corpus sites"],
        )

    report = InspectReport(
        target_url=url,
        name=name,
        timestamp=datetime.now(UTC).isoformat(),
        duration_s=round(duration, 1),
        reachability=reach,
        anti_bot_stack=anti_bot,
        frameworks=frameworks,
        endpoints=endpoints,
        graphql_calls=graphql_calls,
        inline_data_islands=islands,
        link_architecture=link_arch,
        robots=robots,
        sitemap=sitemap_a,
        structural_features=struct,
        ethics_check=ethics,
        category_prediction=category_pred,
        scraping_difficulty=difficulty,
        tier_recommendation=rec,
        purpose=purpose,
        skipped_browser_stage2=False,
        knn_prior=knn_prior,
        browser_ran=True,
    )
    report.trackers = detect_trackers(request_urls + [r["url"] for r in captured_responses], html, url)
    report.human_gate = predict_human_gate(report)
    return report


# ── Navigateur (étape 2) : configuration et arrêt ─────────────────────────
def _browser_config(nd, *, headless: bool, profile_dir: str, browser_args: list[str]):
    """Config nodriver durcie.

    nodriver désactive l'isolation des sites (--disable-features=IsolateOrigins,
    site-per-process) et ouvre le port de débogage à toute origine
    (--remote-allow-origins=*). On rétablit l'isolation et on limite l'origine
    à 127.0.0.1 (nodriver se connecte sans en-tête Origin, donc sans effet sur lui).
    """

    class _HardenedConfig(nd.Config):
        def __call__(self):
            out = []
            for a in super().__call__():
                if a.startswith("--remote-allow-origins="):
                    a = "--remote-allow-origins=http://127.0.0.1"
                elif a.startswith("--disable-features="):
                    feats = [
                        f
                        for f in a.split("=", 1)[1].split(",")
                        if f and f not in ("IsolateOrigins", "site-per-process")
                    ]
                    if not feats:
                        continue
                    a = "--disable-features=" + ",".join(feats)
                out.append(a)
            out.append("--site-per-process")
            return out

    return _HardenedConfig(
        user_data_dir=profile_dir,
        headless=headless,
        browser_executable_path=CHROME_PATH,
        browser_args=list(browser_args),
    )


def _kill_browser_processes(marker: str) -> None:
    """Termine les processus dont la ligne de commande contient exactement
    `marker` (ex. `--user-data-dir=<profil jetable>`), et eux seuls."""
    import os
    import signal
    import subprocess

    try:
        ps = subprocess.run(
            ["ps", "-axo", "pid=,command="],
            capture_output=True,
            text=True,
            check=False,
            timeout=3,
        ).stdout
    except Exception:
        return
    for line in ps.splitlines():
        pid_s, _, cmd = line.strip().partition(" ")
        if not pid_s.isdigit():
            continue
        if any(tok == marker for tok in cmd.split()):
            try:
                os.kill(int(pid_s), signal.SIGKILL)
            except OSError:
                pass


# ── Markdown formatter ──────────────────────────────────────────────────
_GATE_LABELS = {"challenge": "défi anti-bot", "login": "connexion", "consent": "consentement"}


def _human_gate_lines(g: HumanGate, name: str, target_url: str) -> list[str]:
    """Annonce du geste humain, hors du bloc de données : ce sont nos conclusions."""
    vendor = f" {g.vendor}" if g.vendor else ""
    return [
        f"## ✋ Geste humain requis : {_GATE_LABELS[g.kind]}{vendor} (≈{g.est_seconds} s)",
        "",
        f"- Indices : {neutralize('; '.join(g.evidence), 200)}",
        f"- Vu depuis : `{neutralize(g.seen_from, 64)}` ; une autre machine (VPS, proxy) peut voir une autre porte.",
        f"- Faire le geste : `python -m accesspath warmup {name} --at {neutralize(target_url, 300)}`"
        " (Chrome visible, profil du site), puis collecter depuis cette même machine.",
        "- Avec `--save`, le geste rejoint la file : `python -m accesspath gestes` la liste, `gestes --faire` l'ouvre.",
        "",
    ]


def _request_seen(event, methods: dict[str, str], post_data: dict[str, str]) -> None:
    """Note la méthode (et le corps éventuel) de chaque requête, par request_id."""
    rid = str(event.request_id)
    methods[rid] = event.request.method or "GET"
    if event.request.post_data:
        post_data[rid] = event.request.post_data


def _response_entry(event, methods: dict[str, str]) -> dict:
    """Entrée de capture d'une réponse, avec la méthode de sa requête."""
    rid = str(event.request_id)
    headers = dict(event.response.headers) if event.response.headers else {}
    return {
        "request_id": rid,
        "url": event.response.url,
        "status": event.response.status,
        "method": methods.get(rid, "GET"),
        "headers": headers,
        "content_type": headers.get("content-type", ""),
    }


def to_markdown(report: InspectReport) -> str:
    """Format human-readable rapport markdown.

    Tout ce qui vient du site (titre, URL, en-têtes, GraphQL, liens, sitemap,
    types Schema.org, liens CGU…) passe par `neutralize` et se trouve entre
    DATA_BEGIN et DATA_END.
    """
    n = neutralize
    lines: list[str] = []
    lines.append(f"# SAP Inspect — {n(report.name, 64)}")
    lines.append("")
    lines.append(f"- **Timestamp** : {n(report.timestamp, 40)}")
    lines.append(f"- **Duration** : {n(report.duration_s, 12)}s")
    lines.append("")
    if report.human_gate:
        lines.extend(_human_gate_lines(report.human_gate, report.name, report.target_url))
    lines.append(DATA_BEGIN)
    lines.append("")
    lines.append(f"- **URL** : {n(report.target_url, 300)}")
    lines.append(
        f"- **Reachability** : `{n(report.reachability.status, 20)}` "
        f"(title={n(report.reachability.title, 120)}, body={int(report.reachability.body_length):,} chars)"
    )
    lines.append("")

    lines.extend(_tracker_lines(report))

    lines.append("## Anti-bot stack")
    detected = [(k, v) for k, v in report.anti_bot_stack.items() if v.detected]
    if not detected:
        lines.append("✓ Aucune signature anti-bot détectée parmi les patterns connus.")
    else:
        for name, det in detected:
            lines.append(f"- ⚠️ **{n(name, 40)}** : ")
            for ev in det.evidence:
                lines.append(f"   - {n(ev, 200)}")
    lines.append("")

    lines.append("## Frameworks / SPA markers")
    for name, det in report.frameworks.items():
        if name.startswith("_"):
            continue
        marker = "✓" if det.detected else "❌"
        lines.append(f"- {marker} **{n(name, 40)}** : {n(det.detail, 200)}")
    lines.append("")

    lines.append(f"## Endpoints capturés ({len(report.endpoints)})")
    if report.endpoints:
        lines.append("")
        lines.append("| Cat | Status | Method | Occurr | URL |")
        lines.append("|---|---:|---|---:|---|")
        for e in report.endpoints[:30]:
            lines.append(
                f"| {n(e.category, 20)} | {n(e.status, 6)} | {n(e.method, 10)} | "
                f"{n(e.occurrences, 8)} | `{n(e.url, 120)}` |"
            )
        if len(report.endpoints) > 30:
            lines.append(f"\n_... +{len(report.endpoints) - 30} autres endpoints_")
    lines.append("")

    if report.graphql_calls:
        lines.append(f"## GraphQL calls ({len(report.graphql_calls)})")
        for i, c in enumerate(report.graphql_calls[:5]):
            lines.append("")
            # pas de titre markdown portant une valeur distante : un élément de liste
            lines.append(f"- **Appel {i + 1}** — opération `{n(c.operation_name or '(anonymous)', 80)}`")
            lines.append(f"- URL : `{n(c.url, 200)}`")
            if c.variables:
                lines.append(f"- variables : `{n(json.dumps(c.variables, ensure_ascii=False), 300)}`")
            if c.query_preview:
                lines.append(f"- query[:300] : `{n(c.query_preview, 300)}`")
            if c.response_preview:
                lines.append(f"- response[:500] : `{n(c.response_preview, 500)}`")
        lines.append("")

    if report.inline_data_islands:
        lines.append(f"## Inline JSON data islands ({len(report.inline_data_islands)})")
        for d in report.inline_data_islands:
            lines.append(f"- `{n(d.selector, 80)}` : {int(d.size):,} chars, top-level keys: `{n(d.keys, 200)}`")
        lines.append("")

    if report.link_architecture:
        la = report.link_architecture
        lines.append("## Link architecture")
        lines.append(
            f"- Total anchors : **{n(la.total_anchors, 8)}** ({n(la.same_domain_count, 8)} same-domain, "
            f"{n(la.nav_anchors_count, 8)} en `<nav>`/`<header>`)"
        )
        if la.external_domains:
            lines.append(f"- External domains (filtrés out) : {n(', '.join(map(str, la.external_domains[:10])), 400)}")
        if la.clusters:
            lines.append("\n### URL clusters (top 15 par count)")
            lines.append("")
            lines.append("| Type | Count | Pattern | Sample |")
            lines.append("|---|---:|---|---|")
            for c in la.clusters[:15]:
                sample = c.samples[0] if c.samples else ""
                lines.append(
                    f"| {n(c.cluster_type, 20)} | {n(c.count, 8)} | `{n(c.pattern, 80)}` | `{n(sample, 80)}` |"
                )
        if la.pagination_patterns:
            lines.append("\n### Pagination patterns détectés")
            for pp in la.pagination_patterns:
                m = f" max={n(pp.max_observed, 10)}" if pp.max_observed else ""
                lines.append(f"- `{n(pp.kind, 60)}`{m} (sample: `{n(pp.sample_url, 120)}`)")
        if la.suggested_seeds:
            lines.append("\n### Suggested seeds")
            for sd in la.suggested_seeds:
                lines.append(f"- {n(sd, 200)}")
        lines.append("")

    if report.robots:
        r = report.robots
        lines.append("## robots.txt")
        if r.fetched:
            lines.append(f"- Fetched OK, {len(r.user_agent_groups)} UA groups, {len(r.sitemaps)} sitemap refs")
            if r.ai_bots_blocked:
                lines.append(f"- ⚠️ AI bots blocked : {n(', '.join(map(str, r.ai_bots_blocked)), 300)}")
            if r.crawl_delay:
                lines.append(f"- crawl-delay : {n(r.crawl_delay, 12)}s")
        else:
            lines.append(f"- ❌ not fetched (status={n(r.status, 6)})")
        lines.append("")

    if report.sitemap and report.sitemap.fetched:
        sm = report.sitemap
        lines.append("## Sitemap")
        kind = "index" if sm.is_index else "urlset"
        cnt = sm.n_sitemaps if sm.is_index else sm.n_urls
        lines.append(f"- {kind} at `{n(sm.url, 200)}`, n={int(cnt):,}")
        if sm.has_extensions:
            lines.append(f"- extensions : {n(sm.has_extensions, 200)}")
        if sm.sample_urls:
            lines.append(f"- sample URLs : {n(sm.sample_urls[:3], 400)}")
        if sm.earliest_lastmod or sm.latest_lastmod:
            lines.append(f"- lastmod range : {n(sm.earliest_lastmod, 40)} → {n(sm.latest_lastmod, 40)}")
        lines.append("")

    if report.structural_features:
        sf = report.structural_features
        lines.append("## Structural features")
        lines.append(
            f"- Links : {sf.n_internal_links} internal / {sf.n_external_links} external "
            f"(ratio {sf.internal_external_ratio:.1f})"
        )
        forms_signals = [
            ("login", sf.has_login_form),
            ("search", sf.has_search_form),
            ("signup", sf.has_signup_form),
            ("cart", sf.has_cart_form),
            ("comment", sf.has_comment_form),
            ("contact", sf.has_contact_form),
        ]
        active = [nm for nm, v in forms_signals if v]
        lines.append(f"- Forms : {sf.n_forms} total, signals: {active or 'none'}")
        lines.append(
            f"- DOM : imgs={sf.n_imgs}, articles={sf.n_articles}, h1={sf.n_h1}, h2-h3={sf.n_h2_h3}, "
            f"p={sf.n_paragraphs}, tables={sf.n_tables}, iframes={sf.n_iframes}"
        )
        lines.append(f"- Schema.org types : {n(sf.schema_types or 'none', 300)}")
        lines.append(f"- Structured data formats : {n(sf.structured_data_formats or 'none', 200)}")
        if sf.has_paywall_marker:
            lines.append("- ⚠️ paywall marker detected")
        if sf.has_consent_wall:
            lines.append("- ⚠️ consent wall detected")
        lines.append("")

    if report.ethics_check:
        e = report.ethics_check
        lines.append("## Ethics & legal preliminary check")
        lines.append(f"- **Estimated legal risk** : `{n(e.estimated_legal_risk, 20)}`")
        lines.append(f"- robots allows root : {e.robots_allows_root}")
        if e.ai_bots_blocked:
            lines.append(f"- AI bots blocked : {n(e.ai_bots_blocked, 300)}")
        if e.crawl_delay:
            lines.append(f"- robots.txt crawl-delay : {n(e.crawl_delay, 12)}s")
        if e.tos_link_found:
            lines.append(f"- ToS link : `{n(e.tos_link_found, 200)}`")
        if e.privacy_link_found:
            lines.append(f"- Privacy link : `{n(e.privacy_link_found, 200)}`")
        if e.has_paywall_marker:
            lines.append("- ⚠️ paywall detected")
        if e.requires_login_marker:
            lines.append("- ⚠️ requires login")
        if e.is_eu_geo_targeting:
            lines.append("- 🇪🇺 EU/GDPR markers detected")
        if e.user_profile_pages_detected:
            lines.append("- 👤 user profile pages (PII risk)")
        for note in e.notes:
            lines.append(f"- _note_: {n(note, 300)}")
        lines.append("")

    if report.category_prediction:
        c = report.category_prediction
        lines.append("## Category prediction (Lindemann + Schema.org)")
        lines.append(f"- **{n(c.category, 40)}** / **{n(c.subcategory, 40)}** (confidence {c.confidence:.2f})")
        for reason in c.reasoning:
            lines.append(f"- _reason_: {n(reason, 300)}")
        lines.append("")

    if report.scraping_difficulty is not None:
        lines.append("## Scraping difficulty (Mitchell + PRITES)")
        lines.append(f"- **{n(report.scraping_difficulty, 4)}/5**")
        lines.append("")

    if report.knn_prior:
        kn = report.knn_prior
        lines.append("## kNN corpus prior (memory-of-prior-examples)")
        if kn.top_k_sites:
            lines.append(f"- Consensus category : **{n(kn.consensus_category, 40)}/{n(kn.consensus_subcategory, 40)}**")
            lines.append(f"- Consensus difficulty : **{n(kn.consensus_difficulty, 4)}/5**")
            lines.append(f"- Consensus rendering : **{n(kn.consensus_rendering, 40)}**")
            lines.append(f"- Consensus public_api : **{n(kn.consensus_public_api, 40)}**")
            if kn.consensus_anti_bot:
                lines.append(f"- Consensus anti-bot : {n(kn.consensus_anti_bot, 200)}")
            lines.append(f"\n### Top {len(kn.top_k_sites)} similar sites in corpus")
            lines.append("| Score | URL | Category | Difficulty |")
            lines.append("|---:|---|---|---:|")
            for st in kn.top_k_sites:
                lines.append(
                    f"| {n(st['score'], 6)} | `{n(st['url'], 120)}` | {n(st['category'], 40)} | "
                    f"{n(st['difficulty'], 4)} |"
                )
        for note in kn.notes:
            lines.append(f"- _note_: {n(note, 300)}")
        lines.append("")

    if report.purpose:
        lines.append("## Purpose")
        lines.append(f"- **{n(report.purpose, 20)}** (used for Krotov legal_check.purpose_risk)")
        lines.append("")

    if report.skipped_browser_stage2:
        lines.append("## Stage path")
        lines.append("- ✓ Stage 1 cheap HTTP probe sufficient — Stage 2 (browser) skipped")
        lines.append("")

    lines.append("## Tier recommendation")
    if report.tier_recommendation:
        lines.append(f"- **Primary** : Tier {n(report.tier_recommendation.primary, 4)}")
        lines.append(f"- **Rationale** : {n(report.tier_recommendation.rationale, 400)}")
        if report.tier_recommendation.fallbacks:
            lines.append(f"- **Fallbacks** : {n(report.tier_recommendation.fallbacks, 40)}")
    lines.append("")
    lines.append(DATA_END)
    lines.append("")

    lines.append("---")
    lines.append("_Généré par `python -m accesspath sap inspect`_")
    return "\n".join(lines)


# ── Save helpers ────────────────────────────────────────────────────────
def _to_serializable(report: InspectReport) -> dict:
    """Convert InspectReport (avec dataclasses imbriqués) en dict JSON-safe."""
    d = asdict(report)
    return d


def _tracker_lines(report: InspectReport) -> list[str]:
    t = report.trackers or {}
    if not t:
        return []
    n = neutralize
    src = "réseau et HTML, page chargée sans clic" if report.browser_ran else "HTML seul, sans navigateur"
    lines = [
        "## Traceurs tiers",
        "",
        f"- Source : {src}",
        f"- Domaines tiers : {len(t.get('third_party_domains', []))}",
    ]
    if t.get("regies"):
        lines.append(f"- **Régies** : {n(', '.join(t['regies']), 300)}")
    if t.get("consent_manager"):
        lines.append(f"- Consentement : {n(', '.join(t['consent_manager']), 200)}")
    if t.get("unclassified"):
        lines.append(f"- Non classés : {n(', '.join(t['unclassified']), 400)}")
    if t.get("vendors"):
        lines += ["", DATA_BEGIN, "", "| Fournisseur | Catégorie | Hôtes |", "|---|---|---|"]
        for vendor, v in t["vendors"].items():
            hosts = ", ".join(v["hosts"]) or v["source"]
            lines.append(f"| {n(vendor, 60)} | {n(v['category'], 20)} | {n(hosts, 200)} |")
        lines += ["", DATA_END]
    else:
        lines.append("- Aucun fournisseur connu.")
    lines.append("")
    return lines


def save_report(report: InspectReport, *, also_json: bool = True) -> dict:
    """Save markdown + JSON sous data/probes/<name>_inspect_<date>.{md,json}."""
    name = validate_site_name(report.name)
    date_str = datetime.now(UTC).strftime("%Y-%m-%d")
    md_path = safe_write_text(PROBES_DIR, f"{name}_inspect_{date_str}.md", text=to_markdown(report))
    out = {"markdown": str(md_path)}
    if also_json:
        json_path = safe_write_text(
            PROBES_DIR,
            f"{name}_inspect_{date_str}.json",
            text=json.dumps(_to_serializable(report), indent=2, ensure_ascii=False),
        )
        out["json"] = str(json_path)
    return out


# ── SAP profile V2 — sharded YAML emitters ───────────────────────────────
SAP_DIR = DATA_DIR / "sap"


def _evidence(value, confidence: float, sources: list[str], phase: str = "stage1_cheap") -> dict:
    """Wrap a field value with traceability metadata."""
    return {
        "value": value,
        "confidence": round(confidence, 2),
        "sources": sources,
        "phase": phase,
    }


def emit_yaml_shards(report: InspectReport) -> dict[str, str]:
    """Emit 4 sharded YAML files under data/sap/<site>/{01,02,03,04}_*.yaml.

    Each field is wrapped in an evidence dict (value/confidence/sources/phase) so
    drift detection between probes can reason about source-level changes, not just
    surface value changes.

    Returns dict {shard_name: path_written}.
    """
    import yaml as _yaml

    site_dir = safe_path(SAP_DIR, validate_site_name(report.name))
    written: dict[str, str] = {}

    observed_at = report.timestamp

    # ── 01_identification.yaml — slow-changing, expert-validated ──
    cp = report.category_prediction
    knn = report.knn_prior
    cat_sources = ["rules_based"]
    cat_conf = cp.confidence if cp else 0.0
    if cp and cp.reasoning and any("kNN" in r for r in cp.reasoning):
        cat_sources = ["knn_corpus"] + cat_sources
    identification = {
        "url": report.target_url,
        "name": report.name,
        "observed_at": observed_at,
        "category": _evidence(
            cp.category if cp else None,
            cat_conf,
            cat_sources,
        ),
        "subcategory": _evidence(
            cp.subcategory if cp else None,
            cat_conf,
            cat_sources,
        ),
        "title": _evidence(
            report.reachability.title or None,
            1.0 if report.reachability.title else 0.0,
            ["html_title_tag"],
            "stage1_cheap",
        ),
        "purpose": report.purpose,
        # knn_prior summary (not the full top-k, just the consensus)
        "knn_prior": {
            "consensus_category": knn.consensus_category if knn else None,
            "consensus_difficulty": knn.consensus_difficulty if knn else None,
            "n_neighbors": len(knn.top_k_sites) if knn else 0,
        }
        if knn
        else None,
    }

    # ── 02_technical.yaml — changing, auto-probed monthly ──
    ab_dict = {}
    for ab_name, ab_det in report.anti_bot_stack.items():
        if ab_det.detected:
            ab_dict[ab_name] = _evidence(
                True,
                0.9 if len(ab_det.evidence) > 1 else 0.7,
                ab_det.evidence,
                "stage1_cheap" if report.skipped_browser_stage2 else "stage2_browser",
            )

    fw_dict = {}
    for fw_name, fw_det in report.frameworks.items():
        if fw_det.detected:
            fw_dict[fw_name] = _evidence(
                True,
                0.85,
                [fw_det.detail] if fw_det.detail else [],
                "stage1_cheap" if report.skipped_browser_stage2 else "stage2_browser",
            )

    sf = report.structural_features
    public_api = None
    api_endpoint = next((e for e in report.endpoints if e.category == "api-rest"), None)
    if api_endpoint:
        public_api = _evidence(
            "rest",
            0.9,
            [f"{api_endpoint.url} → {api_endpoint.status} {api_endpoint.content_type}"],
            "stage1_cheap",
        )
    elif report.graphql_calls:
        public_api = _evidence(
            "graphql",
            0.7,
            [f"observed {len(report.graphql_calls)} graphql call(s)"],
            "stage2_browser",
        )

    technical = {
        "url": report.target_url,
        "observed_at": observed_at,
        "reachability": {
            "status": report.reachability.status,
            "page_status": report.reachability.page_status,
            "body_length": report.reachability.body_length,
        },
        "anti_bot": ab_dict if ab_dict else None,
        "frameworks": fw_dict if fw_dict else None,
        "structured_data": {
            "formats": _evidence(
                sf.structured_data_formats,
                0.9,
                ["regex_scan_homepage_html"],
                "stage1_cheap",
            )
            if sf and sf.structured_data_formats
            else None,
            "schema_types": _evidence(
                sf.schema_types[:10],
                0.9,
                ["json-ld_parse"],
                "stage1_cheap",
            )
            if sf and sf.schema_types
            else None,
        },
        "public_api": public_api,
        "rendering": _evidence(
            "ssr" if report.skipped_browser_stage2 and (sf and sf.schema_types) else "unknown",
            0.6,
            ["stage1_html_present + schema_types"],
            "stage1_cheap",
        )
        if report.skipped_browser_stage2
        else None,
        "sitemap": {
            "url": report.sitemap.url if report.sitemap and report.sitemap.fetched else None,
            "n_urls": report.sitemap.n_urls if report.sitemap else None,
            "n_sub_sitemaps": report.sitemap.n_sitemaps if report.sitemap else None,
            "is_index": report.sitemap.is_index if report.sitemap else None,
        }
        if report.sitemap and report.sitemap.fetched
        else None,
    }

    # ── 03_ethics.yaml — rarely-changing, expert-validated ──
    ec = report.ethics_check
    rb = report.robots
    ethics = {
        "url": report.target_url,
        "observed_at": observed_at,
        "robots": {
            "fetched": rb.fetched if rb else False,
            "allows_root": ec.robots_allows_root if ec else None,
            "ai_bots_blocked": ec.ai_bots_blocked if ec else [],
            "crawl_delay": ec.crawl_delay if ec else None,
        }
        if ec
        else None,
        "paywall": _evidence(
            ec.has_paywall_marker if ec else False,
            0.7,
            ["regex_paywall|subscriber|premium"],
            "stage1_cheap",
        )
        if ec and ec.has_paywall_marker
        else None,
        "consent_wall": _evidence(
            ec.has_consent_wall if ec else False,
            0.8,
            ["regex_cookie-consent|cmp-banner|onetrust"],
            "stage1_cheap",
        )
        if ec and ec.has_consent_wall
        else None,
        "requires_login_marker": ec.requires_login_marker if ec else False,
        "estimated_legal_risk": _evidence(
            ec.estimated_legal_risk if ec else "unknown",
            0.6,
            ec.notes if ec else [],
            "rules_based_synthesis",
        )
        if ec
        else None,
        "purpose": report.purpose,
    }

    # ── 04_strategy.yaml — operational, updated by run feedback ──
    tr = report.tier_recommendation
    strategy = {
        "url": report.target_url,
        "observed_at": observed_at,
        "scraping_difficulty": _evidence(
            report.scraping_difficulty,
            0.7,
            [
                "rules_based_score",
                "knn_consensus" if knn and knn.consensus_difficulty else None,
            ],
            "rules_based_synthesis",
        )
        if report.scraping_difficulty
        else None,
        "tier_recommendation": {
            "primary": tr.primary if tr else None,
            "rationale": tr.rationale if tr else None,
            "fallbacks": tr.fallbacks if tr else [],
        }
        if tr
        else None,
        "implementation_status": "AUDITED",  # AUDITED | PARTIAL | OPERATIONAL | DEFERRED
        "rehearsal": {
            "tested": False,
            "last_run": None,
            "result": None,
        },
    }

    # Write all 4 shards
    shards = {
        "01_identification.yaml": identification,
        "02_technical.yaml": technical,
        "03_ethics.yaml": ethics,
        "04_strategy.yaml": strategy,
    }

    # Custom dumper that disables alias deduplication (better diffs)
    class _NoAliasDumper(_yaml.SafeDumper):
        def ignore_aliases(self, data):
            return True

    for fname, payload in shards.items():
        # Strip None-valued top-level keys for cleanliness
        cleaned = {k: v for k, v in payload.items() if v is not None}
        path = safe_write_text(
            site_dir,
            fname,
            text=_yaml.dump(
                cleaned,
                Dumper=_NoAliasDumper,
                sort_keys=False,
                allow_unicode=True,
                default_flow_style=False,
            ),
        )
        written[fname] = str(path)
    return written


# ── SAP V2 — rehearsal step (validate strategy on a real fetch) ──────────
def _in_scope(url: str, homepage_url: str) -> bool:
    """Vrai si `url` est en http(s) sur l'hôte audité ou l'un de ses sous-domaines.

    Les fragments YAML relus par rehearse sont des données : une adresse qui
    sortirait du site audité (API tierce, sitemap ailleurs) est refusée.
    """
    from urllib.parse import urlparse as _up

    u, h = _up(url or ""), _up(homepage_url or "")
    if u.scheme not in ("http", "https") or not u.hostname or not h.hostname:
        return False
    base = h.hostname.lower()
    if base.startswith("www."):
        base = base[4:]
    host = u.hostname.lower()
    return host == base or host.endswith("." + base)


def _load_yaml_shard(name: str, fname: str) -> dict | None:
    """Load data/sap/<name>/<fname> if it exists, else None."""
    import yaml as _yaml

    p = safe_path(SAP_DIR, validate_site_name(name), fname)
    if not p.exists():
        return None
    return _yaml.safe_load(p.read_text(encoding="utf-8"))


def _save_yaml_shard(name: str, fname: str, payload: dict) -> str:
    """Re-save shard with current timestamp."""
    import yaml as _yaml

    class _NoAliasDumper(_yaml.SafeDumper):
        def ignore_aliases(self, data):
            return True

    site_dir = safe_path(SAP_DIR, validate_site_name(name))
    cleaned = {k: v for k, v in payload.items() if v is not None}
    p = safe_write_text(
        site_dir,
        fname,
        text=_yaml.dump(
            cleaned,
            Dumper=_NoAliasDumper,
            sort_keys=False,
            allow_unicode=True,
            default_flow_style=False,
        ),
    )
    return str(p)


def _rehearse_tier1(api_url: str, *, expected_fields: list[str] | None = None) -> dict:
    """Fetch a public REST API endpoint, validate JSON structure + key fields.

    Returns dict {status, n_items, fields_present, fields_missing, sample_id, evidence}.
    """
    from .stealth import random_headers

    expected_fields = expected_fields or ["id", "title", "content", "link", "date"]
    out = {
        "tier": 1,
        "endpoint": api_url,
        "status": "FAIL",
        "evidence": [],
        "probes_tried": [],
    }

    # Try multiple param variants (some sites have plugin bugs with per_page>1 or _embed=1)
    base = api_url.split("?", 1)[0]
    is_wp = "wp-json/wp/v2/posts" in base
    variants = (
        [
            f"{base}?per_page=5&_embed=1",
            f"{base}?per_page=5",
            f"{base}?per_page=1",
            base,
        ]
        if is_wp
        else [api_url]
    )
    data = None
    probe_url = None
    try:
        with _http.client(timeout=8.0) as c:
            for v in variants:
                out["probes_tried"].append(v)
                try:
                    r = _http.get(c, v, headers=random_headers(accept="application/json"))
                except Exception as e:
                    out["evidence"].append(f"{v}: {type(e).__name__}")
                    continue
                if r.status_code != 200:
                    out["evidence"].append(f"{v}: HTTP {r.status_code}")
                    continue
                # Try to parse as JSON; some servers leak HTML into the response on certain params
                # (observed on dezeen.com when per_page>1 — meta tags injected before JSON).
                # Workaround : skip leading garbage, retry parse from first '[' or '{'.
                parsed = None
                quirk_recovered = False
                try:
                    parsed = r.json()
                except Exception:
                    raw = r.text
                    i_arr = raw.find("[")
                    i_obj = raw.find("{")
                    candidates = [i for i in (i_arr, i_obj) if i >= 0]
                    if candidates:
                        start = min(candidates)
                        try:
                            parsed = json.loads(raw[start:])
                            quirk_recovered = True
                        except Exception:
                            parsed = None
                if parsed is None:
                    out["evidence"].append(f"{v}: malformed JSON (server quirk, skip-leading-garbage retry failed)")
                    continue
                if isinstance(parsed, list):
                    data = parsed
                    probe_url = v
                    out["http_status"] = r.status_code
                    if quirk_recovered:
                        out["evidence"].append(
                            f"{v}: server quirk (leading garbage), recovered via skip-to-bracket parse"
                        )
                    break
                out["evidence"].append(f"{v}: response is {type(parsed).__name__}, not list")

        out["endpoint"] = probe_url or api_url
        if data is None:
            return out  # all variants failed
        out["n_items"] = len(data)
        if not data:
            out["evidence"].append("empty array — endpoint reachable but returns 0 items")
            out["status"] = "WARN"
            return out
        # Field validation on first item
        first = data[0]
        present = [f for f in expected_fields if f in first]
        missing = [f for f in expected_fields if f not in first]
        out["fields_present"] = present
        out["fields_missing"] = missing
        out["sample_id"] = first.get("id")
        # Render-able content check
        title_ok = bool(
            (first.get("title", {}) or {}).get("rendered")
            if isinstance(first.get("title"), dict)
            else first.get("title")
        )
        content_ok = bool(
            (first.get("content", {}) or {}).get("rendered")
            if isinstance(first.get("content"), dict)
            else first.get("content")
        )
        embedded = first.get("_embedded") or {}
        media = embedded.get("wp:featuredmedia") or []
        media_ok = bool(media and isinstance(media, list) and media[0].get("source_url"))
        out["title_rendered"] = title_ok
        out["content_rendered"] = content_ok
        out["featured_media"] = media_ok
        # Verdict
        if missing:
            out["evidence"].append(f"missing fields: {missing}")
            out["status"] = "WARN"
        elif not (title_ok and content_ok):
            out["evidence"].append("title or content is empty in sample record")
            out["status"] = "WARN"
        else:
            out["evidence"].append(
                f"{len(data)} items, all expected fields present, content rendered, sample id={first.get('id')}"
            )
            out["status"] = "PASS"
    except Exception as e:
        out["evidence"].append(f"{type(e).__name__}: {str(e)[:120]}")
    return out


def _rehearse_tier2(homepage_url: str, sitemap_url: str | None) -> dict:
    """Fetch a sample article via sitemap, validate OpenGraph + JSON-LD presence.

    Returns dict {status, n_og_tags, n_jsonld, evidence, sample_url}.
    """
    import xml.etree.ElementTree as ET

    from .stealth import random_headers

    out = {"tier": 2, "status": "FAIL", "evidence": []}
    sample_url = None
    # Find a real article URL via sitemap (keep client open for sitemap-index recursion)
    if sitemap_url:
        try:
            with _http.client(timeout=8.0) as c:
                r = _http.get(c, sitemap_url, headers=random_headers())
                if r.status_code == 200 and r.text:
                    root = ET.fromstring(r.text.lstrip())
                    ns = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
                    # Try urls first, fall back to nested sitemap (index)
                    urls = root.findall(".//sm:url/sm:loc", ns)
                    if not urls:
                        sitemaps = root.findall(".//sm:sitemap/sm:loc", ns)
                        # AGGREGATE up to 4 sub-sitemaps (don't break at first non-empty —
                        # editorial blog sub-sitemaps often come AFTER product sub-sitemaps in
                        # Shopify/WooCommerce indexes ; cabanamagazine.com case 2026-04-26).
                        aggregated = []
                        for sm_node in sitemaps[:4]:
                            sub_url = (sm_node.text or "").strip()
                            if not sub_url:
                                continue
                            if not _in_scope(sub_url, homepage_url):
                                out["evidence"].append(f"sub-sitemap hors du site audité, ignoré : {sub_url[:120]}")
                                continue
                            try:
                                rs = _http.get(c, sub_url, headers=random_headers())
                            except Exception as e:
                                out["evidence"].append(f"sub-sitemap fetch err on {sub_url}: {type(e).__name__}")
                                continue
                            if rs.status_code != 200:
                                continue
                            try:
                                sub = ET.fromstring(rs.text.lstrip())
                            except Exception:
                                continue
                            sub_urls = sub.findall(".//sm:url/sm:loc", ns)
                            aggregated.extend(sub_urls)
                        urls = aggregated
                    if urls:
                        # Score-based picking : prefer URLs that look like real articles
                        # (deep paths, year/date segments, article-like prefixes) over
                        # listing pages (/stories, /tag, /category, /author).
                        from urllib.parse import urlparse as _urlparse

                        article_prefixes = (
                            "/article",
                            "/articles/",
                            "/post",
                            "/posts/",
                            "/story/",
                            "/stories/",
                            "/news/",
                            "/blog/",
                            "/blogs/",
                            "/projects/",
                            "/p/",
                            "/issue",
                            "/feature",
                            "/interview",
                            "/journal/",
                        )
                        listing_paths = (
                            "/tag/",
                            "/category/",
                            "/author/",
                            "/topic/",
                            "/page/",
                            "/search",
                            "/about",
                            "/contact",
                            "/subscribe",
                        )
                        candidates: list[tuple[int, str]] = []
                        for u in urls:
                            ut = (u.text or "").strip()
                            if not ut:
                                continue
                            if ut == homepage_url or ut.rstrip("/") == homepage_url.rstrip("/"):
                                continue
                            if not _in_scope(ut, homepage_url):
                                continue
                            path = _urlparse(ut).path or ""
                            score = 0
                            depth = len([s for s in path.split("/") if s])
                            score += depth  # deeper = more article-like
                            if any(p in path for p in article_prefixes):
                                score += 5
                            if re.search(r"/20\d{2}/", path):
                                score += 3  # year segment
                            if any(p in path for p in listing_paths):
                                score -= 10  # listings penalized
                            candidates.append((score, ut))
                        if candidates:
                            candidates.sort(key=lambda x: x[0], reverse=True)
                            sample_url = candidates[0][1]
                else:
                    out["evidence"].append(f"sitemap HTTP {r.status_code}")
        except Exception as e:
            out["evidence"].append(f"sitemap parse err: {type(e).__name__}: {str(e)[:80]}")
    if not sample_url:
        out["evidence"].append("no sample URL found via sitemap")
        return out
    out["sample_url"] = sample_url
    try:
        with _http.client(timeout=10.0) as c:
            r = _http.get(c, sample_url, headers=random_headers())
        out["http_status"] = r.status_code
        if r.status_code != 200:
            out["evidence"].append(f"HTTP {r.status_code}")
            return out
        body = r.text or ""
        # OpenGraph tag count
        n_og = len(re.findall(r'<meta[^>]+property=["\']og:', body, re.I))
        # JSON-LD blocks
        jsonld = re.findall(
            r'<script[^>]*type=["\']application/ld\+json["\'][^>]*>(.+?)</script>',
            body,
            re.S | re.I,
        )
        n_jsonld = len(jsonld)
        # Extract a sample title via og:title or <title>
        m = re.search(
            r'<meta[^>]+property=["\']og:title["\'][^>]+content=["\']([^"\']+)',
            body,
            re.I,
        )
        sample_title = m.group(1) if m else None
        out["n_og_tags"] = n_og
        out["n_jsonld_blocks"] = n_jsonld
        out["sample_title"] = sample_title
        if n_og >= 3 and n_jsonld >= 1:
            out["status"] = "PASS"
            out["evidence"].append(f"{n_og} OG tags + {n_jsonld} JSON-LD blocks, title='{(sample_title or '')[:60]}'")
        elif n_og >= 1 or n_jsonld >= 1:
            out["status"] = "WARN"
            out["evidence"].append(f"thin metadata: {n_og} OG, {n_jsonld} JSON-LD")
        else:
            out["evidence"].append("no OG or JSON-LD found — page may need Tier 3/4 escalation")
    except Exception as e:
        out["evidence"].append(f"{type(e).__name__}: {str(e)[:120]}")
    return out


def rehearse_strategy(name: str, *, save: bool = False) -> dict:
    """Read data/sap/<name>/04_strategy.yaml + 02_technical.yaml, run a tier-specific
    rehearsal probe, then (only if `save`) update 04_strategy.yaml with the result.

    Returns the rehearsal dict.
    """
    validate_site_name(name)
    strategy = _load_yaml_shard(name, "04_strategy.yaml")
    technical = _load_yaml_shard(name, "02_technical.yaml")
    if not strategy or not technical:
        return {
            "status": "FAIL",
            "evidence": [f"missing shards for {name} (run sap inspect --emit-yaml first)"],
        }

    tier = (strategy.get("tier_recommendation") or {}).get("primary")
    homepage_url = strategy.get("url") or technical.get("url")

    if tier == 1:
        api_field = technical.get("public_api") or {}
        # Recover URL from sources line
        api_url = None
        for s in api_field.get("sources") or []:
            if isinstance(s, str) and "→" in s:
                api_url = s.split("→")[0].strip()
                break
        if not api_url:
            return {
                "status": "FAIL",
                "evidence": ["no api endpoint in technical shard"],
            }
        if not _in_scope(api_url, homepage_url):
            return {
                "status": "FAIL",
                "tier": 1,
                "evidence": [f"endpoint hors du site audité, refusé : {api_url}"],
            }
        result = _rehearse_tier1(api_url)
    elif tier == 2:
        sitemap_url = (technical.get("sitemap") or {}).get("url")
        if sitemap_url and not _in_scope(sitemap_url, homepage_url):
            return {
                "status": "FAIL",
                "tier": 2,
                "evidence": [f"sitemap hors du site audité, refusé : {sitemap_url}"],
            }
        result = _rehearse_tier2(homepage_url, sitemap_url)
    elif tier in (3, 4):
        result = {
            "tier": tier,
            "status": "DEFERRED",
            "evidence": [
                f"Tier {tier} rehearsal needs warmed session / marionnette — not yet implemented in auto-rehearsal"
            ],
        }
    else:
        result = {"status": "FAIL", "evidence": [f"unknown tier {tier!r}"]}

    # Update 04_strategy.yaml with the rehearsal result
    strategy["rehearsal"] = {
        "tested": True,
        "last_run": datetime.now(UTC).isoformat(),
        "result": result.get("status"),
        "details": result,
    }
    if result.get("status") == "PASS":
        strategy["implementation_status"] = "REHEARSAL_PASS"
    elif result.get("status") == "WARN":
        strategy["implementation_status"] = "REHEARSAL_WARN"
    elif result.get("status") == "DEFERRED":
        strategy["implementation_status"] = "DEFERRED"
    else:
        strategy["implementation_status"] = "REHEARSAL_FAIL"

    if save:
        _save_yaml_shard(name, "04_strategy.yaml", strategy)
    return result
