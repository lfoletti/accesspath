"""Auto-probe : génère un portrait-robot de site sans connaissance préalable.

Workflow appliqué (mêmes 4 axes que l'audit manuel designboom) :

  1. discover_tier1(base) — teste 20+ endpoints API/RSS/sitemap connus
  2. discover_tier2(base) — analyse statique HTML (WP ? Next.js ? SPA ? data inline ?)
  3. measure_rate_limit(url) — burst ≤ 20 req, arrêté au premier 429/503, Retry-After relevé

Politesse : robots.txt lu d'abord (chemins interdits pour `*` sautés et
signalés), tier 1 à 4 requêtes simultanées au plus, Retry-After respecté.
  4. sample_schema(api_url) — si API trouvée, échantillonne 100 items et caractérise champs

Sortie : un dict structuré conforme au format `site_architecture_profiles.json`
+ un rapport markdown archivé dans data/probes/{host}_{date}.md.

Usage CLI : `accesspath sap probe https://www.example.com [--save] [--name myname]`

Design : 100% HTTP (httpx via accesspath._http, lecture bornée) + stealth.random_headers. Pas de Chrome.
Si tier 4 (Chrome) est manifestement nécessaire, on le note mais on ne le teste pas.
"""

from __future__ import annotations

import ast
import asyncio
import json
import logging
import re
import time
from collections import Counter
from contextvars import ContextVar
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlparse
from urllib.robotparser import RobotFileParser

from . import _http, usage_prefs
from ._safe import (
    DATA_BEGIN,
    DATA_END,
    neutralize,
    safe_path,
    safe_write_text,
    validate_site_name,
)
from .config import DATA_DIR
from .stealth import random_headers

log = logging.getLogger(__name__)
SITES_DIR = Path.cwd() / "sites"  # squelettes de collecteurs (--skeleton), dossier appelant

TIER1_MAX_PARALLEL = 4  # requêtes simultanées au plus en tier 1
RETRY_AFTER_MAX_WAIT_S = 30.0  # au-delà, les requêtes suivantes sont abandonnées
THROTTLE_STATUSES = (429, 503)


# ── HTTP utility ───────────────────────────────────────────────────────────
# Empreinte imitée par `_fetch` (None : httpx). Posée pour le reste d'une sonde quand
# l'accueil ne refuse que l'empreinte TLS de Python (`check_tls_fingerprint`).
_IMPERSONATE: ContextVar[str | None] = ContextVar("probe_impersonate", default=None)


async def _fetch(
    url: str,
    *,
    timeout: float = 15.0,
    accept: str | None = None,
    extra_headers: dict | None = None,
) -> dict:
    """GET borné (taille sur le fil et après décompression, cf. `_http`).

    `timeout` est l'échéance totale de la requête, lecture du corps comprise.

    Retourne dict avec status, ok, headers, body, content_type, duration_s, error.
    """
    target = _IMPERSONATE.get()
    if target:
        # L'imitation porte ses propres en-têtes de navigateur, accordés à son empreinte TLS :
        # un User-Agent tiré au hasard la trahirait. Seuls Accept et les en-têtes demandés passent.
        headers = {**({"Accept": accept} if accept else {}), **(extra_headers or {})}
    else:
        headers = random_headers(accept=accept, extra=extra_headers)
    t0 = time.monotonic()
    try:
        if target:
            r = await _http.aimpersonate_get(url, headers=headers, impersonate=target, total_timeout=timeout)
        else:
            async with _http.async_client(timeout=timeout) as client:
                r = await _http.aget(client, url, headers=headers, total_timeout=timeout)
    except Exception as e:
        return {
            "status": -1,
            "ok": False,
            "content_type": "",
            "headers": {},
            "body": b"",
            "duration_s": time.monotonic() - t0,
            "error": f"{type(e).__name__}: {e}",
        }
    ok = r.status_code < 400
    return {
        "status": r.status_code,
        "ok": ok,
        "content_type": r.headers.get("Content-Type", ""),
        "headers": dict(r.headers),
        "body": r.content,
        "duration_s": time.monotonic() - t0,
        "error": None if ok else f"HTTP {r.status_code}",
    }


# ── Tier 1 : endpoints API/RSS/sitemap discovery ──────────────────────────
TIER1_PROBES = [
    # Static metadata
    ("/robots.txt", None),
    ("/sitemap.xml", None),
    ("/sitemap_index.xml", None),
    # RSS / Atom standard
    ("/feed", None),
    ("/feed/", None),
    ("/rss", None),
    ("/feed.xml", None),
    ("/atom.xml", None),
    ("/?feed=rss2", None),  # WP query-string
    # WordPress REST
    ("/wp-json", "application/json"),
    ("/wp-json/wp/v2/posts?per_page=1", "application/json"),
    # Generic API patterns
    ("/api", "application/json"),
    ("/api/", "application/json"),
    ("/api/v1", "application/json"),
    ("/api/v2", "application/json"),
    ("/api/posts", "application/json"),
    ("/api/articles", "application/json"),
    # GraphQL
    ("/graphql", "application/json"),
    # Webflow / Hugo / Jekyll feeds
    ("/index.xml", None),
    ("/posts.json", "application/json"),
]


# ── Portes de confiance ─────────────────────────────────────────────────────
# Avant de deviner, la sonde lit ce que le site déclare lui-même (flux, oEmbed,
# AMP : des chemins qu'il sert à ses propres machines), puis les points d'accès
# connus de la plateforme reconnue. Les chemins génériques de TIER1_PROBES ne
# partent que pour une plateforme inconnue.
PLATFORM_SIGNS: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    # plateforme : (sous-chaînes du HTML, en-têtes de réponse)
    "shopify": (("cdn.shopify.com", "shopify.theme", "myshopify.com"), ("x-shopid", "x-shopify-stage")),
    "wordpress": (("/wp-content/", "/wp-includes/", "https://api.w.org/"), ()),
    "squarespace": (("squarespace-cdn.com", "static1.squarespace.com", "squarespace.com/universal"), ()),
    "webflow": (("data-wf-site", "webflow.js", "assets.website-files.com"), ()),
}

PLATFORM_DOORS: dict[str, list[tuple[str, str | None]]] = {
    "shopify": [
        ("/products.json?limit=250", "application/json"),
        ("/collections.json", "application/json"),
        ("/collections/all.atom", None),
        ("/sitemap.xml", None),
    ],
    "wordpress": [
        ("/wp-json", "application/json"),
        ("/wp-json/wp/v2/posts?per_page=1", "application/json"),
        ("/feed", None),
        ("/wp-sitemap.xml", None),
        ("/sitemap.xml", None),
    ],
    "squarespace": [
        ("/?format=json", "application/json"),
        ("/sitemap.xml", None),
    ],
    "webflow": [
        ("/sitemap.xml", None),
        ("/rss.xml", None),
    ],
}

_DECLARED_TYPES = {
    "application/rss+xml": "rss",
    "application/atom+xml": "atom",
    "application/feed+json": "json_feed",
    "application/json+oembed": "oembed",
    "text/xml+oembed": "oembed",
}


_USEFUL_KINDS = ("json", "rss", "atom", "sitemap")


def fingerprint_platform(html: str, headers: dict) -> str:
    """Plateforme reconnue à l'accueil : shopify, wordpress, squarespace, webflow ou generic."""
    low = html.lower()
    keys = {k.lower() for k in headers}
    for name, (marks, hdrs) in PLATFORM_SIGNS.items():
        if any(m in low for m in marks) or any(h in keys for h in hdrs):
            return name
    return "generic"


class _LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links: list[dict[str, str]] = []

    def handle_starttag(self, tag, attrs):
        if tag == "link":
            self.links.append({k: (v or "") for k, v in attrs})


def declared_doors(html: str, base: str) -> list[dict]:
    """Portes que l'accueil déclare : `<link rel=alternate>` (RSS, Atom, JSON Feed,
    oEmbed) et `<link rel=amphtml>`. Une porte sur un autre hôte est notée
    `external` et n'est pas sondée."""
    parser = _LinkParser()
    try:
        parser.feed(html)
    except Exception:
        return []
    host = urlparse(base).netloc.lower()
    out: list[dict] = []
    seen: set[str] = set()
    for link in parser.links:
        rel = link.get("rel", "").lower().split()
        href = link.get("href", "").strip()
        if not href:
            continue
        if "amphtml" in rel:
            kind = "amp"
        elif "alternate" in rel and (kind := _DECLARED_TYPES.get(link.get("type", "").lower().strip())):
            pass
        else:
            continue
        url = urljoin(base.rstrip("/") + "/", href)
        u = urlparse(url)
        if u.scheme not in ("http", "https") or url in seen:
            continue
        seen.add(url)
        path = (u.path or "/") + (f"?{u.query}" if u.query else "")
        out.append({"kind": kind, "url": url, "path": path, "external": u.netloc.lower() != host})
    return out


# ── Abonnements ─────────────────────────────────────────────────────────────
# Une newsletter ou une alerte (appels d'offres, nouvelles parutions) pousse la
# source vers une boîte dédiée : aucun anti-bot sur ce chemin. S'y inscrire est
# un geste humain, fait une fois.
_SUB_WORDS = re.compile(r"newsletter|abonn|subscri|inscri|alerte?s?\b|alerts?\b|benachrichtig|anmeld|veille", re.I)
_UNSUB = re.compile(r"unsubscri|d[ée]sabonn|d[ée]sinscri|abmeld", re.I)
SUBSCRIPTIONS_MAX = 5


class _SubParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms: list[dict] = []  # {action, has_email, text}
        self.anchors: list[tuple[str, str]] = []  # (href, texte)
        self._form: dict | None = None
        self._a: list | None = None

    def handle_starttag(self, tag, attrs):
        a = {k: (v or "") for k, v in attrs}
        if tag == "form":
            self._form = {"action": a.get("action", ""), "has_email": False, "text": " ".join(a.values())}
        elif tag == "input" and self._form is not None:
            if a.get("type", "").lower() == "email" or "mail" in a.get("name", "").lower():
                self._form["has_email"] = True
            self._form["text"] += " " + " ".join(a.values())
        elif tag == "a" and a.get("href"):
            self._a = [a["href"], ""]

    def handle_endtag(self, tag):
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None
        elif tag == "a" and self._a is not None:
            self.anchors.append((self._a[0], self._a[1]))
            self._a = None

    def handle_data(self, data):
        if self._form is not None:
            self._form["text"] += " " + data
        if self._a is not None:
            self._a[1] += data


def find_subscriptions(html: str, base: str) -> list[dict]:
    """Formulaires d'inscription par e-mail et liens vers newsletters ou alertes."""
    parser = _SubParser()
    try:
        parser.feed(html)
    except Exception:
        return []
    root = base.rstrip("/") + "/"
    out: list[dict] = []
    seen: set[str] = set()

    def _add(href: str, text: str) -> None:
        url = urljoin(root, href.strip())
        if urlparse(url).scheme not in ("http", "https") or url in seen or len(out) >= SUBSCRIPTIONS_MAX:
            return
        seen.add(url)
        kind = "alerte" if re.search(r"alert|benachrichtig", text + " " + href, re.I) else "newsletter"
        out.append({"url": url, "kind": kind})

    for f in parser.forms:
        if f["has_email"] and _SUB_WORDS.search(f["text"] + " " + f["action"]) and not _UNSUB.search(f["text"]):
            _add(f["action"] or "/", f["text"])
    for href, text in parser.anchors:
        hay = f"{href} {text}"
        if _SUB_WORDS.search(hay) and not _UNSUB.search(hay):
            _add(href, text)
    return out


# ── Évolution des portes ────────────────────────────────────────────────────
STALE_DAYS = 30  # une porte sans élément plus récent que ça est figée
EMPTIED_RATIO = 0.5  # moins de la moitié des éléments d'avant : vidée


def _days_between(a: str | None, b: str | None) -> int | None:
    try:
        return (datetime.fromisoformat(b[:10]).date() - datetime.fromisoformat(a[:10]).date()).days
    except (TypeError, ValueError):
        return None


def door_changes(prev_entry: dict, report: ProbeReport) -> list[dict]:
    """Compare les portes de la sonde au tableau du profil enregistré.

    fermée : porte utile d'avant, absente ou devenue inutile ; vidée : moins de
    la moitié des éléments ; figée : plus rien de récent alors qu'elle vivait ;
    nouvelle : porte utile qui n'existait pas.
    """
    prev = (prev_entry or {}).get("doors") or {}
    if not prev:
        return []
    today = report.timestamp[:10]
    prev_audit = (prev_entry or {}).get("last_audit")
    now = {f["endpoint"]: f for f in report.tier1.get("found", [])}
    out: list[dict] = []
    for ep, old in prev.items():
        if old.get("type") not in _USEFUL_KINDS:
            continue
        cur = now.get(ep)
        if cur is None or cur.get("type") not in _USEFUL_KINDS:
            out.append(
                {"endpoint": ep, "change": "fermée", "before": old.get("type"), "after": cur and cur.get("type")}
            )
            continue
        oi, ci = old.get("items"), cur.get("items")
        if oi and ci is not None and ci < oi * EMPTIED_RATIO:
            out.append({"endpoint": ep, "change": "vidée", "before": oi, "after": ci})
            continue
        lag_now = _days_between(cur.get("newest"), today)
        lag_before = _days_between(old.get("newest"), prev_audit)
        if lag_now is not None and lag_now > STALE_DAYS and (lag_before is None or lag_before <= STALE_DAYS):
            out.append({"endpoint": ep, "change": "figée", "before": old.get("newest"), "after": cur.get("newest")})
    for ep, cur in now.items():
        if ep not in prev and cur.get("type") in _USEFUL_KINDS:
            out.append({"endpoint": ep, "change": "nouvelle", "before": None, "after": cur.get("items")})
    return out


def _iso_date(value) -> str | None:
    """Date lisible (ISO 8601 ou RFC 822) → AAAA-MM-JJ en UTC, None sinon."""
    if not isinstance(value, str) or not value.strip():
        return None
    v = value.strip()
    try:
        dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        try:
            dt = parsedate_to_datetime(v)
        except (TypeError, ValueError):
            return None
    if dt.tzinfo is not None:
        dt = dt.astimezone(UTC)
    return dt.date().isoformat()


_JSON_DATE_KEYS = ("updated_at", "date_gmt", "modified_gmt", "published_at", "date", "updatedOn", "publishOn")


def door_stats(kind: str, r: dict) -> dict:
    """Nombre d'éléments et date la plus récente d'une porte ; None quand illisible."""
    out: dict = {"items": None, "newest": None}
    if not r.get("ok") or not r.get("body"):
        return out
    try:
        if kind in ("rss", "atom", "sitemap", "xml"):
            import xml.etree.ElementTree as ET

            root = ET.fromstring(r["body"])
            local = lambda t: t.rsplit("}", 1)[-1]  # noqa: E731
            if kind == "sitemap" or local(root.tag) in ("urlset", "sitemapindex"):
                item_tag = "sitemap" if local(root.tag) == "sitemapindex" else "url"
            else:
                item_tag = {"rss": "item", "atom": "entry"}.get(kind, "item")
            items = [e for e in root.iter() if local(e.tag) == item_tag]
            dates = [
                d
                for e in items
                for c in e
                if local(c.tag) in ("pubDate", "updated", "published", "lastmod") and (d := _iso_date(c.text or ""))
            ]
            out["items"] = len(items)
            out["newest"] = max(dates) if dates else None
        elif kind == "json":
            data = json.loads(r["body"])
            items = data
            if isinstance(data, dict):
                items = next((v for v in data.values() if isinstance(v, list)), None)
            if isinstance(items, list):
                out["items"] = len(items)
                dates = [
                    d for it in items if isinstance(it, dict) for k in _JSON_DATE_KEYS if (d := _iso_date(it.get(k)))
                ]
                out["newest"] = max(dates) if dates else None
            total = _header(r.get("headers") or {}, "X-WP-Total")
            if total and total.isdigit():
                out["items"] = int(total)
    except Exception:
        return {"items": None, "newest": None}
    return out


# ── Copies tierces ──────────────────────────────────────────────────────────
# Quand le site ne laisse passer aucune porte, ce que d'autres ont déjà capturé
# (Wayback Machine, Common Crawl) sert au moins à énumérer ses adresses et à
# dater son activité. Une requête par service, identité déclarée, échéance
# propre ; les valeurs rendues viennent d'un tiers et restent des données.
WAYBACK_CDX = "https://web.archive.org/cdx/search/cdx"
CC_COLLINFO = "https://index.commoncrawl.org/collinfo.json"
# Agrégateur Memento (RFC 7089) : toutes les archives qui parlent le protocole, en une requête.
MEMENTO_TIMETRAVEL = "https://timetravel.mementoweb.org/api/json"
THIRD_PARTY_LIMIT = 1000
THIRD_PARTY_WINDOW_DAYS = 365  # le compte Wayback porte sur l'année écoulée
THIRD_PARTY_TIMEOUT_S = 30.0
THIRD_PARTY_HEADERS = {
    "User-Agent": "accesspath (site access audit; a few requests per audit)",  # ASCII : en-tête HTTP
    "Accept": "application/json",
}
THIRD_PARTY_LEGAL = (
    "copie tierce : contenu archivé par un tiers, sous ses propres conditions ; "
    "les droits de l'éditeur du site restent entiers, et la fraîcheur se lit au retard"
)


def _ts_date(ts) -> str | None:
    """Horodatage CDX AAAAMMJJhhmmss → AAAA-MM-JJ."""
    if not isinstance(ts, str) or len(ts) < 8 or not ts[:8].isdigit():
        return None
    return f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}"


def parse_wayback_cdx(payload: bytes) -> dict:
    """Réponse CDX (sortie json : en-tête puis lignes) → {items, newest}."""
    try:
        rows = json.loads(payload)
        if not isinstance(rows, list):
            raise ValueError
    except ValueError:
        return {"items": None, "newest": None}
    if not rows:
        return {"items": 0, "newest": None}
    header, data = rows[0], rows[1:]
    i = header.index("timestamp") if "timestamp" in header else 1
    dates = [d for row in data if isinstance(row, list) and len(row) > i and (d := _ts_date(row[i]))]
    return {"items": len(data), "newest": max(dates) if dates else None}


def parse_cc_index(payload: bytes) -> dict:
    """Réponse de l'index Common Crawl (une ligne JSON par capture) → {items, newest}."""
    recs = []
    for line in payload.decode("utf-8", "replace").splitlines():
        if not line.strip():
            continue
        try:
            recs.append(json.loads(line))
        except ValueError:
            continue
    if not recs:
        return {"items": None, "newest": None}
    dates = [d for r in recs if isinstance(r, dict) and (d := _ts_date(r.get("timestamp")))]
    return {"items": len(recs), "newest": max(dates) if dates else None}


async def _third_party_get(url: str) -> dict:
    """GET vers une archive : identité déclarée, lecture bornée, échéance propre."""
    try:
        async with _http.async_client(timeout=THIRD_PARTY_TIMEOUT_S) as client:
            r = await _http.aget(client, url, headers=THIRD_PARTY_HEADERS, total_timeout=THIRD_PARTY_TIMEOUT_S)
    except Exception as e:
        return {"ok": False, "status": -1, "body": b"", "error": f"{type(e).__name__}: {e}"}
    ok = r.status_code < 400
    return {"ok": ok, "status": r.status_code, "body": r.content, "error": None if ok else f"HTTP {r.status_code}"}


def _lag_days(newest: str | None) -> int | None:
    if not newest:
        return None
    return (datetime.now(UTC).date() - datetime.fromisoformat(newest).date()).days


def _copy_result(stats: dict, query: str, error: str | None, **extra) -> dict:
    return {**stats, "lag_days": _lag_days(stats.get("newest")), "query": query, "error": error, **extra}


async def wayback_copies(netloc: str) -> dict:
    """Deux requêtes légères : la capture la plus récente (index rapide), puis
    les adresses distinctes capturées sur l'année écoulée, plafonnées. Une
    requête « les N dernières » balaie tout l'index et dépasse l'échéance."""
    from datetime import timedelta
    from urllib.parse import urlencode

    base = {"url": f"{netloc}/", "matchType": "prefix", "output": "json", "filter": "statuscode:200"}
    q_latest = WAYBACK_CDX + "?" + urlencode({**base, "fl": "original,timestamp", "limit": "-1", "fastLatest": "true"})
    since = (datetime.now(UTC) - timedelta(days=THIRD_PARTY_WINDOW_DAYS)).strftime("%Y%m%d")
    q_count = (
        WAYBACK_CDX
        + "?"
        + urlencode(
            {**base, "fl": "original,timestamp", "collapse": "urlkey", "from": since, "limit": str(THIRD_PARTY_LIMIT)}
        )
    )
    latest = await _third_party_get(q_latest)
    if not latest["ok"]:  # archive indisponible : inutile d'insister
        return _copy_result({"items": None, "newest": None}, q_latest, latest["error"])
    count = await _third_party_get(q_count)
    counted = parse_wayback_cdx(count["body"]) if count["ok"] else {"items": None, "newest": None}
    dates = [d for d in (parse_wayback_cdx(latest["body"])["newest"], counted["newest"]) if d]
    stats = {"items": counted["items"], "newest": max(dates) if dates else None}
    return _copy_result(stats, q_count, count["error"], window_days=THIRD_PARTY_WINDOW_DAYS)


async def commoncrawl_copies(netloc: str) -> dict:
    from urllib.parse import urlencode

    info = await _third_party_get(CC_COLLINFO)
    empty = {"items": None, "newest": None}
    try:
        latest = json.loads(info["body"])[0] if info["ok"] else None
        api, crawl = latest["cdx-api"], latest["id"]
    except (ValueError, LookupError, TypeError):
        return _copy_result(empty, CC_COLLINFO, info["error"] or "collinfo illisible")
    q = (
        api
        + "?"
        + urlencode(
            {"url": f"{netloc}/*", "output": "json", "fl": "url,timestamp,status", "limit": str(THIRD_PARTY_LIMIT)}
        )
    )
    r = await _third_party_get(q)
    if r["status"] == 404 and b"No Captures found" in r["body"]:
        # Réponse de l'index quand le dernier crawl n'a rien du site : 0, pas une panne.
        return _copy_result({"items": 0, "newest": None}, q, None, crawl=crawl)
    stats = parse_cc_index(r["body"]) if r["ok"] else empty
    return _copy_result(stats, q, r["error"], crawl=crawl)


def parse_timetravel(payload: bytes) -> dict:
    """Réponse JSON de Time Travel → dernière et première capture, archives détentrices."""
    try:
        mementos = json.loads(payload)["mementos"]
    except (ValueError, KeyError, TypeError):
        return {"items": None, "newest": None}
    hosts = {urlparse(u).hostname for m in mementos.values() if isinstance(m, dict) for u in m.get("uri") or []}
    return {
        "items": None,
        "newest": _iso_date((mementos.get("last") or {}).get("datetime")),
        "oldest": _iso_date((mementos.get("first") or {}).get("datetime")),
        "archives": sorted(h for h in hosts if h),
    }


async def memento_copies(netloc: str) -> dict:
    stamp = datetime.now(UTC).strftime("%Y%m%d%H%M%S")
    q = f"{MEMENTO_TIMETRAVEL}/{stamp}/https://{netloc}/"
    r = await _third_party_get(q)
    if r["status"] == 404:  # aucune archive ne détient le site : 0, pas une panne
        return _copy_result({"items": 0, "newest": None}, q, None)
    stats = parse_timetravel(r["body"]) if r["ok"] else {"items": None, "newest": None}
    return _copy_result(stats, q, r["error"])


async def third_party_copies(netloc: str) -> dict:
    wb, cc, mm = await asyncio.gather(wayback_copies(netloc), commoncrawl_copies(netloc), memento_copies(netloc))
    return {"wayback": wb, "commoncrawl": cc, "memento": mm, "legal": THIRD_PARTY_LEGAL}


def _classify_response(r: dict) -> str:
    """Classifie un response : 'json' | 'rss' | 'atom' | 'sitemap' | 'html' | 'plain' | 'fail' | 'redirect'."""
    if not r["ok"]:
        return "fail"
    ct = r["content_type"].lower()
    body_head = r["body"][:300].decode("utf-8", "ignore").strip().lower() if r["body"] else ""
    if "json" in ct:
        try:
            json.loads(r["body"])
            return "json"
        except Exception:
            return "json_invalid"
    if "rss" in ct or body_head.startswith("<?xml") and "<rss" in body_head:
        return "rss"
    if "atom" in ct or "<feed" in body_head[:100]:
        return "atom"
    if "xml" in ct and ("<urlset" in body_head or "<sitemapindex" in body_head):
        return "sitemap"
    if "xml" in ct:
        return "xml"
    if ct.startswith("text/html"):
        return "html"
    if ct.startswith("text/plain"):
        return "plain"
    return ct or "?"


def _parse_retry_after(value: str | None) -> int | None:
    """Retry-After en secondes (nombre ou date HTTP), None si illisible."""
    if not value:
        return None
    v = value.strip()
    if v.isdigit():
        return int(v)
    try:
        from email.utils import parsedate_to_datetime

        dt = parsedate_to_datetime(v)
        return max(0, int((dt - datetime.now(UTC)).total_seconds()))
    except Exception:
        return None


def _header(headers: dict, name: str) -> str | None:
    name = name.lower()
    return next((v for k, v in headers.items() if k.lower() == name), None)


def _robots_parser(r: dict) -> RobotFileParser:
    """robots.txt → RobotFileParser. 401/403 : tout interdit ; absent : tout permis."""
    rp = RobotFileParser()
    if r["status"] in (401, 403):
        rp.disallow_all = True
    elif r["ok"] and r["body"]:
        rp.parse(r["body"].decode("utf-8", "replace").splitlines())
    else:
        rp.parse([])
    return rp


async def _load_robots(base: str) -> tuple[dict, RobotFileParser]:
    r = await _fetch(base.rstrip("/") + "/robots.txt", timeout=10)
    return r, _robots_parser(r)


async def discover_tier1(
    base_url: str,
    *,
    robots: tuple[dict, RobotFileParser] | None = None,
    home: dict | None = None,
) -> dict:
    """Probe systématique des endpoints connus. Retourne dict avec :
      - found : list de {endpoint, type, status, size}
      - api_endpoints : sous-set des "json" trouvés
      - rss_feeds : sous-set des "rss/atom"
      - sitemap : URL trouvée
      - wordpress : True si /wp-json détecté
      - skipped_by_robots : chemins interdits pour `*` par robots.txt, non demandés

    robots.txt est lu d'abord (ou repris de `robots`) ; les autres chemins
    partent à TIER1_MAX_PARALLEL requêtes simultanées au plus.

    Avec `home` (réponse de l'accueil), l'ordre devient : portes déclarées par
    l'accueil, portes de la plateforme reconnue, puis TIER1_PROBES seulement si
    la plateforme est inconnue. Chaque porte trouvée porte `source`, `items`
    et `newest`.
    """
    base = base_url.rstrip("/")
    robots_fetch, rp = robots if robots is not None else await _load_robots(base)
    html = home["body"].decode("utf-8", "ignore") if home and home.get("ok") and home.get("body") else ""
    platform = fingerprint_platform(html, home.get("headers") or {}) if home else "generic"
    declared = declared_doors(html, base) if html else []
    plan: list[tuple[str, str | None, str]] = [
        (d["path"], "application/json" if d["kind"] in ("oembed", "json_feed") else None, "déclarée")
        for d in declared
        if not d["external"]
    ]
    plan += [(p, a, "plateforme") for p, a in PLATFORM_DOORS.get(platform, [])]
    if platform == "generic":
        plan += [(p, a, "générique") for p, a in TIER1_PROBES]
    sem = asyncio.Semaphore(TIER1_MAX_PARALLEL)

    async def _one(path: str, accept: str | None) -> dict:
        async with sem:
            return await _fetch(base + path, timeout=10, accept=accept)

    skipped: list[str] = []
    seen: set[str] = {"/robots.txt"}

    async def _batch(entries: list[tuple[str, str | None, str]]) -> list:
        todo: list[tuple[str, str | None, str]] = []
        for path, accept, source in entries:
            if path in seen:
                continue
            seen.add(path)
            if not rp.can_fetch("*", base + path):
                skipped.append(path)
                continue
            todo.append((path, accept, source))
        results = await asyncio.gather(*(_one(p, a) for p, a, _s in todo))
        return list(zip(todo, results, strict=True))

    pairs = [(("/robots.txt", None, "générique"), robots_fetch)] + await _batch(plan)
    if platform != "generic" and not any(_classify_response(r) in _USEFUL_KINDS for _e, r in pairs[1:]):
        # Portes de la plateforme toutes fermées (cas dezeen : /wp-json et sitemaps en 403) :
        # on essaie quand même les chemins génériques.
        pairs += await _batch([(p, a, "générique") for p, a in TIER1_PROBES])
    found = []
    for (path, _accept, source), r in pairs:
        kind = _classify_response(r)
        size = len(r["body"]) if r["body"] else 0
        if kind not in ("fail",):  # garde même les html pour analyse
            found.append(
                {
                    "endpoint": path,
                    "type": kind,
                    "status": r["status"],
                    "size": size,
                    "duration_s": round(r["duration_s"], 2),
                    "source": source,
                    **door_stats(kind, r),
                }
            )

    api_endpoints = [f for f in found if f["type"] == "json"]
    rss_feeds = [f for f in found if f["type"] in ("rss", "atom")]
    sitemap = next((f for f in found if f["type"] == "sitemap"), None)
    wordpress = any(f["endpoint"].startswith("/wp-json") and f["type"] == "json" for f in found)

    return {
        "found": found,
        "api_endpoints": api_endpoints,
        "rss_feeds": rss_feeds,
        "sitemap": sitemap,
        "wordpress_detected": wordpress,
        "skipped_by_robots": skipped,
        "platform": platform,
        "declared_external": [d["url"] for d in declared if d["external"]],
        "subscriptions": find_subscriptions(html, base) if html else [],
    }


# ── Tier 2 : analyse HTML statique ─────────────────────────────────────────
async def discover_tier2(url: str, *, home: dict | None = None) -> dict:
    """Fetch l'URL principale et analyse :
    - framework signatures (WP, Next.js __NEXT_DATA__, Apollo, Hotwire/Turbo)
    - inline JSON dans <script>
    - count d'éléments candidats (liens vers /<id>/, articles, products)
    - SPA detection (HTML brut sans contenu)
    """
    r = home if home is not None else await _fetch(url, timeout=20)
    if not r["ok"]:
        return {"error": r["error"], "fetched": False}

    html = r["body"].decode("utf-8", "ignore")
    out = {
        "fetched": True,
        "size": len(html),
        "frameworks": [],
        "inline_json": [],
        "patterns": {},
        "is_likely_spa": False,
    }

    # Framework detection
    if "wp-content/" in html or "wp-json" in html:
        out["frameworks"].append("wordpress")
    if "__NEXT_DATA__" in html:
        out["frameworks"].append("nextjs")
    if "__APOLLO_STATE__" in html:
        out["frameworks"].append("apollo_graphql")
    if "data-turbo" in html or "turbo-frame" in html:
        out["frameworks"].append("rails_turbo")
    if "data-react-helmet" in html or "react-root" in html or 'id="root"' in html:
        out["frameworks"].append("react")
    if "ng-version" in html or "ng-app" in html:
        out["frameworks"].append("angular")
    if "data-vue" in html or "v-cloak" in html:
        out["frameworks"].append("vue")

    # Inline JSON (Next.js, Apollo, etc.)
    for marker in ("__NEXT_DATA__", "__APOLLO_STATE__", "__INITIAL_STATE__"):
        m = re.search(rf"{re.escape(marker)}[^>]*>([^<]+)</script>", html, re.S)
        if m:
            try:
                data = json.loads(m.group(1))
                top_keys = list(data.keys())[:8] if isinstance(data, dict) else []
                out["inline_json"].append(
                    {
                        "marker": marker,
                        "size": len(m.group(1)),
                        "top_keys": top_keys,
                    }
                )
            except Exception:
                pass

    # Patterns de "data-like"
    out["patterns"]["links_with_id"] = len(re.findall(r'href="[^"]*?/\d{6,}/[^"]*"', html))
    out["patterns"]["picture_img"] = html.count("<picture>")
    out["patterns"]["article_tags"] = html.count("<article")
    out["patterns"]["data_testid"] = len(set(re.findall(r'data-testid="([^"]+)"', html)))
    out["patterns"]["script_application_json"] = html.count('<script type="application/json"')

    # SPA heuristic : peu de patterns "data" + framework JS détecté
    has_js_framework = any(f in out["frameworks"] for f in ("react", "nextjs", "angular", "vue"))
    low_content = out["patterns"]["links_with_id"] < 5 and out["patterns"]["article_tags"] < 5 and len(html) < 200_000
    out["is_likely_spa"] = has_js_framework and low_content

    return out


# ── Rate-limit probe ───────────────────────────────────────────────────────
async def measure_rate_limit(url: str, *, n: int = 20, parallel: bool = False) -> dict:
    """Burst ≤ N requêtes, mesure latence + erreurs.

    La rafale s'arrête au premier 429/503 (en parallèle : après la vague qui
    l'a reçu, vagues de TIER1_MAX_PARALLEL) ; le Retry-After est relevé.
    """
    results = []
    rate_limit_headers = {}
    stopped_by: dict | None = None

    if parallel:
        while len(results) < n and stopped_by is None:
            wave = min(TIER1_MAX_PARALLEL, n - len(results))
            batch = await asyncio.gather(*(_fetch(url, timeout=15) for _ in range(wave)))
            results.extend(batch)
            stopped_by = next((r for r in batch if r["status"] in THROTTLE_STATUSES), None)
    else:
        for _ in range(n):
            r = await _fetch(url, timeout=15)
            results.append(r)
            if r["status"] in THROTTLE_STATUSES:
                stopped_by = r
                break
            await asyncio.sleep(0.05)  # tiny gap

    # Collecte rate-limit headers
    for r in results:
        for h, v in r["headers"].items():
            if any(k in h.lower() for k in ("rate", "limit", "retry")):
                rate_limit_headers.setdefault(h, []).append(v)

    statuses = Counter(r["status"] for r in results)
    durations = [r["duration_s"] for r in results if r["ok"]]
    n_ok = sum(1 for r in results if r["ok"])

    return {
        "mode": "parallel" if parallel else "sequential",
        "n_requests": len(results),
        "n_planned": n,
        "n_ok": n_ok,
        "stopped_early": stopped_by is not None and len(results) < n,
        "stopped_status": stopped_by["status"] if stopped_by else None,
        "retry_after_s": _parse_retry_after(_header(stopped_by["headers"], "retry-after")) if stopped_by else None,
        "statuses": dict(statuses),
        "duration_s": {
            "min": round(min(durations), 2) if durations else None,
            "max": round(max(durations), 2) if durations else None,
            "avg": round(sum(durations) / len(durations), 2) if durations else None,
        },
        "rate_limit_headers": rate_limit_headers,
        "throttling_detected": any(s in (429, 503) for s in statuses),
    }


# ── Schema sample ──────────────────────────────────────────────────────────
async def sample_schema(api_url: str, *, n: int = 100) -> dict:
    """Fetch un sample d'items depuis une API JSON et caractérise le schéma."""
    # Try with per_page=N (WP convention)
    sep = "&" if "?" in api_url else "?"
    sample_url = f"{api_url}{sep}per_page={n}"
    r = await _fetch(sample_url, timeout=20, accept="application/json")
    if not r["ok"]:
        return {"error": r["error"]}
    try:
        data = json.loads(r["body"])
    except json.JSONDecodeError:
        return {"error": "JSON parse failed"}

    if not isinstance(data, list):
        return {
            "shape": type(data).__name__,
            "top_keys": list(data.keys())[:10] if isinstance(data, dict) else [],
        }

    if not data:
        return {"shape": "list", "n_items": 0}

    # Field presence stats
    field_counts: Counter = Counter()
    field_types: dict = {}
    field_samples: dict = {}
    for item in data[:n]:
        if not isinstance(item, dict):
            continue
        for k, v in item.items():
            field_counts[k] += 1
            t = type(v).__name__
            field_types.setdefault(k, set()).add(t)
            if k not in field_samples:
                field_samples[k] = str(v)[:80] if not isinstance(v, (list, dict)) else f"<{t}>"

    # Pagination clues
    pagination = {}
    for h_name in ("X-WP-Total", "X-WP-TotalPages", "X-Total-Count", "Link"):
        if h_name in r["headers"]:
            pagination[h_name] = r["headers"][h_name][:200]

    n_items = len(data)
    return {
        "shape": "list",
        "n_items": n_items,
        "fields": {
            k: {
                "presence_rate": f"{100 * field_counts[k] / n_items:.0f}%",
                "types": sorted(field_types[k]),
                "sample": field_samples[k],
            }
            for k in sorted(field_counts.keys())
        },
        "pagination": pagination,
        "fetched_url": sample_url,
    }


# ── Préférences d'usage déclarées ─────────────────────────────────────────
async def discover_usage(base: str, home: dict, robots: tuple[dict, RobotFileParser]) -> dict:
    """AIPREF, TDMRep, llms.txt, robots d'IA, accès payant (voir usage_prefs)."""
    robots_resp, rp = robots
    robots_txt = robots_resp["body"].decode("utf-8", "replace") if robots_resp.get("ok") else ""
    html = home.get("body", b"")[:200_000].decode("utf-8", "replace")
    out = {
        "content_usage_header": usage_prefs.parse_content_usage(_header(home["headers"], "content-usage")),
        "robots_content_usage": usage_prefs.robots_content_usage(robots_txt),
        "ai_crawlers": usage_prefs.ai_crawler_rules(robots_txt),
        "tdmrep": {
            "header": usage_prefs.tdm_from_headers(home["headers"]),
            "html": usage_prefs.tdm_from_html(html),
            "well_known": None,
        },
        "llms_txt": {"present": False},
        "pay_per_crawl": usage_prefs.pay_per_crawl(home["status"], home["headers"]),
    }
    tdm_url, llms_url = base + usage_prefs.WELL_KNOWN_TDMREP, base + usage_prefs.LLMS_TXT
    if rp.can_fetch("*", tdm_url):
        r = await _fetch(tdm_url, timeout=10, accept="application/json")
        if r["ok"]:
            out["tdmrep"]["well_known"] = usage_prefs.parse_tdmrep_json(r["body"])
    if rp.can_fetch("*", llms_url):
        r = await _fetch(llms_url, timeout=10, accept="text/plain, text/markdown")
        if r["ok"] and "html" not in r["content_type"].lower():
            out["llms_txt"] = {"present": True, "bytes": len(r["body"]), "title": usage_prefs.llms_title(r["body"])}
    else:
        out["llms_txt"]["skipped"] = "interdit par robots.txt pour *"
    return out


def _usage_lines(u: dict) -> list[str]:
    n = neutralize
    lines = ["", "## Préférences d'usage déclarées", ""]
    declared = False
    if u.get("content_usage_header"):
        declared = True
        lines.append(f"- Content-Usage (en-tête) : {n(_kv(u['content_usage_header']), 200)}")
    for rule in u.get("robots_content_usage") or []:
        declared = True
        lines.append(f"- Content-Usage (robots.txt, {n(rule['path'], 80)}) : {n(_kv(rule['prefs']), 200)}")
    tdm = u.get("tdmrep") or {}
    for where in ("header", "html"):
        if tdm.get(where):
            declared = True
            lines.append(f"- TDMRep ({where}) : {n(_kv(tdm[where]), 200)}")
    if tdm.get("well_known"):
        declared = True
        lines.append(f"- TDMRep ({usage_prefs.WELL_KNOWN_TDMREP}) : {len(tdm['well_known'])} règle(s)")
    llms = u.get("llms_txt") or {}
    if llms.get("present"):
        declared = True
        lines.append(f"- llms.txt : {n(llms.get('title') or '(sans titre)', 120)} ({llms['bytes']} octets)")
    if u.get("pay_per_crawl"):
        declared = True
        lines.append(f"- **Accès payant** : {n(_kv(u['pay_per_crawl']), 200)}")
    if not declared:
        lines.append("- Aucune préférence déclarée (Content-Usage, TDMRep, llms.txt).")
    bots = u.get("ai_crawlers") or {}
    for state in ("bloqué", "partiel"):
        names = [b for b, v in bots.items() if v == state]
        if names:
            lines.append(f"- Robots d'IA {state}s dans robots.txt : {', '.join(names)}")
    return lines


# ── Empreinte TLS ─────────────────────────────────────────────────────────
TLS_REFUSAL_STATUSES = (403, 503)
# Erreurs nées de nos propres gardes : elles ne disent rien de l'empreinte.
_OWN_GUARD_ERRORS = ("BlockedDestination", "DeadlineExceeded", "ResponseTooLarge", "TooManyRedirects")
CHALLENGE_MARKERS = re.compile(
    rb"just a moment|attention required|cf-chl|challenge-platform|captcha-delivery|"
    rb"_incapsula_resource|px-captcha|perimeterx|kpsdk|ak-challenge",
    re.I,
)


# Page de blocage explicite : refus net de l'adresse, sans défi à passer (avant les défis :
# la page de blocage Cloudflare porte aussi le titre « Attention Required! »).
BLOCK_PAGE_MARKERS = re.compile(
    rb"sorry, you have been blocked|why have i been blocked|used cloudflare to restrict access", re.I
)
# Erreurs de connexion : le serveur n'a jamais répondu (DNS, refus TCP, délai d'ouverture).
_UNREACHABLE_ERRORS = ("ConnectError", "ConnectTimeout")


def _unreachable(resp: dict) -> bool:
    return resp["status"] == -1 and (resp.get("error") or "").startswith(_UNREACHABLE_ERRORS)


def _python_refused(home: dict) -> bool:
    if home["status"] in TLS_REFUSAL_STATUSES:
        return True
    return home["status"] == -1 and not (home.get("error") or "").startswith(_OWN_GUARD_ERRORS)


async def check_tls_fingerprint(url: str, home: dict) -> tuple[dict, dict | None]:
    """L'accueil refuse Python (403, 503, connexion coupée) : une requête de contrôle imite Chrome.

    Verdicts : « empreinte » (Chrome imité passe : le site filtre sur l'empreinte TLS ;
    rend la page obtenue), « défi » (Chrome imité reçoit une page de défi : navigateur
    réel), « bloqué » (refusé aussi), « indisponible » (curl_cffi absent). Aucune requête
    de plus quand Python passe."""
    if not _python_refused(home):
        return {"tested": False}, None
    if not _http.impersonation_available():
        return {"tested": False, "verdict": "indisponible", "python_status": home["status"]}, None
    token = _IMPERSONATE.set(_http.IMPERSONATE_TARGET)
    try:
        chrome = await _fetch(url, timeout=20)
    finally:
        _IMPERSONATE.reset(token)
    head = chrome["body"][:200_000]
    challenge = bool(CHALLENGE_MARKERS.search(head))
    if _unreachable(home) and _unreachable(chrome):
        verdict = "injoignable"
    elif BLOCK_PAGE_MARKERS.search(head):
        verdict = "refusé"
    elif chrome["ok"] and not challenge:
        verdict = "empreinte"
    elif challenge:
        verdict = "défi"
    else:
        verdict = "bloqué"
    tls = {
        "tested": True,
        "python_status": home["status"],
        "chrome_status": chrome["status"],
        "impersonate": _http.IMPERSONATE_TARGET,
        "profile": _http.impersonation_profile(_http.IMPERSONATE_TARGET),
        "verdict": verdict,
    }
    return tls, (chrome if verdict == "empreinte" else None)


def _tls_note(tls: dict) -> str:
    v = tls.get("verdict")
    if v == "empreinte":
        return f" — empreinte TLS Chrome requise (curl_cffi, impersonate={tls['impersonate']})"
    if v in ("défi", "bloqué"):
        return (
            f" — accueil refusé à Python ({tls['python_status']}) et à Chrome imité ({tls['chrome_status']}, "
            f"{v}) : navigateur réel, voire geste humain ; si Chrome échoue aussi, tier 5 (pas d'accès machine)"
        )
    if v == "refusé":
        return (
            f" — page de blocage servie à Python ({tls['python_status']}) et à Chrome imité "
            f"({tls['chrome_status']}) : refus net de cette adresse, sans défi à passer ; une main n'y change rien"
        )
    if v == "injoignable":
        return " — site injoignable : ni Python ni Chrome imité n'ont obtenu de connexion ; à revoir plus tard"
    if v == "indisponible":
        return " — accueil refusé à Python ; empreinte non testée (curl_cffi absent)"
    return ""


# ── Aggregation : full probe report ────────────────────────────────────────
@dataclass
class ProbeReport:
    url: str
    timestamp: str
    tier1: dict = field(default_factory=dict)
    tier2: dict = field(default_factory=dict)
    rate_limit: dict = field(default_factory=dict)
    schema_sample: dict = field(default_factory=dict)
    chosen_tier: int = 4
    rationale: str = ""
    copies: dict = field(default_factory=dict)
    door_changes: list = field(default_factory=list)
    tls: dict = field(default_factory=lambda: {"tested": False})
    usage: dict = field(default_factory=dict)
    known_platforms: list = field(default_factory=list)
    fingerprint: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "timestamp": self.timestamp,
            "chosen_tier": self.chosen_tier,
            "rationale": self.rationale,
            "tier1_discovery": self.tier1,
            "tier2_static_html": self.tier2,
            "rate_limit_burst": self.rate_limit,
            "schema_sample": self.schema_sample,
            "third_party_copies": self.copies,
            "tls_fingerprint": self.tls,
            "usage_preferences": self.usage,
            "known_platforms": self.known_platforms,
            "fingerprint": self.fingerprint,
        }


def _platform_api(t1: dict) -> dict | None:
    """Première porte JSON de la plateforme reconnue qui a rendu des éléments."""
    return next(
        (f for f in t1.get("found", []) if f.get("source") == "plateforme" and f["type"] == "json" and f.get("items")),
        None,
    )


def _decide_tier(report: ProbeReport) -> tuple[int, str]:
    """Choisit le tier optimal selon les findings, avec la note d'empreinte TLS."""
    tier, why = _decide_tier_doors(report)
    return tier, why + _tls_note(report.tls)


def _decide_tier_doors(report: ProbeReport) -> tuple[int, str]:
    """Choisit le tier optimal selon les portes trouvées."""
    t1 = report.tier1
    t2 = report.tier2
    if t1.get("wordpress_detected"):
        return 1, "WordPress REST API détectée (/wp-json/wp/v2/posts) — voie reine"
    platform_api = _platform_api(t1)
    if platform_api:
        items = platform_api.get("items")
        return 1, (
            f"API de la plateforme {t1.get('platform')} : {platform_api['endpoint']}"
            + (f" ({items} éléments)" if items is not None else "")
        )
    if t1.get("api_endpoints"):
        return 1, f"{len(t1['api_endpoints'])} endpoint(s) JSON trouvé(s)"
    if t1.get("rss_feeds"):
        return 1, f"{len(t1['rss_feeds'])} RSS/Atom feed(s) trouvé(s)"
    if t1.get("sitemap"):
        return 1, "Sitemap XML disponible (utile pour énumération URLs)"
    if t2.get("inline_json"):
        return (
            2,
            f"Inline JSON détecté ({', '.join(j['marker'] for j in t2['inline_json'])})",
        )
    if t2.get("is_likely_spa"):
        return 4, "Site SPA sans alternative API — Chrome render nécessaire"
    if t2.get("fetched"):
        return 2, "HTML statique — extracteurs HTML/CSS classiques"
    return 4, "Aucune voie identifiée — tier 4 par défaut"


PROBE_DEADLINE_S = 180.0


async def probe(url: str, *, deadline: float = PROBE_DEADLINE_S, copies: bool | None = None) -> ProbeReport:
    """Lance les 4 axes de probe puis agrège, sous une échéance globale.

    `copies` : interroger les copies tierces (Wayback, Common Crawl). None =
    seulement si le site ne laisse passer aucune porte.

    Lève TimeoutError si la sonde entière dépasse `deadline` secondes.
    """
    try:
        return await asyncio.wait_for(_probe(url, copies=copies), deadline)
    except TimeoutError:
        raise TimeoutError(f"échéance globale de la sonde dépassée ({deadline:g} s)") from None


async def _probe(url: str, *, copies: bool | None = None) -> ProbeReport:
    # Garde de destination sur la cible avant toute requête (chaque requête
    # et chaque redirection restent gardées ensuite par le client _http).
    await _http.assert_public_async(url)
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    log.info(f"  [probe] cible : {url}")
    log.info(f"  [probe] base  : {base}")

    log.info("  [probe] robots.txt…")
    robots = await _load_robots(base)
    rp = robots[1]

    log.info("  [probe] accueil…")
    home = await _fetch(url, timeout=20)
    tls, chrome_home = await check_tls_fingerprint(url, home)
    if tls.get("tested") or tls.get("verdict"):
        log.info(f"  [probe] empreinte TLS — {tls.get('verdict')} (Python {home['status']})")
    if chrome_home is not None:
        # Le reste de la sonde (tâche propre à `probe`) passe par l'imitation ; robots.txt
        # est relu : refusé à Python (403), il valait « tout interdit ».
        _IMPERSONATE.set(tls["impersonate"])
        home = chrome_home
        robots = await _load_robots(base)
        rp = robots[1]

    log.info("  [probe] préférences d'usage déclarées (AIPREF, TDMRep, llms.txt)…")
    usage = await discover_usage(base, home, robots)
    from .acquisition import learn
    from .acquisition import platforms as known

    home_html = (home.get("body") or b"")[:300_000].decode("utf-8", "replace")
    known_platforms = known.detect(url, html=home_html, headers=home.get("headers") or {})
    fingerprint = learn.fingerprint(home_html, url)

    log.info("  [probe] tier 1 — portes déclarées, de la plateforme, puis génériques…")
    t1 = await discover_tier1(base, robots=robots, home=home)
    log.info(
        f"          → plateforme={t1['platform']}, "
        f"{len(t1['found'])} endpoints repondu, {len(t1['api_endpoints'])} JSON, "
        f"{len(t1['rss_feeds'])} RSS, WordPress={t1['wordpress_detected']}, "
        f"sautés (robots.txt)={len(t1['skipped_by_robots'])}"
    )

    log.info("  [probe] tier 2 — analyse HTML statique…")
    t2 = await discover_tier2(url, home=home)
    if t2.get("fetched"):
        log.info(
            f"          → frameworks={t2['frameworks']}, SPA={t2['is_likely_spa']}, "
            f"inline_json={len(t2['inline_json'])}"
        )

    if rp.can_fetch("*", url):
        log.info("  [probe] rate-limit — burst ≤ 20 séquentielles…")
        rl = await measure_rate_limit(url, n=20, parallel=False)
    else:
        rl = {
            "mode": "sequential",
            "n_requests": 0,
            "n_planned": 20,
            "n_ok": 0,
            "statuses": {},
            "duration_s": {"min": None, "max": None, "avg": None},
            "rate_limit_headers": {},
            "throttling_detected": False,
            "stopped_early": False,
            "retry_after_s": None,
            "skipped": "URL interdite par robots.txt pour * : rafale non lancée",
        }
    log.info(
        f"          → {rl['n_ok']}/{rl['n_requests']} OK, avg {rl['duration_s']['avg']}s, "
        f"throttling={rl['throttling_detected']}, retry_after={rl.get('retry_after_s')}"
    )

    schema = {}
    api_url, n_sample = None, 0
    if t1.get("wordpress_detected"):
        api_url, n_sample = base + "/wp-json/wp/v2/posts", 100
    elif t1.get("api_endpoints"):
        api_url, n_sample = base + t1["api_endpoints"][0]["endpoint"], 20
    if api_url:
        wait = rl.get("retry_after_s")
        if not rp.can_fetch("*", api_url):
            schema = {"skipped": "API interdite par robots.txt pour *"}
        elif wait is not None and wait > RETRY_AFTER_MAX_WAIT_S:
            schema = {"skipped": f"Retry-After {wait} s > {RETRY_AFTER_MAX_WAIT_S:g} s : échantillon non demandé"}
        else:
            if wait:
                log.info(f"  [probe] Retry-After : attente {wait} s…")
                await asyncio.sleep(wait)
            log.info(f"  [probe] schema sample — {api_url} (n={n_sample})…")
            schema = await sample_schema(api_url, n=n_sample)
            if "fields" in schema:
                log.info(f"          → {schema['n_items']} items, {len(schema['fields'])} champs")

    report = ProbeReport(
        url=url,
        timestamp=datetime.now(UTC).isoformat(),
        tier1=t1,
        tier2=t2,
        rate_limit=rl,
        schema_sample=schema,
        tls=tls,
        usage=usage,
        known_platforms=known_platforms,
        fingerprint=fingerprint,
    )
    site_doors = any(f["type"] in _USEFUL_KINDS for f in t1.get("found", []))
    if copies or (copies is None and not site_doors):
        log.info("  [probe] copies tierces — Wayback CDX, index Common Crawl…")
        report.copies = await third_party_copies(parsed.netloc)
        log.info(
            f"          → wayback={report.copies['wayback'].get('items')}, "
            f"commoncrawl={report.copies['commoncrawl'].get('items')}"
        )
    report.chosen_tier, report.rationale = _decide_tier(report)
    return report


# ── Output : markdown + SAP entry + skeleton ──────────────────────────────
def _kv(d: dict, max_len: int = 300) -> str:
    """dict distant → texte neutralisé `clé: valeur; …`."""
    if not d:
        return "aucun"
    return neutralize("; ".join(f"{k}: {v}" for k, v in d.items()), max_len)


def emit_markdown(report: ProbeReport, name: str) -> str:
    """Rapport markdown human-readable.

    Tout ce qui vient du site (types MIME, en-têtes, noms et valeurs de champs,
    URL) passe par `neutralize` et se trouve entre DATA_BEGIN et DATA_END.
    """
    n = neutralize
    t1 = report.tier1
    t2 = report.tier2
    rl = report.rate_limit
    schema = report.schema_sample

    lines = [
        f"# Probe report : {n(name, 64)}",
        "",
        f"- **Audit** : {n(report.timestamp, 40)}",
        f"- **Tier choisi** : **{n(report.chosen_tier, 4)}** — {n(report.rationale, 300)}",
        "",
        DATA_BEGIN,
        "",
        f"- **URL** : {n(report.url, 300)}",
        f"- **Plateforme reconnue** : {n(t1.get('platform', 'generic'), 20)}",
        "",
        "## Tier 1 — endpoints discovery",
        "",
        "| Endpoint | Source | Type | Status | Size | Éléments | Plus récent |",
        "|---|---|---|---|---|---|---|",
    ]
    for f in t1.get("found", []):
        items = f.get("items")
        lines.append(
            f"| `{n(f['endpoint'], 80)}` | {n(f.get('source', ''), 12)} | {n(f['type'], 60)} | {n(f['status'], 6)} "
            f"| {int(f['size']):,} B | {'' if items is None else n(items, 10)} | {n(f.get('newest') or '', 12)} |"
        )
    if report.door_changes:
        lines.extend(
            [
                "",
                "## Évolution des portes (depuis le dernier profil)",
                "",
                "| Porte | Changement | Avant | Après |",
                "|---|---|---|---|",
            ]
        )
        for c in report.door_changes:
            lines.append(
                f"| `{n(c['endpoint'], 80)}` | {n(c['change'], 12)} | {n(c.get('before') or '', 20)} "
                f"| {n(c.get('after') or '', 20)} |"
            )
    if t1.get("subscriptions"):
        lines.extend(["", "## Abonnements proposés", ""])
        for sub in t1["subscriptions"]:
            lines.append(f"- {n(sub['kind'], 12)} : {n(sub['url'], 200)}")
        lines.append(
            "\nS'y inscrire une fois avec une adresse dédiée : la source arrive ensuite d'elle-même. "
            "C'est un geste humain ; avec `--save`, il rejoint la file (`python -m accesspath gestes`)."
        )
    if t1.get("declared_external"):
        lines.append(
            "\n**Portes déclarées sur un autre hôte (non sondées)** : "
            + ", ".join(f"`{n(u, 120)}`" for u in t1["declared_external"])
            + "\n"
        )
    if t1.get("wordpress_detected"):
        lines.append("\n**WordPress détecté** : utiliser `/wp-json/wp/v2/posts?per_page=100&page=N`.\n")
    if t1.get("skipped_by_robots"):
        lines.append(
            "\n**Chemins sautés (robots.txt, `*`)** : "
            + ", ".join(f"`{n(p, 80)}`" for p in t1["skipped_by_robots"])
            + "\n"
        )

    lines.extend(
        [
            "",
            "## Tier 2 — HTML statique",
            f"- frameworks détectés : {n(t2.get('frameworks', []), 200)}",
            f"- SPA probable : {t2.get('is_likely_spa', False)}",
            f"- inline JSON : {n([j['marker'] for j in t2.get('inline_json', [])], 200)}",
            f"- patterns : {_kv(t2.get('patterns', {}))}",
            "",
            "## Rate-limit",
            f"- mode : {n(rl.get('mode'), 20)}",
            f"- {n(rl.get('n_ok'), 6)}/{n(rl.get('n_requests'), 6)} OK",
            f"- latence avg : {n(rl.get('duration_s', {}).get('avg'), 12)}s",
            f"- throttling détecté : {rl.get('throttling_detected')}",
            f"- rafale arrêtée : {rl.get('stopped_early', False)} (statut {n(rl.get('stopped_status'), 6)}, "
            f"Retry-After {n(rl.get('retry_after_s'), 12)} s)",
            f"- rafale sautée : {n(rl.get('skipped') or 'non', 200)}",
            f"- rate-limit headers : {_kv(rl.get('rate_limit_headers') or {}, 500)}",
            "",
        ]
    )

    if schema.get("skipped"):
        lines.extend(["## Schema sample", f"- sauté : {n(schema['skipped'], 200)}", ""])
    if schema and "fields" in schema:
        lines.extend(
            [
                f"## Schema sample (n={n(schema['n_items'], 8)})",
                f"- pagination : {_kv(schema.get('pagination', {}))}",
                "",
                "| Champ | Présence | Types | Sample |",
                "|---|---|---|---|",
            ]
        )
        for fname, info in list(schema["fields"].items())[:30]:
            lines.append(
                f"| `{n(fname, 60)}` | {n(info['presence_rate'], 8)} | "
                f"{n(','.join(info['types']), 40)} | {n(info['sample'], 60)} |"
            )

    if report.tls.get("tested") or report.tls.get("verdict"):
        tls = report.tls
        lines.extend(["", "## Empreinte TLS", ""])
        lines.append(f"- Python (httpx) : {n(tls.get('python_status'), 6)}")
        if tls.get("tested"):
            lines.append(f"- Chrome imité (curl_cffi, {n(tls['impersonate'], 20)}) : {n(tls['chrome_status'], 6)}")
        prof = tls.get("profile") or {}
        if prof.get("resolved"):
            pq = {True: "oui", False: "non", None: "?"}[prof.get("post_quantum")]
            lines.append(
                f"- Profil imité : {n(prof['resolved'], 30)} ; échange de clés post-quantique (X25519MLKEM768) : {pq}"
            )
        lines.append(f"- Verdict : **{n(tls['verdict'], 20)}**")
        if tls["verdict"] == "empreinte":
            lines.append(
                "- Une empreinte qui passe l'accueil ne garantit pas une session : les anti-bots cumulent "
                "les signaux (réseau, navigateur, comportement) sur toute la visite ; répéter (`rehearse`) "
                "sur plusieurs pages avant de compter sur cette voie."
            )

    if report.known_platforms:
        from .acquisition import platforms as known

        lines.extend(known.report_lines(report.known_platforms, n))

    if report.usage:
        lines.extend(_usage_lines(report.usage))

    if report.copies:
        lines.extend(["", "## Copies tierces", f"- {THIRD_PARTY_LEGAL}", ""])
        lines.extend(["| Archive | Adresses | Plus récente | Retard (j) | Erreur |", "|---|---|---|---|---|"])
        for key in ("wayback", "commoncrawl", "memento"):
            if key not in report.copies:
                continue
            c = report.copies.get(key) or {}
            label = key + (f" ({n(c['crawl'], 30)})" if c.get("crawl") else "")
            if c.get("archives"):
                label += f" ({len(c['archives'])} archives : {n(', '.join(c['archives']), 200)})"
            items = c.get("items")
            shown = "" if items is None else (f"≥ {items}" if items >= THIRD_PARTY_LIMIT else n(items, 10))
            lines.append(
                f"| {label} | {shown} | {n(c.get('newest') or '', 12)} "
                f"| {'' if c.get('lag_days') is None else n(c['lag_days'], 8)} | {n(c.get('error') or '', 80)} |"
            )

    lines.extend(
        [
            "",
            DATA_END,
            "",
            "## Suggestion next steps",
            f"1. Implémenter `sites/{n(name, 64)}.py` selon le tier {n(report.chosen_tier, 4)}",
            "2. Ajouter `sap_verify()` testant le tier choisi",
            "3. Compléter `data/site_architecture_profiles.json` (entrée auto-écrite par cette probe)",
        ]
    )
    return "\n".join(lines)


def emit_sap_entry(report: ProbeReport) -> dict:
    """Construit l'entrée JSON pour site_architecture_profiles.json."""
    t1 = report.tier1
    t2 = report.tier2
    rl = report.rate_limit

    chosen_endpoint = None
    platform_api = _platform_api(t1)
    if t1.get("wordpress_detected"):
        chosen_endpoint = "/wp-json/wp/v2/posts?per_page=100&page=N"
    elif platform_api:
        chosen_endpoint = platform_api["endpoint"]
    elif t1.get("rss_feeds"):
        chosen_endpoint = t1["rss_feeds"][0]["endpoint"]
    elif t1.get("api_endpoints"):
        chosen_endpoint = t1["api_endpoints"][0]["endpoint"]

    entry = {
        "url_base": report.url,
        "rendering": "WordPress + REST API"
        if t1.get("wordpress_detected")
        else "SPA"
        if t2.get("is_likely_spa")
        else "SSR HTML",
        "chosen_method": {
            "tier": report.chosen_tier,
            "rationale": report.rationale,
            "endpoint": chosen_endpoint,
            "tested": [
                f"tier 1 : {len(t1.get('api_endpoints', []))} JSON, "
                f"{len(t1.get('rss_feeds', []))} RSS, "
                f"WordPress={t1.get('wordpress_detected')}",
                f"tier 2 : frameworks={t2.get('frameworks', [])}, SPA={t2.get('is_likely_spa', False)}",
            ],
        },
        "stealth_measures": {
            "header_rotation": "stealth.random_headers() — pool 6 profils browser",
            "rate_limit_observed": (
                f"{rl.get('n_ok')}/{rl.get('n_requests')} OK en mode "
                f"{rl.get('mode')}, throttling={rl.get('throttling_detected')}"
            ),
            "rate_limit_recommandé": "1-2 req/s soutenu (politesse), bursts < 5 req/s",
            "delays": "à appliquer par site (sleep entre pages)",
            "anti_bot_marker": "non détecté lors du probe initial",
        },
        "endpoints_discovered": {f["endpoint"]: f["type"] for f in t1.get("found", [])},
        "platform": t1.get("platform", "generic"),
        "subscriptions": t1.get("subscriptions", []),
        "doors": {
            f["endpoint"]: {
                "type": f["type"],
                "source": f.get("source", "générique"),
                "items": f.get("items"),
                "newest": f.get("newest"),
            }
            for f in t1.get("found", [])
            if f["endpoint"] != "/robots.txt"
        },
        "schema_sample": report.schema_sample if "fields" in report.schema_sample else {},
        "third_party_copies": {
            **{
                k: {f: c.get(f) for f in ("items", "newest", "lag_days", "crawl")}
                for k, c in report.copies.items()
                if isinstance(c, dict)
            },
            "legal": report.copies.get("legal", ""),
        }
        if report.copies
        else {},
        "implementation_status": "TODO — auto-probed, à valider et implémenter",
        "last_audit": report.timestamp[:10],
        "_probe_report_path": None,  # rempli par save_findings
    }
    if report.usage:
        entry["usage_preferences"] = report.usage
    if report.known_platforms:
        entry["known_platforms"] = [f["platform"] for f in report.known_platforms]
    if report.tls.get("tested") or report.tls.get("verdict"):
        entry["tls_check"] = report.tls
    if report.tls.get("verdict") == "empreinte":
        entry["tls_fingerprint"] = report.tls["impersonate"]  # lu par fingerprint.make_client
    return entry


def emit_skeleton(report: ProbeReport, name: str) -> str:
    """Squelette `sites/<name>.py` à finir manuellement.

    Toute valeur issue de la sonde (URL, justification, date) est insérée par
    `repr()` : elle reste une chaîne Python, jamais du code. Le résultat est
    relu par `ast.parse` avant d'être rendu.
    """
    validate_site_name(name)
    chosen = int(report.chosen_tier)
    is_wp = bool(report.tier1.get("wordpress_detected"))
    fetch_method = "rss" if report.tier1.get("rss_feeds") else "http"
    doc = (
        f"{name} — auto-generated from probe ({report.timestamp[:10]}).\n\n"
        f"Tier choisi : {chosen}\n"
        f"Rationale  : {report.rationale}\n"
        f"URL base   : {report.url}\n\n"
        "AUTO-GÉNÉRÉ — à finir manuellement (extracteurs, tests, sap_verify).\n"
    )
    wp_hint = (
        "# WordPress REST API exposée — utiliser /wp-json/wp/v2/posts?per_page=100&page=N\n"
        "# Filtres natifs : ?after=ISO, ?before=ISO, ?categories=ID, ?_fields=...\n"
        if is_wp
        else ""
    )
    tls_line = (
        f"\n    tls_fingerprint={report.tls['impersonate']!r},  # sonde : seule l'empreinte Chrome imitée passe"
        if report.tls.get("verdict") == "empreinte"
        else ""
    )
    src = f'''{doc!r}
from __future__ import annotations

from ..config import BrowserMode, SiteConfig
from ..stealth import random_headers
from ..sap import CheckResult, SapResult, _aggregate

BASE_URL = {report.url.rstrip("/")!r}


# ── TODO : implémenter selon le tier {chosen} ───────────────────────────────
{wp_hint}

async def seed_urls(_):
    """TODO : itérer sur l'API/RSS et retourner [{{id, product_url, ...}}]."""
    return []


async def sap_verify():
    """TODO : auto-test du portrait-robot contre une page sample."""
    from datetime import datetime, timezone
    return SapResult(
        site={name!r},
        timestamp=datetime.now(timezone.utc).isoformat(),
        fetch_url=BASE_URL,
        fetch_method={fetch_method!r},
        overall="warn",
        checks=[CheckResult(name="sap_verify_implementation", status="warn", detail="TODO")],
    )


def _dummy_extract(_): return None
def _dummy_is_bot(_): return False
def _dummy_get_items(_): return []


CONFIG = SiteConfig(
    name={name!r},
    enabled=True,
    browser_mode=BrowserMode.PERSISTENT_PROFILE,
    categories=[],
    extract=_dummy_extract,
    is_bot=_dummy_is_bot,
    get_items=_dummy_get_items,
    seed_urls=seed_urls,
    seed_needs_browser=False,  # tier 1 → pure HTTP
    fetch_via_http=True,
    enrich_by_default=False,{tls_line}
)
'''
    ast.parse(src)  # lève SyntaxError si une valeur avait cassé la structure
    return src


# ── Save findings to exploitable files ────────────────────────────────────
def save_findings(report: ProbeReport, name: str, *, save_skeleton: bool = False) -> dict:
    """Persiste : data/probes/{name}_{date}.md + entrée dans site_architecture_profiles.json
       + squelette optionnel sites/{name}.py.
    Retourne dict avec les paths écrits. Chaque chemin est vérifié sous sa base."""
    import os

    validate_site_name(name)
    out: dict = {}

    # 1. Markdown report archive
    md_path = safe_write_text(
        DATA_DIR,
        "probes",
        f"{name}_{report.timestamp[:10]}.md",
        text=emit_markdown(report, name),
    )
    out["markdown"] = str(md_path)

    # 2. SAP entry merge
    sap_path = safe_path(DATA_DIR, "site_architecture_profiles.json")
    if sap_path.exists():
        sap = json.loads(sap_path.read_text())
    else:
        sap = {}
    entry = emit_sap_entry(report)
    entry["_probe_report_path"] = str(md_path.relative_to(Path(DATA_DIR).resolve().parent))
    sap[name] = entry
    tmp = sap_path.with_suffix(sap_path.suffix + ".tmp")
    tmp.write_text(json.dumps(sap, indent=2, ensure_ascii=False))
    os.replace(tmp, sap_path)
    out["sap_entry"] = f"{sap_path}#{name}"

    # 3. Skeleton (optionnel)
    if save_skeleton:
        skel_path = safe_path(SITES_DIR, f"{name}.py")
        if skel_path.exists():
            out["skeleton"] = f"⚠️ {skel_path} existe déjà, skip — supprime pour regénérer"
        else:
            skel_path.write_text(emit_skeleton(report, name), encoding="utf-8")
            out["skeleton"] = str(skel_path)

    return out
