"""Volet contenus du profil d'un site : ses pages de contenu (projets, œuvres, articles,
fiches) et leurs images.

Où sont les contenus, combien, et comment viennent leurs images. Sources essayées dans
l'ordre : API REST WordPress (type de contenu, total annoncé par `X-WP-Total`), page de
liste de la recette du site (`websites.yaml`), sitemap, page de liste trouvée depuis
l'accueil. Une URL est un contenu si un motif la reconnaît : motifs génériques, profils
de CMS, familles des sites (`patterns.match_project`, nom hérité des premiers collecteurs,
qui cherchaient des pages de projet), puis l'heuristique de
profondeur ; l'étiquette du motif est rendue (`matched_by`).

Sur trois contenus répartis : images de la page (attributs de chargement différé, plus
grande largeur annoncée par `srcset`), opengraph, hôtes. Une image est relue sans puis
avec `Referer`, si robots.txt la permet. Écart avec la collecte déjà faite : contenus en
ligne moins contenus sur le disque.
"""

from __future__ import annotations

import json
import re
import statistics
from collections import Counter
from pathlib import Path
from urllib.parse import urljoin, urlsplit
from urllib.robotparser import RobotFileParser

from bs4 import BeautifulSoup

from . import patterns as op

SAMPLE = 3
# Sous-plans de site lus au plus : un index WordPress peut lister une archive d'articles par
# mois, et les projets s'y trouver (cas Eglin, 80 entrées, projets publiés de 2017 à 2026).
MAX_SITEMAPS = 100
WP_PROJECT_TYPES = {
    "project", "projects", "projekt", "projekte", "projet", "projets", "progetto", "progetti",
    "portfolio", "portfolio_page", "portfolio-item", "portfolio-items", "work", "works", "werk",
    "werke", "referenzen", "references", "realisation", "realisations",
}  # fmt: skip
LAZY_ATTRS = ("data-src", "data-lazy-src", "data-original", "data-hw-src", "data-image", "data-srcset")
_SKIP_IMAGE = ("logo", "icon", "favicon", "sprite", "placeholder")
_IMAGE_EXT = (".jpg", ".jpeg", ".png", ".webp", ".avif", ".gif")
_CSS_URL = re.compile(r"background(?:-image)?\s*:[^;\"]*url\(\s*['\"]?([^'\")]+)", re.I)
_FILE_EXT = (".pdf", ".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp", ".zip", ".mp4", ".css", ".js", ".xml")

# Rubriques dont les pages ne sont pas des projets, même profondes.
NEWS_SECTIONS = {
    "journal", "news", "blog", "aktuell", "aktuelles", "actualites", "actualite", "attualita", "notizie",
    "presse", "press", "medien", "media", "events", "agenda", "jobs", "stellen", "team", "kontakt", "contact",
}  # fmt: skip

# Pages d'un site à plat (/kontakt, /buero) qui ne sont pas des contenus, en plus des
# listes des collecteurs (NON_PROJECT_SLUGS) et des rubriques d'actualité.
FLAT_NON_CONTENT = {
    "buero", "büro", "wir", "uns", "ueber-uns", "uber-uns", "about-us", "landing-page", "main", "start",
    "startseite", "links", "downloads", "download", "faq", "partner", "partners", "awards",
    "auszeichnungen", "anfahrt", "standort", "kontaktformular", "offene-stellen", "credits", "disclaimer",
}  # fmt: skip
# Noms de pages d'index qui ne figurent pas dans les mots de projet des collecteurs.
INDEX_EXTRA = {"projektauswahl", "projektliste", "referenzliste", "auswahl", "werkauswahl"}
# Pages à plat à partir desquelles on conclut à des contenus : moins, c'est la navigation.
MIN_FLAT = 3
_PAGE_EXT = (".html", ".htm", ".php", ".asp", ".aspx")
_NUM_SUFFIX = re.compile(r"-?\d+$")
_LANGUAGES = {"de", "fr", "it", "en", "es", "nl", "rm", "pt"}

_DOC: dict | None = None


def _patterns(doc: dict | None) -> dict:
    global _DOC
    if doc is not None:
        return doc
    if _DOC is None:
        from . import learn

        _DOC = learn.with_local(op.load())
    return _DOC


# ── Unités ───────────────────────────────────────────────────────────────
def content_label(url: str, doc: dict | None = None) -> str | None:
    """Étiquette du motif qui reconnaît `url` comme projet, ou None."""
    from . import pages as h

    path = urlsplit(url).path
    last = path.rstrip("/").rsplit("/", 1)[-1].lower()
    if not last or last.endswith(_FILE_EXT) or last in h.NON_PROJECT_SLUGS or last in h.PROJECT_WORDS_IN_PATH:
        return None
    if any(seg.lower() in NEWS_SECTIONS for seg in path.strip("/").split("/")[:-1]):
        return None
    label = op.match_project(_patterns(doc), url)
    if label:
        return label
    return "profondeur" if h.slug_from_deep_path(url) else None


def is_content_url(url: str, doc: dict | None = None) -> bool:
    return content_label(url, doc) is not None


def _segments(url: str) -> list[str]:
    segs = [s.lower() for s in urlsplit(url).path.strip("/").split("/") if s]
    return segs[1:] if segs and segs[0] in _LANGUAGES else segs


def _page_stem(segment: str) -> str:
    """`projekte.html` → `projekte`, `work2` → `work`, `projekte-2` → `projekte`."""
    for ext in _PAGE_EXT:
        if segment.endswith(ext):
            segment = segment[: -len(ext)]
            break
    return _NUM_SUFFIX.sub("", segment) or segment


def is_index_page(url: str) -> bool:
    """Page qui liste les contenus : un mot de projet, aux variantes près (.html, .php, -2, 2)."""
    from . import pages as h

    segs = _segments(url)
    return bool(segs) and _page_stem(segs[-1]) in (h.PROJECT_WORDS_IN_PATH | INDEX_EXTRA)


def is_flat_content(url: str) -> bool:
    """Page de premier niveau (langue à part) qui n'est ni l'accueil, ni une page de service,
    ni une page d'index : sur un site à plat, c'est un contenu."""
    from . import pages as h

    segs = _segments(url)
    if len(segs) != 1 or segs[0].endswith(_FILE_EXT):
        return False
    stem = _page_stem(segs[0])
    excluded = h.NON_PROJECT_SLUGS | NEWS_SECTIONS | FLAT_NON_CONTENT
    return stem not in excluded and segs[0] not in excluded and not is_index_page(url)


def home_failure(home: dict) -> str | None:
    """Pourquoi l'accueil ne se lit pas : certificat refusé, injoignable, ou statut HTTP."""
    if home.get("ok"):
        return None
    error = home.get("error") or ""
    if "CERTIFICATE" in error.upper() or "SSL" in error.upper():
        return "certificat refusé"
    if error.startswith(("ConnectError", "ConnectTimeout", "BlockedDestination")):
        return "injoignable"
    if home.get("status", -1) > 0:
        return f"HTTP {home['status']}"
    return error.split(":", 1)[0] or "erreur"


def distinct_contents(urls: list[str]) -> int:
    """Projets distincts : une page traduite (/de/architektur/x, /en/architecture/x) compte une
    fois, les onglets d'un projet (/projekte/x/bilder, /projekte/x/plaene) aussi. Sous un même
    chemin, plus de parents que de derniers segments, et aucun parent qui soit une page
    d'index (/de/projekte/x, /en/projects/x) : ces derniers segments sont des onglets."""
    from . import pages as h

    index_words = h.PROJECT_WORDS_IN_PATH | INDEX_EXTRA
    paths = [_segments(u) for u in urls]
    parents: dict[tuple, set[str]] = {}
    lasts: dict[tuple, set[str]] = {}
    for segs in paths:
        if len(segs) >= 2:
            parents.setdefault(tuple(segs[:-2]), set()).add(segs[-2])
            lasts.setdefault(tuple(segs[:-2]), set()).add(segs[-1])
    tabs = {
        g for g, ps in parents.items() if len(ps) > len(lasts[g]) and not any(_page_stem(x) in index_words for x in ps)
    }
    return len({segs[-2] if len(segs) >= 2 and tuple(segs[:-2]) in tabs else segs[-1] for segs in paths if segs})


def max_width(srcset: str) -> tuple[str | None, int | None]:
    """`a.jpg 300w, b.jpg 1600w` → ("b.jpg", 1600) ; densités (`2x`) : la dernière, largeur inconnue."""
    best, width = None, None
    for part in (srcset or "").split(","):
        bits = part.strip().split()
        if not bits:
            continue
        w = int(bits[1][:-1]) if len(bits) > 1 and bits[1].endswith("w") and bits[1][:-1].isdigit() else None
        if w is not None and (width is None or w > width):
            best, width = bits[0], w
        elif width is None:
            best = bits[0]
    return best, width


def _usable(url: str | None) -> bool:
    if not url or url.startswith(("data:", "blob:")):
        return False
    name = urlsplit(url).path.lower()
    return not name.endswith(".svg") and not any(s in name.rsplit("/", 1)[-1] for s in _SKIP_IMAGE)


def page_images(html: str, base: str) -> dict:
    """Images d'une page de projet : URL absolues, largeur connue, provenance (balise,
    lien direct vers le fichier, arrière-plan CSS), chargement différé, opengraph."""
    soup = BeautifulSoup(html or "", "html.parser")
    og = soup.find("meta", attrs={"property": "og:image"})
    found: dict[str, dict] = {}
    lazy = False

    def add(url, width, via="img"):
        if _usable(url):
            u = urljoin(base, url)
            if u not in found or (width or 0) > (found[u]["width"] or 0):
                found[u] = {"url": u, "width": width, "via": via}

    for tag in soup.find_all(["img", "source"]):
        srcset = tag.get("srcset") or tag.get("data-srcset")
        if srcset:
            add(*max_width(srcset))
            lazy = lazy or bool(tag.get("data-srcset"))
            continue
        lazy_url = next((tag.get(a) for a in LAZY_ATTRS if tag.get(a)), None)
        if lazy_url:
            lazy = True
            add(lazy_url, None)
        elif tag.name == "img":
            add(tag.get("src"), None)
    for a in soup.find_all("a", href=True):  # visionneuses : le lien mène au fichier
        if urlsplit(a["href"]).path.lower().endswith(_IMAGE_EXT):
            add(a["href"], None, "lien")
    for tag in soup.find_all(style=True):
        for url in _CSS_URL.findall(tag["style"]):
            add(url, None, "css")
    images = list(found.values())
    widths = [i["width"] for i in images if i["width"]]
    return {
        "og": urljoin(base, og["content"]) if og and og.get("content") else None,
        "images": images,
        "lazy": lazy,
        "max_width": max(widths) if widths else None,
    }


def image_mode(page: dict) -> str:
    via = {i.get("via", "img") for i in page["images"]}
    if "img" in via:
        return "chargement différé" if page["lazy"] else "html"
    if "lien" in via:
        return "liens directs"
    if "css" in via:
        return "arrière-plan CSS"
    return "opengraph seul" if page["og"] else "aucune (navigateur probable)"


def spread(items: list, n: int) -> list:
    if len(items) <= n:
        return list(items)
    step = (len(items) - 1) / (n - 1)
    return [items[round(i * step)] for i in range(n)]


def disk_contents(root: Path, slug: str) -> int | None:
    d = Path(root) / slug / "projects"
    return len(list(d.glob("*.json"))) if d.is_dir() else None


# ── Découverte ───────────────────────────────────────────────────────────
async def _get(url: str, **kw) -> dict:
    from ..probe import _fetch

    return await _fetch(url, timeout=kw.pop("timeout", 15), **kw)


def _json(r: dict):
    try:
        return json.loads(r["body"]) if r["ok"] else None
    except ValueError:
        return None


def _same_site(url: str, base: str) -> bool:
    return op._bare(urlsplit(url).hostname or "") == op._bare(urlsplit(base).hostname or "")


async def _wp_rest(base: str) -> dict | None:
    types = _json(await _get(urljoin(base, "/wp-json/wp/v2/types"), accept="application/json"))
    if not isinstance(types, dict):
        return None
    for slug, t in types.items():
        rest = (t or {}).get("rest_base") or slug
        if slug.lower() in WP_PROJECT_TYPES or str(rest).lower() in WP_PROJECT_TYPES:
            r = await _get(urljoin(base, f"/wp-json/wp/v2/{rest}?per_page=100&_fields=link"), accept="application/json")
            items = _json(r)
            if not isinstance(items, list) or not items:
                continue
            links = [i["link"] for i in items if isinstance(i, dict) and i.get("link")]
            total = r["headers"].get("X-WP-Total") or r["headers"].get("x-wp-total")
            return {"source": "wp-rest", "wp_type": slug, "urls": links, "count": int(total) if total else len(links)}
    return None


def _links(html: str, base: str) -> list[str]:
    soup = BeautifulSoup(html or "", "html.parser")
    out = []
    for a in soup.find_all("a", href=True):
        u = urljoin(base, a["href"]).split("#", 1)[0]
        if _same_site(u, base) and u not in out:
            out.append(u)
    return out


async def _from_listing(listing: str, base: str, doc: dict, nav: set[str] | None = None) -> tuple[list[str], bool]:
    """Contenus d'une page de liste, et s'ils sont à plat. Sans motif reconnu, les pages à plat
    propres à la liste (absentes de la navigation de l'accueil, `nav`) comptent dès MIN_FLAT."""
    r = await _get(listing, accept="text/html")
    if not r["ok"]:
        return [], False
    links = _links(r["body"].decode("utf-8", "replace"), listing)
    found = [u for u in links if is_content_url(u, doc)]
    if found or nav is None:
        return found, False
    flat = [u for u in links if u not in nav and is_flat_content(u)]
    return (flat, True) if distinct_contents(flat) >= MIN_FLAT else ([], False)


async def _sitemap_urls(base: str, robots_txt: str, recipe: dict | None) -> list[str]:
    from . import pages as h

    todo = [ln.split(":", 1)[1].strip() for ln in robots_txt.splitlines() if ln.lower().startswith("sitemap:")]
    if recipe and recipe.get("sitemap"):
        todo.append(recipe["sitemap"])
    todo += [urljoin(base, "/sitemap.xml"), urljoin(base, "/sitemap_index.xml")]
    seen: set[str] = set()
    urls: list[str] = []
    while todo and len(seen) < MAX_SITEMAPS:
        sm = todo.pop(0)
        if sm in seen or not _same_site(sm, base):
            continue
        seen.add(sm)
        r = await _get(sm, accept="application/xml, text/xml")
        if not r["ok"]:
            continue
        subs, entries = h.parse_sitemap_xml(r["body"])
        todo += subs
        urls += [e["loc"] for e in entries if e.get("loc")]
        if urls and not subs and not todo:
            break
    return list(dict.fromkeys(urls))


async def _discover(base: str, home_html: str, robots_txt: str, recipe: dict | None, doc: dict) -> dict:
    wp = await _wp_rest(base)
    if wp:
        return wp
    if recipe and recipe.get("index_page"):
        found, _flat = await _from_listing(recipe["index_page"], base, doc)
        if found:
            return {
                "source": "liste (recette)",
                "listing": recipe["index_page"],
                "urls": found,
                "count": distinct_contents(found),
            }
    site_urls = [u for u in await _sitemap_urls(base, robots_txt, recipe) if _same_site(u, base)]
    sm = [u for u in site_urls if is_content_url(u, doc)]
    if sm:
        return {"source": "sitemap", "urls": sm, "count": distinct_contents(sm)}
    nav = set(_links(home_html, base))
    for candidate in _links(home_html, base):
        if is_index_page(candidate):  # page d'index : /projekte/, projekte.html, work2
            found, flat = await _from_listing(candidate, base, doc, nav)
            if found:
                return {
                    "source": "liste",
                    "listing": candidate,
                    "urls": found,
                    "count": distinct_contents(found),
                    "flat": flat,
                }
    flat_sm = [u for u in site_urls if is_flat_content(u)]
    if distinct_contents(flat_sm) >= MIN_FLAT:
        return {"source": "sitemap (à plat)", "urls": flat_sm, "count": distinct_contents(flat_sm), "flat": True}
    return {"source": None, "urls": [], "count": 0}


# ── Profil ───────────────────────────────────────────────────────────────
async def _check_image(url: str, page: str) -> dict:
    r = await _get(url, accept="image/avif,image/webp,image/*;q=0.8")
    needs = False
    if r["status"] in (401, 403):
        r2 = await _get(url, accept="image/avif,image/webp,image/*;q=0.8", extra_headers={"Referer": page})
        if r2["ok"]:
            r, needs = r2, True
    return {"status": r["status"], "needs_referer": needs, "content_type": r["content_type"].split(";")[0].strip()}


async def profile_contents(url: str, *, disk_contents: int | None = None, patterns: dict | None = None) -> dict:
    doc = _patterns(patterns)
    base = f"{urlsplit(url).scheme}://{urlsplit(url).netloc}/"
    site = op.site_for_url(doc, url)
    recipe = (doc.get("sites") or {}).get(site) if site else None
    home = await _get(url, accept="text/html")
    robots = await _get(urljoin(base, "/robots.txt"), accept="text/plain")
    robots_txt = robots["body"].decode("utf-8", "replace") if robots["ok"] else ""
    rp = RobotFileParser()
    rp.parse(robots_txt.splitlines())
    found = await _discover(
        base, home["body"].decode("utf-8", "replace") if home["ok"] else "", robots_txt, recipe, doc
    )
    sample = spread(found["urls"], SAMPLE)
    labels = Counter(content_label(u, doc) for u in found["urls"])
    pages = []
    for u in sample:
        r = await _get(u, accept="text/html")
        if r["ok"]:
            pages.append((u, page_images(r["body"].decode("utf-8", "replace"), u)))
    images = [i for _, p in pages for i in p["images"]]
    widths = [p["max_width"] for _, p in pages if p["max_width"]]
    modes = Counter(image_mode(p) for _, p in pages)
    first = max(images, key=lambda i: i["width"] or 0) if images else None
    allowed = rp.can_fetch("*", first["url"]) if first else None
    check = None
    if first and allowed:
        check = await _check_image(first["url"], next(u for u, p in pages if first in p["images"]))
    count = found["count"]
    return {
        "site": site,
        "source": found["source"],
        "wp_type": found.get("wp_type"),
        "listing": found.get("listing"),
        "matched_by": "à plat"
        if found.get("flat")
        else (labels.most_common(1)[0][0] if labels and found["source"] != "wp-rest" else None),
        "count": count,
        "sample": sample,
        "image_mode": modes.most_common(1)[0][0] if modes else None,
        "images_per_page": round(statistics.median(len(p["images"]) for _, p in pages)) if pages else None,
        "max_width": max(widths) if widths else None,
        "image_hosts": sorted({urlsplit(i["url"]).hostname for i in images}),
        "image_check": check,
        "robots_images_allowed": allowed,
        "disk_contents": disk_contents,
        "gap": count - disk_contents if disk_contents is not None and count else None,
        "home_error": home_failure(home),
    }


def contents_row(p: dict) -> dict:
    return {
        "status": "ok",
        "content_source": p["source"],
        "contents": p["count"],
        "image_mode": p["image_mode"],
        "images_per_page": p["images_per_page"],
        "max_width": p["max_width"],
        "image_hosts": p["image_hosts"],
        "needs_referer": (p["image_check"] or {}).get("needs_referer"),
        "robots_images_allowed": p["robots_images_allowed"],
        "disk_contents": p["disk_contents"],
        "gap": p["gap"],
        "matched_by": p.get("matched_by"),
        "home_error": p.get("home_error"),
        "content_samples": [urlsplit(u).path for u in p.get("sample") or []],
    }
