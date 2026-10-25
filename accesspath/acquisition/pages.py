"""Pages de contenu d'un site : lecture de sitemap, profils de CMS, repérage des pages.

Savoir commun aux audits de contenu (`sap batch --mode contents`) et aux collecteurs.
Les mots de projet reconnaissent les pages de réalisation, de portfolio ou de projet,
en plusieurs langues.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET

# ── Sitemap discovery ──────────────────────────────────────────────────────
# Standard sitemaps.org namespace + legacy Google namespace (rare, ancien wp/IIS exports).
SM_NS_CANDIDATES = (
    {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"},
    {"sm": "http://www.google.com/schemas/sitemap/0.9"},
)


SM_NS = SM_NS_CANDIDATES[0]  # rétro-compat exposed symbol


def parse_sitemap_xml(xml_bytes: bytes) -> tuple[list[str], list[dict]]:
    """Parse sitemap or sitemap index XML.

    Returns (sub_sitemaps, urls) where :
      - sub_sitemaps : list of sub-sitemap URLs (if this is an index)
      - urls : list of {loc, lastmod} dicts (if this is a urlset)
    Exactly one of the two will be populated depending on the XML type.
    """
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError:
        # Tolerate leading whitespace, BOM, and quirky xml decl (`version = "1.0"` with spaces)
        cleaned = xml_bytes.lstrip()
        if cleaned.startswith(b"\xef\xbb\xbf"):
            cleaned = cleaned[3:]
        try:
            root = ET.fromstring(cleaned)
        except ET.ParseError:
            return [], []

    # Detect actual namespace used by the root element ; fall back to candidates.
    actual_ns = None
    if root.tag.startswith("{"):
        actual_ns = root.tag[1:].split("}", 1)[0]
    if actual_ns:
        ns = {"sm": actual_ns}
    else:
        ns = SM_NS_CANDIDATES[0]

    sub_sitemaps: list[str] = []
    urls: list[dict] = []

    # sitemap index
    for sm in root.findall("sm:sitemap", ns):
        loc = (sm.findtext("sm:loc", default="", namespaces=ns) or "").strip()
        if loc:
            sub_sitemaps.append(loc)

    # urlset
    for u in root.findall("sm:url", ns):
        loc = (u.findtext("sm:loc", default="", namespaces=ns) or "").strip()
        if not loc:
            continue
        lastmod = (u.findtext("sm:lastmod", default="", namespaces=ns) or "").strip()
        urls.append({"loc": loc, "lastmod": lastmod})

    return sub_sitemaps, urls


_SAFE_SLUG_RE = re.compile(r"[\w.-]{1,150}")


def is_safe_slug(slug: str) -> bool:
    """Vrai si `slug` peut servir de nom de fichier sans sortir de son dossier.

    Lettres, chiffres (Unicode compris), `_`, `.`, `-` ; 1 à 150 caractères ;
    jamais `..` (ni seul, ni à l'intérieur). Refuse donc `/`, `\\`, les
    caractères de contrôle et les espaces.
    """
    return bool(slug) and _SAFE_SLUG_RE.fullmatch(slug) is not None and ".." not in slug


# ALL_PROJECT_PATH_PATTERNS accepte aussi des paths cross-language (ex: /de/projects/...
# pour un site allemand qui utilise des paths en anglais comme met_architects).
_ALL_LANG_PREFIXES = r"(?:fr|de|it|en)/"


_ALL_PROJECT_WORDS = (
    r"project|projects|projet|projets|realisation|realisations|oeuvre|oeuvres|"
    r"portfolio|projekt|projekte|werk|werke|bau|bauten|arbeit|arbeiten|"
    r"architektur|architekturen|architecture|architettura|"
    r"referenz|referenzen|interior|interiors|interieur|interieurs|interno|interni|"
    r"progetto|progetti|lavoro|lavori|opera|opere|work|works|building|buildings"
)


ALL_PROJECT_PATH_PATTERNS: list[re.Pattern] = [
    re.compile(rf"^/(?:{_ALL_LANG_PREFIXES})?(?:{_ALL_PROJECT_WORDS})/[^/]+/?$", re.I),
]


NON_PROJECT_SLUGS: frozenset[str] = frozenset(
    {
        # Standard pages
        "about",
        "contact",
        "impressum",
        "kontakt",
        "kontakte",
        "team",
        "home",
        "index",
        "profil",
        "profile",
        "portrait",
        "portfolio",
        "kompetenz",
        "kompetenzen",
        "leistung",
        "leistungen",
        "leistungsspektrum",
        "angebot",
        "angebote",
        "services",
        "service",
        # Index pages (singular/plural of project words — they show the list, not a project)
        "projekt",
        "projekte",
        "projects",
        "project",
        "projet",
        "projets",
        "arbeit",
        "arbeiten",
        "werk",
        "werke",
        "items",
        "referenzen",
        "referenz",
        "bauten",
        "bau",
        "realisations",
        "realisation",
        # Legal
        "datenschutz",
        "agb",
        "privacy",
        "mentions-legales",
        "cookies",
        "newsletter",
        "datenschutzerklaerung",
        "datenschuterklaerung",
        "imprint",
        # News/blog
        "news",
        "aktuell",
        "aktuelles",
        "blog",
        "press",
        "presse",
        "publications",
        "publikationen",
        "events",
        "event",
        "agenda",
        # Bureau/équipe
        "philosophie",
        "philosophy",
        "geschichte",
        "history",
        "unternehmen",
        "company",
        "firma",
        "bureau",
        "office",
        "studio",
        "atelier",
        "mitarbeiter",
        "team-1",
        "team-2",
        "equipe",
        # Admin/jobs
        "jobs",
        "careers",
        "stellenangebote",
        "stellen",
        "karriere",
        "admin",
        "login",
        "register",
        "search",
        # Tech
        "sitemap",
        "robots",
        "assets",
        "wp-content",
        "wp-includes",
        "wp-admin",
        "feed",
        "rss",
        "category",
        "tag",
        "author",
        "user",
        # Liens et partenaires
        "links",
        "partner",
        "partners",
        "kunden",
        "clients",
        "references",
        "auftraggeber",
        "beratung",
        "dienstleistung",
        "gewerbedienstleistungen",
        "mitgliedschatften",
        "mitgliedschaft",
        "mitgliedschaften",
        # Langs (en cas où le slug-at-root est une langue, pas un projet)
        "de",
        "fr",
        "en",
        "it",
        "rm",
    }
)


PROJECT_WORDS_IN_PATH = frozenset(
    {
        "projekt",
        "projekte",
        "project",
        "projects",
        "projet",
        "projets",
        "werk",
        "werke",
        "werkliste",
        "werkverzeichnis",
        "bau",
        "bauten",
        "neubau",
        "umbau",
        "umbauten",
        "neubauten",
        "innenausbau",
        "innenausbauten",
        "arbeit",
        "arbeiten",
        "realisation",
        "realisations",
        "wettbewerb",
        "wettbewerbe",
        "konkurrenz",
        "portfolio",
        "architektur",
        "architecture",
        "architektur-",
        "referenz",
        "referenzen",
        "lavoro",
        "lavori",
        "opera",
        "opere",
        "progetto",
        "progetti",
        "interior",
        "interiors",
        "interieur",
        "interno",
        "interni",
        "studie",
        "studien",
        "study",
        "building",
        "buildings",
        "house",
        "houses",
        "work",
        "works",
    }
)


def slug_from_deep_path(url: str, extra_exclude: set[str] | None = None) -> str | None:
    """Return the last meaningful slug if URL's path contains a project-word at ANY depth.

    Couvre les sites avec patterns custom multi-niveaux :
      /projekte/detail/show/museum-x        → returns "museum-x"
      /projekte/details/105/zentrum-toedi   → returns "zentrum-toedi"
      /umbau/villa-bellavista                → returns "villa-bellavista"
      /werkliste/gewerbebauten/halle-x       → returns "halle-x"

    Heuristique : si un des segments du path est dans PROJECT_WORDS_IN_PATH ET
    le dernier segment du path n'est pas dans NON_PROJECT_SLUGS, on considère
    le dernier segment comme le slug projet.

    `extra_exclude` permet d'ajouter des slugs site-spécifiques à filtrer.
    """
    from urllib.parse import unquote, urlparse

    path = urlparse(url).path.rstrip("/")
    segments = [s for s in path.split("/") if s]
    if len(segments) < 2:
        return None
    # Drop optional language prefix
    if segments[0].lower() in ("de", "fr", "en", "it", "rm"):
        segments = segments[1:]
    if len(segments) < 2:
        return None

    # At least one project-word in path (exact match OR composite substring like "bauten-und-projekte")
    def has_proj_word(seg):
        s = seg.lower()
        if s in PROJECT_WORDS_IN_PATH:
            return True
        # Check if seg contains a project word as substring (eg. "projektauswahl", "bauten-und-projekte", "projektliste")
        for w in (
            "projekt",
            "project",
            "projet",
            "progetto",
            "werk",
            "bau",
            "arbeit",
            "portfolio",
            "architektur",
            "architecture",
            "referenz",
            "wettbewerb",
            "studie",
            "building",
            "work",
            "maawork",
        ):
            if w in s and len(s) > len(w):  # composite
                return True
        return False

    if not any(has_proj_word(seg) for seg in segments):
        return None
    # Last segment = candidate slug
    last_full = unquote(segments[-1])
    last_lower = last_full.lower()
    if not last_lower:
        return None
    # Filter BINARY file extensions only
    if any(
        last_lower.endswith(ext)
        for ext in (
            ".pdf",
            ".jpg",
            ".jpeg",
            ".png",
            ".gif",
            ".svg",
            ".css",
            ".js",
            ".xml",
            ".mp4",
            ".zip",
            ".docx",
            ".webp",
        )
    ):
        return None
    # Strip HTML page extensions for blacklist check
    last_base = re.sub(r"\.(html?|php|aspx?|jsp)$", "", last_lower)
    if last_base in NON_PROJECT_SLUGS or last_base in PROJECT_WORDS_IN_PATH:
        return None
    if extra_exclude and last_base in extra_exclude:
        return None
    if last_base.isdigit():
        return None
    if not is_safe_slug(last_full):
        return None
    return last_full


WORDPRESS_PROFILE = {
    "body_scope": ".entry-content, article.post, article, main",
    "lazy_attrs": ("data-src", "data-lazy-src", "data-hw-src", "src"),
    # Standard WP /wp-content/uploads/ + Bedrock variant /app/uploads/
    # (Bedrock = Roots/Sage stack, met WP sous /wp/ et uploads sous /app/uploads/).
    # Inclure les 2 par défaut couvre 99% des sites WP modernes sans override.
    "image_allow_substrings": ("/wp-content/uploads/", "/app/uploads/"),
    "image_canonical_strip_patterns": [
        # Yoast / WordPress image thumb suffixes : -NNNNxMMMM-c-<crop>.jpg
        re.compile(r"-\d+x\d+(?:-c-[a-z]+)?(?=\.[a-z]+(?:[?#]|$))", re.I),
    ],
    "project_path_patterns": [
        # WordPress permalinks : /<post_type>/<slug>/ ou /<slug>/
        # Inclut les CPT (custom post types) les plus fréquents : portfolio_page
        # (Portfolio plugin), references / referenzen (theme custom suisses).
        re.compile(
            r"^/(?:[a-z]{2}/)?(?:project|projects|projet|projets|projekt|projekte|"
            r"progetto|progetti|realisation|realisations|portfolio|portfolio_page|"
            r"work|works|werk|werke|oeuvre|oeuvres|references|referenzen|bauten)"
            r"/[^/]+/?$",
            re.I,
        ),
    ],
}


DRUPAL_PROFILE = {
    "body_scope": "main, article, .field--name-body, .node__content",
    "lazy_attrs": ("data-src", "src"),
    "image_allow_substrings": ("/sites/default/files/", "/sites/all/files/", "/files/"),
    "image_canonical_strip_patterns": [
        # Drupal image styles : /styles/<style_name>/public/uploads/... → strip /styles/<X>/public
        re.compile(r"/styles/[^/]+/public/", re.I),
    ],
    "project_path_patterns": [
        # Drupal mod path could be anything — defaults match common patterns
        re.compile(
            r"^/(?:[a-z]{2}/)?(?:project|projects|projekt|projekte|referenzen|references|realisations|portfolio)/[^/]+/?$",
            re.I,
        ),
    ],
}


IMAGINATOR_PROFILE = {
    # CMS suisse propriétaire (ex: wdmra.ch). Pages projets accessibles via
    # query string ?template=progetti_img&id=N. Body sur #content.
    # Pas de h1 ni og:title utiles ; le title est embarqué dans le body après
    # les liens de menu + langues. Le sitemap pollue de dummy ids qui renvoient
    # tous la même page → dedup_by_title obligatoire.
    "body_scope": "#content",
    "lazy_attrs": ("src",),
    "image_allow_substrings": ("opere_images/", "proj_images/", "/images/"),
    "image_canonical_strip_patterns": [],
    "project_path_patterns": [],  # use url_is_imaginator_project() instead (query-based)
    "uses_query_id_routing": True,  # signals scaffold this CMS needs special handling
    "dedup_by_title": True,  # sitemap dummies → many records with identical title
    "title_extractor": "imaginator_extract_title",  # name of helpers.* function for custom title
}


DJANGO_FILER_PROFILE = {
    # Django CMS + Filer storage app (fréquent en Suisse).
    # Image CDN : /media/filer_public/<uuid>/<filename>.ext (canonique)
    #          ou /media/filer_public_thumbnails/filer_public/<uuid>/<filename>__<hash>.<size>.<ext>
    # Body sur `.content` (template Django par défaut).
    # URLs avec trailing `?` parfois (Django routing weirdness).
    "body_scope": ".content, main, article",
    "lazy_attrs": ("data-src", "src"),
    "image_allow_substrings": ("/media/filer_public/", "/media/filer_public_thumbnails/", "/media/uploads/"),
    "image_canonical_strip_patterns": [
        # Filer thumbnail path → canonical : strip "filer_public_thumbnails/" path segment
        re.compile(r"/filer_public_thumbnails/filer_public/", re.I),
        # Strip __<hash>.<size>x<size>_<quality>.<ext> suffix to get canonical filename
        re.compile(r"__[a-f0-9]{6,}\.[0-9]+x[0-9]+(?:_[a-z0-9]+)?(?=\.[a-z]+(?:[?#]|$))", re.I),
    ],
    "project_path_patterns": [],  # standard patterns work
    "skip_image_substrings": ("/static/img/", "/static/icons/", "logo", "favicon"),
}


TYPO3_PROFILE = {
    "body_scope": "main, article, .frame-default, #c1",
    "lazy_attrs": ("data-src", "src"),
    "image_allow_substrings": ("/fileadmin/", "/typo3conf/", "/uploads/", "/_processed_/"),
    "image_canonical_strip_patterns": [],
    "project_path_patterns": [
        re.compile(r"^/(?:[a-z]{2}/)?(?:project|projekt|projekte|referenzen|references)/[^/]+/?$", re.I),
    ],
}


SQUARESPACE_PROFILE = {
    # Squarespace : image CDN sur images.squarespace-cdn.com ou static1.squarespace.com.
    # URLs avec query string `?format=NNNNw` ou `?format=original` pour resize.
    # Body sur article / main / .sqs-block-content.
    "body_scope": "article, main, .sqs-block-content, .content",
    "lazy_attrs": ("data-src", "data-image", "src"),
    "image_allow_substrings": ("squarespace-cdn.com", "static1.squarespace.com", "static.squarespace.com"),
    "image_canonical_strip_patterns": [
        # Squarespace ?format=NNNNw query string
        re.compile(r"\?format=[^&#\"']+", re.I),
        # Trailing & cleanup
        re.compile(r"&(?:dpr|width|height)=[^&#\"']+", re.I),
    ],
    "project_path_patterns": [],  # use standard
}


CMS_PROFILES: dict[str, dict] = {
    "wordpress": WORDPRESS_PROFILE,
    "drupal": DRUPAL_PROFILE,
    "imaginator": IMAGINATOR_PROFILE,
    "typo3": TYPO3_PROFILE,
    "django_filer": DJANGO_FILER_PROFILE,
    "squarespace": SQUARESPACE_PROFILE,
}


# Imaginator nav menu items en italien / allemand (à strip du début du body
# pour extraire le titre projet). Liste extensible si nouveaux items observés.
_IMAGINATOR_NAV_TERMS = (
    # IT
    "opere",
    "progetti",
    "concorsi",
    "affittasi",
    "monografie",
    "persone",
    "contatto",
    # DE
    "werke",
    "projekte",
    "wettbewerbe",
    "zu vermieten",
    "monografien",
    "personen",
    "kontakt",
    # Lang switchers
    "italiano",
    "deutsch",
    "english",
    "français",
    "русский",
    "中文",
    "日本語",
)


def imaginator_extract_title(content_text: str) -> str | None:
    """Extract project title from Imaginator #content text.

    Pattern : `<nav items IT> <nav items DE> <lang switchers> <TITLE> opera id=... foto id=...`
    On strip les items de nav puis on tronque au 1er marker `opera id=` / `foto id=`.
    """
    if not content_text:
        return None
    txt = content_text
    # Strip leading nav menu items (any sequence of known terms separated by whitespace)
    nav_pattern = r"^\s*(?:(?:" + "|".join(re.escape(t) for t in _IMAGINATOR_NAV_TERMS) + r")\s+)+"
    txt = re.sub(nav_pattern, "", txt, count=1, flags=re.I)
    # Truncate at first "opera id=" or "foto id="
    m = re.search(r"\b(?:opera|foto)\s+id\s*=", txt)
    if m:
        txt = txt[: m.start()]
    txt = txt.strip()
    if len(txt) > 300:
        txt = txt[:300].rsplit(" ", 1)[0] + "…"
    return txt or None
