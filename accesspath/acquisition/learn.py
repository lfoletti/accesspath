"""Motifs appris au fil des campagnes.

Après un lot, les signaux que plusieurs sites partagent sans qu'aucune plateforme connue
les explique deviennent des candidats : générateur déclaré (`<meta name="generator">`),
hôte d'où l'accueil charge ses ressources, gabarit d'URL de projet trouvé par la seule
heuristique de profondeur. Ils entrent dans le dataset local (hors du dépôt), servent
aussitôt à la détection, et peuvent être proposés aux créateurs de l'outil par une
pull request qui ajoute un fichier à `contrib/patterns/` : en anglais, sans la campagne
ni les sites, sauf demande.
"""

from __future__ import annotations

import base64
import hashlib
import os
import re
import subprocess
from collections import defaultdict
from datetime import date
from pathlib import Path
from urllib.parse import urlsplit

import yaml

LOCAL_FILE = Path(os.environ.get("ACCESSPATH_PATTERNS_LOCAL", "~/.accesspath/patterns.local.yaml")).expanduser()
UPSTREAM_REPO = "lfoletti/accesspath"
MIN_SITES = 3
MIN_SITES_PROJECTS = 2
# Ressources communes à tous les sites : elles ne signent aucune plateforme.
COMMON_HOSTS = {
    "fonts.googleapis.com", "fonts.gstatic.com", "ajax.googleapis.com", "maps.googleapis.com",
    "cdnjs.cloudflare.com", "cdn.jsdelivr.net", "unpkg.com", "code.jquery.com", "use.typekit.net",
    "use.fontawesome.com", "kit.fontawesome.com", "www.google.com", "www.gstatic.com",
    "www.youtube.com", "player.vimeo.com", "www.recaptcha.net",
}  # fmt: skip
# Bibliothèques et polices servies à tous : elles ne signent aucune plateforme.
COMMON_SUFFIXES = ("bootstrapcdn.com", "maxcdn.com", "fonts.net", "typekit.net", "fontawesome.com", "jsdelivr.net")
# Générateurs qui ne sont pas une plateforme : éditeurs de pages et numéros seuls.
NON_PLATFORM_GENERATORS = {"bbedit", "adobe", "dreamweaver", "microsoft", "frontpage", "coffeecup", "notepad++"}
# Extensions qui se déclarent générateur à la place de leur CMS.
GENERATOR_ALIASES = {"seomatic": "craft"}
# Rubriques de classement : leurs pages listent des contenus, ce n'en sont pas.
TAXONOMY_SEGMENTS = {"category", "categories", "tag", "tags", "kategorie", "kategorien", "schlagwort", "author", "page"}
LANGUAGE_SEGMENTS = {"de", "fr", "it", "en", "es", "nl", "rm", "pt"}
# Suivi d'erreurs et de performance : présent sur toutes sortes de sites, ne signe rien.
MONITORING_SUFFIXES = (
    "sentry-cdn.com", "sentry.io", "bugsnag.com", "newrelic.com", "nr-data.net",
    "datadoghq-browser-agent.com", "datadoghq.com", "rollbar.com", "logrocket.com",
)  # fmt: skip
# Deux signaux décrivent la même plateforme si l'un vit presque entièrement sur les sites de l'autre.
SAME_PLATFORM_OVERLAP = 0.8
_GENERATOR = re.compile(r"""<meta\b[^>]*\bname\s*=\s*["']generator["'][^>]*>""", re.I)
_CONTENT = re.compile(r"""\bcontent\s*=\s*["']([^"']*)["']""", re.I)


# ── Signaux ──────────────────────────────────────────────────────────────
def fingerprint(html: str, url: str) -> dict:
    """Générateur déclaré et hôtes tiers d'où l'accueil charge ses ressources (hors
    traceurs connus et ressources communes)."""
    from .. import trackers

    tag = _GENERATOR.search(html or "")
    content = _CONTENT.search(tag.group(0)) if tag else None
    own = trackers.site_domain(url)
    hosts = set()
    for u in trackers._loaded_urls(html or ""):
        host = (urlsplit(u if "//" in u else "//" + u).hostname or "").lower()
        if (
            host
            and trackers.site_domain(host) != own
            and host not in COMMON_HOSTS
            and not host.endswith(COMMON_SUFFIXES)
            and not host.endswith(MONITORING_SUFFIXES)
            and not trackers._match(host)
        ):
            hosts.add(host)
    return {"generator": content.group(1).strip() if content else None, "asset_hosts": sorted(hosts)}


def _generator_family(value: str) -> str:
    """Premier mot du générateur, en minuscules ; vide pour un éditeur ou un numéro seul."""
    fam = value.split()[0].lower() if value and value.split() else ""
    if not re.search(r"[a-z]", fam) or fam in NON_PLATFORM_GENERATORS:
        return ""
    return GENERATOR_ALIASES.get(fam, fam)


def _known_markers() -> list[str]:
    from . import platforms

    return [m.lower() for p in platforms.load()["platforms"].values() for m in p["detect"].get("html") or []]


def _domain(row: dict) -> str:
    return (urlsplit(row.get("url") or "").hostname or row.get("name") or "").removeprefix("www.")


def platform_candidates(rows: list[dict]) -> list[dict]:
    """Plateformes candidates : signaux partagés par au moins MIN_SITES sites sans
    plateforme connue, regroupés quand ils vivent sur les mêmes sites (le générateur
    « Wix.com » et les hôtes de Wix forment un seul motif)."""
    known = _known_markers()
    groups: dict[tuple[str, str], list[str]] = defaultdict(list)
    for r in rows:
        if r.get("status") != "ok" or r.get("known_platform"):
            continue
        fam = _generator_family(r.get("generator") or "")
        if fam:
            groups[("generator", fam)].append(_domain(r))
        for h in r.get("asset_hosts") or []:
            groups[("asset_host", h)].append(_domain(r))
    signals = [
        (kind, marker, set(sites))
        for (kind, marker), sites in groups.items()
        if len(set(sites)) >= MIN_SITES and not any(marker in k or k in marker for k in known)
    ]
    signals.sort(key=lambda s: (-len(s[2]), s[0] != "generator", s[1]))
    clusters: list[dict] = []
    for kind, marker, sites in signals:
        home = next(
            (
                c
                for c in clusters
                if len(sites & c["sites"]) / min(len(sites), len(c["sites"])) >= SAME_PLATFORM_OVERLAP
            ),
            None,
        )
        if home is None:
            home = {"markers": [], "sites": set()}
            clusters.append(home)
        home["markers"].append({"kind": kind, "marker": marker})
        home["sites"] |= sites
    out = []
    for c in clusters:
        markers = sorted(c["markers"], key=lambda m: (m["kind"] != "generator", m["marker"]))
        out.append(
            {
                "kind": "platform",
                "name": markers[0]["marker"],
                "markers": markers,
                "sites": len(c["sites"]),
                "examples": sorted(c["sites"]),
            }
        )
    return sorted(out, key=lambda c: c["name"])


def _template(path: str) -> str | None:
    parts = [p for p in path.split("/") if p]
    if len(parts) < 2:
        return None
    return "^/" + "/".join(re.escape(p) for p in parts[:-1]) + "/[^/]+/?$"


def _new_content_path(path: str, doc: dict) -> bool:
    """Un chemin vaut gabarit neuf si aucun motif connu ne le reconnaît déjà, et si son
    préfixe n'est ni une rubrique de classement ni une langue seule."""
    from . import patterns

    prefix = [p.lower() for p in path.split("/") if p][:-1]
    if any(p in TAXONOMY_SEGMENTS or p.endswith(("_category", "_tag")) for p in prefix):
        return False
    if len(prefix) == 1 and prefix[0] in LANGUAGE_SEGMENTS:
        return False
    return patterns.match_project(doc, "https://x.invalid" + path) is None


def content_candidates(rows: list[dict]) -> list[dict]:
    """Gabarits d'URL de contenu que seule l'heuristique de profondeur a reconnus."""
    from . import patterns

    doc = patterns.load()
    groups: dict[str, set[str]] = defaultdict(set)
    for r in rows:
        if r.get("status") != "ok" or r.get("matched_by") != "profondeur":
            continue
        for path in r.get("content_samples") or []:
            t = _template(path)
            if t and _new_content_path(path, doc):
                groups[t].add(_domain(r))
    return [
        {"kind": "content_url", "regex": t, "sites": len(s), "examples": sorted(s)}
        for t, s in sorted(groups.items())
        if len(s) >= MIN_SITES_PROJECTS
    ]


# ── Dataset local ────────────────────────────────────────────────────────
def _key(c: dict) -> str:
    return f"{c['kind']}:{c.get('name') or c.get('marker') or c.get('regex')}"


def describe(c: dict) -> str:
    """`generator `wix.com`; asset_host `static.wixstatic.com`` : les marqueurs d'un motif."""
    if c.get("markers"):
        return "; ".join(f"{m['kind']} `{m['marker']}`" for m in c["markers"])
    return f"{c['kind']} `{c.get('marker') or c.get('regex')}`"


def load_local(path: Path | None = None) -> dict:
    path = path or LOCAL_FILE
    if path.exists():
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {"version": 1, "candidates": []}
    return {"version": 1, "candidates": []}


def _save(doc: dict) -> None:
    LOCAL_FILE.parent.mkdir(parents=True, exist_ok=True)
    LOCAL_FILE.write_text(yaml.safe_dump(doc, allow_unicode=True, sort_keys=False), encoding="utf-8")


def learn_from_batch(rows: list[dict], campaign: str) -> list[dict]:
    """Ajoute au dataset local les candidats nouveaux ; rend ceux qui ont été ajoutés."""
    doc = load_local()
    seen = {_key(c) for c in doc["candidates"]}
    added = []
    for c in platform_candidates(rows) + content_candidates(rows):
        if _key(c) in seen:
            continue
        added.append({**c, "campaign": campaign, "seen": date.today().isoformat(), "shared": None})
        seen.add(_key(c))
    if added:
        doc["candidates"] += added
        _save(doc)
        from . import platforms

        platforms._DOC = None
    return added


def relearn(rows: list[dict], campaign: str) -> list[dict]:
    """Réapprend une campagne : ses motifs non partagés sont remplacés par ceux du code actuel."""
    doc = load_local()
    doc["candidates"] = [c for c in doc["candidates"] if c.get("campaign") != campaign or c.get("shared")]
    _save(doc)
    return learn_from_batch(rows, campaign)


def announce(added: list[dict]) -> str:
    if not added:
        return ""
    n = len(added)
    head = (
        f"{n} nouveau motif a été identifié et ajouté"
        if n == 1
        else f"{n} nouveaux motifs ont été identifiés et ajoutés"
    )
    return f"{head} au dataset local ({LOCAL_FILE})\n  Share with the tool's creators: python -m accesspath sap patterns share"


def local_platforms() -> dict:
    """Candidats de plateforme du dataset local, au format de `platforms.yaml`."""
    out = {}
    for c in load_local()["candidates"]:
        if c["kind"] != "platform":
            continue
        html = [m["marker"] if m["kind"] == "asset_host" else f'content="{m["marker"]}' for m in c["markers"]]
        out[f"local:{c['name']}"] = {
            "domain": "à qualifier",
            "description": f"Candidat appris : {describe(c)}, partagé par {c['sites']} sites.",
            "detect": {"html": html},
            "recipe": {"discovery": "à compléter"},
            "instances": {"count": c["sites"], "list": []},
            "source": f"dataset local (campagne {c['campaign']})",
            "candidate": True,
        }
    return out


def with_local(doc: dict) -> dict:
    """Motifs enrichis des gabarits de projet appris (étiquette « local »)."""
    regexes = [{"regex": c["regex"], "flags": "i"} for c in load_local()["candidates"] if c["kind"] == "content_url"]
    return {**doc, "local_project_patterns": regexes}


# ── Partage ──────────────────────────────────────────────────────────────
def _pending() -> list[dict]:
    return [c for c in load_local()["candidates"] if not c.get("shared")]


def share_report(include_sites: bool = False) -> str:
    todo = _pending()
    n = len(todo)
    lines = [
        f"# accesspath pattern contribution: {n} new pattern{'s' if n != 1 else ''}",
        "",
        "Patterns learned locally after audit campaigns, shared by sites that no known platform explained.",
        "",
        "| Kind | Markers | Seen on |",
        "|---|---|---|",
    ]
    for c in todo:
        lines.append(f"| {c['kind']} | {describe(c)} | {c['sites']} sites |")
        if include_sites:
            lines.append(f"| | examples | {', '.join(c['examples'])} |")
    return "\n".join(lines) + "\n"


def _entry(c: dict, include_sites: bool) -> dict:
    keep = ("kind", "name", "markers", "regex", "sites") + (("examples",) if include_sites else ())
    return {k: c[k] for k in keep if k in c}


def contribution_file(include_sites: bool = False) -> tuple[str, str]:
    """Chemin et contenu du fichier proposé au dépôt de l'outil (`contrib/patterns/`)."""
    doc = {
        "version": 1,
        "contributed": date.today().isoformat(),
        "patterns": [_entry(c, include_sites) for c in _pending()],
    }
    text = yaml.safe_dump(doc, allow_unicode=True, sort_keys=False)
    digest = hashlib.sha256(text.encode()).hexdigest()[:8]
    return f"contrib/patterns/{doc['contributed']}-{digest}.yaml", text


def validate_contribution(doc: dict) -> list[str]:
    """Erreurs de format d'une contribution ; liste vide si elle est valide."""
    errors = []
    if not isinstance(doc, dict) or doc.get("version") != 1 or not isinstance(doc.get("patterns"), list):
        return ["version 1 et liste « patterns » attendues"]
    for i, p in enumerate(doc["patterns"]):
        if not isinstance(p.get("sites"), int) or p["sites"] < 1:
            errors.append(f"motif {i} : « sites » entier positif attendu")
        if p.get("kind") == "platform":
            markers = p.get("markers")
            if (
                not p.get("name")
                or not markers
                or any(m.get("kind") not in ("generator", "asset_host") or not m.get("marker") for m in markers)
            ):
                errors.append(f"motif {i} : plateforme sans « name » ou « markers » valides")
        elif p.get("kind") == "content_url":
            try:
                re.compile(p.get("regex") or "")
            except re.error:
                errors.append(f"motif {i} : « regex » invalide")
            if not p.get("regex"):
                errors.append(f"motif {i} : « regex » manquante")
        else:
            errors.append(f"motif {i} : genre inconnu « {p.get('kind')} »")
    return errors


def _gh(args: list[str]) -> str:
    r = subprocess.run(["gh", *args], capture_output=True, text=True, check=True)
    return r.stdout.strip()


def _open_pr(path: str, text: str, title: str, body: str) -> str:
    """Pull request qui ajoute `path` au dépôt de l'outil : depuis un fork, en brouillon,
    pour un contributeur ; depuis une branche du dépôt pour son mainteneur."""
    login = _gh(["api", "user", "-q", ".login"])
    owner, repo = UPSTREAM_REPO.split("/")
    fork = login != owner
    if fork:
        _gh(["repo", "fork", UPSTREAM_REPO, "--clone=false", "--default-branch-only"])
    target = f"{login}/{repo}" if fork else UPSTREAM_REPO
    branch = "patterns/" + Path(path).stem
    sha = _gh(["api", f"repos/{UPSTREAM_REPO}/git/ref/heads/main", "-q", ".object.sha"])
    _gh(["api", "-X", "POST", f"repos/{target}/git/refs", "-f", f"ref=refs/heads/{branch}", "-f", f"sha={sha}"])
    content = base64.b64encode(text.encode()).decode()
    _gh(["api", "-X", "PUT", f"repos/{target}/contents/{path}", "-f", f"message={title}", "-f", f"content={content}",
         "-f", f"branch={branch}"])  # fmt: skip
    pr = ["pr", "create", "--repo", UPSTREAM_REPO, "--base", "main", "--head", f"{login}:{branch}" if fork else branch,
          "--title", title, "--body", body]  # fmt: skip
    return _gh(pr + (["--draft"] if fork else []))


def share(*, send: bool = False, include_sites: bool = False) -> str:
    """Sans `send` : le rapport, à relire. Avec : une pull request qui ajoute les motifs au
    dépôt de l'outil (`contrib/patterns/`), et les motifs envoyés sont marqués."""
    body = share_report(include_sites)
    if not send:
        return body
    n = len(_pending())
    if not n:
        return "nothing to share"
    path, text = contribution_file(include_sites)
    url = _open_pr(path, text, f"Pattern contribution: {n} new pattern{'s' if n != 1 else ''}", body)
    doc = load_local()
    for c in doc["candidates"]:
        c["shared"] = c.get("shared") or date.today().isoformat()
    _save(doc)
    return url
