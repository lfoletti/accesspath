"""Savoir des collecteurs de sites, en un fichier lisible par la machine.

`websites.yaml` regroupe ce que des collecteurs ont appris sur la forme des sites :
profils de CMS, heuristiques génériques, familles de motifs (motifs d'URL de contenu,
attributs de chargement différé, chemins d'images, suffixes de miniature, zones de
contenu) et gabarits classés par la borne basse de Wilson de leur taux de réussite.

Le fichier livré avec le moteur est une vue publique (`public_view`) : chaque famille
dit combien de sites la portent, jamais lesquels, et aucune recette par site n'y figure.
Un projet de collecte peut pointer `ACCESSPATH_PATTERNS` sur son fichier complet.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from urllib.parse import urlsplit

import yaml

FORMAT_VERSION = 1
MIN_SHARED = 2  # sites au moins pour qu'un motif soit publié
PATTERNS_FILE = Path(os.environ.get("ACCESSPATH_PATTERNS") or Path(__file__).parent / "websites.yaml")


def load(path: Path | None = None) -> dict:
    return yaml.safe_load(Path(path or PATTERNS_FILE).read_text(encoding="utf-8"))


def public_view(doc: dict) -> dict:
    """Le savoir sans les sites : chaque liste de sites devient un nombre, les recettes et
    les pages de liste (des adresses) sont retirées, les gabarits perdent leurs exemples,
    les motifs et variantes d'un seul site disparaissent."""

    def strip(x):
        if isinstance(x, dict):
            out = {}
            for k, v in x.items():
                if k == "sites" and isinstance(v, list):
                    out["n_sites"] = len(v)
                elif k == "examples":
                    continue
                else:
                    out[k] = strip(v)
            return out
        if isinstance(x, list):
            return [strip(v) for v in x]
        return x

    pub = strip({k: v for k, v in doc.items() if k not in ("unreadable", "source")})
    # Un motif porté par un seul site le désigne : seuls restent les motifs partagés.
    pub["families"] = {
        k: [f for f in v if f.get("n_sites", MIN_SHARED) >= MIN_SHARED]
        for k, v in pub.get("families", {}).items()
        if k != "index_pages"
    }
    for t in pub.get("templates", []):
        t["variants"] = [v for v in t.get("variants", []) if v.get("sites", MIN_SHARED) >= MIN_SHARED]
    pub["sites"] = {}
    return pub


# ── Usage ────────────────────────────────────────────────────────────────
def _compile(p: dict) -> re.Pattern:
    return re.compile(p["regex"], re.I if "i" in (p.get("flags") or "") else 0)


def compiled_project_patterns(doc: dict) -> list[tuple[str, re.Pattern]]:
    """Motifs d'URL de contenu, du général au particulier : motifs génériques, profils de
    CMS, familles. Une famille n'est créditée que si les motifs plus généraux ne suffisent
    pas : l'étiquette mesure la valeur de ce savoir."""
    out: list[tuple[str, re.Pattern]] = [("générique", _compile(p)) for p in doc["generic"]["project_path_patterns"]]
    for name, prof in doc["cms_profiles"].items():
        out += [(f"cms:{name}", _compile(p)) for p in prof["project_path_patterns"]]
    for i, fam in enumerate(doc["families"]["project_url_patterns"], 1):
        label = f"site:{fam['sites'][0]}" if fam.get("sites") else f"famille:{i}"
        out.append((label, _compile(fam)))
    out += [("local", _compile(p)) for p in doc.get("local_project_patterns", [])]
    return out


def match_project(doc: dict, url: str) -> str | None:
    """Étiquette du premier motif qui reconnaît `url` comme page de contenu, ou None."""
    path = urlsplit(url).path
    for label, pat in compiled_project_patterns(doc):
        if pat.match(path):
            return label
    return None


def _bare(host: str) -> str:
    host = (host or "").lower()
    return host[4:] if host.startswith("www.") else host


def site_for_url(doc: dict, url: str) -> str | None:
    host = _bare(urlsplit(url).hostname or "")
    for slug, r in (doc.get("sites") or {}).items():
        if _bare(urlsplit(r["base_url"]).hostname or "") == host:
            return slug
    return None
