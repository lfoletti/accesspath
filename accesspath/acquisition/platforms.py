"""Base de plateformes commune aux études (`platforms.yaml`).

Une plateforme logicielle reconnue (portail de registre, CMS de communes, CMS de site)
donne sa recette d'accès, ses instances connues et la source du savoir : un site
inconnu qui est une instance d'une plateforme connue n'a pas à être redécouvert.
"""

from __future__ import annotations

from fnmatch import fnmatch
from pathlib import Path
from urllib.parse import urlsplit

import yaml

PLATFORMS_FILE = Path(__file__).parent / "platforms.yaml"
_DOC: dict | None = None


def load(path: Path = PLATFORMS_FILE) -> dict:
    global _DOC
    if path != PLATFORMS_FILE:
        return yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if _DOC is None:
        from . import learn

        _DOC = yaml.safe_load(PLATFORMS_FILE.read_text(encoding="utf-8"))
        known = {m.lower() for p in _DOC["platforms"].values() for m in p["detect"].get("html") or []}
        local = {  # un motif appris puis promu dans platforms.yaml n'est plus un candidat
            k: p for k, p in learn.local_platforms().items() if not any(m.lower() in known for m in p["detect"]["html"])
        }
        _DOC["platforms"] = {**_DOC["platforms"], **local}
    return _DOC


def _cookies(headers: dict) -> set[str]:
    raw = [v for k, v in headers.items() if k.lower() == "set-cookie"]
    return {c.split("=", 1)[0].strip() for v in raw for c in v.split(",") if "=" in c}


def detect(url: str, *, html: str = "", headers: dict | None = None, doc: dict | None = None) -> list[dict]:
    """Plateformes connues reconnues pour `url`, avec leurs preuves."""
    doc = doc or load()
    parts = urlsplit(url)
    host, path = (parts.hostname or "").lower(), parts.path or "/"
    headers = headers or {}
    names = {k.lower() for k in headers}
    cookies = _cookies(headers)
    page = (html or "").lower()
    found = []
    for name, p in doc["platforms"].items():
        d = p["detect"]
        evidence = [f"hôte {host} ({pat})" for pat in d.get("hosts") or [] if fnmatch(host, pat)]
        evidence += [
            f"instance {i['label']} : {i['host']}{i['prefix']}"
            for i in d.get("instances") or []
            if host == i["host"] and path.startswith(i["prefix"])
        ]
        evidence += [f"marqueur « {m} »" for m in d.get("html") or [] if m.lower() in page]
        evidence += [f"en-tête {h}" for h in d.get("headers") or [] if h.lower() in names]
        evidence += [f"cookie {c}" for c in d.get("cookies") or [] if c in cookies]
        if evidence:
            found.append(
                {
                    "platform": name,
                    "domain": p["domain"],
                    "description": p["description"],
                    "evidence": evidence,
                    "recipe": p["recipe"],
                    "instances": (p.get("instances") or {}).get("count"),
                    "source": p["source"],
                }
            )
    return sorted(found, key=lambda f: -len(f["evidence"]))


def report_lines(found: list[dict], n) -> list[str]:
    """Section « Plateforme connue » d'un rapport (`n` neutralise les valeurs du site)."""
    lines = ["", "## Plateforme connue", ""]
    for f in found:
        r = f["recipe"]
        inst = f" ; {f['instances']} instance(s) connue(s)" if f.get("instances") else ""
        lines.append(f"- **{f['platform']}** ({f['domain']}{inst}) : {f['description']}")
        lines.append(f"  - Reconnue par : {n('; '.join(f['evidence']), 300)}")
        for key, label in (
            ("tier", "Tier"),
            ("barrier", "Barrière"),
            ("discovery", "Découverte"),
            ("auth", "Accès"),
            ("format", "Format"),
        ):
            if r.get(key) is not None:
                lines.append(f"  - {label} : {r[key]}")
        for e in r.get("endpoints") or []:
            lines.append(f"  - `{e}`")
        lines.append(f"  - Source du savoir : `{f['source']}`")
    return lines
