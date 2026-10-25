"""Gestion des profils Chrome persistants par site.

Un profil est "warm" quand un humain a visité le site, accepté les cookies
et potentiellement résolu un captcha. On le marque par un fichier .warmed_at
dans le user-data-dir : un JSON {at, host}. La machine compte : les défenseurs
lient le passage (cf_clearance, datadome) à l'empreinte et à l'IP, un profil
préparé sur le Mac puis copié sur le VPS échoue en silence. L'ancien format
(date ISO seule) reste lisible.
"""

from __future__ import annotations

import json
import socket
from datetime import UTC, datetime
from pathlib import Path

from ..config import PROFILES_DIR


def profile_dir(site_name: str) -> Path:
    d = PROFILES_DIR / site_name
    d.mkdir(parents=True, exist_ok=True)
    return d


def _marker(site_name: str) -> Path:
    return profile_dir(site_name) / ".warmed_at"


def is_warm(site_name: str) -> bool:
    return _marker(site_name).exists()


def _hostname() -> str:
    return socket.gethostname()


def mark_warm(site_name: str) -> None:
    rec = {"at": datetime.now(UTC).isoformat(), "host": _hostname()}
    _marker(site_name).write_text(json.dumps(rec))


def _read_marker(site_name: str) -> dict:
    m = _marker(site_name)
    if not m.exists():
        return {}
    text = m.read_text().strip()
    try:
        rec = json.loads(text)
    except ValueError:
        return {"at": text}  # ancien format : la date seule
    return rec if isinstance(rec, dict) else {"at": text}


def warmed_at(site_name: str) -> datetime | None:
    try:
        return datetime.fromisoformat(_read_marker(site_name).get("at", ""))
    except ValueError:
        return None


def warmed_elsewhere(site_name: str) -> str | None:
    """Machine qui a préparé le profil, si ce n'est pas celle-ci (None sinon ou si inconnue)."""
    host = _read_marker(site_name).get("host")
    return host if host and host != _hostname() else None


def invalidate(site_name: str) -> None:
    """Appelé quand un sanity-check détecte que le profil est périmé."""
    m = _marker(site_name)
    if m.exists():
        m.unlink()
