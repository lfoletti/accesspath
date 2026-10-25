"""Chargement des credentials depuis data/credentials.json (gitignored).

Format attendu :
{
  "site_exemple": {"email": "...", "password": "..."},
  "other_site": {...}
}

TODO: migrer vers macOS Keychain pour la prod.
"""

from __future__ import annotations

import json

from .config import DATA_DIR

CREDENTIALS_FILE = DATA_DIR / "credentials.json"


def load(site_name: str) -> dict[str, str] | None:
    """Retourne {email, password, ...} pour `site_name`, ou None si absent."""
    if not CREDENTIALS_FILE.exists():
        return None
    try:
        data = json.loads(CREDENTIALS_FILE.read_text())
    except json.JSONDecodeError:
        return None
    creds = data.get(site_name)
    if not isinstance(creds, dict):
        return None
    return creds
