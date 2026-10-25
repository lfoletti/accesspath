"""File de gestes humains (data/gestures.jsonl).

Un geste nécessaire (défi anti-bot, connexion, consentement, profil à
préchauffer) devient un ticket au lieu d'un échec : `run` sans humain en
dépose un quand le profil est froid, `sap inspect --save` quand l'audit
l'annonce. `python -m accesspath gestes` les liste, `gestes --faire` les ouvre
un par un dans Chrome. Le fichier ne fait que s'allonger : un ticket est
ouvert si sa dernière ligne n'est pas une résolution.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime

from ._safe import normalize_target_url, validate_site_name
from .config import DATA_DIR

GESTURES_FILE = DATA_DIR / "gestures.jsonl"


@dataclass
class Gesture:
    site: str
    kind: str  # challenge | login | consent | warmup
    open_url: str
    reason: str
    at: str


def _append(record: dict) -> None:
    GESTURES_FILE.parent.mkdir(parents=True, exist_ok=True)
    with GESTURES_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def pending() -> list[Gesture]:
    """Tickets ouverts, dans l'ordre de leur dépôt."""
    if not GESTURES_FILE.exists():
        return []
    open_: dict[str, Gesture] = {}
    for line in GESTURES_FILE.read_text(encoding="utf-8").splitlines():
        try:
            rec = json.loads(line)
            site = rec["site"]
        except (ValueError, KeyError, TypeError):
            continue
        if rec.get("done"):
            open_.pop(site, None)
        elif site not in open_:
            open_[site] = Gesture(site, rec["kind"], rec["open_url"], rec.get("reason", ""), rec.get("at", ""))
    return list(open_.values())


def add(site: str, kind: str, open_url: str, reason: str) -> bool:
    """Dépose un ticket ; False si le site en a déjà un ouvert."""
    validate_site_name(site)
    open_url = normalize_target_url(open_url)
    if any(g.site == site for g in pending()):
        return False
    _append({"site": site, "kind": kind, "open_url": open_url, "reason": reason[:300], "at": _now()})
    return True


def resolve(site: str, why: str = "") -> None:
    """Ferme le ticket ouvert du site, s'il y en a un ; `why` dit comment (fait, inutile, revu)."""
    if any(g.site == site for g in pending()):
        _append({"site": site, "done": True, "at": _now(), **({"why": why[:300]} if why else {})})
