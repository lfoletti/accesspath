"""Geste humain annoncé par l'audit.

`predict_human_gate` lit un rapport d'inspect et dit, avant toute collecte,
si une main humaine sera nécessaire : défi anti-bot, connexion, ou
consentement à accepter dans le navigateur. Le rapport l'annonce en tête,
avec la commande qui ouvre la fenêtre (`warmup`).

La prédiction ne vaut que pour la machine qui a sondé : un défi dépend
surtout de la réputation de l'IP. `seen_from` le rappelle.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .sap_inspect import InspectReport

# Ordre de préférence quand plusieurs signatures coexistent : Cloudflare sert
# souvent de simple CDN devant un anti-bot dédié, il vient donc en dernier.
VENDOR_PRIORITY = ("datadome", "perimeterx", "kasada", "akamai", "imperva", "fortiadc", "cloudflare")
BLOCKING_STATUSES = (403, 429, 503)
EST_SECONDS = {"challenge": 20, "login": 60, "consent": 5}
# Accueil réduit à un formulaire : moins de liens internes que ça.
LOGIN_PAGE_MAX_LINKS = 10


@dataclass
class HumanGate:
    kind: str  # challenge | login | consent
    vendor: str
    open_url: str
    est_seconds: int
    evidence: list[str] = field(default_factory=list)
    seen_from: str = ""


def _gate(kind: str, vendor: str, report: InspectReport, evidence: list[str]) -> HumanGate:
    return HumanGate(
        kind=kind,
        vendor=vendor,
        open_url=report.target_url,
        est_seconds=EST_SECONDS[kind],
        evidence=evidence,
        seen_from=socket.gethostname(),
    )


def predict_human_gate(report: InspectReport) -> HumanGate | None:
    """Défi, puis connexion, puis consentement ; None si la voie est libre.

    Rien non plus quand une main n'y peut rien : page de blocage explicite (refus net),
    ou accueil qui redirige vers un autre site (le geste porterait sur ce site-là)."""
    reach = report.reachability
    if reach.hard_block or reach.redirected_to:
        return None
    detected = [v for v in VENDOR_PRIORITY if (d := report.anti_bot_stack.get(v)) and d.detected]

    if reach.status == "challenge" or (detected and reach.page_status in BLOCKING_STATUSES):
        vendor = detected[0] if detected else "inconnu"
        why = f"page de défi ({reach.status})" if reach.status == "challenge" else f"HTTP {reach.page_status}"
        return _gate("challenge", vendor, report, [why, f"anti-bot : {', '.join(detected) or 'non identifié'}"])

    struct = report.structural_features
    if reach.page_status == 401:
        return _gate("login", "", report, ["HTTP 401"])
    if struct and struct.has_login_form and struct.n_internal_links < LOGIN_PAGE_MAX_LINKS:
        return _gate(
            "login", "", report, [f"accueil réduit à un formulaire ({struct.n_internal_links} liens internes)"]
        )

    rec = report.tier_recommendation
    if struct and struct.has_consent_wall and rec and rec.primary == 4:
        return _gate("consent", "", report, ["bannière de consentement, collecte en navigateur"])
    return None
