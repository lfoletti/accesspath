"""Rapport propriétaire : ce que le site expose aux machines, relu du côté de son propriétaire.

Le moteur lit les deux audits (sonde et inspect, sous forme de dictionnaires) et rend des
constats. Chaque constat dit ce qu'une machine voit, avec la preuve, son état (ouvert et
déclaré, ouvert sans être déclaré, protégé, incohérent, hors du périmètre de protection) et
que faire. Les recommandations vont dans les deux sens : fermer ce qui n'est pas voulu,
déclarer ce qui l'est. Le rapport ne donne aucune technique de contournement.
"""

from __future__ import annotations

from dataclasses import dataclass, field

THEMES = ("declaration", "coherence", "doors", "protection", "copies", "visitors")
THEME_TITLES = {
    "declaration": "Ce que le site déclare aux machines",
    "coherence": "Cohérence entre déclaration et exposition",
    "doors": "Portes ouvertes",
    "protection": "Protection",
    "copies": "Copies hors du périmètre de protection",
    "visitors": "Coût pour les visiteurs humains",
}

OPEN_DECLARED = "ouvert, déclaré"
OPEN_UNDECLARED = "ouvert, non déclaré"
NOT_DECLARED = "non déclaré"
INCONSISTENT = "incohérent"
PROTECTED = "protégé"
PARTIAL = "protection partielle"
UNPROTECTED = "non protégé"
OUTSIDE = "hors du périmètre"
STATES = (OPEN_DECLARED, OPEN_UNDECLARED, NOT_DECLARED, INCONSISTENT, PROTECTED, PARTIAL, UNPROTECTED, OUTSIDE)

TDM_KEY = "tdm-reservation"


@dataclass
class Finding:
    rule: str
    theme: str
    state: str
    weight: int  # 3 : à traiter d'abord ; 1 : pour information
    observation: str
    evidence: list[str] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)


# ── Lecture des audits ───────────────────────────────────────────────────
def _t1(p: dict) -> dict:
    return p.get("tier1_discovery") or {}


def _usage(p: dict) -> dict:
    return p.get("usage_preferences") or {}


def _blocked_ai(p: dict) -> list[str]:
    return [bot for bot, rule in (_usage(p).get("ai_crawlers") or {}).items() if rule == "bloqué"]


def _tdm_reserved(p: dict) -> bool:
    tdm = _usage(p).get("tdmrep") or {}
    if any(TDM_KEY in (tdm.get(k) or {}) for k in ("header", "html")):
        return True
    return bool(tdm.get("well_known"))


def _content_usage(p: dict) -> bool:
    u = _usage(p)
    return bool(u.get("content_usage_header") or u.get("robots_content_usage"))


def _endpoint(d: dict) -> str:
    return d.get("endpoint") or d.get("url") or "?"


def _items(d: dict) -> str:
    n = d.get("items")
    return f"{_endpoint(d)} ({n} éléments)" if n is not None else _endpoint(d)


def _open_doors(p: dict) -> list[dict]:
    t1 = _t1(p)
    doors = list(t1.get("api_endpoints") or []) + list(t1.get("rss_feeds") or [])
    if t1.get("sitemap"):
        doors.append(t1["sitemap"])
    return doors


def _antibots(i: dict) -> list[str]:
    return [name for name, d in (i.get("anti_bot_stack") or {}).items() if (d or {}).get("detected")]


def _python_refused(p: dict) -> bool:
    """La sonde a vu l'accueil refusé à un client Python (et a donc testé l'empreinte TLS)."""
    return bool((p.get("tls_fingerprint") or {}).get("tested"))


REFUSED_VERDICTS = ("bloqué", "défi", "refusé")
REFUSED_STATUSES = ("blocked", "challenge")


def _protected(p: dict, i: dict) -> bool:
    """Le site montre une volonté de protéger ou de réserver son contenu."""
    tls = p.get("tls_fingerprint") or {}
    return bool(_antibots(i) or _blocked_ai(p) or _tdm_reserved(p) or _content_usage(p) or tls.get("tested"))


# ── Règles ───────────────────────────────────────────────────────────────
def _declaration(p: dict, i: dict) -> list[Finding]:
    if not p:
        return []
    out = []
    robots = [d for d in _t1(p).get("found") or [] if d.get("endpoint") == "/robots.txt" and d.get("status") == 200]
    if not robots and _python_refused(p):
        out.append(
            Finding(
                "robots_refused",
                "declaration",
                NOT_DECLARED,
                2,
                "robots.txt est refusé aux robots comme le reste du site. Selon la RFC 9309, un robots.txt "
                "inaccessible (erreur 4xx) permet tout : les robots qui respectent la règle ne lisent pas vos consignes.",
                evidence=[f"Python : HTTP {(p.get('tls_fingerprint') or {}).get('python_status', '?')}"],
                actions=["Servir robots.txt à tout client, hors de la protection anti-robot, avec les règles voulues."],
            )
        )
    elif not robots:
        out.append(
            Finding(
                "robots_absent",
                "declaration",
                NOT_DECLARED,
                2,
                "Le site ne sert pas de robots.txt : il ne dit rien aux robots, ni ce qui est permis ni ce qui ne l'est pas.",
                actions=[
                    "Publier un robots.txt, même court, avec l'adresse du sitemap et les règles voulues pour les robots d'IA."
                ],
            )
        )
    u = _usage(p)
    declared = _content_usage(p) or _tdm_reserved(p) or (u.get("llms_txt") or {}).get("present") or _blocked_ai(p)
    if not declared:
        out.append(
            Finding(
                "usage_absent",
                "declaration",
                NOT_DECLARED,
                2,
                "Le site ne déclare aucune préférence d'usage pour les machines : rien sur la fouille de textes "
                "et de données, l'entraînement des modèles ou les robots d'IA.",
                actions=[
                    "Pour réserver le contenu : déclarer la réserve TDM (TDMRep : en-tête `tdm-reservation` ou "
                    "`/.well-known/tdmrep.json`) ; en Europe, c'est la forme lisible par machine qui compte.",
                    "Pour l'ouvrir : publier un `/llms.txt` et un en-tête `Content-Usage` (AIPREF) qui disent ce qui est permis.",
                ],
            )
        )
    return out


def _coherence(p: dict, i: dict) -> list[Finding]:
    blocked = _blocked_ai(p) if p else []
    if not blocked:
        return []
    out = []
    bots = ", ".join(blocked)
    if not (_tdm_reserved(p) or _content_usage(p)):
        out.append(
            Finding(
                "ai_blocked_without_tdm",
                "coherence",
                INCONSISTENT,
                2,
                "robots.txt refuse des robots d'IA, mais aucune réserve d'usage n'est déclarée : la règle vise "
                "des robots nommés, pas l'usage du contenu.",
                evidence=[f"robots.txt bloque : {bots}"],
                actions=[
                    "Déclarer aussi la réserve TDM (TDMRep) ou un en-tête `Content-Usage` (AIPREF) : ils valent "
                    "pour tout robot, même ceux que la liste ne nomme pas."
                ],
            )
        )
    doors = _open_doors(p)
    if doors:
        out.append(
            Finding(
                "ai_blocked_doors_open",
                "coherence",
                INCONSISTENT,
                3,
                "robots.txt refuse des robots d'IA, mais des portes pour machines restent servies à tout client. "
                "robots.txt est une demande, pas une barrière.",
                evidence=[f"robots.txt bloque : {bots}"] + [f"servi : {_items(d)}" for d in doors],
                actions=[
                    "Si le contenu doit rester réservé : protéger ces portes elles-mêmes (authentification, limite "
                    "de débit, protection anti-robot).",
                    "Si ces portes sont voulues : le dire dans robots.txt et les préférences d'usage.",
                ],
            )
        )
    return out


def _doors(p: dict, i: dict) -> list[Finding]:
    out = []
    t1 = _t1(p) if p else {}
    apis = t1.get("api_endpoints") or []
    if apis:
        out.append(
            Finding(
                "platform_api_open",
                "doors",
                OPEN_UNDECLARED,
                3,
                "L'API de la plateforme répond sans authentification : une machine lit le contenu sans passer par les pages.",
                evidence=[_items(d) for d in apis],
                actions=[
                    "Si ce n'est pas voulu : fermer la route ou exiger une authentification.",
                    "Si c'est voulu : la documenter, fixer une limite de débit et déclarer les préférences d'usage.",
                ],
            )
        )
    declared = ([t1["sitemap"]] if t1.get("sitemap") else []) + list(t1.get("rss_feeds") or [])
    if declared:
        out.append(
            Finding(
                "declared_doors",
                "doors",
                OPEN_DECLARED,
                1,
                "Le site publie des portes déclarées pour machines (sitemap, flux).",
                evidence=[_items(d) for d in declared],
                actions=[
                    "Rien à faire si c'est voulu : c'est la voie la moins coûteuse pour le site et pour les robots."
                ],
            )
        )
    calls = (i or {}).get("graphql_calls") or []
    if calls:
        ops = sorted({c.get("operation_name") or c.get("url") or "?" for c in calls})
        out.append(
            Finding(
                "graphql_visible",
                "doors",
                OPEN_UNDECLARED,
                2,
                "Les pages chargent leurs données par GraphQL : ces requêtes sont visibles dans le navigateur et "
                "peuvent être rejouées hors des pages.",
                evidence=[f"opération : {op}" for op in ops],
                actions=[
                    "Vérifier que l'API refuse les requêtes arbitraires (requêtes persistées seules, profondeur "
                    "et débit limités).",
                    "Si les données sont publiques par nature : offrir un export ou une API déclarée.",
                ],
            )
        )
    islands = list((i or {}).get("inline_data_islands") or [])
    inline = list(((p or {}).get("tier2_static_html") or {}).get("inline_json") or [])
    if islands or inline:
        ev = [f"{d.get('selector', '?')} ({d.get('size', '?')} octets)" for d in islands]
        ev += [f"JSON dans la page : {d.get('id') or d.get('selector') or '?'}" for d in inline]
        out.append(
            Finding(
                "inline_data",
                "doors",
                OPEN_UNDECLARED,
                1,
                "Les pages contiennent leurs données structurées en JSON, lisibles sans exécuter de JavaScript.",
                evidence=ev,
                actions=["Vérifier que ces données ne contiennent rien de plus que ce que la page affiche."],
            )
        )
    return out


def _protection(p: dict, i: dict) -> list[Finding]:
    out = []
    rl = (p or {}).get("rate_limit_burst") or {}
    n = rl.get("n_requests")
    if n and rl.get("n_ok") == n and not rl.get("throttling_detected") and not rl.get("rate_limit_headers"):
        out.append(
            Finding(
                "no_rate_limit",
                "protection",
                UNPROTECTED,
                2,
                f"{n} requêtes de suite ont toutes été servies, sans ralentissement ni en-tête de limite de débit.",
                actions=[
                    "Fixer une limite de débit et l'annoncer (`RateLimit`, `Retry-After`) : un robot honnête "
                    "s'y tient, les autres sont freinés."
                ],
            )
        )
    vendors = _antibots(i or {})
    if vendors:
        out.append(
            Finding(
                "antibot_found",
                "protection",
                PROTECTED,
                1,
                f"Protection anti-robot trouvée : {', '.join(vendors)}.",
                evidence=[e for v in vendors for e in ((i["anti_bot_stack"][v] or {}).get("evidence") or [])][:6],
                actions=[
                    "Vérifier que la protection couvre aussi les portes listées dans ce rapport (API, sitemap, "
                    "ressources servies par un CDN) : le contenu ne doit pas passer à côté."
                ],
            )
        )
    tls = (p or {}).get("tls_fingerprint") or {}
    reach = (i or {}).get("reachability") or {}
    if not vendors and (tls.get("verdict") in REFUSED_VERDICTS or reach.get("status") in REFUSED_STATUSES):
        ev = []
        if tls.get("tested"):
            ev.append(f"Python : HTTP {tls.get('python_status', '?')}")
            ev.append(f"Empreinte de Chrome : {tls.get('verdict')} (HTTP {tls.get('chrome_status', '?')})")
        if reach.get("status") in REFUSED_STATUSES:
            ev.append(f"Navigateur : {reach['status']} (HTTP {reach.get('page_status', '?')})")
        out.append(
            Finding(
                "access_refused",
                "protection",
                PROTECTED,
                1,
                "Le site refuse les clients automatisés, sans protection anti-robot reconnue par l'audit.",
                evidence=ev,
                actions=[
                    "Vérifier que ce refus est voulu et qu'il épargne les visiteurs humains ; offrir une voie "
                    "déclarée (API, export) aux usages légitimes."
                ],
            )
        )
    if tls.get("verdict") == "empreinte":
        out.append(
            Finding(
                "tls_only",
                "protection",
                PARTIAL,
                3,
                "Le site refuse un client Python, mais sert la page à un client qui reprend l'empreinte TLS de "
                "Chrome : le filtre ne porte que sur l'empreinte, que des outils courants imitent.",
                evidence=[f"Python : HTTP {tls.get('python_status', '?')}", "Empreinte de Chrome : page servie"],
                actions=[
                    "Ne pas compter sur l'empreinte seule : la compléter par une limite de débit ou un contrôle "
                    "du comportement.",
                    "Ou ouvrir une porte déclarée pour les usages légitimes.",
                ],
            )
        )
    return out


def _copies(p: dict, i: dict) -> list[Finding]:
    copies = (p or {}).get("third_party_copies") or {}
    held = {k: v for k, v in copies.items() if isinstance(v, dict) and (v.get("items") or 0) > 0}
    if not held or not _protected(p, i or {}):
        return []
    ev = [
        f"{k} : {v['items']} copies" + (f" (dernière {v['newest']})" if v.get("newest") else "")
        for k, v in held.items()
    ]
    return [
        Finding(
            "copies_outside",
            "copies",
            OUTSIDE,
            2,
            "Des copies du site restent lisibles chez des tiers, en dehors de votre périmètre de protection.",
            evidence=ev,
            actions=[
                "Si ces copies ne sont pas voulues : demander leur retrait aux archives ; une règle robots.txt "
                "n'arrête que les collectes futures.",
                "Si elles le sont : rien à faire, elles servent aussi la mémoire du site.",
            ],
        )
    ]


def _visitors(p: dict, i: dict) -> list[Finding]:
    if not i:
        return []
    out = []
    if (i.get("reachability") or {}).get("status") == "challenge" and not i.get("browser_ran"):
        out.append(
            Finding(
                "challenge_everyone",
                "visitors",
                PROTECTED,
                3,
                "Toute requête reçoit une page de défi avant le contenu : les visiteurs humains la voient aussi.",
                actions=[
                    "Réserver le défi aux requêtes suspectes (débit, réputation) plutôt qu'à toutes.",
                    "Offrir une voie déclarée (API, export) aux usages légitimes, qui n'ont alors plus de raison de forcer le défi.",
                ],
            )
        )
    tr = i.get("trackers") or {}
    if tr.get("regies") and not tr.get("consent_manager"):
        out.append(
            Finding(
                "ads_without_consent",
                "visitors",
                NOT_DECLARED,
                2,
                "Des régies publicitaires se chargent sans qu'un gestionnaire de consentement ait été observé.",
                evidence=[f"régie : {r}" for r in tr["regies"]],
                actions=["Vérifier que ces régies attendent le consentement du visiteur."],
            )
        )
    return out


RULES = (_declaration, _coherence, _doors, _protection, _copies, _visitors)


def findings(probe: dict | None, inspect: dict | None) -> list[Finding]:
    """Constats tirés des deux audits, du plus important au moins important."""
    if not probe and not inspect:
        return []
    out = [f for rule in RULES for f in rule(probe or {}, inspect or {})]
    return sorted(out, key=lambda f: (-f.weight, THEMES.index(f.theme)))


# ── Rapport ──────────────────────────────────────────────────────────────
HEADER = (
    "Ce rapport s'adresse au propriétaire du site, ou à la personne qu'il a chargée de l'audit. Il dit ce "
    "qu'une machine voit du site et ce que le site déclare, depuis une seule adresse IP et à un moment "
    "donné. Il ne teste pas la résistance de la protection, ne cherche pas de faille et ne donne aucune "
    "technique de contournement."
)


def to_markdown(url: str, found: list[Finding]) -> str:
    lines = [f"# Rapport propriétaire : {url}", "", HEADER, "", "## Synthèse", "", "| Thème | État |", "|---|---|"]
    for theme in THEMES:
        first = next((f for f in found if f.theme == theme), None)
        lines.append(f"| {THEME_TITLES[theme]} | {first.state if first else 'rien trouvé'} |")
    lines += ["", "## Constats", ""]
    if not found:
        lines.append("Aucun constat : les audits n'ont rien relevé.")
    for f in found:
        lines += [f"### {THEME_TITLES[f.theme]} : {f.state}", "", f.observation, ""]
        lines += [f"- Preuve : {e}" for e in f.evidence]
        lines += [f"- Que faire : {a}" for a in f.actions]
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


async def audit(
    url: str, name: str, *, headless: bool = False, timeout: float = 30.0
) -> tuple[dict | None, dict | None]:
    """Sonde (copies tierces comprises) puis inspect ; un audit qui échoue laisse l'autre parler."""
    from dataclasses import asdict

    from . import probe as _probe
    from . import sap_inspect

    try:
        p = (await _probe.probe(url, copies=True)).to_dict()
    except Exception as e:  # noqa: BLE001 — le rapport dit ce qu'il a pu lire
        p = None
        print(f"  ⚠ sonde : {type(e).__name__}: {e}")
    try:
        i = asdict(await sap_inspect.inspect(url, name, headless=headless, timeout=timeout))
    except Exception as e:  # noqa: BLE001
        i = None
        print(f"  ⚠ inspect : {type(e).__name__}: {e}")
    return p, i
