"""Rapport propriétaire : ce que le site expose aux machines, relu du côté de son propriétaire.

Le moteur lit les deux audits (sonde et inspect, sous forme de dictionnaires) et rend des
constats : thème, état, poids, constat, preuves, que faire. Les recommandations vont dans
les deux sens : fermer ce qui n'est pas voulu, déclarer ce qui l'est.
"""

from __future__ import annotations

import copy

import pytest

from accesspath import owner

ROBOTS = {"endpoint": "/robots.txt", "type": "plain", "status": 200, "source": "générique"}
WPJSON = {"endpoint": "/wp-json", "type": "json", "status": 200, "source": "plateforme", "items": 18}
SITEMAP = {"endpoint": "/sitemap.xml", "type": "sitemap", "status": 200, "source": "plateforme", "items": 298}
FEED = {"endpoint": "/feed", "type": "rss", "status": 200, "source": "déclarée", "items": 10}
PERMIS = dict.fromkeys(("GPTBot", "ClaudeBot", "CCBot"), "permis")


def _probe(**over) -> dict:
    p = {
        "url": "https://exemple.ch/",
        "tier1_discovery": {"found": [ROBOTS], "api_endpoints": [], "rss_feeds": [], "sitemap": None},
        "tier2_static_html": {"inline_json": []},
        "rate_limit_burst": {
            "n_requests": 20,
            "n_ok": 20,
            "throttling_detected": False,
            "rate_limit_headers": {},
            "stopped_early": False,
        },
        "third_party_copies": {},
        "tls_fingerprint": {"tested": False},
        "usage_preferences": {
            "content_usage_header": {},
            "robots_content_usage": [],
            "ai_crawlers": dict(PERMIS),
            "tdmrep": {"header": {}, "html": {}, "well_known": None},
            "llms_txt": {"present": False},
        },
    }
    for path, value in over.items():
        node = p
        *head, last = path.split("__")
        for k in head:
            node = node[k]
        node[last] = value
    return p


def _inspect(**over) -> dict:
    i = {
        "reachability": {"status": "OK", "page_status": 200},
        "anti_bot_stack": {"cloudflare": {"detected": False, "evidence": []}},
        "graphql_calls": [],
        "inline_data_islands": [],
        "browser_ran": True,
        "trackers": {},
    }
    i.update(over)
    return i


def _rules(probe=None, inspect=None) -> dict:
    return {f.rule: f for f in owner.findings(probe, inspect)}


def _ai(**rules) -> dict:
    return {**PERMIS, **rules}


# ── Déclaration ──────────────────────────────────────────────────────────
def test_robots_absent():
    f = _rules(_probe(tier1_discovery__found=[]))["robots_absent"]
    assert f.theme == "declaration" and f.state == owner.NOT_DECLARED
    assert "robots.txt" in f.observation
    assert "robots_absent" not in _rules(_probe())


def test_aucune_preference_d_usage():
    f = _rules(_probe())["usage_absent"]
    assert f.theme == "declaration"
    assert any("TDMRep" in a for a in f.actions) and any("llms.txt" in a for a in f.actions)


@pytest.mark.parametrize(
    "path, value",
    [
        ("usage_preferences__llms_txt", {"present": True}),
        ("usage_preferences__content_usage_header", {"train-ai": "n"}),
        ("usage_preferences__tdmrep", {"header": {"tdm-reservation": "1"}, "html": {}, "well_known": None}),
        ("usage_preferences__ai_crawlers", _ai(GPTBot="bloqué")),
    ],
)
def test_une_declaration_suffit(path, value):
    assert "usage_absent" not in _rules(_probe(**{path: value}))


# ── Cohérence ────────────────────────────────────────────────────────────
def test_robots_bloque_l_ia_sans_reserve_tdm():
    f = _rules(_probe(usage_preferences__ai_crawlers=_ai(GPTBot="bloqué")))["ai_blocked_without_tdm"]
    assert f.theme == "coherence" and f.state == owner.INCONSISTENT
    assert "GPTBot" in " ".join(f.evidence)
    tdm = {"header": {}, "html": {"tdm-reservation": "1"}, "well_known": None}
    assert "ai_blocked_without_tdm" not in _rules(
        _probe(usage_preferences__ai_crawlers=_ai(GPTBot="bloqué"), usage_preferences__tdmrep=tdm)
    )


def test_robots_bloque_l_ia_mais_les_portes_restent_ouvertes():
    p = _probe(usage_preferences__ai_crawlers=_ai(ClaudeBot="bloqué"), tier1_discovery__sitemap=SITEMAP)
    f = _rules(p)["ai_blocked_doors_open"]
    assert f.theme == "coherence" and f.weight == 3
    assert "/sitemap.xml" in " ".join(f.evidence)
    assert "ai_blocked_doors_open" not in _rules(_probe(usage_preferences__ai_crawlers=_ai(ClaudeBot="bloqué")))
    assert "ai_blocked_doors_open" not in _rules(_probe(tier1_discovery__sitemap=SITEMAP))


# ── Portes ouvertes ──────────────────────────────────────────────────────
def test_api_de_plateforme_ouverte():
    f = _rules(_probe(tier1_discovery__api_endpoints=[WPJSON]))["platform_api_open"]
    assert f.theme == "doors" and f.state == owner.OPEN_UNDECLARED and f.weight == 3
    assert "/wp-json" in " ".join(f.evidence)
    assert len(f.actions) == 2  # fermer, ou déclarer
    assert "platform_api_open" not in _rules(_probe())


def test_flux_et_sitemap_sont_des_portes_declarees():
    f = _rules(_probe(tier1_discovery__sitemap=SITEMAP, tier1_discovery__rss_feeds=[FEED]))["declared_doors"]
    assert f.state == owner.OPEN_DECLARED and f.weight == 1
    assert {"/sitemap.xml", "/feed"} <= {e.split(" ")[0] for e in f.evidence}
    assert "declared_doors" not in _rules(_probe())


def test_graphql_visible_dans_le_navigateur():
    calls = [{"url": "https://exemple.ch/api/graphql", "operation_name": "Catalog"}]
    f = _rules(_probe(), _inspect(graphql_calls=calls))["graphql_visible"]
    assert f.theme == "doors" and "Catalog" in " ".join(f.evidence)
    assert "graphql_visible" not in _rules(_probe(), _inspect())


def test_donnees_dans_la_page():
    islands = [{"selector": "script#__NEXT_DATA__", "size": 40_000}]
    assert "inline_data" in _rules(_probe(), _inspect(inline_data_islands=islands))
    assert "inline_data" in _rules(_probe(tier2_static_html__inline_json=[{"id": "x"}]))
    assert "inline_data" not in _rules(_probe(), _inspect())


# ── Protection ───────────────────────────────────────────────────────────
def test_aucune_limite_de_debit():
    f = _rules(_probe())["no_rate_limit"]
    assert f.theme == "protection" and "20" in f.observation
    assert "no_rate_limit" not in _rules(_probe(rate_limit_burst__throttling_detected=True))
    assert "no_rate_limit" not in _rules(_probe(rate_limit_burst__rate_limit_headers={"ratelimit-limit": "60"}))
    assert "no_rate_limit" not in _rules(_probe(rate_limit_burst__n_ok=12))


def test_anti_bot_trouve():
    stack = {"cloudflare": {"detected": True, "evidence": ["cf-ray"]}, "akamai": {"detected": False, "evidence": []}}
    f = _rules(_probe(), _inspect(anti_bot_stack=stack))["antibot_found"]
    assert f.state == owner.PROTECTED and "cloudflare" in f.observation and "akamai" not in f.observation
    assert "antibot_found" not in _rules(_probe(), _inspect())


def test_filtre_sur_l_empreinte_tls_seule():
    f = _rules(_probe(tls_fingerprint={"tested": True, "verdict": "empreinte", "python_status": 403}))["tls_only"]
    assert f.theme == "protection" and f.weight == 3
    for verdict in ("défi", "bloqué"):
        assert "tls_only" not in _rules(_probe(tls_fingerprint={"tested": True, "verdict": verdict}))


# ── Copies hors du périmètre de protection ───────────────────────────────
def test_copies_hors_du_perimetre():
    copies = {"wayback": {"items": 1200, "newest": "2026-10-01"}, "commoncrawl": {"items": 0}}
    p = _probe(third_party_copies=copies, usage_preferences__ai_crawlers=_ai(CCBot="bloqué"))
    f = _rules(p)["copies_outside"]
    assert f.theme == "copies" and f.state == owner.OUTSIDE
    assert "périmètre de protection" in f.observation and "wayback" in " ".join(f.evidence)
    assert "commoncrawl" not in " ".join(f.evidence)  # aucune copie : pas de preuve
    empty = {"wayback": {"items": 0}, "commoncrawl": {"items": None}}
    assert "copies_outside" not in _rules(
        _probe(third_party_copies=empty, usage_preferences__ai_crawlers=_ai(CCBot="bloqué"))
    )
    stack = {"datadome": {"detected": True, "evidence": []}}
    assert "copies_outside" in _rules(_probe(third_party_copies=copies), _inspect(anti_bot_stack=stack))
    # Site sans protection ni réserve : rien n'est « hors du périmètre ».
    assert "copies_outside" not in _rules(_probe(third_party_copies=copies))
    assert "copies_outside" not in _rules(_probe(usage_preferences__ai_crawlers=_ai(CCBot="bloqué")))


# ── Visiteurs humains ────────────────────────────────────────────────────
def test_defi_impose_a_toute_requete():
    reach = {"status": "challenge", "page_status": 200}
    f = _rules(_probe(), _inspect(reachability=reach, browser_ran=False))["challenge_everyone"]
    assert f.theme == "visitors" and f.weight == 3
    assert "challenge_everyone" not in _rules(_probe(), _inspect(reachability=reach, browser_ran=True))


def test_regies_sans_gestionnaire_de_consentement():
    trackers = {"regies": ["doubleclick"], "consent_manager": []}
    f = _rules(_probe(), _inspect(trackers=trackers))["ads_without_consent"]
    assert f.theme == "visitors" and "doubleclick" in " ".join(f.evidence)
    ok = {"regies": ["doubleclick"], "consent_manager": ["onetrust"]}
    assert "ads_without_consent" not in _rules(_probe(), _inspect(trackers=ok))


# ── Ensemble ─────────────────────────────────────────────────────────────
def test_sans_audit_rien_ne_casse():
    assert owner.findings(None, None) == []
    assert isinstance(owner.findings(_probe(), None), list)
    assert isinstance(owner.findings(None, _inspect()), list)


def test_constats_tries_par_poids():
    p = _probe(tier1_discovery__api_endpoints=[WPJSON], tier1_discovery__sitemap=SITEMAP)
    weights = [f.weight for f in owner.findings(p, _inspect())]
    assert weights == sorted(weights, reverse=True)


def test_chaque_constat_est_complet():
    p = _probe(
        tier1_discovery__found=[],
        tier1_discovery__api_endpoints=[WPJSON],
        tier1_discovery__sitemap=SITEMAP,
        usage_preferences__ai_crawlers=_ai(GPTBot="bloqué"),
        tls_fingerprint={"tested": True, "verdict": "empreinte"},
        third_party_copies={"wayback": {"items": 5}},
    )
    i = _inspect(
        reachability={"status": "challenge"},
        browser_ran=False,
        graphql_calls=[{"operation_name": "Q"}],
        trackers={"regies": ["x"], "consent_manager": []},
    )
    for f in owner.findings(p, i):
        assert f.theme in owner.THEMES and f.state in owner.STATES, f.rule
        assert f.observation and f.actions and 1 <= f.weight <= 3, f.rule


def test_les_audits_ne_sont_pas_modifies():
    p, i = _probe(tier1_discovery__api_endpoints=[WPJSON]), _inspect()
    p0, i0 = copy.deepcopy(p), copy.deepcopy(i)
    owner.findings(p, i)
    assert (p, i) == (p0, i0)


# ── Rapport ──────────────────────────────────────────────────────────────
def _full():
    p = _probe(
        tier1_discovery__api_endpoints=[WPJSON],
        tier1_discovery__sitemap=SITEMAP,
        usage_preferences__ai_crawlers=_ai(GPTBot="bloqué"),
    )
    return p, _inspect()


def test_rapport_markdown():
    p, i = _full()
    md = owner.to_markdown("https://exemple.ch/", owner.findings(p, i))
    assert md.startswith("# Rapport propriétaire : https://exemple.ch/")
    # L'en-tête dit à qui le rapport est destiné et ce qu'il ne fait pas.
    assert "propriétaire du site" in md and "contournement" in md
    # Synthèse : un thème par ligne, avec son pire état.
    assert "| Cohérence entre déclaration et exposition | incohérent |" in md
    assert "| Copies hors du périmètre de protection | rien trouvé |" in md
    # Les constats de poids 3 viennent d'abord, avec preuves et actions.
    first = md.index("## Constats")
    assert md.index("/wp-json", first) < md.index("Rien à faire si c'est voulu", first)
    assert "- Que faire :" in md


def test_rapport_sans_constat():
    md = owner.to_markdown("https://exemple.ch/", [])
    assert "Aucun constat" in md


# ── Commande ─────────────────────────────────────────────────────────────
def test_commande_sap_owner(monkeypatch, capsys):
    from accesspath import cli

    p, i = _full()
    seen = {}

    async def fake_audit(url, name, **kw):
        seen.update(url=url, name=name, **kw)
        return p, i

    monkeypatch.setattr(owner, "audit", fake_audit)
    rc = cli.main(["sap", "owner", "exemple.ch", "--headless"])
    out = capsys.readouterr().out
    assert rc == 0
    assert seen["url"] == "https://exemple.ch" and seen["headless"] is True
    assert "# Rapport propriétaire" in out and "/wp-json" in out


def test_commande_sap_owner_sans_url(capsys):
    from accesspath import cli

    assert cli.main(["sap", "owner"]) == 3


# ── Cas réel : registre chregister (25.10.2026) ──────────────────────────
# Python reçoit 403 sur l'accueil et sur robots.txt ; Chrome imité aussi ; aucun vendeur reconnu.
REFUSED = {"tested": True, "verdict": "bloqué", "python_status": 403, "chrome_status": 403}


def test_robots_refuse_n_est_pas_absent():
    r = _rules(_probe(tier1_discovery__found=[], tls_fingerprint=REFUSED))
    assert "robots_absent" not in r
    f = r["robots_refused"]
    assert f.theme == "declaration" and "RFC 9309" in f.observation


def test_refus_sans_vendeur_reconnu_est_une_protection():
    f = _rules(_probe(tls_fingerprint=REFUSED), _inspect())["access_refused"]
    assert f.theme == "protection" and f.state == owner.PROTECTED
    assert any("403" in e for e in f.evidence)
    reach = {"status": "blocked", "page_status": 403}
    assert "access_refused" in _rules(_probe(), _inspect(reachability=reach))
    # Vendeur reconnu : le constat « anti-robot » suffit.
    stack = {"akamai": {"detected": True, "evidence": []}}
    assert "access_refused" not in _rules(_probe(tls_fingerprint=REFUSED), _inspect(anti_bot_stack=stack))
    assert "access_refused" not in _rules(_probe(), _inspect())
