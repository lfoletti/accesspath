"""Geste humain annoncé par l'audit : `predict_human_gate` lit un InspectReport
et dit si une main humaine sera nécessaire (défi anti-bot, connexion, consentement)."""

from accesspath.human_gate import HumanGate, predict_human_gate
from accesspath.sap_inspect import (
    AntiBotDetection,
    InspectReport,
    Reachability,
    Stage1Findings,
    StructuralFeatures,
    TierRecommendation,
    _build_report_from_stage1,
    to_markdown,
)

VENDORS = ("cloudflare", "akamai", "datadome", "perimeterx", "kasada", "imperva", "fortiadc")


def _report(*, status="OK", page_status=200, body=50_000, title="", vendors=(), struct=None, tier=1):
    return InspectReport(
        target_url="https://exemple.ch/",
        name="exemple_ch",
        timestamp="2026-10-24T00:00:00+00:00",
        duration_s=1.0,
        reachability=Reachability(status=status, page_status=page_status, body_length=body, title=title),
        anti_bot_stack={
            v: AntiBotDetection(detected=v in vendors, evidence=["x"] if v in vendors else []) for v in VENDORS
        },
        frameworks={},
        endpoints=[],
        graphql_calls=[],
        inline_data_islands=[],
        link_architecture=None,
        structural_features=struct or StructuralFeatures(n_internal_links=80),
        tier_recommendation=TierRecommendation(primary=tier, rationale=""),
    )


def test_cloudflare_qui_bloque_demande_un_defi():
    g = predict_human_gate(_report(status="blocked", page_status=403, body=4000, vendors=("cloudflare",)))
    assert isinstance(g, HumanGate)
    assert (g.kind, g.vendor) == ("challenge", "cloudflare")
    assert g.est_seconds > 0
    assert g.open_url == "https://exemple.ch/"


def test_cloudflare_present_mais_page_servie_ne_demande_rien():
    # Le cas le plus courant : Cloudflare sert de CDN (cf-ray, __cf_bm) et laisse passer.
    assert predict_human_gate(_report(vendors=("cloudflare",))) is None


def test_datadome_prime_sur_cloudflare_cdn():
    g = predict_human_gate(_report(status="blocked", page_status=403, vendors=("cloudflare", "datadome")))
    assert (g.kind, g.vendor) == ("challenge", "datadome")


def test_page_de_defi_sans_fournisseur_reconnu():
    g = predict_human_gate(_report(status="challenge", page_status=200, title="Just a moment..."))
    assert (g.kind, g.vendor) == ("challenge", "inconnu")


def test_statut_401_demande_une_connexion():
    g = predict_human_gate(_report(status="error", page_status=401, body=800))
    assert g.kind == "login"


def test_accueil_reduit_a_un_formulaire_de_connexion():
    struct = StructuralFeatures(has_login_form=True, n_internal_links=3)
    assert predict_human_gate(_report(body=3000, struct=struct)).kind == "login"


def test_lien_de_connexion_sur_un_site_ouvert_ne_demande_rien():
    struct = StructuralFeatures(has_login_form=True, has_login_link=True, n_internal_links=120)
    assert predict_human_gate(_report(struct=struct)) is None


def test_defi_prime_sur_connexion():
    struct = StructuralFeatures(has_login_form=True, n_internal_links=2)
    g = predict_human_gate(_report(status="blocked", page_status=403, vendors=("akamai",), struct=struct))
    assert (g.kind, g.vendor) == ("challenge", "akamai")


def test_consentement_seulement_quand_le_navigateur_est_requis():
    struct = StructuralFeatures(has_consent_wall=True, n_internal_links=80)
    assert predict_human_gate(_report(struct=struct, tier=2)) is None
    assert predict_human_gate(_report(struct=struct, tier=4)).kind == "consent"


def test_le_rapport_stage1_porte_le_geste_et_le_markdown_l_annonce():
    s1 = Stage1Findings(homepage_status=403, homepage_body_length=4000, cf_detected=True)
    rep = _build_report_from_stage1(s1, "https://exemple.ch/", "exemple_ch", 0.0)
    assert rep.human_gate is not None and rep.human_gate.kind == "challenge"
    md = to_markdown(rep)
    head = md.split("⟦DÉBUT")[0]
    assert "Geste humain requis" in head
    assert "warmup exemple_ch" in head


def test_le_markdown_ne_dit_rien_sans_geste():
    assert "Geste humain requis" not in to_markdown(_report())
