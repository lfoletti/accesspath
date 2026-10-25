"""Lot en mode probe : préférences d'usage par site (robots d'IA bloqués, AIPREF,
TDMRep, llms.txt, accès payant) et leur synthèse."""

from __future__ import annotations

from accesspath import batch
from accesspath import probe as probe_mod


def _report(usage):
    r = probe_mod.ProbeReport(url="https://m.ch/", timestamp="t", chosen_tier=1, rationale="x")
    r.usage = usage
    return r


USAGE = {
    "content_usage_header": {"train-ai": "n"},
    "robots_content_usage": [{"path": "/", "prefs": {"search": "y"}}, {"path": "/x", "prefs": {"train-ai": "y"}}],
    "ai_crawlers": {"GPTBot": "bloqué", "CCBot": "bloqué", "ClaudeBot": "partiel", "Amazonbot": "permis"},
    "tdmrep": {"header": {}, "html": {"tdm-reservation": "1"}, "well_known": None},
    "llms_txt": {"present": True, "bytes": 10, "title": "M"},
    "pay_per_crawl": None,
}


def test_probe_row_preferences_d_usage():
    row = batch.probe_row(_report(USAGE))
    assert row["ai_blocked"] == ["CCBot", "GPTBot"]
    assert row["ai_partial"] == ["ClaudeBot"]
    assert row["content_usage"] == {"train-ai": "n", "search": "y"}
    assert row["tdm_reservation"] is True
    assert row["llms_txt"] is True
    assert row["pay_per_crawl"] is False


def test_probe_row_sans_preferences():
    row = batch.probe_row(_report({}))
    assert row["ai_blocked"] == [] and row["ai_partial"] == [] and row["content_usage"] == {}
    assert row["tdm_reservation"] is False and row["llms_txt"] is False and row["pay_per_crawl"] is False


def test_reservation_tdm_par_well_known_et_payant():
    u = {**USAGE, "tdmrep": {"header": {}, "html": {}, "well_known": [{"location": "/", "tdm-reservation": 1}]}}
    u["pay_per_crawl"] = {"status": 402}
    row = batch.probe_row(_report(u))
    assert row["tdm_reservation"] is True and row["pay_per_crawl"] is True


def test_reservation_tdm_zero_n_est_pas_une_reservation():
    u = {**USAGE, "tdmrep": {"header": {"tdm-reservation": "0"}, "html": {}, "well_known": None}}
    assert batch.probe_row(_report(u))["tdm_reservation"] is False


def test_synthese_robots_d_ia():
    rows = [
        {
            "status": "ok",
            "tier": 1,
            "ai_blocked": ["GPTBot", "CCBot"],
            "llms_txt": True,
            "content_usage": {"train-ai": "n"},
        },
        {"status": "ok", "tier": 1, "ai_blocked": ["GPTBot"], "tdm_reservation": True},
        {"status": "ok", "tier": 2, "ai_blocked": []},
    ]
    md = batch.summarize("medias", rows)
    assert "- Sites qui bloquent au moins un robot d'IA : 2 sur 3" in md
    assert "- llms.txt : 1 ; Content-Usage : 1 ; réservation TDM : 1" in md
    section = md.split("## Robots d'IA bloqués")[1]
    assert "| GPTBot | 2 |" in section and "| CCBot | 1 |" in section


def test_content_usage_racine_seule_et_en_tete_prioritaire():
    u = {
        "robots_content_usage": [{"path": "/x", "prefs": {"train-ai": "y"}}, {"path": "/", "prefs": {"train-ai": "n"}}]
    }
    assert batch.probe_row(_report(u))["content_usage"] == {"train-ai": "n"}
    u["content_usage_header"] = {"train-ai": "y"}
    assert batch.probe_row(_report(u))["content_usage"] == {"train-ai": "y"}


def test_tdm_policy_seule_n_est_pas_une_reservation():
    u = {"tdmrep": {"header": {}, "html": {"tdm-policy": "1"}, "well_known": None}}
    assert batch.probe_row(_report(u))["tdm_reservation"] is False


def test_llms_txt_absent_ou_saute():
    u = {"llms_txt": {"present": False, "skipped": "interdit par robots.txt pour *"}}
    assert batch.probe_row(_report(u))["llms_txt"] is False
