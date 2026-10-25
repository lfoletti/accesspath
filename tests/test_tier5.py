"""Tier 5 : pas d'accès machine. Seul un vrai Chrome resté sur une page de défi le
constate (inspect, étape 2) ; un refus en HTTP laisse le tier 4 à essayer. Le rapport
donne les voies sans accès machine direct : geste humain puis session rejouée, copie
tierce, abonnement, demande à l'éditeur."""

from __future__ import annotations

import asyncio

from accesspath import batch
from accesspath import probe as probe_mod
from accesspath import sap_inspect as si
from accesspath.sap_inspect import AntiBotDetection, FrameworkDetection, Reachability, _recommend_tier

from .test_sap_browser_lifecycle import (  # noqa: F401 — fixtures
    FakeBrowser,
    FakeTab,
    _allow_local,
    fake_nodriver,
    no_pkill,
    stage1_needs_browser,
)


def _rec(status, *, browser):
    return _recommend_tier(
        reachability=Reachability(status=status, evidence="test"),
        anti_bot={"cloudflare": AntiBotDetection(detected=True)},
        frameworks={"nextjs": FrameworkDetection(detected=False)},
        endpoints=[],
        graphql_calls=[],
        browser=browser,
    )


def test_defi_dans_chrome_donne_le_tier_5():
    rec = _rec("challenge", browser=True)
    assert rec.primary == 5 and rec.fallbacks == [4]
    for voie in ("geste humain", "ghost", "copie tierce", "abonnement", "éditeur"):
        assert voie in rec.rationale


def test_refus_en_http_laisse_le_tier_4():
    assert _rec("challenge", browser=False).primary == 4
    assert _rec("blocked", browser=False).primary == 4


def test_page_vide_dans_chrome_reste_au_tier_4():
    assert _rec("throttled", browser=True).primary == 4
    assert _rec("error", browser=True).primary == 4


class ChallengeTab(FakeTab):
    async def evaluate(self, expr):
        if expr == "document.title":
            return "Just a moment..."
        if "innerText" in expr:
            return "Checking your browser"
        return ""


def test_inspect_de_bout_en_bout_sur_un_defi(fake_nodriver, stage1_needs_browser, monkeypatch, no_pkill):  # noqa: F811
    async def get(self, url):
        return ChallengeTab()

    monkeypatch.setattr(FakeBrowser, "get", get)
    report = asyncio.run(si.inspect("http://127.0.0.1:9/", "site_x", timeout=0, headless=True))
    assert report.reachability.status == "challenge"
    assert report.tier_recommendation.primary == 5
    assert report.human_gate and report.human_gate.kind == "challenge"
    assert "Tier 5" in si.to_markdown(report)


def test_probe_annonce_le_tier_5_si_chrome_echoue_aussi():
    r = probe_mod.ProbeReport(url="https://x.ch/", timestamp="t")
    r.tls = {"tested": True, "python_status": 403, "chrome_status": 403, "impersonate": "chrome", "verdict": "bloqué"}
    tier, why = probe_mod._decide_tier(r)
    assert tier == 4 and "tier 5" in why


def test_synthese_batch_compte_le_tier_5():
    rows = [{"name": "a", "status": "ok", "tier": 5}, {"name": "b", "status": "ok", "tier": 1}]
    md = batch.summarize("x", rows)
    assert "| 5 | 1 |" in md and "Sans accès machine (tier 5) : 1" in md
