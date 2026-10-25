"""Refus net, défi, redirection vers un autre site, site injoignable : l'audit les
distingue, et seul un défi qu'une main peut passer devient un geste humain.

Cas d'origine (campagne bureaux d'architecture, octobre 2026) : dix domaines de bureaux
redirigeaient vers leur fiche d'annuaire, et l'annuaire servait « Sorry, you have been
blocked » ; l'audit en avait fait dix tickets « challenge » que personne ne pouvait passer.
"""

from __future__ import annotations

import asyncio

import httpx

from accesspath import batch
from accesspath import probe as probe_mod
from accesspath import sap_inspect as si
from accesspath.human_gate import predict_human_gate
from accesspath.sap_inspect import AntiBotDetection, FrameworkDetection, Reachability, _recommend_tier

from .test_human_gate import _report
from .test_sap_browser_lifecycle import (  # noqa: F401 — fixtures
    FakeBrowser,
    FakeTab,
    _allow_local,
    fake_nodriver,
    no_pkill,
    stage1_needs_browser,
)
from .test_tls_fingerprint import _fake_chrome, _home

CF_BLOCK_TITLE = "Attention Required! | Cloudflare"
CF_BLOCK_BODY = "Sorry, you have been blocked\nYou are unable to access exemple.ch\nWhy have I been blocked?"


# ── Page lue par Chrome ──────────────────────────────────────────────────
def test_page_de_blocage_est_un_refus_net():
    reach = si.classify_page(CF_BLOCK_TITLE, CF_BLOCK_BODY, "https://exemple.ch/", "https://exemple.ch/")
    assert reach.status == "blocked" and reach.hard_block


def test_page_de_defi_reste_un_defi():
    reach = si.classify_page("Just a moment...", "Checking your browser", "https://exemple.ch/", "https://exemple.ch/")
    assert reach.status == "challenge" and not reach.hard_block


def test_page_servie():
    reach = si.classify_page("Atelier", "Projets " * 50, "https://exemple.ch/", "https://www.exemple.ch/projets")
    assert reach.status == "OK" and not reach.hard_block and reach.redirected_to == ""


def test_redirection_vers_un_autre_site():
    reach = si.classify_page(
        "Atelier", "x" * 500, "https://www.atelier.ch/", "https://www.annuaire.com/de/atelier?nonav=1"
    )
    assert reach.redirected_to == "www.annuaire.com"


def test_meme_site_avec_ou_sans_www_ou_sous_domaine():
    assert si.foreign_redirect("https://atelier.ch/", "https://www.atelier.ch/fr/") == ""
    assert si.foreign_redirect("https://www.atelier.ch/", "https://atelier.ch/") == ""
    assert si.foreign_redirect("https://www.atelier.ch/", "https://projets.atelier.ch/") == ""
    assert si.foreign_redirect("https://www.atelier.ch/", "") == ""


def test_meme_suffixe_n_est_pas_le_meme_site():
    assert si.foreign_redirect("https://a.co.jp/", "https://b.co.jp/") == "b.co.jp"


# ── Tier ─────────────────────────────────────────────────────────────────
def _rec(reach, *, browser=True):
    return _recommend_tier(
        reachability=reach,
        anti_bot={"cloudflare": AntiBotDetection(detected=True)},
        frameworks={"nextjs": FrameworkDetection(detected=False)},
        endpoints=[],
        graphql_calls=[],
        browser=browser,
    )


def test_refus_net_dans_chrome_donne_le_tier_5_sans_geste():
    rec = _rec(Reachability(status="blocked", hard_block=True, evidence="page de blocage"))
    assert rec.primary == 5
    assert "refus net" in rec.rationale and "geste humain" not in rec.rationale


def test_refus_sans_page_de_blocage_reste_au_tier_4():
    assert _rec(Reachability(status="blocked", evidence="403")).primary == 4


def test_la_raison_nomme_le_site_de_destination():
    rec = _rec(Reachability(status="OK", redirected_to="www.annuaire.com"))
    assert rec.rationale.startswith("Le domaine redirige vers www.annuaire.com")


# ── Geste humain ─────────────────────────────────────────────────────────
def test_refus_net_ne_demande_pas_de_geste():
    report = _report(status="blocked", page_status=403, vendors=("cloudflare",))
    report.reachability.hard_block = True
    assert predict_human_gate(report) is None


def test_defi_sur_un_autre_site_ne_demande_pas_de_geste():
    report = _report(status="challenge", page_status=200, title="Just a moment...", vendors=("cloudflare",))
    report.reachability.redirected_to = "www.annuaire.com"
    assert predict_human_gate(report) is None


def test_defi_sur_le_site_demande_toujours_un_geste():
    report = _report(status="challenge", page_status=200, title="Just a moment...", vendors=("cloudflare",))
    assert predict_human_gate(report).kind == "challenge"


# ── De bout en bout dans Chrome ──────────────────────────────────────────
class BlockTab(FakeTab):
    async def evaluate(self, expr):
        if expr == "document.title":
            return CF_BLOCK_TITLE
        if "innerText" in expr:
            return CF_BLOCK_BODY
        if "location" in expr:
            return "https://www.annuaire.com/de/site-x?nonav=1"
        return ""


def test_inspect_de_bout_en_bout_sur_un_refus(fake_nodriver, stage1_needs_browser, monkeypatch, no_pkill):  # noqa: F811
    async def get(self, url):
        return BlockTab()

    monkeypatch.setattr(FakeBrowser, "get", get)
    report = asyncio.run(si.inspect("http://127.0.0.1:9/", "site_x", timeout=0, headless=True))
    assert report.reachability.status == "blocked" and report.reachability.hard_block
    assert report.reachability.redirected_to == "www.annuaire.com"
    assert report.tier_recommendation.primary == 5
    assert report.human_gate is None
    row = batch.inspect_row(si.asdict(report))
    assert row["redirected_to"] == "www.annuaire.com" and row["human_gate"] is None


# ── Sonde ────────────────────────────────────────────────────────────────
def test_sonde_page_de_blocage_est_un_refus(monkeypatch):
    page = f"<html><title>{CF_BLOCK_TITLE}</title><body>{CF_BLOCK_BODY}</body></html>".encode()
    _fake_chrome(monkeypatch, (403, page))
    tls, _ = asyncio.run(probe_mod.check_tls_fingerprint("https://x.ch/", _home(403)))
    assert tls["verdict"] == "refusé"
    r = probe_mod.ProbeReport(url="https://x.ch/", timestamp="t", tls=tls)
    _tier, why = probe_mod._decide_tier(r)
    assert "refus net" in why and "geste humain" not in why


def test_sonde_site_injoignable(monkeypatch):
    _fake_chrome(monkeypatch, httpx.ConnectError("unreachable"))
    tls, _ = asyncio.run(probe_mod.check_tls_fingerprint("https://x.ch/", _home(-1, error="ConnectError: unreachable")))
    assert tls["verdict"] == "injoignable"
    r = probe_mod.ProbeReport(url="https://x.ch/", timestamp="t", tls=tls)
    _tier, why = probe_mod._decide_tier(r)
    assert "injoignable" in why and "refusé" not in why


def test_sonde_connexion_coupee_puis_chrome_refuse_reste_bloque(monkeypatch):
    _fake_chrome(monkeypatch, (403, b"Forbidden"))
    tls, _ = asyncio.run(probe_mod.check_tls_fingerprint("https://x.ch/", _home(-1, error="ConnectError: reset")))
    assert tls["verdict"] == "bloqué"


def test_ligne_de_lot_sans_tier_pour_un_site_injoignable():
    r = probe_mod.ProbeReport(url="https://x.ch/", timestamp="t", tls={"tested": True, "verdict": "injoignable"})
    assert batch.probe_row(r)["tier"] is None


# ── Synthèse du lot ──────────────────────────────────────────────────────
def test_synthese_annonce_les_gestes_et_les_redirections():
    rows = [
        {"name": "a", "status": "ok", "tier": 5, "human_gate": "challenge", "redirected_to": None},
        {"name": "b", "status": "ok", "tier": 5, "human_gate": None, "redirected_to": "www.annuaire.com"},
        {"name": "c", "status": "ok", "tier": 5, "human_gate": None, "redirected_to": "www.annuaire.com"},
    ]
    md = batch.summarize("x", rows)
    assert "Gestes humains annoncés : 1 — python -m accesspath gestes --faire" in md
    assert "Redirigés vers un autre site : 2" in md
    assert "| www.annuaire.com | 2 |" in md


def test_synthese_sans_geste_ne_le_mentionne_pas():
    md = batch.summarize("x", [{"name": "a", "status": "ok", "tier": 1, "human_gate": None, "redirected_to": None}])
    assert "Gestes humains" not in md and "Redirigés" not in md


def test_synthese_compte_les_sites_injoignables():
    rows = [{"name": "a", "status": "ok", "tier": None, "tls": "injoignable"}, {"name": "b", "status": "ok", "tier": 1}]
    assert "Sites injoignables : 1" in batch.summarize("x", rows)
