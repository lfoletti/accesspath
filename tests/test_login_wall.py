"""Tier 3 seulement derrière un vrai mur de connexion : un accueil réduit à un formulaire
de connexion (moins de LOGIN_PAGE_MAX_LINKS liens internes). Un lien « Connexion » vers
un espace réservé, sur un site public, ne fait pas un mur (faux positif vu sur les sites
communaux, 24.10.2026)."""

from __future__ import annotations

import asyncio

from accesspath import sap_inspect as si
from accesspath.human_gate import LOGIN_PAGE_MAX_LINKS
from accesspath.sap_inspect import StructuralFeatures, login_wall

from .test_sap_browser_lifecycle import (  # noqa: F401 — fixtures
    FakeBrowser,
    FakeTab,
    _allow_local,
    fake_nodriver,
    no_pkill,
    stage1_needs_browser,
)


def test_lien_de_connexion_sur_un_site_public():
    assert not login_wall(StructuralFeatures(has_login_link=True, n_internal_links=80))


def test_formulaire_sur_un_site_riche():
    assert not login_wall(StructuralFeatures(has_login_form=True, n_internal_links=80))


def test_accueil_reduit_a_un_formulaire():
    assert login_wall(StructuralFeatures(has_login_form=True, n_internal_links=LOGIN_PAGE_MAX_LINKS - 1))
    assert not login_wall(StructuralFeatures(has_login_form=True, n_internal_links=LOGIN_PAGE_MAX_LINKS))


def test_sans_structure():
    assert not login_wall(None)


class PageTab(FakeTab):
    async def evaluate(self, expr):
        if expr == "document.title":
            return "Gemeinde"
        if "innerText" in expr:
            return "Willkommen"
        return ""


def _inspect(monkeypatch, struct):
    async def get(self, url):
        return PageTab()

    async def features(tab):
        return struct

    monkeypatch.setattr(FakeBrowser, "get", get)
    monkeypatch.setattr(si, "_extract_structural_features", features)
    return asyncio.run(si.inspect("http://127.0.0.1:9/", "site_x", timeout=0, headless=True))


def test_inspect_site_public_avec_lien_de_connexion(fake_nodriver, stage1_needs_browser, monkeypatch, no_pkill):  # noqa: F811
    report = _inspect(monkeypatch, StructuralFeatures(has_login_link=True, n_internal_links=80))
    assert report.tier_recommendation.primary != 3
    assert not any("login wall" in n for n in report.ethics_check.notes)


def test_inspect_mur_de_connexion(fake_nodriver, stage1_needs_browser, monkeypatch, no_pkill):  # noqa: F811
    report = _inspect(monkeypatch, StructuralFeatures(has_login_form=True, n_internal_links=2))
    assert report.tier_recommendation.primary == 3
    assert any("login wall" in n for n in report.ethics_check.notes)
