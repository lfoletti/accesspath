"""CAPTCHA FortiADC : l'audit le reconnaît comme un défi, pas comme une page servie.

Cas d'origine (25.10.2026) : les 24 registres du commerce chregister (AG à ZG, les trois
du Valais) renvoient toute requête, en-têtes de navigateur ou non, vers
`/fortiadc_captcha/index.html`, qui répond 200. L'étape 1 de l'audit y voyait une page
servie de 4 ko ; Chrome sans fenêtre, lui, restait figé sur la page à 100 % du processeur.
"""

from __future__ import annotations

import asyncio

import pytest

from accesspath import sap_inspect as si
from accesspath.acquisition import platforms as pf
from accesspath.human_gate import predict_human_gate

from ._localserver import LocalServer, body
from .test_human_gate import _report

CAPTCHA_PATH = "/fortiadc_captcha/index.html"
CAPTCHA_HTML = (
    b"<!DOCTYPE html><html><head><title>Captcha verify</title></head><body>"
    b'<div id="ftntlogo"></div><iframe src="fortiadc_captcha_iframe.html"></iframe></body></html>'
)


@pytest.fixture(autouse=True)
def _allow_local(monkeypatch):
    monkeypatch.setenv("ACCESSPATH_ALLOW_PRIVATE", "1")


@pytest.fixture(scope="module")
def srv():
    routes = {
        "/": body(302, b"", Location=CAPTCHA_PATH),
        # Sans le marqueur de contenu : seule l'adresse finale trahit le CAPTCHA.
        CAPTCHA_PATH: body(200, b"<title>Captcha verify</title>", Content_Type="text/html"),
        "/sur-place": body(200, CAPTCHA_HTML, Content_Type="text/html"),
        "/robots.txt": body(302, b"", Location=CAPTCHA_PATH),
    }
    with LocalServer(routes) as s:
        yield s


# ── Page lue par Chrome ──────────────────────────────────────────────────
def test_page_captcha_lue_par_chrome_est_un_defi():
    reach = si.classify_page(
        "Captcha verify", "", "https://zh.chregister.ch/", "https://zh.chregister.ch" + CAPTCHA_PATH
    )
    assert reach.status == "challenge" and not reach.hard_block
    assert "FortiADC" in reach.evidence


def test_signature_dans_le_trafic():
    out = si._detect_anti_bot(
        title="Captcha verify",
        html="",
        captured_urls=["https://zh.chregister.ch" + CAPTCHA_PATH],
        captured_headers=[],
    )
    assert out["fortiadc"].detected


def test_signature_dans_la_page():
    out = si._detect_anti_bot(
        title="", html=CAPTCHA_HTML.decode(), captured_urls=["https://x.ch/"], captured_headers=[]
    )
    assert out["fortiadc"].detected


def test_geste_humain_nomme_fortiadc():
    g = predict_human_gate(_report(status="challenge", vendors=("fortiadc",)))
    assert (g.kind, g.vendor) == ("challenge", "fortiadc")


def test_fortiadc_passe_avant_cloudflare():
    g = predict_human_gate(_report(status="challenge", vendors=("cloudflare", "fortiadc")))
    assert g.vendor == "fortiadc"


# ── Étape 1 (HTTP seul) ──────────────────────────────────────────────────
def test_etape1_reconnait_la_redirection_vers_le_captcha(srv):
    f = asyncio.run(si._stage1_cheap_probe(srv.url("/"), timeout=10))
    assert f.homepage_status == 200
    assert f.fortiadc_detected
    assert f.homepage_final_url.endswith(CAPTCHA_PATH)
    # Chrome sans fenêtre fige sur cette page : l'audit s'arrête à l'étape 1.
    assert not f.needs_browser
    assert "FortiADC" in f.decision_rationale


def test_etape1_reconnait_le_captcha_servi_sans_redirection(srv):
    f = asyncio.run(si._stage1_cheap_probe(srv.url("/sur-place"), timeout=10))
    assert f.fortiadc_detected and not f.needs_browser


def test_rapport_d_etape1_annonce_un_defi(srv):
    f = asyncio.run(si._stage1_cheap_probe(srv.url("/"), timeout=10))
    rep = si._build_report_from_stage1(f, srv.url("/"), "x", 0.0)
    assert rep.reachability.status == "challenge"
    assert rep.reachability.final_url.endswith(CAPTCHA_PATH)
    assert rep.anti_bot_stack["fortiadc"].detected
    g = predict_human_gate(rep)
    assert (g.kind, g.vendor) == ("challenge", "fortiadc")


def test_page_servie_sans_captcha_reste_ok():
    f = si.Stage1Findings(homepage_status=200, homepage_body_length=5000, homepage_html_first_kb="<title>A</title>")
    rep = si._build_report_from_stage1(f, "https://a.ch/", "a", 0.0)
    assert rep.reachability.status == "OK"
    assert not rep.anti_bot_stack["fortiadc"].detected


# ── Plateforme chregister ────────────────────────────────────────────────
def test_recette_chregister_annonce_la_barriere():
    hit = pf.detect("https://zh.chregister.ch/cr-portal/")[0]
    assert "FortiADC" in hit["recipe"]["barrier"]
    lines = "\n".join(pf.report_lines([hit], lambda s, n: s))
    assert "Barrière : " in lines and "FortiADC" in lines
