"""Préférences d'usage déclarées par un site (AIPREF Content-Usage, TDMRep, llms.txt),
robots d'IA dans robots.txt, accès payant (HTTP 402, Pay Per Crawl). Lues dans ce que la
sonde a déjà (en-têtes, HTML, robots.txt) et dans deux fichiers prévus pour cela."""

from __future__ import annotations

import asyncio

import pytest

from accesspath import probe as probe_mod
from accesspath.usage_prefs import (
    ai_crawler_rules,
    parse_content_usage,
    pay_per_crawl,
    robots_content_usage,
    tdm_from_html,
)

from ._localserver import LocalServer, body


@pytest.fixture(autouse=True)
def _allow_local(monkeypatch):
    monkeypatch.setenv("ACCESSPATH_ALLOW_PRIVATE", "1")


def test_content_usage_en_tete():
    assert parse_content_usage("train-ai=n, search=y") == {"train-ai": "n", "search": "y"}
    assert parse_content_usage("train-ai=n;q=1,  bulk = y ") == {"train-ai": "n", "bulk": "y"}
    assert parse_content_usage("") == {} and parse_content_usage(None) == {}


def test_content_usage_dans_robots():
    txt = "User-agent: *\nContent-Usage: train-ai=n\nContent-Usage: /actu/ train-ai=y\nDisallow: /admin\n"
    assert robots_content_usage(txt) == [
        {"path": "/", "prefs": {"train-ai": "n"}},
        {"path": "/actu/", "prefs": {"train-ai": "y"}},
    ]


ROBOTS = """User-agent: GPTBot
Disallow: /

User-agent: CCBot
Disallow: /archives/

User-agent: *
Allow: /
"""


def test_robots_d_ia():
    rules = ai_crawler_rules(ROBOTS)
    assert rules["GPTBot"] == "bloqué"
    assert rules["CCBot"] == "partiel"
    assert rules["ClaudeBot"] == "permis"


def test_robots_d_ia_tous_bloques_par_defaut():
    rules = ai_crawler_rules("User-agent: *\nDisallow: /\n")
    assert set(rules.values()) == {"bloqué"}


def test_tdm_dans_le_html():
    html = '<meta name="tdm-reservation" content="1"><meta name="tdm-policy" content="https://x.ch/p.json">'
    assert tdm_from_html(html) == {"tdm-reservation": "1", "tdm-policy": "https://x.ch/p.json"}
    assert tdm_from_html("<p>rien</p>") == {}


def test_acces_payant():
    assert pay_per_crawl(402, {}) == {"status": 402}
    assert pay_per_crawl(200, {"crawler-price": "USD 0.01"}) == {"status": 200, "crawler-price": "USD 0.01"}
    assert pay_per_crawl(200, {}) is None


def _site(robots: bytes, *, home_headers=None, extra=None):
    routes = {
        "/": body(
            200,
            b"<html><head><title>C</title></head><body>" + b"mot " * 300 + b"</body></html>",
            Content_Type="text/html",
            **(home_headers or {}),
        ),
        "/robots.txt": body(200, robots, Content_Type="text/plain"),
    }
    routes.update(extra or {})
    return LocalServer(routes)


def test_probe_rapporte_les_preferences():
    robots = b"User-agent: GPTBot\nDisallow: /\n\nUser-agent: *\nContent-Usage: train-ai=n\nAllow: /\n"
    extra = {
        "/llms.txt": body(200, b"# Commune\n> Site officiel\n", Content_Type="text/plain"),
        "/.well-known/tdmrep.json": body(
            200, b'[{"location":"/","tdm-reservation":1}]', Content_Type="application/json"
        ),
    }
    with _site(robots, home_headers={"Content_Usage": "train-ai=n", "Tdm_Reservation": "1"}, extra=extra) as s:
        rep = asyncio.run(probe_mod.probe(s.url("/")))
    u = rep.usage
    assert u["content_usage_header"] == {"train-ai": "n"}
    assert u["robots_content_usage"] == [{"path": "/", "prefs": {"train-ai": "n"}}]
    assert u["ai_crawlers"]["GPTBot"] == "bloqué"
    assert u["tdmrep"]["header"] == {"tdm-reservation": "1"}
    assert u["tdmrep"]["well_known"] == [{"location": "/", "tdm-reservation": 1}]
    assert u["llms_txt"]["present"] is True and u["llms_txt"]["title"] == "Commune"
    assert u["pay_per_crawl"] is None
    md = probe_mod.emit_markdown(rep, "x")
    assert "## Préférences d'usage déclarées" in md and "train-ai" in md and "GPTBot" in md
    assert probe_mod.emit_sap_entry(rep)["usage_preferences"]["llms_txt"]["present"] is True


def test_probe_sans_rien_de_declare():
    with _site(b"User-agent: *\nAllow: /\n") as s:
        rep = asyncio.run(probe_mod.probe(s.url("/")))
    u = rep.usage
    assert u["content_usage_header"] == {} and u["robots_content_usage"] == []
    assert u["llms_txt"]["present"] is False and u["tdmrep"]["well_known"] is None
    assert "Aucune préférence déclarée" in probe_mod.emit_markdown(rep, "x")


def test_probe_respecte_robots_pour_les_fichiers():
    robots = b"User-agent: *\nDisallow: /llms.txt\nDisallow: /.well-known/\n"
    with _site(robots, extra={"/llms.txt": body(200, b"# X\n")}) as s:
        rep = asyncio.run(probe_mod.probe(s.url("/")))
        log = list(s.log)
    assert "/llms.txt" not in log and "/.well-known/tdmrep.json" not in log
    assert rep.usage["llms_txt"]["skipped"]


def test_disallow_vide_permet_tout():
    assert ai_crawler_rules("User-agent: GPTBot\nDisallow:\n")["GPTBot"] == "permis"


def test_groupes_de_robots_separes():
    rules = ai_crawler_rules("User-agent: GPTBot\nAllow: /\n\nUser-agent: ClaudeBot\nDisallow: /tmp/\n")
    assert rules["GPTBot"] == "permis" and rules["ClaudeBot"] == "partiel"


def test_meta_sans_rapport_ignoree():
    assert tdm_from_html('<meta name="description" content="Commune"><meta content="x">') == {}


def test_tdmrep_json_et_titre_llms():
    from accesspath.usage_prefs import llms_title, parse_tdmrep_json

    assert parse_tdmrep_json(b'{"tdm-reservation": 1}') is None
    assert parse_tdmrep_json(b"pas du json") is None
    assert llms_title(b"## Section\n# Titre\n") == "Titre"


def test_llms_txt_en_html_n_est_pas_un_llms_txt():
    page = b"<html><body>Page introuvable</body></html>"
    with _site(b"User-agent: *\nAllow: /\n", extra={"/llms.txt": body(200, page, Content_Type="text/html")}) as s:
        rep = asyncio.run(probe_mod.probe(s.url("/")))
    assert rep.usage["llms_txt"]["present"] is False
