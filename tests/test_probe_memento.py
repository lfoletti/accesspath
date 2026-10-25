"""Copies d'archive par Memento (RFC 7089) : l'agrégateur Time Travel interroge en une
requête toutes les archives qui parlent le protocole (Wayback, Arquivo.pt, archive.today,
archives nationales…). Rendu : première et dernière capture, archives qui détiennent le
site."""

from __future__ import annotations

import asyncio
import json

import pytest

from accesspath import probe as probe_mod

from ._localserver import LocalServer, body

TT = {
    "original_uri": "https://x.ch/",
    "mementos": {
        "first": {
            "datetime": "2004-05-01T10:00:00Z",
            "uri": ["https://arquivo.pt/wayback/20040501100000/https://x.ch/"],
        },
        "last": {
            "datetime": "2026-10-20T08:00:00Z",
            "uri": ["http://web.archive.org/web/20261020080000/https://x.ch/"],
        },
        "closest": {
            "datetime": "2026-10-20T08:00:00Z",
            "uri": ["http://web.archive.org/web/20261020080000/https://x.ch/", "https://archive.ph/abc"],
        },
    },
}


def test_parse_timetravel():
    stats = probe_mod.parse_timetravel(json.dumps(TT).encode())
    assert stats == {
        "items": None,
        "newest": "2026-10-20",
        "oldest": "2004-05-01",
        "archives": ["archive.ph", "arquivo.pt", "web.archive.org"],
    }


def test_parse_timetravel_illisible():
    assert probe_mod.parse_timetravel(b"pas du json") == {"items": None, "newest": None}


@pytest.fixture(autouse=True)
def _allow_local(monkeypatch):
    monkeypatch.setenv("ACCESSPATH_ALLOW_PRIVATE", "1")


@pytest.fixture
def timetravel(monkeypatch):
    with LocalServer({"*": body(200, json.dumps(TT).encode(), Content_Type="application/json")}) as s:
        monkeypatch.setattr(probe_mod, "MEMENTO_TIMETRAVEL", s.url("/api/json"))
        yield s


def test_memento_copies(timetravel):
    r = asyncio.run(probe_mod.memento_copies("x.ch"))
    assert r["oldest"] == "2004-05-01" and r["archives"] == ["archive.ph", "arquivo.pt", "web.archive.org"]
    path = list(timetravel.log)[-1]
    assert path.startswith("/api/json/") and path.endswith("/https://x.ch/")


def test_memento_sans_capture(monkeypatch):
    with LocalServer({"*": body(404, b"", Content_Type="application/json")}) as s:
        monkeypatch.setattr(probe_mod, "MEMENTO_TIMETRAVEL", s.url("/api/json"))
        r = asyncio.run(probe_mod.memento_copies("x.ch"))
    assert r["items"] == 0 and r["error"] is None


def test_memento_injoignable():
    r = asyncio.run(probe_mod.memento_copies("x.ch"))  # conftest : port fermé
    assert r["items"] is None and r["error"]


def test_copies_tierces_comprennent_memento(timetravel):
    copies = asyncio.run(probe_mod.third_party_copies("x.ch"))
    assert copies["memento"]["archives"] == ["archive.ph", "arquivo.pt", "web.archive.org"]


def test_rapport_ligne_memento(timetravel):
    rep = probe_mod.ProbeReport(url="https://x.ch/", timestamp="2026-10-24T00:00:00")
    rep.copies = asyncio.run(probe_mod.third_party_copies("x.ch"))
    md = probe_mod.emit_markdown(rep, "x").split("## Copies tierces")[1]
    assert "| memento (3 archives : archive.ph, arquivo.pt, web.archive.org) |" in md
    assert "2026-10-20" in md


def test_ancien_rapport_sans_memento():
    rep = probe_mod.ProbeReport(url="https://x.ch/", timestamp="2026-10-24T00:00:00")
    rep.copies = {"wayback": {"items": 2, "newest": "2026-10-20"}, "commoncrawl": {"items": 0}, "legal": "x"}
    md = probe_mod.emit_markdown(rep, "x").split("## Copies tierces")[1]
    assert "| memento" not in md and "| wayback" in md
