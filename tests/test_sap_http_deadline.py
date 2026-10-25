"""M3 — échéances : par requête (lecture comprise) et globale (probe, étape 1).

Serveur local « goutte-à-goutte » : en-têtes immédiats puis un octet toutes les
0,2 s ; un délai par opération ne se déclenche donc jamais.
"""

from __future__ import annotations

import asyncio
import time

import pytest

from accesspath import _http, sap_inspect
from accesspath import probe as probe_mod

from ._localserver import LocalServer, drip


@pytest.fixture(autouse=True)
def _allow_local(monkeypatch):
    monkeypatch.setenv("ACCESSPATH_ALLOW_PRIVATE", "1")


@pytest.fixture(scope="module")
def srv():
    with LocalServer({"*": drip(seconds=30, interval=0.2)}) as s:
        yield s


def test_probe_fetch_total_deadline(srv):
    t0 = time.monotonic()
    r = asyncio.run(probe_mod._fetch(srv.url("/"), timeout=1.0))
    assert time.monotonic() - t0 < 5
    assert r["ok"] is False


def test_sync_get_total_deadline(srv, monkeypatch):
    monkeypatch.setattr(_http, "REQUEST_DEADLINE_S", 1.0)
    t0 = time.monotonic()
    out = sap_inspect._rehearse_tier1(srv.url("/api.json"))
    assert time.monotonic() - t0 < 5
    assert out["status"] == "FAIL"


def test_probe_global_deadline(srv):
    t0 = time.monotonic()
    with pytest.raises(TimeoutError):
        asyncio.run(probe_mod.probe(srv.url("/"), deadline=2.0))
    assert time.monotonic() - t0 < 6


def test_stage1_global_deadline(srv):
    t0 = time.monotonic()
    f = asyncio.run(sap_inspect._stage1_cheap_probe(srv.url("/"), timeout=6.0, deadline=2.0))
    assert time.monotonic() - t0 < 6
    assert "échéance" in f.homepage_fetch_error
    assert f.needs_browser is True
