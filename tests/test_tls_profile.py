"""Profil imité réellement (l'alias « chrome » de curl_cffi désigne une version) et
annonce de l'échange de clés post-quantique (X25519MLKEM768, Chrome 131 et après) : un
client qui ne l'annonce pas se signale de lui-même. Avertissement de session quand
l'empreinte passe : les anti-bots cumulent les signaux sur toute la visite."""

from __future__ import annotations

import asyncio

import pytest

from accesspath import _http
from accesspath import probe as probe_mod


@pytest.mark.parametrize(
    "resolved, version, pq",
    [("chrome150", 150, True), ("chrome131", 131, True), ("chrome124", 124, False), ("chrome131_android", 131, True)],
)
def test_profil_et_post_quantique(monkeypatch, resolved, version, pq):
    monkeypatch.setattr(_http, "_resolve_target", lambda target: resolved)
    p = _http.impersonation_profile("chrome")
    assert p == {"target": "chrome", "resolved": resolved, "version": version, "post_quantum": pq}


def test_profil_hors_chrome(monkeypatch):
    monkeypatch.setattr(_http, "_resolve_target", lambda target: "safari2601")
    assert _http.impersonation_profile("safari")["post_quantum"] is None


def test_alias_chrome_resolu_par_curl_cffi():
    p = _http.impersonation_profile("chrome")
    assert p["resolved"].startswith("chrome") and p["resolved"] != "chrome" and p["version"] >= 131


def _report(verdict):
    r = probe_mod.ProbeReport(url="https://x.ch/", timestamp="2026-10-24T00:00:00")
    r.tls = {
        "tested": True,
        "python_status": 403,
        "chrome_status": 200 if verdict == "empreinte" else 403,
        "impersonate": "chrome",
        "profile": {"target": "chrome", "resolved": "chrome150", "version": 150, "post_quantum": True},
        "verdict": verdict,
    }
    return r


def test_rapport_profil_et_avertissement_de_session():
    md = probe_mod.emit_markdown(_report("empreinte"), "x")
    assert "chrome150" in md and "post-quantique (X25519MLKEM768) : oui" in md
    assert "ne garantit pas une session" in md


def test_pas_d_avertissement_de_session_si_bloque():
    assert "ne garantit pas une session" not in probe_mod.emit_markdown(_report("bloqué"), "x")


def test_controle_tls_enregistre_le_profil(monkeypatch):
    async def fake_fetch(url, **kw):
        return {"status": 200, "ok": True, "body": b"<html>ok</html>", "headers": {}, "content_type": "text/html"}

    monkeypatch.setattr(probe_mod, "_fetch", fake_fetch)
    home = {"status": 403, "ok": False, "body": b"", "error": None}
    tls, _ = asyncio.run(probe_mod.check_tls_fingerprint("https://x.ch/", home))
    assert tls["profile"]["resolved"].startswith("chrome")


def test_rapport_profil_sans_post_quantique():
    r = _report("bloqué")
    r.tls["profile"] = {"target": "chrome", "resolved": "chrome124", "version": 124, "post_quantum": False}
    assert "post-quantique (X25519MLKEM768) : non" in probe_mod.emit_markdown(r, "x")
