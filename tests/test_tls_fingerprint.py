"""Empreinte TLS : quand l'accueil refuse Python, une requête de contrôle imite Chrome
(curl_cffi). Si elle passe, le site filtre sur l'empreinte : la sonde continue par
l'imitation et l'entrée SAP porte tls_fingerprint. Même garde et mêmes bornes qu'httpx."""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from accesspath import _http
from accesspath import probe as probe_mod

from ._localserver import LocalServer, _send, body, slow


@pytest.fixture(autouse=True)
def _allow_local(monkeypatch):
    monkeypatch.setenv("ACCESSPATH_ALLOW_PRIVATE", "1")


# ── _http.aimpersonate_get : imitation bornée et gardée ──────────────────
def test_imitation_lit_une_page():
    with LocalServer({"/": body(200, b"<html>ok</html>", Content_Type="text/html")}) as s:
        r = asyncio.run(_http.aimpersonate_get(s.url("/")))
    assert r.status_code == 200 and r.content == b"<html>ok</html>"
    assert r.headers["content-type"] == "text/html"


def test_imitation_envoie_une_empreinte_de_navigateur():
    seen = {}

    def h(req):
        seen.update(req.headers)
        _send(req, 200, b"ok", {"Content-Type": "text/plain"})

    with LocalServer({"/": h}) as s:
        asyncio.run(_http.aimpersonate_get(s.url("/"), headers={"Accept": "text/html"}))
    assert "Chrome" in seen.get("User-Agent", "")
    assert seen.get("Accept") == "text/html"


def test_imitation_garde_chaque_redirection(monkeypatch):
    checked = []
    real = _http.assert_public_async

    async def guard(url):
        checked.append(url)
        await real(url)

    monkeypatch.setattr(_http, "assert_public_async", guard)
    with LocalServer({"/a": body(302, b"", Location="/b"), "/b": body(200, b"fin", Content_Type="text/plain")}) as s:
        r = asyncio.run(_http.aimpersonate_get(s.url("/a")))
    assert r.content == b"fin" and checked == [s.url("/a"), s.url("/b")]
    assert r.history == [s.url("/a")] and r.url == s.url("/b")


def test_imitation_refuse_une_redirection_interne(monkeypatch):
    async def guard(url):
        if url.endswith("/interne"):
            raise _http.BlockedDestination("interne")

    monkeypatch.setattr(_http, "assert_public_async", guard)
    with LocalServer({"/a": body(302, b"", Location="/interne"), "/interne": body(200, b"secret")}) as s:
        with pytest.raises(_http.BlockedDestination):
            asyncio.run(_http.aimpersonate_get(s.url("/a")))
        assert s.hits["/interne"] == 0


def test_imitation_borne_les_redirections():
    with LocalServer({"*": body(302, b"", Location="/boucle")}) as s:
        with pytest.raises(_http.TooManyRedirects):
            asyncio.run(_http.aimpersonate_get(s.url("/boucle")))
        assert s.hits["/boucle"] == _http.MAX_REDIRECTS + 1


def test_imitation_borne_la_taille():
    with LocalServer({"/": body(200, b"x" * 5000, Content_Type="text/plain")}) as s:
        with pytest.raises(_http.ResponseTooLarge):
            asyncio.run(_http.aimpersonate_get(s.url("/"), max_decoded=1000))


def test_imitation_borne_le_temps():
    with LocalServer({"/": slow(3.0, status=200, payload=b"tard")}) as s:
        with pytest.raises(_http.DeadlineExceeded):
            asyncio.run(_http.aimpersonate_get(s.url("/"), total_timeout=0.5))


# ── Le contrôle d'empreinte dans la sonde ────────────────────────────────
def _home(status, body_=b"", error=None):
    return {
        "status": status,
        "ok": 0 < status < 400,
        "content_type": "text/html",
        "headers": {},
        "body": body_,
        "duration_s": 0.1,
        "error": error,
    }


def _fake_chrome(monkeypatch, result, calls=None):
    async def fake(url, *, headers=None, impersonate=_http.IMPERSONATE_TARGET, max_decoded=0, total_timeout=None):
        if calls is not None:
            calls.append((url, headers, impersonate))
        if isinstance(result, Exception):
            raise result
        return _http.Response(result[0], httpx.Headers({"content-type": "text/html"}), result[1], url)

    monkeypatch.setattr(_http, "aimpersonate_get", fake)


def test_pas_de_controle_quand_python_passe(monkeypatch):
    calls = []
    _fake_chrome(monkeypatch, (200, b"ok"), calls)
    tls, chrome = asyncio.run(probe_mod.check_tls_fingerprint("https://x.ch/", _home(200, b"ok")))
    assert tls == {"tested": False} and chrome is None and calls == []


@pytest.mark.parametrize("status", [403, 503])
def test_empreinte_quand_chrome_passe(monkeypatch, status):
    _fake_chrome(monkeypatch, (200, b"<html><title>Boutique</title></html>"))
    tls, chrome = asyncio.run(probe_mod.check_tls_fingerprint("https://x.ch/", _home(status)))
    assert tls == {
        "tested": True,
        "python_status": status,
        "chrome_status": 200,
        "impersonate": "chrome",
        "profile": _http.impersonation_profile("chrome"),
        "verdict": "empreinte",
    }
    assert chrome["body"].startswith(b"<html><title>Boutique")


def test_connexion_coupee_declenche_le_controle(monkeypatch):
    _fake_chrome(monkeypatch, (200, b"ok"))
    tls, _ = asyncio.run(
        probe_mod.check_tls_fingerprint("https://x.ch/", _home(-1, error="RemoteProtocolError: reset"))
    )
    assert tls["verdict"] == "empreinte"


@pytest.mark.parametrize("error", ["BlockedDestination: interne", "DeadlineExceeded: lent", "ResponseTooLarge: gros"])
def test_erreurs_de_garde_ne_declenchent_pas(monkeypatch, error):
    calls = []
    _fake_chrome(monkeypatch, (200, b"ok"), calls)
    tls, _ = asyncio.run(probe_mod.check_tls_fingerprint("https://x.ch/", _home(-1, error=error)))
    assert tls == {"tested": False} and calls == []


def test_defi_quand_chrome_recoit_une_page_de_defi(monkeypatch):
    _fake_chrome(monkeypatch, (200, b"<html><title>Just a moment...</title></html>"))
    tls, chrome = asyncio.run(probe_mod.check_tls_fingerprint("https://x.ch/", _home(403)))
    assert tls["verdict"] == "défi" and chrome is None


def test_defi_aussi_sur_un_refus_qui_porte_un_defi(monkeypatch):
    _fake_chrome(monkeypatch, (403, b"<script src='https://geo.captcha-delivery.com/c.js'></script>"))
    tls, _ = asyncio.run(probe_mod.check_tls_fingerprint("https://x.ch/", _home(403)))
    assert tls["verdict"] == "défi"


def test_bloque_quand_chrome_est_refuse(monkeypatch):
    _fake_chrome(monkeypatch, (403, b"Forbidden"))
    tls, chrome = asyncio.run(probe_mod.check_tls_fingerprint("https://x.ch/", _home(403)))
    assert tls["verdict"] == "bloqué" and tls["chrome_status"] == 403 and chrome is None


def test_bloque_quand_chrome_echoue(monkeypatch):
    _fake_chrome(monkeypatch, httpx.ConnectError("reset"))
    tls, _ = asyncio.run(probe_mod.check_tls_fingerprint("https://x.ch/", _home(403)))
    assert tls["verdict"] == "bloqué" and tls["chrome_status"] == -1


def test_imitation_indisponible(monkeypatch):
    calls = []
    _fake_chrome(monkeypatch, (200, b"ok"), calls)
    monkeypatch.setattr(_http, "impersonation_available", lambda: False)
    tls, chrome = asyncio.run(probe_mod.check_tls_fingerprint("https://x.ch/", _home(403)))
    assert tls == {"tested": False, "verdict": "indisponible", "python_status": 403} and chrome is None
    assert calls == []


def test_fetch_imite_sans_en_tetes_de_navigateur_aleatoires(monkeypatch):
    calls = []
    _fake_chrome(monkeypatch, (200, b"{}"), calls)

    async def run():
        token = probe_mod._IMPERSONATE.set("chrome")
        try:
            return await probe_mod._fetch("https://x.ch/a", accept="application/json", extra_headers={"X-K": "v"})
        finally:
            probe_mod._IMPERSONATE.reset(token)

    r = asyncio.run(run())
    assert r["status"] == 200
    _url, headers, target = calls[0]
    assert target == "chrome"
    assert headers == {"Accept": "application/json", "X-K": "v"}


# ── De bout en bout : un site qui ne refuse que l'empreinte de Python ─────
def _tls_site(monkeypatch):
    """Le serveur refuse toute requête sans l'en-tête que pose la fausse imitation."""

    async def fake(url, *, headers=None, impersonate="chrome", max_decoded=_http.MAX_DECODED_BYTES, total_timeout=None):
        async with _http.async_client() as c:
            return await _http.aget(c, url, headers={**(headers or {}), "X-Imite": impersonate})

    monkeypatch.setattr(_http, "aimpersonate_get", fake)

    def gate(payload, ctype):
        def h(req):
            if req.headers.get("X-Imite") != "chrome":
                _send(req, 403, b"Forbidden", {"Content-Type": "text/plain"})
            else:
                _send(req, 200, payload, {"Content-Type": ctype})

        return h

    feed = (
        b'<?xml version="1.0"?><rss><channel><item><title>a</title></item><item><title>b</title></item></channel></rss>'
    )
    return {
        "/": gate(
            b"<html><head><title>Boutique</title></head><body><p>" + b"texte " * 300 + b"</p></body></html>",
            "text/html",
        ),
        "/robots.txt": gate(b"User-agent: *\nAllow: /\n", "text/plain"),
        "/feed": gate(feed, "application/rss+xml"),
        "*": gate(b"not found", "text/plain"),
    }


def test_sonde_de_bout_en_bout_par_l_empreinte(monkeypatch):
    with LocalServer(_tls_site(monkeypatch)) as s:
        report = asyncio.run(probe_mod.probe(s.url("/"), copies=False))
    assert report.tls["verdict"] == "empreinte"
    assert report.tier1["skipped_by_robots"] == []  # robots relu par l'imitation, pas « tout interdit »
    assert report.tier1["rss_feeds"]
    assert report.chosen_tier == 1 and "empreinte TLS" in report.rationale
    entry = probe_mod.emit_sap_entry(report)
    assert entry["tls_fingerprint"] == "chrome" and entry["tls_check"]["verdict"] == "empreinte"
    md = probe_mod.emit_markdown(report, "boutique")
    assert "## Empreinte TLS" in md and "curl_cffi" in md
    assert json.dumps(report.to_dict())  # sérialisable
    assert report.to_dict()["tls_fingerprint"]["verdict"] == "empreinte"


def test_sonde_sans_refus_ne_teste_pas(monkeypatch):
    calls = []
    _fake_chrome(monkeypatch, (200, b"ok"), calls)
    page = b"<html><head><title>T</title></head><body>" + b"mot " * 300 + b"</body></html>"
    with LocalServer({"/": body(200, page, Content_Type="text/html")}) as s:
        report = asyncio.run(probe_mod.probe(s.url("/"), copies=False))
    assert report.tls == {"tested": False} and calls == []
    assert "tls_fingerprint" not in probe_mod.emit_sap_entry(report)
    assert "## Empreinte TLS" not in probe_mod.emit_markdown(report, "t")


def test_raison_quand_meme_chrome_est_refuse():
    r = probe_mod.ProbeReport(url="https://x.ch/", timestamp="t")
    r.tls = {"tested": True, "python_status": 403, "chrome_status": 403, "impersonate": "chrome", "verdict": "bloqué"}
    _tier, why = probe_mod._decide_tier(r)
    assert "Chrome imité" in why and "navigateur" in why


def test_squelette_porte_l_empreinte():
    import ast

    r = probe_mod.ProbeReport(url="https://x.ch/", timestamp="2026-10-24T00:00:00")
    r.tls = {
        "tested": True,
        "python_status": 403,
        "chrome_status": 200,
        "impersonate": "chrome",
        "verdict": "empreinte",
    }
    src = probe_mod.emit_skeleton(r, "x_ch")
    ast.parse(src)
    assert "tls_fingerprint='chrome'" in src
    r.tls = {"tested": False}
    assert "tls_fingerprint" not in probe_mod.emit_skeleton(r, "x_ch")


def test_imitation_absente_sans_curl_cffi(monkeypatch):
    import sys

    monkeypatch.setitem(sys.modules, "curl_cffi.requests", None)
    assert _http.impersonation_available() is False


def test_sonde_analyse_la_page_obtenue_par_l_imitation(monkeypatch):
    with LocalServer(_tls_site(monkeypatch)) as s:
        report = asyncio.run(probe_mod.probe(s.url("/"), copies=False))
    assert report.tier2.get("fetched") is True


def test_imitation_disponible_dans_un_processus_neuf():
    """macOS 13 : les roues curl_cffi 0.15+ exigent CoreFoundation déjà chargé."""
    import subprocess
    import sys

    code = "from accesspath import _http; print(_http.impersonation_available())"
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60)
    assert out.stdout.strip() == "True", out.stderr
