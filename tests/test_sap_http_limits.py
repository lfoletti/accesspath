"""E3 — lecture bornée sur le fil et décompression bornée (bombes gzip/deflate/br).

Serveur local sur 127.0.0.1 ; ACCESSPATH_ALLOW_PRIVATE=1 lève la garde de
destination pour ces tests (et seulement eux).
"""

from __future__ import annotations

import asyncio
import gzip

import pytest

from accesspath import probe as probe_mod
from accesspath import sap_inspect, stealth

from ._localserver import LocalServer, MiB, body, br_bomb, deflate_bomb, gzip_bomb, huge

LIMIT = 50 * MiB


@pytest.fixture(autouse=True)
def _allow_local(monkeypatch):
    monkeypatch.setenv("ACCESSPATH_ALLOW_PRIVATE", "1")


@pytest.fixture(scope="module")
def srv():
    xml_bomb = gzip.compress(b'<?xml version="1.0"?><urlset>' + b" " * (64 * MiB), 9)
    json_bomb = gzip.compress(b"[" + b" " * (64 * MiB), 9)
    routes = {
        "/gzip": gzip_bomb(),
        "/deflate": deflate_bomb(),
        "/br": br_bomb(),
        "/huge": huge(),
        "/zstd": body(
            200, b"\x28\xb5\x2f\xfd\x00\x58\x01\x00\x00garbage", Content_Type="text/html", Content_Encoding="zstd"
        ),
        "/ok": body(200, gzip.compress(b"<html>hello</html>"), Content_Type="text/html", Content_Encoding="gzip"),
        "/": gzip_bomb(),
        "/robots.txt": br_bomb(),
        "/sitemap.xml": body(200, xml_bomb, Content_Type="application/xml", Content_Encoding="gzip"),
        "/api.json": body(200, json_bomb, Content_Type="application/json", Content_Encoding="gzip"),
    }
    with LocalServer(routes) as s:
        yield s


# ── probe (sonde rapide) ───────────────────────────────────────────────────
@pytest.mark.parametrize("path", ["/gzip", "/deflate", "/br", "/huge"])
def test_probe_fetch_refuses_bombs(srv, path):
    r = asyncio.run(probe_mod._fetch(srv.url(path), timeout=20))
    assert r["ok"] is False
    assert len(r["body"]) <= LIMIT
    assert "volumineuse" in (r["error"] or "")


def test_probe_fetch_decodes_normal_gzip(srv):
    r = asyncio.run(probe_mod._fetch(srv.url("/ok"), timeout=10))
    assert r["ok"] is True
    assert r["body"] == b"<html>hello</html>"


def test_probe_fetch_refuses_unrequested_zstd(srv):
    r = asyncio.run(probe_mod._fetch(srv.url("/zstd"), timeout=10))
    assert r["ok"] is False


def test_no_profile_announces_zstd():
    for p in stealth.BROWSER_PROFILES:
        assert "zstd" not in p["Accept-Encoding"], p["_name"]


# ── inspect, étape 1 et robots/sitemap ─────────────────────────────────────
def test_stage1_homepage_bomb_is_an_error(srv):
    f = asyncio.run(sap_inspect._stage1_cheap_probe(srv.url("/"), timeout=20))
    assert f.homepage_fetch_error
    assert f.homepage_body_length <= LIMIT


def test_fetch_robots_bomb_not_fetched(srv):
    r = asyncio.run(sap_inspect._fetch_robots(srv.base))
    assert r.fetched is False


def test_fetch_sitemap_bomb_never_parsed(srv, monkeypatch):
    seen = []
    monkeypatch.setattr(sap_inspect, "_parse_sitemap", lambda text, url: seen.append(len(text)))
    asyncio.run(sap_inspect._fetch_sitemap(srv.base, []))
    assert seen == []


def test_rehearse_tier1_bomb(srv):
    out = sap_inspect._rehearse_tier1(srv.url("/api.json"))
    assert out["status"] == "FAIL"
    assert any("ResponseTooLarge" in e for e in out["evidence"])


def test_rehearse_tier2_sitemap_bomb(srv):
    out = sap_inspect._rehearse_tier2(srv.base + "/", srv.url("/sitemap.xml"))
    assert out["status"] == "FAIL"
    assert any("ResponseTooLarge" in e for e in out["evidence"])


# ── unités du module partagé ───────────────────────────────────────────────
@pytest.mark.parametrize("enc", ["gzip", "deflate", "br"])
def test_bounded_decoder_stops_at_limit(enc):
    import zlib

    import brotli

    from accesspath import _http

    raw = b"\0" * (8 * MiB)
    data = {"gzip": gzip.compress(raw), "deflate": zlib.compress(raw), "br": brotli.compress(raw)}[enc]
    dec = _http.BoundedDecoder(enc, max_out=MiB)
    with pytest.raises(_http.ResponseTooLarge):
        for i in range(0, len(data), 1024):
            dec.feed(data[i : i + 1024])
        dec.flush()
    # gzip/deflate : exact (max_length) ; br : au plus un tampon de plus
    assert dec.produced <= MiB + 256 * 1024


@pytest.mark.parametrize("enc", ["gzip", "deflate", "br", "identity", ""])
def test_bounded_decoder_roundtrip(enc):
    import zlib

    import brotli

    from accesspath import _http

    raw = b"hello world " * 100_000  # > 1 Mio : exerce la vidange par pas du décodeur br
    data = {"gzip": gzip.compress(raw), "deflate": zlib.compress(raw), "br": brotli.compress(raw)}.get(enc, raw)
    dec = _http.BoundedDecoder(enc, max_out=4 * MiB)
    out = b"".join(dec.feed(data[i : i + 4096]) for i in range(0, len(data), 4096)) + dec.flush()
    assert out == raw


def test_bounded_decoder_raw_deflate():
    import zlib

    from accesspath import _http

    c = zlib.compressobj(wbits=-15)
    data = c.compress(b"abc" * 100) + c.flush()
    dec = _http.BoundedDecoder("deflate", max_out=MiB)
    assert dec.feed(data) + dec.flush() == b"abc" * 100


def test_bounded_decoder_refuses_unknown_encoding():
    from accesspath import _http

    with pytest.raises(_http.UnsupportedEncoding):
        _http.BoundedDecoder("zstd", max_out=MiB)


def test_br_not_announced_without_brotli(monkeypatch):
    monkeypatch.setattr(stealth, "_HAS_BROTLI", False, raising=False)
    for _ in range(30):
        h = stealth.random_headers()
        assert "br" not in [e.strip() for e in h["Accept-Encoding"].split(",")]
    monkeypatch.setattr(stealth, "_HAS_BROTLI", True)
    assert any("br" in stealth.random_headers()["Accept-Encoding"] for _ in range(30))
