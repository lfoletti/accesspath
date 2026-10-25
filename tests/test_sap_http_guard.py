"""M2 — garde de destination : pas d'adresse interne, ni pour la cible, ni
après une redirection, ni via une ligne Sitemap de robots.txt ; rehearse
reste sur le site audité.

Aucun accès réseau : les transports httpx sont espionnés et refusent tout
hôte autre que 127.0.0.1.
"""

from __future__ import annotations

import asyncio
import ipaddress

import httpx
import pytest
import yaml

from accesspath import _http, cli, sap_inspect
from accesspath import probe as probe_mod

from ._localserver import LocalServer, body


@pytest.fixture(autouse=True)
def transport_spy(monkeypatch):
    """Enregistre chaque hôte contacté ; seul 127.0.0.1 passe réellement."""
    seen: list[str] = []
    real_async = httpx.AsyncHTTPTransport.handle_async_request
    real_sync = httpx.HTTPTransport.handle_request

    async def _a(self, request):
        seen.append(request.url.host)
        if request.url.host != "127.0.0.1":
            raise httpx.ConnectError("réseau interdit dans les tests", request=request)
        return await real_async(self, request)

    def _s(self, request):
        seen.append(request.url.host)
        if request.url.host != "127.0.0.1":
            raise httpx.ConnectError("réseau interdit dans les tests", request=request)
        return real_sync(self, request)

    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", _a)
    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", _s)
    return seen


@pytest.fixture(autouse=True)
def _strict(monkeypatch):
    monkeypatch.delenv("ACCESSPATH_ALLOW_PRIVATE", raising=False)
    if hasattr(_http, "_ALLOW_PRIVATE"):
        monkeypatch.setattr(_http, "_ALLOW_PRIVATE", False)


@pytest.fixture
def loopback_is_public(monkeypatch):
    """127.0.0.1 traité comme public pour simuler un site ; tout le reste privé."""
    monkeypatch.setattr(_http, "_ip_is_public", lambda ip: str(ip) == "127.0.0.1", raising=False)


@pytest.fixture(scope="module")
def srv():
    with LocalServer({}) as s:
        routes = s.routes
        routes["/"] = body(200, b"<html>home</html>", Content_Type="text/html")
        routes["/to-v6"] = body(302, b"", Location=f"http://[::1]:{s.port}/secret")
        routes["/to-meta"] = body(302, b"", Location="http://169.254.169.254/latest/meta-data/")
        routes["/to-ftp"] = body(302, b"", Location="ftp://127.0.0.1/x")
        routes["/secret"] = body(200, b"secret", Content_Type="text/plain")
        routes["/api.json"] = body(200, b"[]", Content_Type="application/json")
        routes["/index.xml"] = body(
            200,
            b'<?xml version="1.0"?><sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
            b"<sitemap><loc>http://other.test/sub.xml</loc></sitemap></sitemapindex>",
            Content_Type="application/xml",
        )
        yield s


# ── classification des adresses ───────────────────────────────────────────
@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",
        "10.1.2.3",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "100.64.0.1",
        "0.0.0.0",
        "224.0.0.1",
        "240.0.0.1",
        "255.255.255.255",
        "::1",
        "fe80::1",
        "fc00::1",
        "::ffff:127.0.0.1",
        "::ffff:10.0.0.1",
        "ff02::1",
        "::",
        "2002:7f00:1::1",
        "2002:a00:1::1",
    ],
)
def test_private_addresses_refused(ip):
    assert _http._ip_is_public(ipaddress.ip_address(ip)) is False


@pytest.mark.parametrize("ip", ["93.184.216.34", "1.1.1.1", "2606:4700:4700::1111"])
def test_public_addresses_allowed(ip):
    assert _http._ip_is_public(ipaddress.ip_address(ip)) is True


def test_assert_public_refuses_localhost_name():
    with pytest.raises(_http.BlockedDestination):
        _http.assert_public("http://localhost/")


def test_assert_public_refuses_other_schemes(monkeypatch):
    with pytest.raises(_http.BlockedDestination):
        _http.assert_public("file:///etc/passwd")
    monkeypatch.setattr(_http, "_ALLOW_PRIVATE", True)  # même --allow-private n'ouvre pas ftp
    with pytest.raises(_http.BlockedDestination):
        _http.assert_public("ftp://127.0.0.1/x")


def test_allow_private_switch(monkeypatch):
    monkeypatch.setattr(_http, "_ALLOW_PRIVATE", True)
    _http.assert_public("http://127.0.0.1/")  # ne lève pas


# ── la cible ───────────────────────────────────────────────────────────────
def test_probe_refuses_private_target(srv):
    r = asyncio.run(probe_mod._fetch(srv.url("/"), timeout=5))
    assert r["ok"] is False
    assert "BlockedDestination" in r["error"]
    assert srv.hits["/"] == 0


def test_rehearse_tier1_refuses_private_target(srv):
    out = sap_inspect._rehearse_tier1(srv.url("/api.json"))
    assert any("BlockedDestination" in e for e in out["evidence"])
    assert srv.hits["/api.json"] == 0


def test_inspect_refuses_private_target_before_any_probe(monkeypatch):
    async def _boom(*a, **k):
        raise AssertionError("l'étape 1 ne doit pas partir")

    monkeypatch.setattr(sap_inspect, "_stage1_cheap_probe", _boom)
    with pytest.raises(_http.BlockedDestination):
        asyncio.run(sap_inspect.inspect("http://127.0.0.1:9/", "x"))


# ── les redirections ───────────────────────────────────────────────────────
@pytest.mark.parametrize("path", ["/to-v6", "/to-meta"])
def test_redirect_to_private_is_blocked(srv, path, loopback_is_public, transport_spy):
    r = asyncio.run(probe_mod._fetch(srv.url(path), timeout=5))
    assert r["ok"] is False
    assert "BlockedDestination" in r["error"]
    assert transport_spy == ["127.0.0.1"]  # seule la première requête est partie


def test_sync_redirect_to_private_is_blocked(srv, loopback_is_public, transport_spy):
    with _http.client(timeout=5) as c:
        with pytest.raises(_http.BlockedDestination):
            _http.get(c, srv.url("/to-meta"))
    assert transport_spy == ["127.0.0.1"]


def test_redirect_to_ftp_is_refused(srv, loopback_is_public):
    r = asyncio.run(probe_mod._fetch(srv.url("/to-ftp"), timeout=5))
    assert r["ok"] is False


# ── robots.txt : lignes Sitemap ────────────────────────────────────────────
def test_robots_sitemap_lines_are_guarded(srv, loopback_is_public, transport_spy):
    asyncio.run(
        sap_inspect._fetch_sitemap(
            srv.base,
            ["http://10.0.0.1/sitemap.xml", "file:///etc/passwd", "http://169.254.169.254/s.xml"],
        )
    )
    assert set(transport_spy) <= {"127.0.0.1"}


# ── rehearse : rester sur le site audité ───────────────────────────────────
def test_in_scope():
    assert sap_inspect._in_scope("https://api.example.com/x", "https://www.example.com/")
    assert sap_inspect._in_scope("https://example.com/x", "https://www.example.com/")
    assert not sap_inspect._in_scope("https://example.com.evil.net/x", "https://example.com/")
    assert not sap_inspect._in_scope("https://evil.net/x", "https://example.com/")
    assert not sap_inspect._in_scope("https://evilexample.com/x", "https://example.com/")
    assert not sap_inspect._in_scope("file:///etc/passwd", "https://example.com/")


@pytest.fixture
def sap_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(sap_inspect, "SAP_DIR", tmp_path / "sap")
    return tmp_path / "sap"


def _shards(sap_dir, name, *, url, tier, api_src=None, sitemap=None):
    d = sap_dir / name
    d.mkdir(parents=True)
    (d / "04_strategy.yaml").write_text(yaml.safe_dump({"url": url, "tier_recommendation": {"primary": tier}}))
    tech = {"url": url}
    if api_src:
        tech["public_api"] = {"value": "rest", "sources": [api_src]}
    if sitemap:
        tech["sitemap"] = {"url": sitemap}
    (d / "02_technical.yaml").write_text(yaml.safe_dump(tech))


def test_rehearse_tier1_stays_on_audited_site(srv, sap_dir, monkeypatch, transport_spy):
    monkeypatch.setattr(_http, "_ALLOW_PRIVATE", True)
    _shards(sap_dir, "site_x", url=srv.base + "/", tier=1, api_src="http://other.test/api → 200 json")
    out = sap_inspect.rehearse_strategy("site_x")
    assert out["status"] == "FAIL"
    assert "other.test" not in transport_spy


def test_rehearse_tier2_stays_on_audited_site(srv, sap_dir, monkeypatch, transport_spy):
    monkeypatch.setattr(_http, "_ALLOW_PRIVATE", True)
    _shards(sap_dir, "site_y", url=srv.base + "/", tier=2, sitemap="http://other.test/sitemap.xml")
    out = sap_inspect.rehearse_strategy("site_y")
    assert out["status"] == "FAIL"
    assert "other.test" not in transport_spy


def test_rehearse_tier2_skips_foreign_sub_sitemaps(srv, monkeypatch, transport_spy):
    monkeypatch.setattr(_http, "_ALLOW_PRIVATE", True)
    sap_inspect._rehearse_tier2(srv.base + "/", srv.url("/index.xml"))
    assert "other.test" not in transport_spy


# ── CLI : --allow-private explicite ────────────────────────────────────────
def test_cli_allow_private_flag(monkeypatch, tmp_path):
    seen = {}

    async def _fake_probe(url, **_k):
        seen["allowed"] = _http.private_allowed()
        return probe_mod.ProbeReport(url=url, timestamp="2026-10-24T00:00:00+00:00")

    monkeypatch.setattr(probe_mod, "probe", _fake_probe)
    cli.main(["sap", "probe", "http://127.0.0.1:8000/", "--allow-private"])
    assert seen["allowed"] is True
    seen.clear()
    monkeypatch.setattr(_http, "_ALLOW_PRIVATE", False)
    cli.main(["sap", "probe", "http://127.0.0.1:8000/"])
    assert seen["allowed"] is False


def test_robots_sitemap_lines_non_http_never_requested(srv, monkeypatch):
    asked = []
    real = _http.aget

    async def _spy(client, url, **k):
        asked.append(url)
        return await real(client, url, **k)

    monkeypatch.setattr(_http, "aget", _spy)
    monkeypatch.setattr(_http, "_ALLOW_PRIVATE", True)
    asyncio.run(sap_inspect._fetch_sitemap(srv.base, ["file:///etc/passwd", "ftp://127.0.0.1/s.xml"]))
    assert not [u for u in asked if not u.startswith("http")]


def test_rehearse_tier2_sample_url_stays_on_site(srv, monkeypatch, transport_spy):
    monkeypatch.setattr(_http, "_ALLOW_PRIVATE", True)
    srv.routes["/urlset.xml"] = body(
        200,
        b'<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
        b"<url><loc>http://other.test/2026/01/article/deep/path</loc></url></urlset>",
        Content_Type="application/xml",
    )
    out = sap_inspect._rehearse_tier2(srv.base + "/", srv.url("/urlset.xml"))
    assert "other.test" not in transport_spy
    assert out.get("sample_url") is None


def test_probe_refuses_private_target_before_any_request(srv):
    before = sum(srv.hits.values())
    with pytest.raises(_http.BlockedDestination):
        asyncio.run(probe_mod.probe(srv.url("/")))
    assert sum(srv.hits.values()) == before
