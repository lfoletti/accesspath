"""M4 — politesse de la sonde : rafale arrêtée au premier 429/503, Retry-After
respecté, tier 1 limité à 4 requêtes simultanées, robots.txt lu d'abord et
chemins interdits pour `*` sautés (et signalés)."""

from __future__ import annotations

import asyncio

import pytest

from accesspath import probe as probe_mod

from ._localserver import LocalServer, body, slow


@pytest.fixture(autouse=True)
def _allow_local(monkeypatch):
    monkeypatch.setenv("ACCESSPATH_ALLOW_PRIVATE", "1")


@pytest.mark.parametrize("status", [429, 503])
def test_burst_stops_at_first_throttle(status):
    with LocalServer({"/": body(status, b"slow down", Content_Type="text/plain", Retry_After="120")}) as s:
        rl = asyncio.run(probe_mod.measure_rate_limit(s.url("/"), n=20))
        assert s.hits["/"] == 1
    assert rl["throttling_detected"] is True
    assert rl["retry_after_s"] == 120


def test_retry_after_http_date_parsed():
    assert probe_mod._parse_retry_after("Wed, 21 Oct 2015 07:28:00 GMT") == 0
    assert probe_mod._parse_retry_after("7") == 7
    assert probe_mod._parse_retry_after("n'importe quoi") is None


def _wp_server(retry_after: str):
    return LocalServer(
        {
            "/": body(429, b"slow down", Content_Type="text/plain", Retry_After=retry_after),
            "/wp-json": body(200, b"{}", Content_Type="application/json"),
            "/wp-json/wp/v2/posts": body(200, b"[]", Content_Type="application/json"),
        }
    )


def test_retry_after_is_waited_before_next_request():
    with _wp_server("1") as s:
        asyncio.run(probe_mod.probe(s.url("/")))
        last_root = max(t for p, t in s.times if p == "/")
        schema = [t for p, t in s.times if p.startswith("/wp-json/wp/v2/posts?per_page=100")]
    assert schema, "l'échantillon de schéma doit partir après l'attente"
    assert schema[0] - last_root >= 0.9


def test_long_retry_after_skips_remaining_requests():
    with _wp_server("3600") as s:
        report = asyncio.run(probe_mod.probe(s.url("/")))
        assert not [p for p in s.log if p.startswith("/wp-json/wp/v2/posts?per_page=100")]
    assert "Retry-After" in report.schema_sample.get("skipped", "")


def test_tier1_parallelism_capped_at_4():
    with LocalServer({"*": slow(0.3)}) as s:
        asyncio.run(probe_mod.discover_tier1(s.base))
        assert 1 <= s.max_active <= 4


ROBOTS = b"User-agent: *\nDisallow: /api\nDisallow: /wp-json\nDisallow: /graphql\n\nUser-agent: gptbot\nDisallow: /\n"


def test_tier1_skips_paths_disallowed_by_robots():
    with LocalServer({"/robots.txt": body(200, ROBOTS, Content_Type="text/plain")}) as s:
        t1 = asyncio.run(probe_mod.discover_tier1(s.base))
        asked = list(s.log)
    assert not [p for p in asked if p.startswith(("/api", "/wp-json", "/graphql"))]
    assert asked.count("/robots.txt") == 1
    assert "/api/v1" in t1["skipped_by_robots"]
    assert "/wp-json" in t1["skipped_by_robots"]
    assert "/feed" not in t1["skipped_by_robots"]


def test_burst_skipped_when_target_disallowed():
    robots = b"User-agent: *\nDisallow: /\n"
    with LocalServer(
        {
            "/robots.txt": body(200, robots, Content_Type="text/plain"),
            "/": body(200, b"<html></html>", Content_Type="text/html"),
        }
    ) as s:
        report = asyncio.run(probe_mod.probe(s.url("/")))
        assert s.hits["/"] <= 1
    assert report.rate_limit.get("skipped")


def test_markdown_reports_robots_skips_and_burst_stop():
    with LocalServer(
        {
            "/robots.txt": body(200, ROBOTS, Content_Type="text/plain"),
            "/": body(429, b"", Content_Type="text/plain", Retry_After="3600"),
        }
    ) as s:
        report = asyncio.run(probe_mod.probe(s.url("/")))
    md = probe_mod.emit_markdown(report, "site_x")
    assert "/wp-json" in md and "robots.txt" in md
    assert "3600" in md


def test_parallel_burst_stops_after_first_wave():
    with LocalServer({"/": body(429, b"", Content_Type="text/plain")}) as s:
        rl = asyncio.run(probe_mod.measure_rate_limit(s.url("/"), n=20, parallel=True))
        assert s.hits["/"] <= 4
    assert rl["stopped_early"] is True


def test_robots_forbidden_means_disallow_all():
    with LocalServer({"/robots.txt": body(403, b"", Content_Type="text/plain")}) as s:
        t1 = asyncio.run(probe_mod.discover_tier1(s.base))
        assert s.log == ["/robots.txt"]
    assert len(t1["skipped_by_robots"]) == len(probe_mod.TIER1_PROBES) - 1
