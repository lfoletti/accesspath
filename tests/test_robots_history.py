"""Histoire du robots.txt d'un site dans la Wayback Machine : versions distinctes
(index CDX, une ligne par contenu), position de chaque robot d'IA à chaque version,
et dates des changements (premier blocage, réouverture)."""

from __future__ import annotations

import asyncio
import json

import pytest

from accesspath import robots_history as rh

from ._localserver import LocalServer, body

OPEN = "User-agent: *\nDisallow:\n"
BLOCK_GPT = OPEN + "\nUser-agent: GPTBot\nDisallow: /\n"
BLOCK_BOTH = BLOCK_GPT + "\nUser-agent: CCBot\nDisallow: /\n"
REOPEN_GPT = OPEN + "\nUser-agent: CCBot\nDisallow: /\n"

CDX = [
    ["timestamp", "digest", "statuscode"],
    ["20220101000000", "A", "200"],
    ["20230815120000", "B", "200"],
    ["20231001000000", "C", "200"],
    ["20250301000000", "D", "200"],
]


def test_parse_cdx():
    assert rh.parse_cdx(json.dumps(CDX).encode()) == [
        ("20220101000000", "A"),
        ("20230815120000", "B"),
        ("20231001000000", "C"),
        ("20250301000000", "D"),
    ]
    assert rh.parse_cdx(b"") == [] and rh.parse_cdx(b"[]") == [] and rh.parse_cdx(b"{oops") == []


def test_echantillon_garde_premiere_et_derniere():
    versions = [(f"2020{i:02d}01000000", str(i)) for i in range(1, 13)]
    kept = rh.sample(versions, 4)
    assert len(kept) == 4 and kept[0] == versions[0] and kept[-1] == versions[-1]
    assert rh.sample(versions[:3], 4) == versions[:3]


def test_evenements():
    snaps = [("2022-01-01", OPEN), ("2023-08-15", BLOCK_GPT), ("2023-10-01", BLOCK_BOTH), ("2025-03-01", REOPEN_GPT)]
    ev = rh.events(snaps)
    assert {"date": "2023-08-15", "bot": "GPTBot", "from": "permis", "to": "bloqué"} in ev
    assert {"date": "2023-10-01", "bot": "CCBot", "from": "permis", "to": "bloqué"} in ev
    assert {"date": "2025-03-01", "bot": "GPTBot", "from": "bloqué", "to": "permis"} in ev
    assert len(ev) == 3


def test_premiers_blocages_et_reouvertures():
    ev = [
        {"date": "2023-08-15", "bot": "GPTBot", "from": "permis", "to": "bloqué"},
        {"date": "2024-01-01", "bot": "GPTBot", "from": "bloqué", "to": "permis"},
        {"date": "2024-06-01", "bot": "GPTBot", "from": "permis", "to": "bloqué"},
        {"date": "2023-10-01", "bot": "CCBot", "from": "permis", "to": "partiel"},
    ]
    assert rh.first_blocked(ev) == {"GPTBot": "2023-08-15"}
    assert rh.reopened(ev) == {"GPTBot": "2024-01-01"}


def test_bloque_des_la_premiere_version():
    snaps = [("2021-01-01", BLOCK_GPT), ("2024-01-01", BLOCK_GPT)]
    h = rh.summarize_snapshots(snaps)
    assert h["first_blocked"] == {"GPTBot": "≤2021-01-01"}
    assert h["events"] == []


@pytest.fixture(autouse=True)
def _allow_local(monkeypatch):
    monkeypatch.setenv("ACCESSPATH_ALLOW_PRIVATE", "1")

    async def no_wait(seconds):  # les pauses de reprise ne ralentissent pas la suite
        pass

    monkeypatch.setattr(rh, "_sleep", no_wait)


def test_histoire_de_bout_en_bout(monkeypatch):
    texts = {
        "20220101000000": OPEN,
        "20230815120000": BLOCK_GPT,
        "20231001000000": BLOCK_BOTH,
        "20250301000000": REOPEN_GPT,
    }
    routes = {"/cdx": body(200, json.dumps(CDX).encode(), Content_Type="application/json")}
    for ts, t in texts.items():
        routes[f"/web/{ts}id_/https://m.ch/robots.txt"] = body(200, t.encode(), Content_Type="text/plain")
    with LocalServer(routes) as s:
        monkeypatch.setattr(rh, "WAYBACK_CDX", s.url("/cdx"))
        monkeypatch.setattr(rh, "WAYBACK_WEB", s.url("/web"))
        h = asyncio.run(rh.robots_history("m.ch", delay=0))
        cdx_query = next(p for p in s.log if p.startswith("/cdx"))
    assert "collapse=digest" in cdx_query and "robots.txt" in cdx_query
    assert h["versions"] == 4 and h["fetched"] == 4
    assert h["first_blocked"] == {"CCBot": "2023-10-01", "GPTBot": "2023-08-15"}
    assert h["reopened"] == {"GPTBot": "2025-03-01"}
    assert h["current"]["CCBot"] == "bloqué" and h["error"] is None


def test_version_illisible_ignoree(monkeypatch):
    routes = {
        "/cdx": body(200, json.dumps(CDX[:3]).encode(), Content_Type="application/json"),
        "/web/20220101000000id_/https://m.ch/robots.txt": body(200, OPEN.encode(), Content_Type="text/plain"),
        "/web/20230815120000id_/https://m.ch/robots.txt": body(503, b"", Content_Type="text/plain"),
    }
    with LocalServer(routes) as s:
        monkeypatch.setattr(rh, "WAYBACK_CDX", s.url("/cdx"))
        monkeypatch.setattr(rh, "WAYBACK_WEB", s.url("/web"))
        h = asyncio.run(rh.robots_history("m.ch", delay=0))
    assert h["versions"] == 2 and h["fetched"] == 1 and h["events"] == []


def test_page_html_n_est_pas_un_robots(monkeypatch):
    routes = {
        "/cdx": body(200, json.dumps(CDX[:2]).encode(), Content_Type="application/json"),
        "/web/20220101000000id_/https://m.ch/robots.txt": body(
            200, b"<html><body>Disallow: /</body></html>", Content_Type="text/html"
        ),
    }
    with LocalServer(routes) as s:
        monkeypatch.setattr(rh, "WAYBACK_CDX", s.url("/cdx"))
        monkeypatch.setattr(rh, "WAYBACK_WEB", s.url("/web"))
        h = asyncio.run(rh.robots_history("m.ch", delay=0))
    assert h["fetched"] == 0


def test_archive_injoignable(monkeypatch):
    async def no_sleep(s):
        pass

    monkeypatch.setattr(rh, "_sleep", no_sleep)
    h = asyncio.run(rh.robots_history("m.ch", delay=0))  # conftest : port fermé
    assert h["versions"] is None and h["error"] and h["unavailable"] is True


def test_ligne_de_lot():
    h = {
        "versions": 4,
        "fetched": 4,
        "first_blocked": {"GPTBot": "2023-08-15"},
        "reopened": {},
        "events": [1, 2],
        "current": {"GPTBot": "bloqué", "CCBot": "permis"},
        "error": None,
    }
    row = rh.history_row(h)
    assert row == {
        "status": "ok",
        "versions": 4,
        "first_blocked": {"GPTBot": "2023-08-15"},
        "reopened": {},
        "changes": 2,
        "ai_blocked_now": ["GPTBot"],
    }
    assert rh.history_row({**h, "versions": None, "error": "x"})["status"] == "error"


# ── Lot : --mode history ─────────────────────────────────────────────────
def test_runner_de_lot(monkeypatch):
    from accesspath import batch

    async def fake(netloc, **kw):
        assert netloc == "m.ch"
        return {
            "versions": 2,
            "fetched": 2,
            "events": [],
            "first_blocked": {},
            "reopened": {},
            "current": {},
            "error": None,
        }

    monkeypatch.setattr(rh, "robots_history", fake)
    row = asyncio.run(batch.history_runner(deadline=5)({"name": "m", "url": "https://m.ch/", "extra": {}}))
    assert row["status"] == "ok" and row["versions"] == 2


def test_runner_de_lot_echeance(monkeypatch):
    from accesspath import batch

    async def lent(netloc, **kw):
        await asyncio.sleep(5)

    monkeypatch.setattr(rh, "robots_history", lent)
    row = asyncio.run(batch.history_runner(deadline=0.1)({"name": "m", "url": "https://m.ch/", "extra": {}}))
    assert row["status"] == "timeout"


def test_synthese_histoire():
    from accesspath import batch

    rows = [
        {
            "status": "ok",
            "first_blocked": {"GPTBot": "2023-08-15", "CCBot": "≤2021-01-01"},
            "reopened": {"GPTBot": "2025-03-01"},
        },
        {"status": "ok", "first_blocked": {"GPTBot": "2023-08-30"}, "reopened": {}},
    ]
    md = batch.summarize("medias", rows)
    months = md.split("## Premiers blocages par mois")[1]
    assert "| 2023-08 | 2 |" in months and "≤" not in months.split("##")[0]
    assert "| GPTBot | 1 |" in md.split("## Réouvertures")[1]


def test_cli_mode_history(tmp_path, monkeypatch):
    from accesspath import batch, cli

    async def fake(netloc, **kw):
        return {
            "versions": 1,
            "fetched": 1,
            "events": [],
            "first_blocked": {},
            "reopened": {},
            "current": {},
            "error": None,
        }

    monkeypatch.setattr(rh, "robots_history", fake)
    lst = tmp_path / "medias.txt"
    lst.write_text("https://m.ch/\n")
    assert cli.main(["sap", "batch", str(lst), "--mode", "history", "--out", str(tmp_path / "o")]) == 0
    assert json.loads((tmp_path / "o" / "results.jsonl").read_text())["versions"] == 1
    assert batch.MAX_CONCURRENCY["history"] <= 4


# ── Dates affinées et reprise ────────────────────────────────────────────
def _cdx(n):
    return [["timestamp", "digest", "statuscode"]] + [
        [f"2023{1 + i // 28:02d}{1 + i % 28:02d}000000", str(i), "200"] for i in range(n)
    ]


def test_date_affinee_par_dichotomie(monkeypatch):
    rows = _cdx(16)
    routes = {"/cdx": body(200, json.dumps(rows).encode(), Content_Type="application/json")}
    for i, (ts, _d, _s) in enumerate(rows[1:]):
        text = BLOCK_GPT if i >= 14 else OPEN
        routes[f"/web/{ts}id_/https://m.ch/robots.txt"] = body(200, text.encode(), Content_Type="text/plain")
    with LocalServer(routes) as s:
        monkeypatch.setattr(rh, "WAYBACK_CDX", s.url("/cdx"))
        monkeypatch.setattr(rh, "WAYBACK_WEB", s.url("/web"))
        h = asyncio.run(rh.robots_history("m.ch", limit=3, delay=0))
        fetched = sum(1 for p in s.log if p.startswith("/web"))
    assert h["first_blocked"] == {"GPTBot": rh._date(rows[15][0])}  # version 14 : le changement exact
    assert fetched == 3 + 3  # échantillon (0, 8, 15), puis 11, 13, 14 : par le milieu


def test_dichotomie_bornee(monkeypatch):
    monkeypatch.setattr(rh, "MAX_FETCHES", 4)
    rows = _cdx(16)
    routes = {"/cdx": body(200, json.dumps(rows).encode(), Content_Type="application/json")}
    for i, (ts, _d, _s) in enumerate(rows[1:]):
        text = BLOCK_GPT if i >= 11 else OPEN
        routes[f"/web/{ts}id_/https://m.ch/robots.txt"] = body(200, text.encode(), Content_Type="text/plain")
    with LocalServer(routes) as s:
        monkeypatch.setattr(rh, "WAYBACK_CDX", s.url("/cdx"))
        monkeypatch.setattr(rh, "WAYBACK_WEB", s.url("/web"))
        asyncio.run(rh.robots_history("m.ch", limit=10, delay=0))
        assert sum(1 for p in s.log if p.startswith("/web")) == 4  # le plafond borne aussi l'échantillon


def test_reprise_apres_429(monkeypatch):
    calls = []

    def flaky(req):
        calls.append(1)
        if len(calls) == 1:
            return body(429, b"slow down", Content_Type="text/plain")(req)
        return body(200, OPEN.encode(), Content_Type="text/plain")(req)

    async def no_sleep(s):
        no_sleep.waits.append(s)

    no_sleep.waits = []
    monkeypatch.setattr(rh, "_sleep", no_sleep)
    routes = {
        "/cdx": body(200, json.dumps(CDX[:2]).encode(), Content_Type="application/json"),
        "/web/20220101000000id_/https://m.ch/robots.txt": flaky,
    }
    with LocalServer(routes) as s:
        monkeypatch.setattr(rh, "WAYBACK_CDX", s.url("/cdx"))
        monkeypatch.setattr(rh, "WAYBACK_WEB", s.url("/web"))
        h = asyncio.run(rh.robots_history("m.ch", delay=0))
    assert h["fetched"] == 1 and len(calls) == 2 and no_sleep.waits == [rh.BACKOFF_S[0]]


def test_abandon_apres_les_reprises(monkeypatch):
    async def no_sleep(s):
        pass

    monkeypatch.setattr(rh, "_sleep", no_sleep)
    routes = {
        "/cdx": body(200, json.dumps(CDX[:2]).encode(), Content_Type="application/json"),
        "/web/20220101000000id_/https://m.ch/robots.txt": body(429, b"", Content_Type="text/plain"),
    }
    with LocalServer(routes) as s:
        monkeypatch.setattr(rh, "WAYBACK_CDX", s.url("/cdx"))
        monkeypatch.setattr(rh, "WAYBACK_WEB", s.url("/web"))
        h = asyncio.run(rh.robots_history("m.ch", delay=0))
        tries = s.hits["/web/20220101000000id_/https://m.ch/robots.txt"]
    assert h["fetched"] == 0 and tries == 1 + len(rh.BACKOFF_S)


def test_cdx_refuse_n_est_pas_repris(monkeypatch):
    async def no_sleep(s):
        raise AssertionError("pas d'attente sur un refus")

    monkeypatch.setattr(rh, "_sleep", no_sleep)
    with LocalServer({"/cdx": body(403, b"requires authorization", Content_Type="text/html")}) as s:
        monkeypatch.setattr(rh, "WAYBACK_CDX", s.url("/cdx"))
        h = asyncio.run(rh.robots_history("m.ch", delay=0))
    assert h["versions"] is None and h["error"] == "HTTP 403"


# ── Archive qui ferme la porte ───────────────────────────────────────────
def test_connexion_refusee_arrete_le_site(monkeypatch):
    rows = _cdx(10)
    with LocalServer({"/cdx": body(200, json.dumps(rows).encode(), Content_Type="application/json")}) as s:
        monkeypatch.setattr(rh, "WAYBACK_CDX", s.url("/cdx"))
        monkeypatch.setattr(rh, "WAYBACK_WEB", "http://127.0.0.1:9/web")
        seen = []
        orig = rh._get

        async def spy(url):
            seen.append(url)
            return await orig(url)

        monkeypatch.setattr(rh, "_get", spy)
        h = asyncio.run(rh.robots_history("m.ch", delay=0))
    assert h["unavailable"] is True and h["versions"] is None and "indisponible" in h["error"]
    assert len(seen) == 2  # index, puis une seule version : on n'insiste pas


def test_runner_attend_puis_reprend(monkeypatch):
    from accesspath import batch

    answers = [
        {"versions": None, "unavailable": True, "error": "archive indisponible"},
        {"versions": 3, "fetched": 3, "events": [], "first_blocked": {}, "reopened": {}, "current": {}, "error": None},
    ]

    async def fake(netloc, **kw):
        return answers.pop(0)

    waits = []

    async def no_sleep(s):
        waits.append(s)

    monkeypatch.setattr(rh, "robots_history", fake)
    monkeypatch.setattr(batch, "_cooldown_sleep", no_sleep)
    row = asyncio.run(batch.history_runner(deadline=5)({"name": "m", "url": "https://m.ch/", "extra": {}}))
    assert row["status"] == "ok" and waits == [batch.ARCHIVE_COOLDOWN_S]


def test_runner_archive_fermee_arrete_le_lot(monkeypatch):
    from accesspath import batch

    calls = []

    async def fake(netloc, **kw):
        calls.append(netloc)
        return {"versions": None, "unavailable": True, "error": "archive indisponible"}

    async def no_sleep(s):
        pass

    monkeypatch.setattr(rh, "robots_history", fake)
    monkeypatch.setattr(batch, "_cooldown_sleep", no_sleep)
    run = batch.history_runner(deadline=5)
    first = asyncio.run(run({"name": "a", "url": "https://a.ch/", "extra": {}}))
    second = asyncio.run(run({"name": "b", "url": "https://b.ch/", "extra": {}}))
    assert first["status"] == second["status"] == "archive_indisponible"
    assert first["retry"] is True and second["retry"] is True
    assert calls == ["a.ch", "a.ch"]  # b n'est pas tenté


def test_reprise_relance_les_lignes_a_refaire(tmp_path):
    from accesspath import batch

    results = tmp_path / "results.jsonl"
    results.write_text(
        json.dumps({"url": "https://a.ch/", "status": "ok"})
        + "\n"
        + json.dumps({"url": "https://b.ch/", "status": "archive_indisponible", "retry": True})
        + "\n"
    )
    assert batch._done_urls(results) == {"https://a.ch/"}


def test_resultats_derniere_ligne_par_site(tmp_path):
    from accesspath import batch

    results = tmp_path / "results.jsonl"
    results.write_text(
        "\n".join(
            json.dumps(r)
            for r in (
                {"url": "https://b.ch/", "status": "archive_indisponible", "retry": True},
                {"url": "https://a.ch/", "status": "ok"},
                {"url": "https://b.ch/", "status": "ok", "versions": 2},
            )
        )
        + "\n\n"
    )
    rows = batch.read_results(results)
    assert [(r["url"], r["status"]) for r in rows] == [("https://b.ch/", "ok"), ("https://a.ch/", "ok")]


def test_dichotomie_seulement_sur_les_blocages(monkeypatch):
    rows = _cdx(16)
    partial = "User-agent: *\nDisallow: /admin\n"  # tous les robots : permis → partiel
    routes = {"/cdx": body(200, json.dumps(rows).encode(), Content_Type="application/json")}
    for i, (ts, _d, _s) in enumerate(rows[1:]):
        text = partial if i >= 11 else OPEN
        routes[f"/web/{ts}id_/https://m.ch/robots.txt"] = body(200, text.encode(), Content_Type="text/plain")
    with LocalServer(routes) as s:
        monkeypatch.setattr(rh, "WAYBACK_CDX", s.url("/cdx"))
        monkeypatch.setattr(rh, "WAYBACK_WEB", s.url("/web"))
        h = asyncio.run(rh.robots_history("m.ch", limit=3, delay=0))
        fetched = sum(1 for p in s.log if p.startswith("/web"))
    assert fetched == 3  # aucun blocage ne change : pas de relecture
    assert h["events"] and all(e["to"] == "partiel" for e in h["events"])


def test_connexion_coupee_n_arrete_pas_le_site(monkeypatch):
    rows = _cdx(3)
    orig = rh._get

    async def flaky(url):
        if url.endswith(f"{rows[2][0]}id_/https://m.ch/robots.txt"):
            return {"ok": False, "status": -1, "body": b"", "error": "RemoteProtocolError: peer closed connection"}
        return await orig(url)

    routes = {"/cdx": body(200, json.dumps(rows).encode(), Content_Type="application/json")}
    for ts, _d, _s in rows[1:]:
        routes[f"/web/{ts}id_/https://m.ch/robots.txt"] = body(200, OPEN.encode(), Content_Type="text/plain")
    with LocalServer(routes) as s:
        monkeypatch.setattr(rh, "WAYBACK_CDX", s.url("/cdx"))
        monkeypatch.setattr(rh, "WAYBACK_WEB", s.url("/web"))
        monkeypatch.setattr(rh, "_get", flaky)
        h = asyncio.run(rh.robots_history("m.ch", delay=0))
    assert h.get("unavailable") is not True and h["versions"] == 3 and h["fetched"] == 2


def test_index_coupe_n_est_pas_une_porte_fermee(monkeypatch):
    async def cut(url):
        return {"ok": False, "status": -1, "body": b"", "error": "ReadTimeout: lecture trop longue"}

    monkeypatch.setattr(rh, "_get", cut)
    h = asyncio.run(rh.robots_history("m.ch", delay=0))
    assert h["unavailable"] is False and h["versions"] is None
