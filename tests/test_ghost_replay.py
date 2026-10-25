"""Rejeu du mode fantôme : un gabarit de ghost_spec.yaml redevient des requêtes,
page après page, sans navigateur ; secrets lus à l'environnement ou dans un HAR,
jamais écrits."""

from __future__ import annotations

import json

import pytest
import yaml

from accesspath import _http, cli, ghost

from ._localserver import LocalServer, _send
from .conftest import FIXTURES

HAR = FIXTURES / "ghost" / "listing.har"


@pytest.fixture(autouse=True)
def _allow_local(monkeypatch):
    monkeypatch.setenv("ACCESSPATH_ALLOW_PRIVATE", "1")


PAGES = {
    "1": {"products": [{"id": 1, "name": "a"}, {"id": 2, "name": "b"}], "next_cursor": "c1"},
    "2": {"products": [{"id": 3, "name": "c"}], "next_cursor": "c2"},
    "3": {"products": [], "next_cursor": None},
}


def _rest_template(url):
    return {
        "method": "GET",
        "url": url,
        "path": "/api/products",
        "params": {
            "page": {"role": "pagination", "start": 1, "step": 1},
            "lang": {"role": "constante", "value": "fr"},
            "sig": {"role": "secret", "value": "{secret:sig}"},
            "cursor": {"role": "curseur", "from": "next_cursor"},
            "q": {"role": "variable"},
        },
        "headers": {"Cookie": "{secret:cookie}", "Accept": "application/json"},
        "fields": [],
    }


def _shop(seen):
    def handler(req):
        from urllib.parse import parse_qs, urlsplit

        q = {k: v[0] for k, v in parse_qs(urlsplit(req.path).query).items()}
        seen.append((q, req.headers.get("Cookie")))
        _send(req, 200, json.dumps(PAGES.get(q.get("page"), PAGES["3"])).encode(), {"Content-Type": "application/json"})

    return handler


# ── Généralisation : le pas de la pagination ──────────────────────────────
def test_pas_de_pagination_deduit():
    assert ghost._roles("page", ["1", "2"], [])["step"] == 1
    assert ghost._roles("start", ["0", "24", "48"], [])["step"] == 24
    assert ghost._roles("offset", ["0"], [])["step"] == "items"
    assert ghost._roles("page", ["3"], [])["step"] == 1


# ── Plan d'une requête ───────────────────────────────────────────────────
def test_plan_premiere_page_sans_curseur():
    t = _rest_template("https://b.ch/api/products")
    method, url, headers, body = ghost.plan_request(
        t, {"page": 0, "items": 0, "prev": None}, {"sig": "S", "cookie": "C"}
    )
    assert method == "GET" and body is None
    assert url == "https://b.ch/api/products?page=1&lang=fr&sig=S"
    assert headers == {"Cookie": "C", "Accept": "application/json"}


def test_plan_page_suivante_curseur_et_pas():
    t = _rest_template("https://b.ch/api/products")
    state = {"page": 2, "items": 3, "prev": {"next_cursor": "zz"}}
    _m, url, _h, _b = ghost.plan_request(t, state, {"sig": "S", "cookie": "C"})
    assert "page=3" in url and "cursor=zz" in url


def test_plan_pas_en_items_et_curseur_imbrique():
    t = {
        "method": "GET",
        "url": "https://b.ch/x",
        "params": {
            "offset": {"role": "pagination", "start": 0, "step": "items"},
            "after": {"role": "curseur", "from": "data.items[].id"},
        },
        "headers": {},
    }
    prev = {"data": {"items": [{"id": "first"}, {"id": "last"}]}}
    _m, url, _h, _b = ghost.plan_request(t, {"page": 1, "items": 2, "prev": prev}, {})
    assert url == "https://b.ch/x?offset=2&after=last"


def test_plan_graphql_post():
    t = {
        "method": "POST",
        "url": "https://b.ch/graphql",
        "params": {},
        "headers": {"Authorization": "{secret:authorization}"},
        "operation": "ProductList",
        "query": "query ProductList { x }",
        "variables": {
            "first": {"role": "constante", "value": 24},
            "after": {"role": "curseur", "from": "data.productList.pageInfo.endCursor"},
        },
    }
    prev = {"data": {"productList": {"pageInfo": {"endCursor": "E1"}}}}
    method, _u, headers, body = ghost.plan_request(
        t, {"page": 1, "items": 2, "prev": prev}, {"authorization": "Bearer T"}
    )
    assert method == "POST" and headers["Authorization"] == "Bearer T"
    assert headers["Content-Type"] == "application/json"
    assert json.loads(body) == {
        "operationName": "ProductList",
        "query": "query ProductList { x }",
        "variables": {"first": 24, "after": "E1"},
    }
    _m, _u, _h, body0 = ghost.plan_request(t, {"page": 0, "items": 0, "prev": None}, {"authorization": "Bearer T"})
    assert json.loads(body0)["variables"] == {"first": 24}


# ── Secrets ──────────────────────────────────────────────────────────────
def test_secrets_requis_listes():
    assert ghost.needed_secrets(_rest_template("https://b.ch/api/products")) == ["cookie", "sig"]


def test_secrets_lus_a_l_environnement_puis_au_har():
    t = _rest_template("https://boutique.ch/api/products")
    got, missing = ghost.resolve_secrets(t, ghost.load_har(HAR), env={"ACCESSPATH_SECRET_SIG": "ENV"})
    assert got == {"sig": "ENV", "cookie": "session=SECRET123; theme=dark"} and missing == []
    got, missing = ghost.resolve_secrets(t, None, env={})
    assert got == {} and missing == ["cookie", "sig"]


def test_secret_du_har_pris_au_meme_chemin():
    t = _rest_template("https://boutique.ch/api/products")
    got, _ = ghost.resolve_secrets(t, ghost.load_har(HAR), env={})
    assert got["sig"] == "SECRETSIG"


# ── Rejeu de bout en bout ────────────────────────────────────────────────
def test_rejeu_pagine_jusqu_a_la_page_vide():
    seen, waits = [], []
    with LocalServer({"*": _shop(seen)}) as s, _http.client() as c:
        t = _rest_template(s.url("/api/products"))
        pages = ghost.replay(t, c, {"sig": "S", "cookie": "C"}, pages=10, delay=0.5, sleep=waits.append)
    assert [p["items"] for p in pages] == [2, 1, 0]
    assert [q["page"] for q, _c in seen] == ["1", "2", "3"]
    assert "cursor" not in seen[0][0] and seen[1][0]["cursor"] == "c1" and seen[2][0]["cursor"] == "c2"
    assert all(cookie == "C" for _q, cookie in seen)
    assert waits == [0.5, 0.5]


def test_rejeu_borne_par_pages():
    seen = []
    with LocalServer({"*": _shop(seen)}) as s, _http.client() as c:
        pages = ghost.replay(
            _rest_template(s.url("/api/products")),
            c,
            {"sig": "S", "cookie": "C"},
            pages=1,
            delay=0,
            sleep=lambda _x: None,
        )
    assert len(pages) == 1 and len(seen) == 1


def test_rejeu_arrete_sur_erreur():
    with (
        LocalServer({"*": lambda req: _send(req, 403, b"{}", {"Content-Type": "application/json"})}) as s,
        _http.client() as c,
    ):
        pages = ghost.replay(
            _rest_template(s.url("/api/products")),
            c,
            {"sig": "S", "cookie": "C"},
            pages=5,
            delay=0,
            sleep=lambda _x: None,
        )
    assert [p["status"] for p in pages] == [403]


def test_rejeu_arrete_sur_reponse_repetee():
    same = json.dumps({"products": [{"id": 1}], "next_cursor": "c1"}).encode()
    with (
        LocalServer({"*": lambda req: _send(req, 200, same, {"Content-Type": "application/json"})}) as s,
        _http.client() as c,
    ):
        pages = ghost.replay(
            _rest_template(s.url("/api/products")),
            c,
            {"sig": "S", "cookie": "C"},
            pages=5,
            delay=0,
            sleep=lambda _x: None,
        )
    assert len(pages) == 2 and pages[-1]["repeated"]


def test_rejeu_arrete_sans_curseur_suivant():
    body = json.dumps({"products": [{"id": 1}]}).encode()
    t = {"method": "GET", "url": "", "params": {"after": {"role": "curseur", "from": "next_cursor"}}, "headers": {}}
    with (
        LocalServer({"*": lambda req: _send(req, 200, body, {"Content-Type": "application/json"})}) as s,
        _http.client() as c,
    ):
        t["url"] = s.url("/x")
        pages = ghost.replay(t, c, {}, pages=5, delay=0, sleep=lambda _x: None)
    assert len(pages) == 1


def test_rejeu_graphql_envoie_le_curseur():
    bodies = []

    def handler(req):
        n = int(req.headers.get("Content-Length") or 0)
        b = json.loads(req.rfile.read(n))
        bodies.append(b)
        after = b["variables"].get("after")
        items = [] if after == "E2" else [{"title": "t"}]
        nxt = {None: "E1", "E1": "E2"}.get(after)
        out = {"data": {"productList": {"items": items, "pageInfo": {"endCursor": nxt}}}}
        _send(req, 200, json.dumps(out).encode(), {"Content-Type": "application/json"})

    with LocalServer({"*": handler}) as s, _http.client() as c:
        t = {
            "method": "POST",
            "url": s.url("/graphql"),
            "params": {},
            "headers": {},
            "operation": "P",
            "query": "q",
            "variables": {"after": {"role": "curseur", "from": "data.productList.pageInfo.endCursor"}},
        }
        pages = ghost.replay(t, c, {}, pages=5, delay=0, sleep=lambda _x: None)
    assert [b["variables"].get("after") for b in bodies] == [None, "E1", "E2"]
    assert [p["items"] for p in pages] == [1, 1, 0]


# ── CLI ──────────────────────────────────────────────────────────────────
def _write_spec(tmp_path, url):
    d = tmp_path / "sap" / "shop"
    d.mkdir(parents=True)
    (d / "ghost_spec.yaml").write_text(yaml.safe_dump({"site": "shop", "calls": [_rest_template(url)]}))


def test_cli_replay_sans_spec(tmp_path, monkeypatch):
    monkeypatch.setattr(ghost, "SAP_DIR", tmp_path / "sap")
    assert cli.main(["ghost", "shop", "--replay"]) == 4


def test_cli_har_requis_hors_rejeu(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(ghost, "SAP_DIR", tmp_path / "sap")
    assert cli.main(["ghost", "shop"]) == 2


def test_cli_replay_secrets_manquants_aucune_requete(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(ghost, "SAP_DIR", tmp_path / "sap")
    monkeypatch.delenv("ACCESSPATH_SECRET_SIG", raising=False)
    monkeypatch.delenv("ACCESSPATH_SECRET_COOKIE", raising=False)
    seen = []
    with LocalServer({"*": _shop(seen)}) as s:
        _write_spec(tmp_path, s.url("/api/products"))
        assert cli.main(["ghost", "shop", "--replay"]) == 5
    assert seen == []
    err = capsys.readouterr().err
    assert "ACCESSPATH_SECRET_COOKIE" in err and "ACCESSPATH_SECRET_SIG" in err


def test_cli_replay_avertit_et_sauve(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(ghost, "SAP_DIR", tmp_path / "sap")
    monkeypatch.setenv("ACCESSPATH_SECRET_SIG", "S")
    monkeypatch.setenv("ACCESSPATH_SECRET_COOKIE", "C")
    seen = []
    with LocalServer({"*": _shop(seen)}) as s:
        _write_spec(tmp_path, s.url("/api/products"))
        assert cli.main(["ghost", "shop", "--replay", "--delay", "0", "--save"]) == 0
    out = capsys.readouterr().out
    assert "voie litigieuse" in out and "session authentifiée" in out
    assert "S" not in [line.strip() for line in out.splitlines()] and "=S" not in out
    lines = (tmp_path / "sap" / "shop" / "ghost_replay.jsonl").read_text().splitlines()
    assert [json.loads(x)["items"] for x in lines] == [2, 1, 0]
    assert "C" not in (tmp_path / "sap" / "shop" / "ghost_replay.jsonl").read_text().split('"')


def test_cli_replay_sans_secret_pas_d_avertissement(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(ghost, "SAP_DIR", tmp_path / "sap")
    body = json.dumps({"items": [{"id": 1}]}).encode()
    with LocalServer({"*": lambda req: _send(req, 200, body, {"Content-Type": "application/json"})}) as s:
        d = tmp_path / "sap" / "shop"
        d.mkdir(parents=True)
        t = {"method": "GET", "url": s.url("/x"), "params": {}, "headers": {}}
        (d / "ghost_spec.yaml").write_text(yaml.safe_dump({"site": "shop", "calls": [t]}))
        assert cli.main(["ghost", "shop", "--replay", "--pages", "1"]) == 0
    assert "voie litigieuse" not in capsys.readouterr().out


def test_cli_replay_echec_premiere_page(tmp_path, monkeypatch):
    monkeypatch.setattr(ghost, "SAP_DIR", tmp_path / "sap")
    with LocalServer({"*": lambda req: _send(req, 500, b"x", {"Content-Type": "text/plain"})}) as s:
        d = tmp_path / "sap" / "shop"
        d.mkdir(parents=True)
        t = {"method": "GET", "url": s.url("/x"), "params": {}, "headers": {}}
        (d / "ghost_spec.yaml").write_text(yaml.safe_dump({"site": "shop", "calls": [t]}))
        assert cli.main(["ghost", "shop", "--replay", "--delay", "0"]) == 1


# ── Cas ajoutés après la preuve par mutation ─────────────────────────────
def test_secret_du_har_ignore_un_autre_chemin():
    t = _rest_template("https://b.ch/api/products")
    other = {"method": "GET", "url": "https://b.ch/api/autre?sig=AUTRE", "headers": {"Cookie": "AUTRE"}}
    mine = {"method": "GET", "url": "https://b.ch/api/products?sig=BON", "headers": {"Cookie": "BON"}}
    got, _ = ghost.resolve_secrets(t, [other, mine], env={})
    assert got == {"sig": "BON", "cookie": "BON"}


def test_plan_pas_de_pagination_superieur_a_un():
    t = {
        "method": "GET",
        "url": "https://b.ch/x",
        "params": {"start": {"role": "pagination", "start": 0, "step": 24}},
        "headers": {},
    }
    _m, url, _h, _b = ghost.plan_request(t, {"page": 2, "items": 5, "prev": {}}, {})
    assert url == "https://b.ch/x?start=48"


def test_rejeu_erreur_avec_corps_json_arrete():
    body = json.dumps({"products": [{"id": 1}], "next_cursor": "c1"}).encode()
    with (
        LocalServer({"*": lambda req: _send(req, 429, body, {"Content-Type": "application/json"})}) as s,
        _http.client() as c,
    ):
        pages = ghost.replay(
            _rest_template(s.url("/api/products")),
            c,
            {"sig": "S", "cookie": "C"},
            pages=5,
            delay=0,
            sleep=lambda _x: None,
        )
    assert len(pages) == 1 and pages[0]["data"] is None


def test_rejeu_page_vide_arrete_meme_avec_curseur():
    bodies = iter(
        [
            {"products": [{"id": 1}], "next_cursor": "a"},
            {"products": [], "next_cursor": "b"},
            {"products": [{"id": 9}], "next_cursor": "c"},
        ]
    )

    def handler(req):
        _send(req, 200, json.dumps(next(bodies)).encode(), {"Content-Type": "application/json"})

    with LocalServer({"*": handler}) as s, _http.client() as c:
        pages = ghost.replay(
            _rest_template(s.url("/api/products")),
            c,
            {"sig": "S", "cookie": "C"},
            pages=5,
            delay=0,
            sleep=lambda _x: None,
        )
    assert [p["items"] for p in pages] == [1, 0]


def test_compte_des_elements_ignore_les_listes_de_chaines():
    assert ghost._item_count({"tags": ["a", "b", "c"], "items": [{"x": 1}]}) == 1
