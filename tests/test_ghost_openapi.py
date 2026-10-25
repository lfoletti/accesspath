"""Mode fantôme → OpenAPI 3.1 : chaque gabarit devient une opération, avec ses
paramètres et leur rôle (pagination, curseur, constante, secret), ses en-têtes, le corps
GraphQL et les champs de la réponse. Les secrets restent des références, jamais des
valeurs."""

from __future__ import annotations

import json

import yaml

from accesspath import cli, ghost

SPEC = {
    "site": "boutique",
    "calls": [
        {
            "method": "GET",
            "url": "https://api.boutique.ch/v1/products/123/reviews",
            "path": "/v1/products/<N>/reviews",
            "score": 40.0,
            "samples": 3,
            "params": {
                "page": {"role": "pagination", "start": 1, "step": 1},
                "cursor": {"role": "curseur", "from": "meta.next"},
                "lang": {"role": "constante", "value": "fr"},
                "api_key": {"role": "secret", "value": "{secret:api_key}"},
                "q": {"role": "variable"},
            },
            "headers": {"Authorization": "{secret:authorization}", "X-Client": "web"},
            "fields": ["items[].id", "items[].title", "meta.next"],
        },
        {
            "method": "POST",
            "url": "https://boutique.ch/graphql",
            "path": "/graphql",
            "score": 30.0,
            "samples": 2,
            "params": {},
            "headers": {},
            "fields": ["data.search.items[].name"],
            "operation": "Search",
            "query": "query Search($first: Int) { search(first: $first) { items { name } } }",
            "variables": {"first": {"role": "constante", "value": 20}},
        },
    ],
}


def test_document_openapi():
    doc = ghost.to_openapi(SPEC)
    assert doc["openapi"].startswith("3.1") and "boutique" in doc["info"]["title"]
    assert set(doc["paths"]) == {"/v1/products/{n1}/reviews", "/graphql"}


def test_operation_get_parametres_et_roles():
    op = ghost.to_openapi(SPEC)["paths"]["/v1/products/{n1}/reviews"]["get"]
    assert ghost.to_openapi(SPEC)["paths"]["/v1/products/{n1}/reviews"]["servers"] == [
        {"url": "https://api.boutique.ch"}
    ]
    params = {(p["in"], p["name"]): p for p in op["parameters"]}
    assert params[("path", "n1")]["required"] is True
    assert params[("query", "page")]["schema"] == {"type": "integer", "minimum": 1}
    assert params[("query", "page")]["x-accesspath-role"] == "pagination"
    assert params[("query", "page")]["x-accesspath-step"] == 1
    assert params[("query", "cursor")]["x-accesspath-from"] == "meta.next"
    assert params[("query", "lang")]["schema"] == {"type": "string", "default": "fr"}
    assert params[("query", "q")]["x-accesspath-role"] == "variable"
    assert params[("header", "X-Client")]["schema"] == {"type": "string", "default": "web"}
    assert op["x-accesspath-score"] == 40.0
    assert op["responses"]["200"]["x-accesspath-fields"] == ["items[].id", "items[].title", "meta.next"]


def test_secrets_en_reference_jamais_en_valeur():
    doc = ghost.to_openapi(SPEC)
    op = doc["paths"]["/v1/products/{n1}/reviews"]["get"]
    params = {(p["in"], p["name"]): p for p in op["parameters"]}
    for key in (("query", "api_key"), ("header", "Authorization")):
        assert params[key]["x-accesspath-role"] == "secret"
        assert "default" not in params[key]["schema"]
    assert params[("query", "api_key")]["x-accesspath-env"] == "ACCESSPATH_SECRET_API_KEY"
    assert "{secret:" not in json.dumps(doc)


def test_operation_graphql():
    op = ghost.to_openapi(SPEC)["paths"]["/graphql"]["post"]
    assert op["operationId"] == "Search"
    body = op["requestBody"]["content"]["application/json"]
    assert body["example"]["operationName"] == "Search"
    assert body["example"]["variables"] == {"first": 20}
    assert "search(first" in body["example"]["query"]


def test_operation_ids_uniques():
    spec = {"site": "s", "calls": [dict(SPEC["calls"][0]), dict(SPEC["calls"][0])]}
    ops = [
        op["operationId"]
        for item in ghost.to_openapi(spec)["paths"].values()
        for op in item.values()
        if isinstance(op, dict) and "operationId" in op
    ]
    assert len(ops) == 1  # même chemin et même méthode : une seule opération, la plus probante


def test_cli_openapi(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(ghost, "SAP_DIR", tmp_path)
    (tmp_path / "boutique").mkdir()
    (tmp_path / "boutique" / "ghost_spec.yaml").write_text(yaml.safe_dump(SPEC))
    assert cli.main(["ghost", "boutique", "--openapi"]) == 0
    out = tmp_path / "boutique" / "openapi.json"
    assert json.loads(out.read_text())["paths"]
    assert str(out) in capsys.readouterr().out


def test_cli_openapi_sans_spec(tmp_path, monkeypatch):
    monkeypatch.setattr(ghost, "SAP_DIR", tmp_path)
    assert cli.main(["ghost", "absent", "--openapi"]) == 4


def test_garde_le_gabarit_le_plus_probant():
    weaker = {**SPEC["calls"][0], "score": 5.0, "params": {}}
    doc = ghost.to_openapi({"site": "s", "calls": [SPEC["calls"][0], weaker]})
    assert doc["paths"]["/v1/products/{n1}/reviews"]["get"]["x-accesspath-score"] == 40.0


def test_secret_nomme_par_sa_reference():
    t = {**SPEC["calls"][0], "params": {"key": {"role": "secret", "value": "{secret:token}"}}, "headers": {}}
    op = ghost.to_openapi({"site": "s", "calls": [t]})["paths"]["/v1/products/{n1}/reviews"]["get"]
    p = next(p for p in op["parameters"] if p["name"] == "key")
    assert p["x-accesspath-env"] == "ACCESSPATH_SECRET_TOKEN"


def test_variables_graphql_sans_valeur_connue_exclues():
    t = {
        **SPEC["calls"][1],
        "variables": {
            "first": {"role": "constante", "value": 20},
            "after": {"role": "curseur", "from": "data.next"},
            "page": {"role": "pagination", "start": 2, "step": 1},
            "term": {"role": "variable"},
        },
    }
    op = ghost.to_openapi({"site": "s", "calls": [t]})["paths"]["/graphql"]["post"]
    assert op["requestBody"]["content"]["application/json"]["example"]["variables"] == {"first": 20, "page": 2}


def test_types_des_constantes():
    from accesspath.ghost import _schema_for

    assert _schema_for(True)["type"] == "boolean"
    assert _schema_for(3)["type"] == "integer"
    assert _schema_for(1.5)["type"] == "number"
    assert _schema_for("x")["type"] == "string"
