"""Mode fantôme : la navigation du porteur, enregistrée en HAR, devient une
spécification d'appels rejouables : appels de données classés, paramètres
généralisés (pagination, curseur, constante), secrets expurgés."""

from __future__ import annotations

import yaml

from accesspath import cli, ghost

from .conftest import FIXTURES

HAR = FIXTURES / "ghost" / "listing.har"
VISIBLE = (FIXTURES / "ghost" / "visible.txt").read_text()


def test_load_har_decode_base64_et_methode():
    calls = ghost.load_har(HAR)
    assert len(calls) == 7
    p2 = next(c for c in calls if "page=2" in c["url"])
    assert '"Table Prouv' in p2["body"]
    gql = next(c for c in calls if c["url"].endswith("/graphql"))
    assert gql["method"] == "POST" and "ProductList" in gql["post"]


def test_rank_data_calls_par_le_texte_affiche():
    ranked = ghost.rank_data_calls(ghost.load_har(HAR), VISIBLE)
    urls = [c["url"] for _s, c in ranked]
    assert urls[0].startswith("https://boutique.ch/api/products") or urls[0].endswith("/graphql")
    top3 = " ".join(urls[:3])
    assert "/api/products" in top3 and "/graphql" in top3
    # bruit et appels sans données affichées : absents
    assert not any(u.endswith(".css") or "google-analytics" in u or u.endswith("/collection") for u in urls)
    assert not any(u.endswith("/api/user/me") for u in urls)


def test_rank_sans_texte_affiche_garde_les_listes():
    ranked = ghost.rank_data_calls(ghost.load_har(HAR), None)
    urls = [c["url"] for _s, c in ranked]
    assert any("/api/products" in u for u in urls) and any(u.endswith("/graphql") for u in urls)
    assert not any(u.endswith("/api/user/me") for u in urls)  # objet seul, pas une liste


def test_generalize_pagination_curseur_constante():
    spec = ghost.build_spec("boutique_ch", ghost.load_har(HAR), VISIBLE)
    rest = next(t for t in spec["calls"] if t["path"] == "/api/products")
    p = rest["params"]
    assert p["page"]["role"] == "pagination"
    assert p["lang"] == {"role": "constante", "value": "fr"}
    assert p["cursor"]["role"] == "curseur" and p["cursor"]["from"] == "next_cursor"
    gql = next(t for t in spec["calls"] if t["path"] == "/graphql")
    assert gql["method"] == "POST" and gql["operation"] == "ProductList"
    assert gql["variables"]["first"] == {"role": "constante", "value": 24}
    assert gql["variables"]["after"]["role"] == "curseur"


def test_secrets_expurges():
    spec = ghost.build_spec("boutique_ch", ghost.load_har(HAR), VISIBLE)
    text = yaml.safe_dump(spec, allow_unicode=True)
    for secret in ("SECRET123", "SECRET456", "SECRET789", "SECRETSIG", "x@y.z"):
        assert secret not in text
    rest = next(t for t in spec["calls"] if t["path"] == "/api/products")
    assert rest["headers"]["Cookie"] == "{secret:cookie}"
    assert rest["headers"]["Authorization"] == "{secret:authorization}"
    assert rest["params"]["sig"] == {"role": "secret", "value": "{secret:sig}"}
    assert "User-Agent" not in rest["headers"]  # en-têtes de navigateur : fournis au rejeu


def test_champs_echantillon_sans_valeurs():
    spec = ghost.build_spec("boutique_ch", ghost.load_har(HAR), VISIBLE)
    rest = next(t for t in spec["calls"] if t["path"] == "/api/products")
    assert {"products[].name", "products[].price", "next_cursor"} <= set(rest["fields"])
    assert "Chaise" not in yaml.safe_dump(spec, allow_unicode=True)


def test_cli_ghost_sans_save_n_ecrit_rien(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(ghost, "SAP_DIR", tmp_path / "sap")
    assert (
        cli.main(["ghost", "boutique_ch", "--har", str(HAR), "--visible", str(FIXTURES / "ghost" / "visible.txt")]) == 0
    )
    out = capsys.readouterr().out
    assert "/api/products" in out and "pagination" in out
    assert not (tmp_path / "sap").exists()


def test_cli_ghost_save_ecrit_la_spec(tmp_path, monkeypatch):
    monkeypatch.setattr(ghost, "SAP_DIR", tmp_path / "sap")
    assert cli.main(["ghost", "boutique_ch", "--har", str(HAR), "--save"]) == 0
    spec = yaml.safe_load((tmp_path / "sap" / "boutique_ch" / "ghost_spec.yaml").read_text())
    assert spec["site"] == "boutique_ch" and spec["calls"]


def test_cli_ghost_nom_invalide(tmp_path, monkeypatch):
    monkeypatch.setattr(ghost, "SAP_DIR", tmp_path / "sap")
    assert cli.main(["ghost", "../x", "--har", str(HAR), "--save"]) == 3


def _call(url, body, status=200, post=""):
    return {
        "method": "POST" if post else "GET",
        "url": url,
        "status": status,
        "mime": "application/json",
        "body": body,
        "post": post,
        "headers": {},
    }


def test_appel_en_erreur_ecarte():
    body = '{"items":[{"name":"Chaise Bouroullec"}]}'
    ranked = ghost.rank_data_calls([_call("https://b.ch/api/x", body, status=500)], VISIBLE)
    assert ranked == []


def test_pagination_reconnue_sur_un_seul_appel():
    body = '{"items":[{"name":"Chaise Bouroullec"}]}'
    spec = ghost.build_spec("b", [_call("https://b.ch/api/x?offset=0&n=7", body)], VISIBLE)
    p = spec["calls"][0]["params"]
    assert p["offset"] == {"role": "pagination", "start": 0, "step": "items"}
    assert p["n"] == {"role": "constante", "value": "7"}


def test_har_trop_gros_refuse(tmp_path, monkeypatch):
    import pytest

    big = tmp_path / "x.har"
    big.write_text('{"log":{"entries":[]}}')
    monkeypatch.setattr(ghost, "HAR_MAX_BYTES", 5)
    with pytest.raises(ValueError):
        ghost.load_har(big)


def test_mesure_d_audience_en_json_ecartee():
    body = '{"events":[{"label":"Chaise Bouroullec"}]}'
    calls = [_call("https://www.google-analytics.com/j/collect", body), _call("https://b.ch/track/v", body)]
    assert ghost.rank_data_calls(calls, VISIBLE) == []


def test_pagination_reconnue_par_valeurs_qui_changent():
    body = '{"items":[{"name":"Chaise Bouroullec"}]}'
    calls = [_call("https://b.ch/api/x?n=1", body), _call("https://b.ch/api/x?n=2", body)]
    assert ghost.build_spec("b", calls, VISIBLE)["calls"][0]["params"]["n"] == {
        "role": "pagination",
        "start": 1,
        "step": 1,
    }


def test_gabarit_le_plus_probant_en_tete():
    pauvre = _call("https://b.ch/api/a", '{"items":[{"name":"Banc Perriand"}]}')
    riche = _call(
        "https://b.ch/api/b",
        '{"items":[{"name":"Banc Perriand"},{"name":"Table Prouvé"},{"name":"Lampe Castiglioni"}]}',
    )
    spec = ghost.build_spec("b", [pauvre, riche], VISIBLE)
    assert [t["path"] for t in spec["calls"]] == ["/api/b", "/api/a"]
    ranked = ghost.rank_data_calls([pauvre, riche], VISIBLE)
    assert [c["url"] for _s, c in ranked] == ["https://b.ch/api/b", "https://b.ch/api/a"]
