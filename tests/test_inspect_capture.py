"""Capture réseau d'inspect : la méthode HTTP enregistrée est celle de la requête."""

from types import SimpleNamespace as NS

from accesspath.sap_inspect import _request_seen, _response_entry


def _req(rid, method, post=None):
    return NS(request_id=rid, request=NS(method=method, post_data=post))


def _resp(rid, url="https://exemple.ch/graphql"):
    return NS(request_id=rid, response=NS(url=url, status=200, headers={"content-type": "application/json"}))


def test_post_graphql_garde_sa_methode_et_son_corps():
    methods, bodies = {}, {}
    _request_seen(_req("1", "POST", '{"query":"{ x }"}'), methods, bodies)
    e = _response_entry(_resp("1"), methods)
    assert e["method"] == "POST"
    assert bodies["1"] == '{"query":"{ x }"}'
    assert e["content_type"] == "application/json"


def test_get_reste_get_et_inconnu_retombe_sur_get():
    methods, bodies = {}, {}
    _request_seen(_req("2", "GET"), methods, bodies)
    assert _response_entry(_resp("2"), methods)["method"] == "GET"
    assert _response_entry(_resp("3"), methods)["method"] == "GET"
    assert bodies == {}
