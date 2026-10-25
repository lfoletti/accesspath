"""Fin des portes de confiance : abonnements repérés à l'accueil (un geste à
faire une fois), et évolution des portes d'une sonde à l'autre (fermée,
vidée, figée, nouvelle)."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta

import pytest

from accesspath import cli, gestures
from accesspath import probe as probe_mod

ACCUEIL = """<html><body>
<form action="/newsletter/inscription" method="post">
  <label>Recevez notre newsletter</label><input type="email" name="email"><button>OK</button>
</form>
<form action="/recherche"><input type="text" name="q"></form>
<a href="/alertes">Alertes appels d'offres</a>
<a href="/compte/unsubscribe">Se désabonner</a>
<a href="https://www.exemple.ch/abonnement">Abonnement</a>
<a href="/contact">Contact</a>
</body></html>"""


def test_find_subscriptions():
    subs = probe_mod.find_subscriptions(ACCUEIL, "https://www.exemple.ch")
    urls = {s["url"]: s["kind"] for s in subs}
    assert urls == {
        "https://www.exemple.ch/newsletter/inscription": "newsletter",
        "https://www.exemple.ch/alertes": "alerte",
        "https://www.exemple.ch/abonnement": "newsletter",
    }


def test_formulaire_sans_email_ignore():
    html = '<form action="/newsletter"><input type="text" name="q"></form>'
    assert probe_mod.find_subscriptions(html, "https://x.ch") == []


def _today(days_ago: int = 0) -> str:
    return (datetime.now(UTC).date() - timedelta(days=days_ago)).isoformat()


def _rep(found: list[dict]) -> probe_mod.ProbeReport:
    return probe_mod.ProbeReport(
        url="https://x.ch/",
        timestamp=datetime.now(UTC).isoformat(),
        tier1={"found": [{"status": 200, "size": 1, "source": "générique", **f} for f in found], "platform": "generic"},
    )


PREV = {
    "last_audit": _today(10),
    "doors": {
        "/feed": {"type": "rss", "source": "générique", "items": 50, "newest": _today(11)},
        "/api/items": {"type": "json", "source": "générique", "items": 400, "newest": _today(10)},
        "/sitemap.xml": {"type": "sitemap", "source": "générique", "items": 900, "newest": _today(12)},
        "/vieux.xml": {"type": "rss", "source": "générique", "items": 5, "newest": _today(400)},
    },
}


def test_door_changes():
    now = _rep(
        [
            # /feed a disparu (fermée)
            {"endpoint": "/api/items", "type": "json", "items": 120, "newest": _today(1)},  # vidée
            {"endpoint": "/sitemap.xml", "type": "sitemap", "items": 905, "newest": _today(45)},  # figée
            {"endpoint": "/vieux.xml", "type": "rss", "items": 5, "newest": _today(410)},  # déjà figée : rien
            {"endpoint": "/products.json?limit=250", "type": "json", "items": 30, "newest": _today(0)},  # nouvelle
        ]
    )
    ch = {c["endpoint"]: c["change"] for c in probe_mod.door_changes(PREV, now)}
    assert ch == {
        "/feed": "fermée",
        "/api/items": "vidée",
        "/sitemap.xml": "figée",
        "/products.json?limit=250": "nouvelle",
    }


def test_door_changes_sans_profil():
    assert probe_mod.door_changes({}, _rep([])) == []
    assert probe_mod.door_changes({"doors": {}}, _rep([])) == []


def test_porte_qui_renvoie_une_erreur_est_fermee():
    now = _rep([{"endpoint": "/feed", "type": "html", "items": None, "newest": None}])
    prev = {"last_audit": _today(1), "doors": {"/feed": {"type": "rss", "items": 3, "newest": _today(2)}}}
    assert [c["change"] for c in probe_mod.door_changes(prev, now)] == ["fermée"]


def test_markdown_evolution_et_abonnements():
    rep = _rep([{"endpoint": "/api/items", "type": "json", "items": 1, "newest": _today(1)}])
    rep.tier1["subscriptions"] = [{"url": "https://x.ch/alertes", "kind": "alerte"}]
    rep.door_changes = probe_mod.door_changes(PREV, rep)
    md = probe_mod.emit_markdown(rep, "x_ch")
    data = md.split("⟦FIN")[0]
    assert "## Évolution des portes" in data and "fermée" in data and "vidée" in data
    assert "## Abonnements proposés" in data and "https://x.ch/alertes" in data
    entry = probe_mod.emit_sap_entry(rep)
    assert entry["subscriptions"] == [{"url": "https://x.ch/alertes", "kind": "alerte"}]


# ── CLI : comparaison au profil enregistré, ticket d'abonnement avec --save ──
@pytest.fixture
def data(tmp_path, monkeypatch):
    from accesspath import sap as sap_mod

    d = tmp_path / "data"
    d.mkdir()
    monkeypatch.setattr(sap_mod, "PROFILES_FILE", d / "site_architecture_profiles.json")
    monkeypatch.setattr(probe_mod, "DATA_DIR", d)
    monkeypatch.setattr(gestures, "GESTURES_FILE", d / "gestures.jsonl")
    return d


def _fake_probe(monkeypatch, report):
    async def _p(url, **kw):
        return report

    monkeypatch.setattr(probe_mod, "probe", _p)


def test_cli_compare_au_profil_enregistre(data, monkeypatch, capsys):
    (data / "site_architecture_profiles.json").write_text(json.dumps({"x_ch": PREV}))
    _fake_probe(monkeypatch, _rep([{"endpoint": "/api/items", "type": "json", "items": 400, "newest": _today(0)}]))
    assert cli.main(["sap", "probe", "https://x.ch/", "--name", "x_ch"]) == 0
    out = capsys.readouterr().out
    assert "## Évolution des portes" in out and "/feed" in out


def test_cli_save_depose_le_geste_d_abonnement(data, monkeypatch):
    rep = _rep([{"endpoint": "/feed", "type": "rss", "items": 3, "newest": _today(0)}])
    rep.tier1["subscriptions"] = [{"url": "https://x.ch/alertes", "kind": "alerte"}]
    _fake_probe(monkeypatch, rep)
    assert cli.main(["sap", "probe", "https://x.ch/", "--name", "x_ch", "--save"]) == 0
    (g,) = gestures.pending()
    assert (g.site, g.kind, g.open_url) == ("x_ch", "subscribe", "https://x.ch/alertes")


def test_cli_sans_save_pas_de_ticket(data, monkeypatch):
    rep = _rep([{"endpoint": "/feed", "type": "rss", "items": 3, "newest": _today(0)}])
    rep.tier1["subscriptions"] = [{"url": "https://x.ch/alertes", "kind": "alerte"}]
    _fake_probe(monkeypatch, rep)
    assert cli.main(["sap", "probe", "https://x.ch/", "--name", "x_ch"]) == 0
    assert gestures.pending() == []


def test_sonde_reelle_remplit_les_abonnements(monkeypatch):
    monkeypatch.setenv("ACCESSPATH_ALLOW_PRIVATE", "1")
    from ._localserver import LocalServer, body

    with LocalServer({"/": body(200, ACCUEIL.encode() + b"<p>x</p>" * 300, Content_Type="text/html")}) as s:
        rep = asyncio.run(probe_mod.probe(s.url("/")))
    kinds = sorted(x["kind"] for x in rep.tier1["subscriptions"])
    assert kinds == ["alerte", "newsletter", "newsletter"]
