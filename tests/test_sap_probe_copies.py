"""Copies tierces : quand le site ne laisse passer aucune porte (ou sur demande,
--copies), la sonde demande à la Wayback Machine (API CDX) et à l'index de
Common Crawl ce qu'ils ont déjà capturé : nombre d'adresses, capture la plus
récente, retard. Une requête par service, identité déclarée, drapeau légal."""

from __future__ import annotations

import asyncio
import json

import pytest

from accesspath import cli
from accesspath import probe as probe_mod

from ._localserver import LocalServer, body

CDX = json.dumps(
    [
        ["original", "timestamp", "statuscode", "mimetype"],
        ["https://dur.ch/a", "20260901120000", "200", "text/html"],
        ["https://dur.ch/b", "20261020083000", "200", "text/html"],
    ]
).encode()

CC_LINES = (
    b'{"url": "https://dur.ch/a", "timestamp": "20260915101010", "status": "200"}\n'
    b'{"url": "https://dur.ch/c", "timestamp": "20260918101010", "status": "200"}\n'
    b'{"url": "https://dur.ch/d", "timestamp": "20260917101010", "status": "200"}\n'
)


@pytest.fixture(autouse=True)
def _allow_local(monkeypatch):
    monkeypatch.setenv("ACCESSPATH_ALLOW_PRIVATE", "1")


def test_parse_wayback():
    assert probe_mod.parse_wayback_cdx(CDX) == {"items": 2, "newest": "2026-10-20"}
    assert probe_mod.parse_wayback_cdx(b"[]") == {"items": 0, "newest": None}
    assert probe_mod.parse_wayback_cdx(b"<html>erreur") == {"items": None, "newest": None}


def test_parse_commoncrawl():
    assert probe_mod.parse_cc_index(CC_LINES) == {"items": 3, "newest": "2026-09-18"}
    assert probe_mod.parse_cc_index(b"pas du json\n") == {"items": None, "newest": None}


@pytest.fixture
def archives(monkeypatch):
    """Faux Wayback + faux Common Crawl sur un serveur local."""
    with LocalServer({}) as s:
        routes = s.routes
        routes["/cdx/search/cdx"] = body(200, CDX, Content_Type="application/json")
        routes["/collinfo.json"] = body(
            200,
            json.dumps([{"id": "CC-MAIN-2026-40", "cdx-api": s.url("/CC-MAIN-2026-40-index")}]).encode(),
            Content_Type="application/json",
        )
        routes["/CC-MAIN-2026-40-index"] = body(200, CC_LINES, Content_Type="text/x-ndjson")
        monkeypatch.setattr(probe_mod, "WAYBACK_CDX", s.url("/cdx/search/cdx"))
        monkeypatch.setattr(probe_mod, "CC_COLLINFO", s.url("/collinfo.json"))
        yield s


def _site_ferme():
    return LocalServer(
        {
            "/robots.txt": body(404, b"", Content_Type="text/plain"),
            "*": body(403, b"<html>Just a moment...</html>", Content_Type="text/html"),
        }
    )


def test_site_ferme_interroge_les_copies(archives):
    with _site_ferme() as site:
        rep = asyncio.run(probe_mod.probe(site.url("/")))
    log = list(archives.log)
    assert sum(p.startswith("/cdx/search/cdx") for p in log) == 2  # la plus récente, puis le compte
    assert sum(p.startswith("/CC-MAIN-2026-40-index") for p in log) == 1
    wb, cc = rep.copies["wayback"], rep.copies["commoncrawl"]
    assert (wb["items"], wb["newest"]) == (2, "2026-10-20")
    assert (cc["items"], cc["newest"], cc["crawl"]) == (3, "2026-09-18", "CC-MAIN-2026-40")
    assert isinstance(wb["lag_days"], int)
    # les requêtes nomment le site audité ; le compte est borné et porte sur l'année
    qs = [p for p in log if p.startswith("/cdx/search/cdx")]
    assert all("127.0.0.1" in q for q in qs)
    assert any("fastLatest=true" in q and "limit=-1" in q for q in qs)
    assert any("limit=1000" in q and "from=" in q for q in qs)
    assert not any("limit=-1000" in q for q in qs)


def test_identite_declaree_pour_les_archives(archives, monkeypatch):
    vus = []
    orig = probe_mod._third_party_get

    async def _spy(url):
        r = await orig(url)
        vus.append(url)
        return r

    monkeypatch.setattr(probe_mod, "_third_party_get", _spy)
    assert probe_mod.THIRD_PARTY_HEADERS["User-Agent"].startswith("accesspath")
    with _site_ferme() as site:
        asyncio.run(probe_mod.probe(site.url("/")))
    assert len(vus) == 5  # cdx (plus récente, compte), collinfo, index, memento


def test_site_ouvert_n_interroge_pas_les_copies(archives):
    rss = b'<?xml version="1.0"?><rss><channel><item></item></channel></rss>'
    with LocalServer(
        {
            "/": body(200, b"<html>" + b"<p>x</p>" * 400 + b"</html>", Content_Type="text/html"),
            "/feed": body(200, rss, Content_Type="application/rss+xml"),
        }
    ) as site:
        rep = asyncio.run(probe_mod.probe(site.url("/")))
    assert archives.log == []
    assert rep.copies == {}


def test_copies_sur_demande(archives):
    rss = b'<?xml version="1.0"?><rss><channel><item></item></channel></rss>'
    with LocalServer(
        {
            "/": body(200, b"<html>" + b"<p>x</p>" * 400 + b"</html>", Content_Type="text/html"),
            "/feed": body(200, rss, Content_Type="application/rss+xml"),
        }
    ) as site:
        rep = asyncio.run(probe_mod.probe(site.url("/"), copies=True))
    assert rep.copies["wayback"]["items"] == 2


def test_archive_injoignable_ne_casse_pas_la_sonde(monkeypatch):
    with LocalServer({"*": body(500, b"panne", Content_Type="text/plain")}) as arch:
        monkeypatch.setattr(probe_mod, "WAYBACK_CDX", arch.url("/cdx"))
        monkeypatch.setattr(probe_mod, "CC_COLLINFO", arch.url("/collinfo.json"))
        with _site_ferme() as site:
            rep = asyncio.run(probe_mod.probe(site.url("/")))
    assert rep.copies["wayback"]["items"] is None and rep.copies["wayback"]["error"]
    assert rep.copies["commoncrawl"]["items"] is None


def test_rapport_et_entree_sap(archives):
    with _site_ferme() as site:
        rep = asyncio.run(probe_mod.probe(site.url("/")))
    md = probe_mod.emit_markdown(rep, "dur_ch")
    section = md.split("## Copies tierces")[1]
    assert "wayback" in section and "2026-10-20" in section
    assert "copie tierce" in section.lower()
    assert md.index("## Copies tierces") < md.index("⟦FIN")  # valeurs tierces dans le bloc de données
    entry = probe_mod.emit_sap_entry(rep)
    assert entry["third_party_copies"]["wayback"]["items"] == 2
    assert "copie tierce" in entry["third_party_copies"]["legal"]


def test_cli_option_copies(monkeypatch):
    vu = {}

    async def _probe(url, **kw):
        vu.update(kw)
        raise RuntimeError("stop")

    monkeypatch.setattr(probe_mod, "probe", _probe)
    cli.main(["sap", "probe", "https://exemple.ch/", "--copies"])
    assert vu.get("copies") is True


def test_en_tetes_tiers_en_ascii():
    # Un en-tête HTTP non ASCII fait échouer la requête avant qu'elle parte.
    for v in probe_mod.THIRD_PARTY_HEADERS.values():
        v.encode("ascii")


def test_user_agent_envoye_aux_archives(archives):
    from ._localserver import _send

    vus = []

    def _cdx(req):
        vus.append(req.headers.get("User-Agent", ""))
        _send(req, 200, CDX, {"Content-Type": "application/json"})

    archives.routes["/cdx/search/cdx"] = _cdx
    with _site_ferme() as site:
        asyncio.run(probe_mod.probe(site.url("/")))
    assert vus and vus[0].startswith("accesspath")


def test_archive_qui_refuse_la_connexion(monkeypatch):
    # Port fermé : la connexion échoue (exception), la sonde rend quand même son rapport.
    monkeypatch.setattr(probe_mod, "WAYBACK_CDX", "http://127.0.0.1:9/cdx")
    monkeypatch.setattr(probe_mod, "CC_COLLINFO", "http://127.0.0.1:9/collinfo.json")
    with _site_ferme() as site:
        rep = asyncio.run(probe_mod.probe(site.url("/")))
    assert rep.copies["wayback"]["items"] is None
    assert "Error" in rep.copies["wayback"]["error"] or "error" in rep.copies["wayback"]["error"].lower()


def test_commoncrawl_sans_capture_vaut_zero(archives):
    archives.routes["/CC-MAIN-2026-40-index"] = body(
        404, b'{"message": "No Captures found for: x/"}', Content_Type="application/json"
    )
    with _site_ferme() as site:
        rep = asyncio.run(probe_mod.probe(site.url("/")))
    cc = rep.copies["commoncrawl"]
    assert (cc["items"], cc["error"]) == (0, None)


def test_wayback_indisponible_une_seule_requete(archives):
    archives.routes["/cdx/search/cdx"] = body(503, b"Temporarily Offline", Content_Type="text/html")
    with _site_ferme() as site:
        rep = asyncio.run(probe_mod.probe(site.url("/")))
    assert sum(p.startswith("/cdx/search/cdx") for p in archives.log) == 1
    assert rep.copies["wayback"]["error"] == "HTTP 503"


def test_wayback_la_plus_recente_vient_de_l_index_rapide(archives):
    from ._localserver import _send

    recente = json.dumps([["original", "timestamp"], ["https://dur.ch/z", "20261023230000"]]).encode()

    def _cdx(req):
        _send(req, 200, recente if "fastLatest=true" in req.path else CDX, {"Content-Type": "application/json"})

    archives.routes["/cdx/search/cdx"] = _cdx
    with _site_ferme() as site:
        rep = asyncio.run(probe_mod.probe(site.url("/")))
    wb = rep.copies["wayback"]
    assert (wb["items"], wb["newest"]) == (2, "2026-10-23")


def test_plafond_affiche_comme_borne():
    rep = probe_mod.ProbeReport(url="https://dur.ch/", timestamp="2026-10-24T00:00:00+00:00")
    rep.copies = {
        "wayback": {"items": None, "error": "HTTP 503"},
        "commoncrawl": {"items": probe_mod.THIRD_PARTY_LIMIT, "newest": "2026-10-18", "lag_days": 6, "crawl": "CC"},
        "legal": probe_mod.THIRD_PARTY_LEGAL,
    }
    md = probe_mod.emit_markdown(rep, "dur_ch")
    assert f"≥ {probe_mod.THIRD_PARTY_LIMIT}" in md
