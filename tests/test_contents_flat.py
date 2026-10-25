"""Contenus des sites aux adresses à plat, et motif de l'échec quand l'accueil ne se lit pas.

Cas d'origine (campagne bureaux d'octobre 2026) : 210 sites sans contenu trouvé, dont
62 au sitemap à plat (/seefeld, /um-und-anbau-riehen/), 30 à la page d'index au nom non
reconnu (projekte.html, work2, projekte-2, projektauswahl), 16 à la liste vide (projets
à plat sous l'index), 23 au certificat refusé, comptés jusque-là comme « sans contenu ».
"""

from __future__ import annotations

import asyncio

import pytest

from accesspath import batch
from accesspath.acquisition import contents as pp

from ._localserver import LocalServer, body


@pytest.fixture(autouse=True)
def _allow_local(monkeypatch):
    monkeypatch.setenv("ACCESSPATH_ALLOW_PRIVATE", "1")


HTML = {"Content_Type": "text/html"}


def _sitemap(host, paths):
    locs = "".join(f"<url><loc>{host}{p}</loc></url>" for p in paths)
    return body(
        200,
        f'<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">{locs}</urlset>'.encode(),
        Content_Type="application/xml",
    )


# ── Unités ───────────────────────────────────────────────────────────────
@pytest.mark.parametrize(
    "url, expected",
    [
        ("https://b.ch/seefeld", True),
        ("https://b.ch/um-und-anbau-riehen/", True),
        ("https://b.ch/de/villa-x", True),
        ("https://b.ch/hochdorf.html", True),
        ("https://b.ch/", False),
        ("https://b.ch/kontakt", False),
        ("https://b.ch/buero", False),
        ("https://b.ch/büro.html", False),
        ("https://b.ch/landing-page", False),
        ("https://b.ch/de/", False),
        ("https://b.ch/plan.pdf", False),
        ("https://b.ch/projekte", False),
        ("https://b.ch/work2", False),
        ("https://b.ch/projektauswahl", False),
        ("https://b.ch/a/b", False),
        ("https://b.ch/news/x", False),
    ],
)
def test_page_a_plat(url, expected):
    assert pp.is_flat_content(url) is expected


@pytest.mark.parametrize(
    "url, expected",
    [
        ("https://b.ch/projekte/", True),
        ("https://b.ch/projekte.html", True),
        ("https://b.ch/neubauten.php", True),
        ("https://b.ch/projekte-2", True),
        ("https://b.ch/work2", True),
        ("https://b.ch/projektauswahl", True),
        ("https://b.ch/werkliste", True),
        ("https://b.ch/kontakt.html", False),
        ("https://b.ch/team-2", False),
    ],
)
def test_page_d_index(url, expected):
    assert pp.is_index_page(url) is expected


@pytest.mark.parametrize(
    "error, expected",
    [
        ("ConnectError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed", "certificat refusé"),
        ("ConnectError: All connection attempts failed", "injoignable"),
        ("BlockedDestination: www.x.ch ne se résout pas", "injoignable"),
        ("HTTP 403", "HTTP 403"),
    ],
)
def test_motif_d_un_accueil_illisible(error, expected):
    status = int(error.split()[1]) if error.startswith("HTTP") else -1
    assert pp.home_failure({"ok": False, "status": status, "error": error}) == expected


def test_accueil_lu_n_a_pas_de_motif():
    assert pp.home_failure({"ok": True, "status": 200, "error": None}) is None


# ── De bout en bout ──────────────────────────────────────────────────────
def test_sitemap_a_plat():
    with LocalServer({}) as s:
        host = s.url("").rstrip("/")
        paths = ["/", "/seefeld", "/zollikon", "/haus-am-see/", "/kontakt", "/buero", "/impressum"]
        s.routes.update(
            {
                "/robots.txt": body(200, f"Sitemap: {host}/sm.xml\n".encode(), Content_Type="text/plain"),
                "/sm.xml": _sitemap(host, paths),
                "*": body(200, b"<html><body><p>texte</p></body></html>", **HTML),
            }
        )
        p = asyncio.run(pp.profile_contents(s.url("/")))
    assert p["source"] == "sitemap (à plat)" and p["count"] == 3 and p["matched_by"] == "à plat"


def test_sitemap_a_plat_trop_court_ne_compte_pas():
    with LocalServer({}) as s:
        host = s.url("").rstrip("/")
        s.routes.update(
            {
                "/robots.txt": body(200, f"Sitemap: {host}/sm.xml\n".encode(), Content_Type="text/plain"),
                "/sm.xml": _sitemap(host, ["/", "/seefeld", "/kontakt"]),
                "*": body(200, b"<html></html>", **HTML),
            }
        )
        p = asyncio.run(pp.profile_contents(s.url("/")))
    assert p["source"] is None and p["count"] == 0


def test_motifs_priment_sur_le_sitemap_a_plat():
    with LocalServer({}) as s:
        host = s.url("").rstrip("/")
        paths = ["/projekte/a/", "/projekte/b/", "/seefeld", "/zollikon", "/wollishofen"]
        s.routes.update(
            {
                "/robots.txt": body(200, f"Sitemap: {host}/sm.xml\n".encode(), Content_Type="text/plain"),
                "/sm.xml": _sitemap(host, paths),
                "*": body(200, b"<html></html>", **HTML),
            }
        )
        p = asyncio.run(pp.profile_contents(s.url("/")))
    assert p["source"] == "sitemap" and p["count"] == 2


def test_index_au_nom_en_variante_et_projets_a_plat():
    with LocalServer({}) as s:
        home = b'<html><a href="/projekte.html">P</a><a href="/buero.html">B</a><a href="/kontakt.html">K</a></html>'
        listing = (
            b'<html><a href="/projekte.html">P</a><a href="/buero.html">B</a><a href="/kontakt.html">K</a>'
            b'<a href="/hochdorf.html">1</a><a href="/waidmatt.html">2</a><a href="/heidiabel.html">3</a></html>'
        )
        s.routes.update(
            {
                "/robots.txt": body(404, b"", Content_Type="text/plain"),
                "/": body(200, home, **HTML),
                "/projekte.html": body(200, listing, **HTML),
                "*": body(200, b"<html></html>", **HTML),
            }
        )
        p = asyncio.run(pp.profile_contents(s.url("/")))
    assert p["source"] == "liste" and p["listing"].endswith("/projekte.html") and p["count"] == 3


def test_liste_a_plat_ne_reprend_pas_la_navigation():
    with LocalServer({}) as s:
        # Pages de navigation à l'allure de contenus : elles figurent déjà sur l'accueil.
        nav = b'<a href="/work2">W</a><a href="/haltung">H</a><a href="/menschen">M</a><a href="/kultur">K</a>'
        s.routes.update(
            {
                "/robots.txt": body(404, b"", Content_Type="text/plain"),
                "/": body(200, b"<html>" + nav + b"</html>", **HTML),
                "/work2": body(200, b"<html>" + nav + b'<a href="/villa">V</a></html>', **HTML),
                "*": body(200, b"<html></html>", **HTML),
            }
        )
        p = asyncio.run(pp.profile_contents(s.url("/")))
    assert p["source"] is None  # une seule page propre à la liste : pas assez pour conclure


def test_profil_dit_pourquoi_l_accueil_ne_se_lit_pas():
    with LocalServer({"*": body(403, b"Forbidden", Content_Type="text/plain")}) as s:
        p = asyncio.run(pp.profile_contents(s.url("/")))
    assert p["source"] is None and p["home_error"] == "HTTP 403"


# ── Lot ──────────────────────────────────────────────────────────────────
def test_ligne_et_synthese_portent_le_motif():
    p = {
        "source": None,
        "count": 0,
        "image_mode": None,
        "images_per_page": None,
        "max_width": None,
        "image_hosts": [],
        "image_check": None,
        "robots_images_allowed": None,
        "disk_contents": None,
        "gap": None,
        "matched_by": None,
        "sample": [],
        "home_error": "certificat refusé",
    }
    row = pp.contents_row(p)
    assert row["home_error"] == "certificat refusé"
    rows = [{"name": "a", "status": "ok", **row}, {"name": "b", "status": "ok", **row}]
    md = batch.summarize("x", rows)
    assert "| certificat refusé | 2 |" in md
    assert "Accueil illisible" in md
