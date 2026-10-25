"""Volet projets du profil d'un bureau : où sont les projets (API REST WordPress,
sitemap, page de liste), combien, et comment viennent leurs images (HTML, chargement
différé, opengraph seul, aucune), en quelle largeur, depuis quel hôte, avec ou sans
Referer ; écart avec la collecte déjà faite."""

from __future__ import annotations

import asyncio
import json

import pytest

from accesspath.acquisition import contents as pp

from ._localserver import LocalServer, body


@pytest.fixture(autouse=True)
def _allow_local(monkeypatch):
    monkeypatch.setenv("ACCESSPATH_ALLOW_PRIVATE", "1")


# ── Unités ───────────────────────────────────────────────────────────────
@pytest.mark.parametrize(
    "url, expected",
    [
        ("https://b.ch/projekte/haus-am-see/", True),
        ("https://b.ch/fr/projets/ecole-x", True),
        ("https://b.ch/werkliste/gewerbe/halle-x", True),
        ("https://b.ch/projekte/", False),
        ("https://b.ch/kontakt/", False),
        ("https://b.ch/projekte/plan.pdf", False),
    ],
)
def test_url_de_projet(url, expected):
    assert pp.is_content_url(url) is expected


def test_largeur_max_srcset():
    assert pp.max_width("a.jpg 300w, b.jpg 1600w, c.jpg 800w") == ("b.jpg", 1600)
    assert pp.max_width("a.jpg 1x, b.jpg 2x") == ("b.jpg", None)
    assert pp.max_width("") == (None, None)


PAGE = """<html><head><meta property="og:image" content="https://cdn.b.ch/og.jpg"></head><body>
<img src="/logo.svg" alt="logo">
<img src="/img/a-300x200.jpg" srcset="/img/a-300x200.jpg 300w, /img/a.jpg 2000w">
<img data-src="/img/b.jpg" src="data:image/gif;base64,R0lGOD">
<picture><source srcset="https://cdn.b.ch/c.webp 1200w"><img src="https://cdn.b.ch/c.jpg"></picture>
</body></html>"""


def test_images_d_une_page():
    imgs = pp.page_images(PAGE, "https://b.ch/projekte/x/")
    assert imgs["og"] == "https://cdn.b.ch/og.jpg"
    urls = [i["url"] for i in imgs["images"]]
    assert "https://b.ch/img/a.jpg" in urls and "https://b.ch/img/b.jpg" in urls
    assert "https://cdn.b.ch/c.webp" in urls
    assert not any(u.endswith(".svg") or u.startswith("data:") for u in urls)
    assert imgs["lazy"] is True
    assert imgs["max_width"] == 2000


def test_mode_des_images():
    assert pp.image_mode({"images": [{"url": "a"}, {"url": "b"}], "lazy": False, "og": None}) == "html"
    assert pp.image_mode({"images": [{"url": "a"}, {"url": "b"}], "lazy": True, "og": None}) == "chargement différé"
    assert pp.image_mode({"images": [], "lazy": False, "og": "x"}) == "opengraph seul"
    assert pp.image_mode({"images": [], "lazy": False, "og": None}) == "aucune (navigateur probable)"


def test_echantillon_reparti():
    urls = [f"u{i}" for i in range(10)]
    assert pp.spread(urls, 3) == ["u0", "u4", "u9"] or pp.spread(urls, 3) == ["u0", "u5", "u9"]
    assert pp.spread(urls[:2], 3) == ["u0", "u1"]


# ── De bout en bout ──────────────────────────────────────────────────────
def _project_page(i, host):
    return (
        f'<html><head><meta property="og:image" content="{host}/img/{i}.jpg"></head><body>'
        f'<img src="{host}/img/{i}-a.jpg" srcset="{host}/img/{i}-a.jpg 1920w"><img src="{host}/img/{i}-b.jpg">'
        "</body></html>"
    ).encode()


def _wp_site(s, n=5, referer=False):
    host = s.url("").rstrip("/")
    types = {"post": {"slug": "post", "rest_base": "posts"}, "project": {"slug": "project", "rest_base": "project"}}
    links = [{"link": f"{host}/projekte/p{i}/"} for i in range(n)]
    routes = {
        "/robots.txt": body(200, b"User-agent: *\nDisallow: /wp-admin/\n", Content_Type="text/plain"),
        "/": body(200, b"<html><a href='/projekte/'>Projekte</a></html>", Content_Type="text/html"),
        "/wp-json/wp/v2/types": body(200, json.dumps(types).encode(), Content_Type="application/json"),
        "/wp-json/wp/v2/project": body(
            200, json.dumps(links).encode(), Content_Type="application/json", X_WP_Total=str(n)
        ),
    }
    for i in range(n):
        routes[f"/projekte/p{i}/"] = body(200, _project_page(i, host), Content_Type="text/html")
        for suffix in ("", "-a", "-b"):
            if referer:

                def guarded(req, _i=i):
                    if req.headers.get("Referer"):
                        return body(200, b"\xff\xd8jpeg", Content_Type="image/jpeg")(req)
                    return body(403, b"", Content_Type="text/plain")(req)

                routes[f"/img/{i}{suffix}.jpg"] = guarded
            else:
                routes[f"/img/{i}{suffix}.jpg"] = body(200, b"\xff\xd8jpeg", Content_Type="image/jpeg")
    s.routes.update(routes)


def test_profil_wordpress():
    with LocalServer({}) as s:
        _wp_site(s)
        p = asyncio.run(pp.profile_contents(s.url("/"), disk_contents=3))
    assert p["source"] == "wp-rest" and p["wp_type"] == "project"
    assert p["count"] == 5 and len(p["sample"]) == 3
    assert p["image_mode"] == "html" and p["images_per_page"] == 2
    assert p["max_width"] == 1920
    assert p["image_check"] == {"status": 200, "needs_referer": False, "content_type": "image/jpeg"}
    assert p["image_hosts"] == ["127.0.0.1"]
    assert p["robots_images_allowed"] is True
    assert p["disk_contents"] == 3 and p["gap"] == 2


def test_images_protegees_par_referer():
    with LocalServer({}) as s:
        _wp_site(s, referer=True)
        p = asyncio.run(pp.profile_contents(s.url("/")))
    assert p["image_check"]["needs_referer"] is True and p["image_check"]["status"] == 200
    assert p["gap"] is None


def test_profil_par_sitemap():
    with LocalServer({}) as s:
        host = s.url("").rstrip("/")
        sm = "".join(f"<url><loc>{host}/projets/{n}/</loc></url>" for n in ("ecole", "villa", "halle"))
        sm += f"<url><loc>{host}/contact/</loc></url>"
        s.routes.update(
            {
                "/robots.txt": body(200, f"Sitemap: {host}/sm.xml\n".encode(), Content_Type="text/plain"),
                "/": body(200, b"<html></html>", Content_Type="text/html"),
                "/sm.xml": body(
                    200,
                    f'<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">{sm}</urlset>'.encode(),
                    Content_Type="application/xml",
                ),
                "*": body(200, b"<html><body><p>texte</p></body></html>", Content_Type="text/html"),
            }
        )
        p = asyncio.run(pp.profile_contents(s.url("/")))
    assert p["source"] == "sitemap" and p["count"] == 3
    assert p["image_mode"] == "aucune (navigateur probable)"


def test_profil_par_page_de_liste():
    with LocalServer({}) as s:
        host = s.url("").rstrip("/")
        listing = "".join(f'<a href="/projekte/{n}/">{n}</a>' for n in ("a1", "b2"))
        s.routes.update(
            {
                "/robots.txt": body(404, b"", Content_Type="text/plain"),
                "/": body(
                    200,
                    b'<html><a href="/projekte/">Projekte</a><a href="/kontakt/">K</a></html>',
                    Content_Type="text/html",
                ),
                "/projekte/": body(200, f"<html>{listing}</html>".encode(), Content_Type="text/html"),
                "/projekte/a1/": body(200, _project_page(1, host), Content_Type="text/html"),
                "/projekte/b2/": body(200, _project_page(2, host), Content_Type="text/html"),
                "*": body(200, b"\xff\xd8jpeg", Content_Type="image/jpeg"),
            }
        )
        p = asyncio.run(pp.profile_contents(s.url("/")))
    assert p["source"] == "liste" and p["count"] == 2 and p["listing"].endswith("/projekte/")


def test_aucun_projet_trouve():
    with LocalServer({"*": body(200, b"<html><a href='/kontakt/'>k</a></html>", Content_Type="text/html")}) as s:
        p = asyncio.run(pp.profile_contents(s.url("/")))
    assert p["source"] is None and p["count"] == 0 and p["image_mode"] is None


def test_robots_interdit_les_images():
    with LocalServer({}) as s:
        _wp_site(s)
        s.routes["/robots.txt"] = body(200, b"User-agent: *\nDisallow: /img/\n", Content_Type="text/plain")
        p = asyncio.run(pp.profile_contents(s.url("/")))
    assert p["robots_images_allowed"] is False
    assert p["image_check"] is None  # on ne télécharge pas ce que robots.txt interdit


# ── Lot ──────────────────────────────────────────────────────────────────
def test_ligne_de_lot():
    p = {
        "source": "wp-rest",
        "wp_type": "project",
        "listing": None,
        "count": 5,
        "sample": ["a"],
        "image_mode": "html",
        "images_per_page": 2,
        "max_width": 1920,
        "image_hosts": ["b.ch"],
        "image_check": {"status": 200, "needs_referer": False, "content_type": "image/jpeg"},
        "robots_images_allowed": True,
        "disk_contents": 3,
        "gap": 2,
    }
    row = pp.contents_row(p)
    assert row == {
        "status": "ok",
        "content_source": "wp-rest",
        "contents": 5,
        "image_mode": "html",
        "images_per_page": 2,
        "max_width": 1920,
        "image_hosts": ["b.ch"],
        "needs_referer": False,
        "robots_images_allowed": True,
        "disk_contents": 3,
        "gap": 2,
        "matched_by": None,
        "home_error": None,
        "content_samples": ["a"],
    }


def test_disque(tmp_path):
    (tmp_path / "bureau" / "projects").mkdir(parents=True)
    for n in ("a", "b"):
        (tmp_path / "bureau" / "projects" / f"{n}.json").write_text("{}")
    assert pp.disk_contents(tmp_path, "bureau") == 2
    assert pp.disk_contents(tmp_path, "absent") is None


def test_runner_et_synthese(monkeypatch, tmp_path):
    from accesspath import batch

    async def fake(url, *, disk_contents=None):
        return {
            "source": "sitemap",
            "count": 4,
            "image_mode": "chargement différé",
            "images_per_page": 6,
            "max_width": 2400,
            "image_hosts": ["cdn.x"],
            "image_check": None,
            "robots_images_allowed": True,
            "disk_contents": disk_contents,
            "gap": None,
            "wp_type": None,
            "listing": None,
            "sample": [],
        }

    monkeypatch.setattr(pp, "profile_contents", fake)
    monkeypatch.setattr(batch, "CONTENTS_DISK_ROOT", tmp_path)
    row = asyncio.run(batch.contents_runner(deadline=5)({"name": "b", "url": "https://b.ch/", "extra": {}}))
    assert row["content_source"] == "sitemap" and row["contents"] == 4
    md = batch.summarize("archi", [row, {**row, "content_source": None, "contents": 0, "image_mode": None}])
    assert "| sitemap | 1 |" in md.split("## Source des contenus")[1]
    assert "| chargement différé | 1 |" in md.split("## Images des contenus")[1]
    assert "- Contenus en ligne : 4 ; sites sans contenu trouvé : 1" in md
    # Sans racine de collecte (ni réglage ni ACCESSPATH_CONTENTS_ROOT) : pas de comparaison au disque.
    monkeypatch.setattr(batch, "CONTENTS_DISK_ROOT", None)
    monkeypatch.delenv("ACCESSPATH_CONTENTS_ROOT", raising=False)
    row = asyncio.run(batch.contents_runner(deadline=5)({"name": "b", "url": "https://b.ch/", "extra": {}}))
    assert row["contents"] == 4 and row["disk_contents"] is None
    monkeypatch.setenv("ACCESSPATH_CONTENTS_ROOT", str(tmp_path))
    (tmp_path / "b" / "projects").mkdir(parents=True)
    (tmp_path / "b" / "projects" / "p.json").write_text("{}")
    row = asyncio.run(batch.contents_runner(deadline=5)({"name": "b", "url": "https://b.ch/", "extra": {}}))
    assert row["disk_contents"] == 1


# ── Recettes et motifs connus ────────────────────────────────────────────
def _doc(host, index=None, pattern=None):
    return {
        "families": {
            "project_url_patterns": [{"regex": pattern, "flags": "i", "sites": ["bureau"]}] if pattern else []
        },
        "cms_profiles": {},
        "generic": {"project_path_patterns": [{"regex": r"^/(?:projekte|projets)/[^/]+/?$", "flags": "i"}]},
        "sites": {"bureau": {"base_url": host, "cms": None, "sitemap": None, "index_page": index, "curl_cffi": False}},
    }


def test_page_de_liste_de_la_recette():
    with LocalServer({}) as s:
        host = s.url("").rstrip("/")
        listing = "".join(f'<a href="/heilen/{n}/">{n}</a>' for n in ("a", "b", "c"))
        s.routes.update(
            {
                "/": body(200, b"<html></html>", Content_Type="text/html"),
                "/werkliste.html": body(200, f"<html>{listing}</html>".encode(), Content_Type="text/html"),
                "*": body(200, _project_page(1, host), Content_Type="text/html"),
            }
        )
        doc = _doc(host, index=f"{host}/werkliste.html", pattern=r"^/heilen/[^/]+/?$")
        p = asyncio.run(pp.profile_contents(s.url("/"), patterns=doc))
    assert p["site"] == "bureau" and p["source"] == "liste (recette)" and p["count"] == 3
    assert p["matched_by"] == "site:bureau"


def test_motif_reconnu_par_la_famille_d_un_autre_bureau():
    with LocalServer({}) as s:
        host = s.url("").rstrip("/")
        sm = "".join(f"<url><loc>{host}/heilen/{n}/</loc></url>" for n in ("a", "b"))
        s.routes.update(
            {
                "/robots.txt": body(200, f"Sitemap: {host}/sm.xml\n".encode(), Content_Type="text/plain"),
                "/sm.xml": body(
                    200,
                    f'<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">{sm}</urlset>'.encode(),
                    Content_Type="application/xml",
                ),
                "*": body(200, b"<html></html>", Content_Type="text/html"),
            }
        )
        doc = _doc("https://ailleurs.ch", pattern=r"^/heilen/[^/]+/?$")
        p = asyncio.run(pp.profile_contents(s.url("/"), patterns=doc))
    assert p["site"] is None and p["source"] == "sitemap" and p["count"] == 2
    assert p["matched_by"] == "site:bureau"


# ── Images en lien direct ou en arrière-plan ─────────────────────────────
def test_images_en_liens_directs():
    html = (
        '<a href="/up/werkhof-1920x1080.jpg">a</a><a href="/up/plan.png">b</a>'
        '<a href="/up/favicon.png">f</a><a href="/projekte/x/">p</a>'
    )
    page = pp.page_images(html, "https://b.ch/projekte/x/")
    assert sorted(i["url"] for i in page["images"]) == [
        "https://b.ch/up/plan.png",
        "https://b.ch/up/werkhof-1920x1080.jpg",
    ]
    assert pp.image_mode(page) == "liens directs"


def test_images_en_arriere_plan():
    html = "<div style=\"background-image: url('/up/facade.webp')\"></div>"
    page = pp.page_images(html, "https://b.ch/projekte/x/")
    assert [i["url"] for i in page["images"]] == ["https://b.ch/up/facade.webp"]
    assert pp.image_mode(page) == "arrière-plan CSS"


def test_balises_img_priment_sur_les_liens():
    html = '<img src="/up/a.jpg"><a href="/up/a-full.jpg">zoom</a>'
    assert pp.image_mode(pp.page_images(html, "https://b.ch/p/")) == "html"


def test_wp_type_projet_choisi_et_total_annonce():
    with LocalServer({}) as s:
        _wp_site(s)
        host = s.url("").rstrip("/")
        posts = [{"link": f"{host}/blog/b{i}/"} for i in range(4)]
        s.routes["/wp-json/wp/v2/posts"] = body(200, json.dumps(posts).encode(), Content_Type="application/json")
        links = [{"link": f"{host}/projekte/p{i}/"} for i in range(5)]
        s.routes["/wp-json/wp/v2/project"] = body(
            200, json.dumps(links).encode(), Content_Type="application/json", X_WP_Total="120"
        )
        p = asyncio.run(pp.profile_contents(s.url("/")))
    assert p["wp_type"] == "project" and p["count"] == 120


def test_liste_ignore_les_liens_externes_et_les_pages_hors_projets():
    with LocalServer({}) as s:
        host = s.url("").rstrip("/")
        s.routes.update(
            {
                "/robots.txt": body(404, b"", Content_Type="text/plain"),
                "/": body(
                    200,
                    b'<html><a href="/kontakt/">K</a><a href="/projekte/">P</a></html>',
                    Content_Type="text/html",
                ),
                "/kontakt/": body(200, b'<html><a href="/projekte/a1/">a1</a></html>', Content_Type="text/html"),
                "/projekte/": body(
                    200,
                    b'<html><a href="/projekte/a1/">a1</a><a href="/projekte/b2/">b2</a>'
                    b'<a href="https://ailleurs.example/projekte/z/">z</a></html>',
                    Content_Type="text/html",
                ),
                "*": body(200, _project_page(1, host), Content_Type="text/html"),
            }
        )
        p = asyncio.run(pp.profile_contents(s.url("/")))
    assert p["listing"].endswith("/projekte/") and p["count"] == 2


def test_synthese_de_projets_sans_lignes_de_sonde():
    from accesspath import batch

    rows = [
        {"status": "ok", "content_source": "sitemap", "contents": 3, "image_hosts": ["cdn.x", f"s{i}.ch"]}
        for i in range(2)
    ]
    md = batch.summarize("b", rows)
    assert "tier" not in md.lower() and "régie" not in md and "robot d'IA" not in md and "llms.txt" not in md
    hosts = md.split("## Hôtes d'images partagés")[1]
    assert "cdn.x" in hosts and "s0.ch" not in hosts


def test_synthese_de_sonde_garde_ses_lignes():
    from accesspath import batch

    md = batch.summarize("b", [{"status": "ok", "tier": 1, "ai_blocked": [], "regies": []}])
    assert "Sans navigateur (tiers 1 et 2) : 1 sur 1" in md and "llms.txt" in md and "régie" in md


@pytest.mark.parametrize(
    "path", ["/de/journal/rohbau-fertig", "/news/2024/fest", "/fr/actualites/inauguration", "/blog/neues-haus"]
)
def test_rubriques_d_actualite_ne_sont_pas_des_projets(path):
    assert not pp.is_content_url("https://b.ch" + path)


def test_versions_linguistiques_comptees_une_fois():
    urls = [
        "https://b.ch/de/architektur/haus-a",
        "https://b.ch/en/architecture/haus-a",
        "https://b.ch/fr/architecture/haus-a/",
        "https://b.ch/de/architektur/haus-b",
    ]
    assert pp.distinct_contents(urls) == 2


def test_sitemap_compte_les_traductions_une_fois():
    sm = "".join(
        f"<url><loc>{{h}}/{p}</loc></url>"
        for p in ("de/projekte/haus-a/", "en/projects/haus-a/", "de/projekte/haus-b/")
    )
    with LocalServer({}) as s:
        host = s.url("").rstrip("/")
        s.routes.update(
            {
                "/robots.txt": body(200, f"Sitemap: {host}/sm.xml".encode(), Content_Type="text/plain"),
                "/sm.xml": body(
                    200,
                    f'<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">{sm.format(h=host)}</urlset>'.encode(),
                    Content_Type="application/xml",
                ),
                "*": body(404, b"", Content_Type="text/html"),
            }
        )
        p = asyncio.run(pp.profile_contents(s.url("/")))
    assert p["source"] == "sitemap" and p["count"] == 2


def test_ancien_nom_du_mode_accepte(tmp_path, monkeypatch):
    from accesspath import batch, cli

    seen = {}

    def fake_runner(**kw):
        seen.update(kw)

        async def run(t):
            return {"status": "ok", "content_source": None, "contents": 0}

        return run

    monkeypatch.setattr(batch, "contents_runner", fake_runner)
    f = tmp_path / "liste.csv"
    f.write_text("url,name\nhttps://a.ch,a\n")
    assert cli.main(["sap", "batch", str(f), "--mode", "projects", "--out", str(tmp_path / "o")]) == 0
    assert seen["deadline"] == batch.SITE_DEADLINE_S["contents"]


def test_onglets_d_un_projet_comptes_une_fois():
    """Cas Roman Hutter : /projekte/<projet>/bilder|beschrieb|modell/, 83 projets comptés 7."""
    urls = [
        f"https://b.ch/projekte/{p}/{tab}/"
        for p in ("haus-a", "haus-b", "schule-c", "halle-d")
        for tab in ("bilder", "beschrieb", "modell")
    ]
    assert pp.distinct_contents(urls) == 4


def test_deux_pages_d_un_meme_projet_ne_sont_pas_des_onglets():
    urls = ["https://b.ch/projekte/haus-a/bilder", "https://b.ch/projekte/haus-a/plaene"]
    assert pp.distinct_contents(urls) == 2


def test_index_d_archives_mensuelles_lu_jusqu_au_bout():
    """Cas Eglin : 80 archives mensuelles d'articles WordPress, les projets publiés comme
    articles de 2017 à 2026 ; l'audit s'arrêtait aux 25 premières."""
    xmlns = 'xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"'
    months = [f"sitemap-pt-post-20{y:02d}-{m:02d}.xml" for y in range(19, 26) for m in range(1, 13)][:80]
    with LocalServer({}) as s:
        host = s.url("").rstrip("/")

        def urlset(paths):
            locs = "".join(f"<url><loc>{host}/{p}</loc></url>" for p in paths)
            return body(200, f"<urlset {xmlns}>{locs}</urlset>".encode(), Content_Type="application/xml")

        index = "".join(f"<sitemap><loc>{host}/{n}</loc></sitemap>" for n in months)
        s.routes.update(
            {
                "/robots.txt": body(200, f"Sitemap: {host}/sitemap.xml".encode(), Content_Type="text/plain"),
                "/sitemap.xml": body(
                    200, f"<sitemapindex {xmlns}>{index}</sitemapindex>".encode(), Content_Type="application/xml"
                ),
                **{f"/{n}": urlset([f"arbeiten/bauten/haus-{n[16:23]}"]) for n in months},
                "*": body(404, b"", Content_Type="text/html"),
            }
        )
        p = asyncio.run(pp.profile_contents(s.url("/")))
    assert p["source"] == "sitemap" and p["count"] == 80


def test_petit_site_en_trois_langues_compte_ses_projets():
    urls = [
        f"https://b.ch/{lang}/{word}/{p}"
        for lang, word in (("de", "projekte"), ("en", "projects"), ("it", "progetti"))
        for p in ("haus-a", "haus-b")
    ]
    assert pp.distinct_contents(urls) == 2


def test_projets_ranges_par_rubrique_comptes_un_a_un():
    urls = [
        f"https://b.ch/work/{rubrique}/{p}"
        for rubrique, p in (("wohnen", "a"), ("wohnen", "b"), ("bildung", "c"), ("bildung", "d"))
    ]
    assert pp.distinct_contents(urls) == 4
