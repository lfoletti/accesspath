"""Portes de confiance : la sonde lit d'abord ce que la page d'accueil déclare
(flux, oEmbed, AMP), puis les points d'accès connus de la plateforme reconnue,
et ne devine les chemins génériques que pour une plateforme inconnue. Chaque
porte rend son nombre d'éléments et sa date la plus récente."""

from __future__ import annotations

import asyncio
import json

import pytest

from accesspath import probe as probe_mod

from ._localserver import LocalServer, body


@pytest.fixture(autouse=True)
def _allow_local(monkeypatch):
    monkeypatch.setenv("ACCESSPATH_ALLOW_PRIVATE", "1")


# ── reconnaissance de plateforme (fonction pure) ────────────────────────────
@pytest.mark.parametrize(
    ("html", "headers", "attendu"),
    [
        ('<script src="https://cdn.shopify.com/s/x.js"></script>', {}, "shopify"),
        ("<html></html>", {"X-ShopId": "123"}, "shopify"),
        ('<link href="/wp-content/themes/t/style.css">', {}, "wordpress"),
        ('<link rel="https://api.w.org/" href="/wp-json/">', {}, "wordpress"),
        ('<img src="https://images.squarespace-cdn.com/a.jpg">', {}, "squarespace"),
        ('<html data-wf-site="abc">', {}, "webflow"),
        ("<html><body>bonjour</body></html>", {}, "generic"),
    ],
)
def test_fingerprint_platform(html, headers, attendu):
    assert probe_mod.fingerprint_platform(html, headers) == attendu


# ── portes déclarées par l'accueil (fonction pure) ──────────────────────────
ACCUEIL = """<html><head>
<link rel="alternate" type="application/rss+xml" title="Actu" href="/actu/feed.xml">
<link rel="alternate" type="application/json+oembed" href="https://www.exemple.ch/oembed?url=x">
<link rel="amphtml" href="/amp/">
<link rel="alternate" type="application/atom+xml" href="https://feeds.ailleurs.com/x.atom">
<link rel="stylesheet" href="/style.css">
<link rel="alternate" hreflang="de" href="/de/">
</head></html>"""


def test_declared_doors():
    doors = probe_mod.declared_doors(ACCUEIL, "https://www.exemple.ch")
    internes = {d["path"]: d["kind"] for d in doors if not d["external"]}
    assert internes == {"/actu/feed.xml": "rss", "/oembed?url=x": "oembed", "/amp/": "amp"}
    externes = [d["url"] for d in doors if d["external"]]
    assert externes == ["https://feeds.ailleurs.com/x.atom"]


# ── statistiques d'une porte (fonction pure) ────────────────────────────────
RSS = b"""<?xml version="1.0"?><rss><channel>
<item><pubDate>Mon, 20 Oct 2026 08:00:00 GMT</pubDate></item>
<item><pubDate>Thu, 23 Oct 2026 09:30:00 GMT</pubDate></item>
<item><pubDate>Tue, 21 Oct 2026 10:00:00 GMT</pubDate></item>
</channel></rss>"""

SITEMAP = b"""<?xml version="1.0"?><urlset>
<url><loc>https://x/a</loc><lastmod>2026-09-01</lastmod></url>
<url><loc>https://x/b</loc><lastmod>2026-10-02T12:00:00+00:00</lastmod></url>
</urlset>"""


def _r(payload: bytes, ct: str, headers: dict | None = None) -> dict:
    return {"ok": True, "status": 200, "body": payload, "content_type": ct, "headers": headers or {}}


def test_stats_rss():
    st = probe_mod.door_stats("rss", _r(RSS, "application/rss+xml"))
    assert st == {"items": 3, "newest": "2026-10-23"}


def test_stats_sitemap():
    st = probe_mod.door_stats("sitemap", _r(SITEMAP, "application/xml"))
    assert st == {"items": 2, "newest": "2026-10-02"}


def test_stats_shopify_et_wordpress():
    produits = json.dumps(
        {"products": [{"updated_at": "2026-10-01T10:00:00-04:00"}, {"updated_at": "2026-10-22T08:00:00+02:00"}]}
    ).encode()
    assert probe_mod.door_stats("json", _r(produits, "application/json")) == {"items": 2, "newest": "2026-10-22"}
    posts = json.dumps([{"date_gmt": "2026-10-24T07:00:00"}]).encode()
    st = probe_mod.door_stats("json", _r(posts, "application/json", {"X-WP-Total": "1532"}))
    assert st == {"items": 1532, "newest": "2026-10-24"}


def test_stats_illisible_reste_inconnu():
    assert probe_mod.door_stats("rss", _r(b"<rss><oops", "application/rss+xml")) == {"items": None, "newest": None}


# ── sonde complète sur un faux Shopify ──────────────────────────────────────
PRODUITS = json.dumps(
    {"products": [{"updated_at": "2026-10-01T10:00:00Z"}, {"updated_at": "2026-10-20T10:00:00Z"}]}
).encode()


def _shopify(robots: bytes = b"User-agent: *\nAllow: /\n"):
    home = (
        b'<html><head><script src="https://cdn.shopify.com/s/t.js"></script>'
        b'<link rel="alternate" type="application/json+oembed" href="/oembed?url=x">'
        b'<link rel="alternate" type="application/atom+xml" href="/blog.atom">'
        b"</head><body>" + b"<p>boutique</p>" * 400 + b"</body></html>"
    )
    atom = b'<?xml version="1.0"?><feed><entry><updated>2026-10-23T00:00:00Z</updated></entry></feed>'
    return LocalServer(
        {
            "/": body(200, home, Content_Type="text/html"),
            "/robots.txt": body(200, robots, Content_Type="text/plain"),
            "/products.json": body(200, PRODUITS, Content_Type="application/json"),
            "/oembed": body(200, b'{"type":"rich"}', Content_Type="application/json"),
            "/blog.atom": body(200, atom, Content_Type="application/atom+xml"),
        }
    )


def test_shopify_portes_de_plateforme_sans_chemins_devines():
    with _shopify() as s:
        rep = asyncio.run(probe_mod.probe(s.url("/")))
        log = list(s.log)
    assert rep.tier1["platform"] == "shopify"
    assert "/products.json?limit=250" in log
    assert "/oembed?url=x" in log and "/blog.atom" in log
    for devine in ("/wp-json", "/api/v1", "/graphql", "/api/posts"):
        assert devine not in log
    portes = {f["endpoint"]: f for f in rep.tier1["found"]}
    assert portes["/products.json?limit=250"]["items"] == 2
    assert portes["/products.json?limit=250"]["newest"] == "2026-10-20"
    assert portes["/products.json?limit=250"]["source"] == "plateforme"
    assert portes["/blog.atom"]["source"] == "déclarée"
    assert portes["/blog.atom"]["items"] == 1
    assert rep.chosen_tier == 1 and "products.json" in rep.rationale


def test_porte_declaree_interdite_par_robots_n_est_pas_demandee():
    with _shopify(robots=b"User-agent: *\nDisallow: /blog.atom\n") as s:
        rep = asyncio.run(probe_mod.probe(s.url("/")))
        log = list(s.log)
    assert "/blog.atom" not in log
    assert "/blog.atom" in rep.tier1["skipped_by_robots"]


def test_plateforme_inconnue_garde_les_chemins_generiques():
    with LocalServer({"/": body(200, b"<html>" + b"<p>x</p>" * 400 + b"</html>", Content_Type="text/html")}) as s:
        rep = asyncio.run(probe_mod.probe(s.url("/")))
        log = list(s.log)
    assert rep.tier1["platform"] == "generic"
    assert "/api/v1" in log and "/graphql" in log


def test_rapport_et_entree_sap():
    with _shopify() as s:
        rep = asyncio.run(probe_mod.probe(s.url("/")))
    md = probe_mod.emit_markdown(rep, "boutique")
    assert "Plateforme reconnue" in md and "shopify" in md
    assert "| Source |" in md or "Source" in md.split("## Tier 1")[1].split("\n")[2]
    entry = probe_mod.emit_sap_entry(rep)
    assert entry["platform"] == "shopify"
    assert entry["chosen_method"]["endpoint"] == "/products.json?limit=250"
    assert entry["doors"]["/products.json?limit=250"] == {
        "type": "json",
        "source": "plateforme",
        "items": 2,
        "newest": "2026-10-20",
    }


def test_date_ramenee_en_utc():
    # 01 h à Zurich le 22 = 23 h UTC le 21 : la fraîcheur se compare en UTC.
    assert probe_mod._iso_date("2026-10-22T01:00:00+02:00") == "2026-10-21"
    assert probe_mod._iso_date("Thu, 23 Oct 2026 01:30:00 +0200") == "2026-10-22"
    assert probe_mod._iso_date("2026-10-02") == "2026-10-02"
    assert probe_mod._iso_date("pas une date") is None


def test_index_de_sitemap_compte_ses_sitemaps():
    idx = b"""<?xml version="1.0"?><sitemapindex>
<sitemap><loc>https://x/s1.xml</loc><lastmod>2026-10-20</lastmod></sitemap>
<sitemap><loc>https://x/s2.xml</loc><lastmod>2026-10-23</lastmod></sitemap>
<sitemap><loc>https://x/s3.xml</loc></sitemap>
</sitemapindex>"""
    assert probe_mod.door_stats("sitemap", _r(idx, "application/xml")) == {"items": 3, "newest": "2026-10-23"}


def test_portes_de_plateforme_fermees_repli_generique():
    # WordPress reconnu, mais /wp-json, /feed et les sitemaps répondent 403 (cas dezeen) :
    # la sonde ne s'arrête pas là, elle essaie aussi les chemins génériques.
    home = b'<html><link href="/wp-content/t.css">' + b"<p>x</p>" * 400 + b"</html>"
    rss = b'<?xml version="1.0"?><rss><channel><item><pubDate>Thu, 23 Oct 2026 09:00:00 GMT</pubDate></item></channel></rss>'
    routes = {
        "/": body(200, home, Content_Type="text/html"),
        "/rss": body(200, rss, Content_Type="application/rss+xml"),
        "/robots.txt": body(404, b"", Content_Type="text/plain"),
        "*": body(403, b"interdit", Content_Type="text/html"),
    }
    with LocalServer(routes) as s:
        rep = asyncio.run(probe_mod.probe(s.url("/")))
        log = list(s.log)
    assert rep.tier1["platform"] == "wordpress"
    assert "/rss" in log
    portes = {f["endpoint"]: f for f in rep.tier1["found"]}
    assert portes["/rss"]["source"] == "générique" and portes["/rss"]["items"] == 1
    assert rep.chosen_tier == 1
