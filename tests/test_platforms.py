"""Base de plateformes commune aux études : une plateforme logicielle reconnue donne sa
recette d'accès, ses instances connues et la source du savoir."""

from __future__ import annotations

import pytest

from accesspath import probe as probe_mod
from accesspath.acquisition import platforms as pf


def test_base_valide():
    doc = pf.load()
    assert {"chregister", "hrc-internet", "zefix", "i-web", "wordpress"} <= set(doc["platforms"])
    for name, p in doc["platforms"].items():
        assert p["domain"] and p["description"], name
        assert any(p["detect"].get(k) for k in ("hosts", "html", "headers", "cookies", "instances")), name
        assert p["recipe"], name
        assert p["source"], name


@pytest.mark.parametrize(
    "url, html, headers, expected",
    [
        ("https://zh.chregister.ch/cr-portal/auszug/auszug.xhtml?uid=CHE-1", "", {}, "chregister"),
        ("https://www.zefix.ch/fr/search/entity/welcome", "", {}, "zefix"),
        ("https://rcnet.ne.ch/", "", {}, "hrc-internet"),
        ("https://prestations.vd.ch/pub/101266/", "", {}, "hrc-internet"),
        ("https://www.hittnau.ch/", '<img src="https://pcdn1.i-web.ch/abc/1920x850/smart/x.jpg">', {}, "i-web"),
        ("https://bureau.ch/", '<link rel="https://api.w.org/" href="/wp-json/">', {}, "wordpress"),
        ("https://x.ch/", "", {"Set-Cookie": "XSRF-TOKEN=abc; Path=/"}, None),
    ],
)
def test_detection(url, html, headers, expected):
    found = pf.detect(url, html=html, headers=headers)
    assert (found[0]["platform"] if found else None) == expected


def test_hote_partage_exige_le_chemin_de_l_instance():
    assert pf.detect("https://prestations.vd.ch/pub/autre-service/") == []


def test_preuves_et_recette():
    hit = pf.detect("https://zh.chregister.ch/cr-portal/")[0]
    assert hit["domain"] == "registres du commerce"
    assert any("chregister.ch" in e for e in hit["evidence"])
    assert hit["instances"] >= 25
    assert "ViewState" in hit["recipe"]["auth"]


def test_rapport_de_sonde():
    r = probe_mod.ProbeReport(url="https://zh.chregister.ch/", timestamp="t")
    r.known_platforms = pf.detect("https://zh.chregister.ch/")
    md = probe_mod.emit_markdown(r, "x")
    section = md.split("## Plateforme connue")[1]
    assert "chregister" in section and "registres du commerce" in section and "ViewState" in section
    assert probe_mod.emit_sap_entry(r)["known_platforms"] == ["chregister"]


def test_rapport_sans_plateforme_connue():
    r = probe_mod.ProbeReport(url="https://x.ch/", timestamp="t")
    assert "## Plateforme connue" not in probe_mod.emit_markdown(r, "x")


def test_ligne_de_lot():
    from accesspath import batch

    r = probe_mod.ProbeReport(url="https://zh.chregister.ch/", timestamp="t", chosen_tier=2, rationale="x")
    r.known_platforms = pf.detect("https://zh.chregister.ch/")
    assert batch.probe_row(r)["known_platform"] == ["chregister"]


def test_la_plateforme_la_mieux_attestee_vient_en_tete():
    html = '<script src="/typo3conf/a.js"></script><img src="/fileadmin/b.jpg"><link href="/wp-content/x.css">'
    assert [f["platform"] for f in pf.detect("https://b.ch/", html=html)] == ["typo3", "wordpress"]


def test_rapport_liste_les_points_d_entree():
    md = "\n".join(pf.report_lines(pf.detect("https://zh.chregister.ch/"), lambda v, _n=0: str(v)))
    assert "`POST /cr-portal/auszug/auszug.xhtml" in md


@pytest.mark.parametrize(
    "html, headers, expected",
    [
        ('<meta name="generator" content="Wix.com Website Builder"><script id="wix-warmup-data">', {}, "wix"),
        ('<html data-wf-page="a" data-wf-site="b"><meta content="Webflow" name="generator">', {}, "webflow"),
        (
            '<img src="/sites/default/files/styles/large/public/a.jpg">',
            {"X-Drupal-Cache": "HIT"},
            "drupal",
        ),
        ('<meta name="generator" content="Contao Open Source CMS"><img src="/assets/images/4/a.jpg">', {}, "contao"),
    ],
)
def test_plateformes_promues(html, headers, expected):
    assert pf.detect("https://b.ch/", html=html, headers=headers)[0]["platform"] == expected


@pytest.mark.parametrize("name", ["wix", "webflow", "drupal", "contao"])
def test_recettes_promues_completes(name):
    p = pf.load()["platforms"][name]
    assert {"tier", "discovery", "auth", "format", "images"} <= set(p["recipe"])
    assert p["source"].startswith("campagne")


def test_motif_appris_promu_n_est_plus_un_candidat(tmp_path, monkeypatch):
    import yaml

    from accesspath.acquisition import learn

    wix = {"kind": "platform", "name": "wix.com", "sites": 36, "examples": [], "campaign": "c", "shared": None,
           "markers": [{"kind": "asset_host", "marker": "static.wixstatic.com"}]}  # fmt: skip
    neuf = {**wix, "name": "neuf", "markers": [{"kind": "asset_host", "marker": "cdn.neuf.example"}]}
    learn.LOCAL_FILE.write_text(yaml.safe_dump({"version": 1, "candidates": [wix, neuf]}))
    pf._DOC = None
    names = set(pf.load()["platforms"])
    assert "local:wix.com" not in names and "local:neuf" in names
