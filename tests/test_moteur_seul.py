"""Le moteur seul : sans collecteur branché, il audite ; un projet de collecte branche les
siens par `ACCESSPATH_SITES`, garde ses données dans son dossier, et le savoir des motifs
publié ne nomme aucun site."""

from __future__ import annotations

import asyncio
import importlib
import sys
import types

import pytest
import yaml

from accesspath import cli, config, sap
from accesspath.acquisition import patterns


@pytest.fixture
def collecteurs(monkeypatch):
    """Un paquet de collecteurs factice : un site, avec son contrôle `sap_verify`."""
    pkg = types.ModuleType("collecteurs_factices")
    pkg.REGISTRY = {"site_a": object()}
    mod = types.ModuleType("collecteurs_factices.site_a")

    async def sap_verify():
        return sap.SapResult(site="site_a", timestamp="t", fetch_url="u", fetch_method="http", overall="pass")

    mod.sap_verify = sap_verify
    monkeypatch.setitem(sys.modules, "collecteurs_factices", pkg)
    monkeypatch.setitem(sys.modules, "collecteurs_factices.site_a", mod)
    monkeypatch.setattr(config, "SITES_PACKAGE", "collecteurs_factices")


def test_sans_collecteur_le_registre_est_vide(monkeypatch):
    monkeypatch.setattr(config, "SITES_PACKAGE", "")
    assert config.sites_registry() == {}
    with pytest.raises(ImportError):
        config.site_module("site_a")


def test_collecteurs_branches(collecteurs):
    assert list(config.sites_registry()) == ["site_a"]
    assert config.site_module("site_a").sap_verify


def test_verify_appelle_le_collecteur_branche(collecteurs):
    r = asyncio.run(sap.verify_site("site_a"))
    assert r.overall == "pass"
    r = asyncio.run(sap.verify_site("site_b"))
    assert r.overall == "fail" and "sans collecteur" in r.error  # refusé avant tout import


def test_warmup_d_un_site_branche_sans_adresse(collecteurs, monkeypatch):
    from accesspath import human

    vus = []

    async def warmup(site, at=None):
        vus.append((site, at))
        return True

    monkeypatch.setattr(human, "warmup", warmup)
    assert cli.main(["warmup", "site_a"]) == 0
    assert vus == [(config.sites_registry()["site_a"], None)]


def test_cli_verify_sans_collecteur(monkeypatch, capsys):
    monkeypatch.setattr(config, "SITES_PACKAGE", "")
    assert cli.main(["sap", "verify", "site_a"]) == 3
    assert "ACCESSPATH_SITES" in capsys.readouterr().err


def test_donnees_dans_le_dossier_appelant(monkeypatch, tmp_path):
    monkeypatch.delenv("ACCESSPATH_DATA", raising=False)
    monkeypatch.chdir(tmp_path)
    assert importlib.reload(config).DATA_DIR == tmp_path / "data"
    monkeypatch.setenv("ACCESSPATH_DATA", str(tmp_path / "ailleurs"))
    assert importlib.reload(config).DATA_DIR == tmp_path / "ailleurs"
    monkeypatch.setenv("ACCESSPATH_SITES", "collecteurs_x")
    assert importlib.reload(config).SITES_PACKAGE == "collecteurs_x"
    monkeypatch.delenv("ACCESSPATH_DATA")
    monkeypatch.delenv("ACCESSPATH_SITES")
    importlib.reload(config)


# ── Savoir des motifs, vue publique ──────────────────────────────────────
FULL = {
    "version": 1,
    "source": "sites/*.py",
    "cms_profiles": {"wordpress": {"project_path_patterns": [{"regex": "^/projets/[^/]+/?$", "flags": "i"}]}},
    "generic": {"project_path_patterns": [{"regex": "^/work/[^/]+/?$", "flags": "i"}]},
    "families": {
        "project_url_patterns": [
            {"regex": "^/referenzen/[^/]+/?$", "flags": "i", "sites": ["bureau_a", "bureau_b"]},
            {"regex": "^/seul/[^/]+/?$", "flags": "i", "sites": ["bureau_c"]},
        ],
        "index_pages": [{"site": "bureau_a", "url": "https://a.ch/projekte"}],
    },
    "templates": [
        {
            "cms": "wordpress",
            "best": {"combo": {"cms": "wordpress"}, "sites": 5, "examples": ["bureau_a"]},
            "variants": [{"combo": {}, "sites": 3, "examples": ["bureau_b"]}, {"combo": {}, "sites": 1}],
        }
    ],
    "sites": {"bureau_a": {"base_url": "https://a.ch"}},
    "unreadable": ["bureau_z"],
}


def test_vue_publique_sans_site():
    pub = patterns.public_view(FULL)
    text = yaml.safe_dump(pub)
    assert "bureau" not in text and "http" not in text
    assert pub["sites"] == {} and "unreadable" not in pub and "source" not in pub
    fams = pub["families"]["project_url_patterns"]
    assert fams == [{"regex": "^/referenzen/[^/]+/?$", "flags": "i", "n_sites": 2}]  # le motif d'un seul site part
    assert "index_pages" not in pub["families"]
    assert [v["sites"] for v in pub["templates"][0]["variants"]] == [3]
    assert "examples" not in pub["templates"][0]["best"]
    assert FULL["sites"]  # l'original n'est pas touché


def test_vue_publique_reste_utilisable():
    pub = patterns.public_view(FULL)
    assert patterns.match_project(pub, "https://x.ch/referenzen/maison") == "famille:1"
    assert patterns.match_project(pub, "https://x.ch/work/maison") == "générique"
    assert patterns.match_project(FULL, "https://x.ch/referenzen/maison") == "site:bureau_a"
    assert patterns.site_for_url(pub, "https://a.ch/") is None
    assert patterns.site_for_url({k: v for k, v in pub.items() if k != "sites"}, "https://a.ch/") is None
    assert patterns.site_for_url(FULL, "https://www.a.ch/x") == "bureau_a"


def test_fichier_livre_ne_nomme_aucun_site():
    doc = patterns.load()
    assert doc["sites"] == {}
    text = patterns.PATTERNS_FILE.read_text(encoding="utf-8")
    assert "http" not in text and "sites:\n    -" not in text and "examples" not in text
    assert patterns.match_project(doc, "https://x.ch/projekte/haus") is not None


def test_fichier_complet_par_variable(monkeypatch, tmp_path):
    f = tmp_path / "websites.yaml"
    f.write_text(yaml.safe_dump(FULL), encoding="utf-8")
    monkeypatch.setenv("ACCESSPATH_PATTERNS", str(f))
    try:
        assert importlib.reload(patterns).load()["sites"] == FULL["sites"]
    finally:
        monkeypatch.delenv("ACCESSPATH_PATTERNS")
        importlib.reload(patterns)


def test_un_projet_ajoute_ses_commandes(capsys):
    vus = []

    def extend(sub):
        run = sub.add_parser("run")
        run.add_argument("site")

    def cmd_run(args):
        vus.append(args.site)
        return 7

    assert cli.main(["run", "site_a"], extend=extend, dispatch={"run": cmd_run}, prog="atelier") == 7
    assert vus == ["site_a"]
    with pytest.raises(SystemExit):
        cli.main(["run", "site_a"])  # le moteur seul ne connaît pas `run`
    assert "atelier" in cli.build_parser(extend, "atelier").format_usage()
