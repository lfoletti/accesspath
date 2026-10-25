"""File de gestes humains : un geste nécessaire devient un ticket, traité en
lot par `gestes --faire`, au lieu d'un échec découvert trop tard."""

from __future__ import annotations

import json
from types import SimpleNamespace as NS

import pytest

from accesspath import cli, gestures, human, sap_inspect
from accesspath._safe import UnsafeInput
from accesspath.browser import profile as profile_mod
from accesspath.human_gate import HumanGate


@pytest.fixture
def data(tmp_path, monkeypatch):
    monkeypatch.setattr(gestures, "GESTURES_FILE", tmp_path / "gestures.jsonl")
    monkeypatch.setattr(profile_mod, "PROFILES_DIR", tmp_path / "profiles")
    return tmp_path


def test_un_ticket_par_site_ouvert(data):
    assert gestures.add("magazine_ch", "challenge", "https://www.magazine.ch/", "403 cloudflare")
    assert not gestures.add("magazine_ch", "challenge", "https://www.magazine.ch/", "encore")
    assert [g.site for g in gestures.pending()] == ["magazine_ch"]
    g = gestures.pending()[0]
    assert (g.kind, g.open_url, g.reason) == ("challenge", "https://www.magazine.ch/", "403 cloudflare")


def test_resolu_puis_rouvert(data):
    gestures.add("a_b", "login", "https://a.b/", "401")
    gestures.resolve("a_b")
    assert gestures.pending() == []
    assert gestures.add("a_b", "login", "https://a.b/", "401 à nouveau")
    assert len(gestures.pending()) == 1


def test_entrees_validees(data):
    with pytest.raises(UnsafeInput):
        gestures.add("../x", "login", "https://a.b/", "r")
    with pytest.raises(UnsafeInput):
        gestures.add("a_b", "login", "file:///etc/passwd", "r")
    with pytest.raises(UnsafeInput):
        gestures.add("a_b", "login", "https://user:pw@a.b/", "r")
    assert not (data / "gestures.jsonl").exists()


def test_ligne_corrompue_ignoree(data):
    gestures.add("a_b", "login", "https://a.b/", "r")
    with (data / "gestures.jsonl").open("a") as f:
        f.write("pas du json\n")
    assert [g.site for g in gestures.pending()] == ["a_b"]


# ── warmup : la session réussie marque le profil et ferme le ticket ──────────
@pytest.fixture
def chrome_factice(monkeypatch):
    ouverts = []

    async def _open(name, url, site=None):
        ouverts.append((name, url))

    monkeypatch.setattr(human, "_open_and_wait", _open)
    monkeypatch.setattr(human, "detect_policy", lambda: human.HumanPolicy.INTERACTIVE)
    return ouverts


def test_warmup_at_pour_un_site_sans_collecteur(data, chrome_factice):
    gestures.add("nouveau_ch", "challenge", "https://nouveau.ch/", "403")
    assert cli.main(["warmup", "nouveau_ch", "--at", "https://nouveau.ch/liste"]) == 0
    assert chrome_factice == [("nouveau_ch", "https://nouveau.ch/liste")]
    assert profile_mod.is_warm("nouveau_ch")
    assert gestures.pending() == []


def test_warmup_inconnu_sans_at_explique(data, chrome_factice, capsys):
    assert cli.main(["warmup", "nouveau_ch"]) == 3
    assert "--at" in capsys.readouterr().err
    assert chrome_factice == []


def test_warmup_at_refuse_une_url_dangereuse(data, chrome_factice):
    assert cli.main(["warmup", "nouveau_ch", "--at", "javascript:alert(1)"]) == 3
    assert chrome_factice == []


def test_gestes_liste_puis_fait(data, chrome_factice, capsys):
    gestures.add("a_ch", "challenge", "https://a.ch/", "403 datadome")
    gestures.add("b_ch", "consent", "https://b.ch/", "bannière")
    assert cli.main(["gestes"]) == 0
    out = capsys.readouterr().out
    assert "a_ch" in out and "https://b.ch/" in out and "2 gestes" in out
    assert chrome_factice == []
    assert cli.main(["gestes", "--faire"]) == 0
    assert chrome_factice == [("a_ch", "https://a.ch/"), ("b_ch", "https://b.ch/")]
    assert gestures.pending() == []


def test_gestes_faire_sans_humain_ne_lance_rien(data, chrome_factice, monkeypatch, capsys):
    monkeypatch.setattr(human, "detect_policy", lambda: human.HumanPolicy.UNATTENDED)
    gestures.add("a_ch", "challenge", "https://a.ch/", "403")
    assert cli.main(["gestes", "--faire"]) == 2
    assert "demande un humain" in capsys.readouterr().err
    assert chrome_factice == []
    assert len(gestures.pending()) == 1


# ── run sans humain : le profil froid dépose un ticket ───────────────────────


# ── inspect : le geste annoncé devient un ticket, seulement avec --save ──────
def _rapport_avec_geste():
    rep = NS(
        name="dur_ch",
        reachability=NS(status="blocked", evidence="HTTP 403"),
        human_gate=HumanGate("challenge", "datadome", "https://dur.ch/", 20, ["HTTP 403"], "mac"),
    )
    return rep


@pytest.fixture
def inspect_factice(monkeypatch):
    async def _inspect(url, name, **kw):
        return _rapport_avec_geste()

    monkeypatch.setattr(sap_inspect, "inspect", _inspect)
    monkeypatch.setattr(sap_inspect, "to_markdown", lambda r: "rapport")
    monkeypatch.setattr(sap_inspect, "save_report", lambda r: {})


def test_inspect_save_depose_le_geste(data, inspect_factice):
    assert cli.main(["sap", "inspect", "https://dur.ch/", "--name", "dur_ch", "--save"]) == 0
    (g,) = gestures.pending()
    assert (g.site, g.kind, g.open_url) == ("dur_ch", "challenge", "https://dur.ch/")
    assert "datadome" in g.reason


def test_inspect_sans_save_n_ecrit_rien(data, inspect_factice):
    assert cli.main(["sap", "inspect", "https://dur.ch/", "--name", "dur_ch"]) == 0
    assert not (data / "gestures.jsonl").exists()


def test_le_rapport_donne_la_commande_avec_at():
    rep = NS(name="dur_ch", target_url="https://dur.ch/")
    lines = "\n".join(sap_inspect._human_gate_lines(_rapport_avec_geste().human_gate, rep.name, rep.target_url))
    assert "warmup dur_ch --at https://dur.ch/" in lines
    assert "gestes" in lines


def test_fichier_jsonl_lisible(data):
    gestures.add("a_ch", "login", "https://a.ch/", "r")
    rec = json.loads((data / "gestures.jsonl").read_text().splitlines()[0])
    assert {"site", "kind", "open_url", "reason", "at"} <= set(rec)
