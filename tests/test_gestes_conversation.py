"""Gestes pilotés depuis la conversation : chaque étape est une commande qui rend la main.

`gestes --ouvrir` lance Chrome sur le profil du site et le laisse ouvert ; la personne fait
le geste (par le partage d'écran quand elle est en SSH), puis dit « fait », « passe » ou
« inutile ». `--verifier` relit la page avant de marquer le profil, `--passer` ferme la
fenêtre en gardant le ticket, `--ecarter` ferme le ticket avec son motif, `--revoir`
réaudite les tickets avec le code actuel.
"""

from __future__ import annotations

import json
from types import SimpleNamespace as NS

import pytest

from accesspath import cli, gestures, human, sap_inspect
from accesspath.browser import profile as profile_mod
from accesspath.human_gate import HumanGate

PAGE_OK = {"title": "Atelier A", "body": "Projekte Kontakt " * 40, "final_url": "https://a.ch/"}
PAGE_DEFI = {"title": "Just a moment...", "body": "Checking your browser", "final_url": "https://a.ch/"}
PAGE_REFUS = {"title": "Attention", "body": "Sorry, you have been blocked", "final_url": "https://a.ch/"}
PAGE_VIDE = {"title": "", "body": "", "final_url": ""}


@pytest.fixture
def chrome(tmp_path, monkeypatch):
    monkeypatch.setattr(gestures, "GESTURES_FILE", tmp_path / "gestures.jsonl")
    monkeypatch.setattr(profile_mod, "PROFILES_DIR", tmp_path / "profiles")
    # Pas de terminal : la conversation pilote, aucune commande n'attend une touche.
    monkeypatch.setattr(human, "detect_policy", lambda: human.HumanPolicy.UNATTENDED)
    etat = NS(lances=[], fermes=[], page=dict(PAGE_OK))

    async def _launch(name, url):
        etat.lances.append((name, url))
        return {"pid": 4242, "port": 9555}

    async def _read(port):
        return dict(etat.page)

    async def _close(port, pid):
        etat.fermes.append((port, pid))

    monkeypatch.setattr(human, "_launch_detached", _launch)
    monkeypatch.setattr(human, "_read_open_page", _read)
    monkeypatch.setattr(human, "_close_chrome", _close)
    monkeypatch.setattr(human, "_window_alive", lambda st: (st["port"], st["pid"]) not in etat.fermes)
    return etat


def _records(tmp_path):
    return [json.loads(line) for line in (tmp_path / "gestures.jsonl").read_text().splitlines()]


def test_ouvrir_lance_chrome_et_rend_la_main(chrome, capsys):
    gestures.add("a_ch", "challenge", "https://a.ch/", "403")
    assert cli.main(["gestes", "--ouvrir", "a_ch"]) == 0
    assert chrome.lances == [("a_ch", "https://a.ch/")]
    assert chrome.fermes == []
    assert [g.site for g in gestures.pending()] == ["a_ch"]
    assert not profile_mod.is_warm("a_ch")
    assert "--verifier a_ch" in capsys.readouterr().out


def test_ouvrir_un_site_sans_ticket(chrome, capsys):
    assert cli.main(["gestes", "--ouvrir", "b_ch"]) == 3
    assert chrome.lances == []
    assert "aucun geste en attente pour b_ch" in capsys.readouterr().err


def test_ouvrir_deux_fois_ne_relance_pas(chrome):
    gestures.add("a_ch", "challenge", "https://a.ch/", "403")
    cli.main(["gestes", "--ouvrir", "a_ch"])
    assert cli.main(["gestes", "--ouvrir", "a_ch"]) == 0
    assert len(chrome.lances) == 1


def test_verifier_page_servie_marque_le_profil(chrome):
    gestures.add("a_ch", "challenge", "https://a.ch/", "403")
    cli.main(["gestes", "--ouvrir", "a_ch"])
    assert cli.main(["gestes", "--verifier", "a_ch"]) == 0
    assert profile_mod.is_warm("a_ch")
    assert gestures.pending() == []
    assert chrome.fermes == [(9555, 4242)]


@pytest.mark.parametrize(("page", "mot"), [(PAGE_DEFI, "défi"), (PAGE_REFUS, "refus net"), (PAGE_VIDE, "page vide")])
def test_verifier_page_encore_bloquee_garde_tout(chrome, capsys, page, mot):
    gestures.add("a_ch", "challenge", "https://a.ch/", "403")
    cli.main(["gestes", "--ouvrir", "a_ch"])
    chrome.page = dict(page)
    assert cli.main(["gestes", "--verifier", "a_ch"]) == 2
    assert not profile_mod.is_warm("a_ch")
    assert [g.site for g in gestures.pending()] == ["a_ch"]
    assert chrome.fermes == []  # la fenêtre reste ouverte pour un nouvel essai
    assert mot in capsys.readouterr().out


def test_verifier_sans_fenetre_ouverte(chrome, capsys):
    gestures.add("a_ch", "challenge", "https://a.ch/", "403")
    assert cli.main(["gestes", "--verifier", "a_ch"]) == 3
    assert "--ouvrir a_ch" in capsys.readouterr().err


def test_passer_ferme_la_fenetre_et_garde_le_ticket(chrome):
    gestures.add("a_ch", "challenge", "https://a.ch/", "403")
    cli.main(["gestes", "--ouvrir", "a_ch"])
    assert cli.main(["gestes", "--passer", "a_ch"]) == 0
    assert chrome.fermes == [(9555, 4242)]
    assert [g.site for g in gestures.pending()] == ["a_ch"]
    assert not profile_mod.is_warm("a_ch")
    # La fenêtre fermée, un nouvel --ouvrir relance Chrome.
    cli.main(["gestes", "--ouvrir", "a_ch"])
    assert len(chrome.lances) == 2


def test_ecarter_ferme_le_ticket_avec_son_motif(chrome, tmp_path):
    gestures.add("a_ch", "challenge", "https://a.ch/", "403")
    cli.main(["gestes", "--ouvrir", "a_ch"])
    assert cli.main(["gestes", "--ecarter", "a_ch", "--motif", "refus net de l'annuaire"]) == 0
    assert gestures.pending() == []
    assert not profile_mod.is_warm("a_ch")
    assert chrome.fermes == [(9555, 4242)]
    assert _records(tmp_path)[-1]["why"] == "inutile : refus net de l'annuaire"


def test_ecarter_sans_fenetre_ouverte(chrome):
    gestures.add("a_ch", "challenge", "https://a.ch/", "403")
    assert cli.main(["gestes", "--ecarter", "a_ch"]) == 0
    assert gestures.pending() == [] and chrome.fermes == []


def _rapport(gate, **reach):
    base = {"status": "OK", "hard_block": False, "redirected_to": ""}
    return NS(human_gate=gate, reachability=NS(**{**base, **reach}))


def test_revoir_ferme_les_tickets_sans_raison_d_etre(chrome, tmp_path, monkeypatch):
    gestures.add("refus_ch", "challenge", "https://refus.ch/", "cloudflare")
    gestures.add("libre_ch", "challenge", "https://libre.ch/", "cloudflare")
    gestures.add("dur_ch", "challenge", "https://dur.ch/", "datadome")
    gestures.add("froid_ch", "warmup", "https://froid.ch/", "profil froid")
    gate = HumanGate("challenge", "datadome", "https://dur.ch/", 20, ["HTTP 403"], "mac")
    rapports = {
        "refus_ch": _rapport(None, status="blocked", hard_block=True, redirected_to="www.annuaire.com"),
        "libre_ch": _rapport(None),
        "dur_ch": _rapport(gate, status="challenge"),
    }
    vus = []

    async def _inspect(url, name, **kw):
        vus.append((name, kw.get("headless")))
        return rapports[name]

    monkeypatch.setattr(sap_inspect, "inspect", _inspect)
    assert cli.main(["gestes", "--revoir"]) == 0
    assert vus == [("refus_ch", True), ("libre_ch", True), ("dur_ch", True)]
    assert [g.site for g in gestures.pending()] == ["dur_ch", "froid_ch"]
    why = {r["site"]: r.get("why") for r in _records(tmp_path) if r.get("done")}
    assert why == {
        "refus_ch": "revu : refus net, redirige vers www.annuaire.com",
        "libre_ch": "revu : voie libre",
    }


def test_revoir_un_site_choisi(chrome, monkeypatch):
    gestures.add("a_ch", "challenge", "https://a.ch/", "403")
    gestures.add("b_ch", "challenge", "https://b.ch/", "403")
    vus = []

    async def _inspect(url, name, **kw):
        vus.append(name)
        return _rapport(None)

    monkeypatch.setattr(sap_inspect, "inspect", _inspect)
    assert cli.main(["gestes", "--revoir", "b_ch"]) == 0
    assert vus == ["b_ch"]
    assert [g.site for g in gestures.pending()] == ["a_ch"]


def test_resoudre_garde_le_motif(chrome, tmp_path):
    gestures.add("a_ch", "login", "https://a.ch/", "401")
    gestures.resolve("a_ch", why="fait")
    assert _records(tmp_path)[-1] == {"site": "a_ch", "done": True, "at": _records(tmp_path)[-1]["at"], "why": "fait"}


@pytest.mark.parametrize("option", ["--ouvrir", "--verifier", "--passer", "--ecarter", "--revoir"])
def test_nom_de_site_invalide_refuse(chrome, option):
    assert cli.main(["gestes", option, "../x"]) == 3
    assert chrome.lances == []


@pytest.mark.parametrize(("session", "headless"), [(True, False), (False, True)])
def test_sans_session_graphique_chrome_sans_fenetre(tmp_path, monkeypatch, session, headless):
    """Mac sur l'écran de connexion (personne en SSH) : Chrome avec fenêtre meurt au
    lancement ; sans fenêtre, DevTools par tunnel montre la page et on y clique."""
    monkeypatch.setattr(profile_mod, "PROFILES_DIR", tmp_path / "profiles")
    monkeypatch.setattr(human, "_has_gui_session", lambda: session)
    vus = {}

    async def _launch(profile, **kw):
        vus.update(kw)
        return NS(pid=1, cdp_port=9333)

    monkeypatch.setattr(human.cdp_mod, "launch_chrome", _launch)
    import asyncio

    assert asyncio.run(human._launch_detached("a_ch", "https://a.ch/")) == {"pid": 1, "port": 9333}
    assert vus["headless"] is headless and vus["detached"] is True and vus["url"] == "https://a.ch/"
    # Sans fenêtre, la page par défaut fait 800 × 600 : les sites servent leur version mobile.
    assert vus.get("window_size") == ("1440,900" if headless else None)


def test_consentement_bandeau_encore_visible(chrome, capsys):
    gestures.add("a_ch", "consent", "https://a.ch/", "bannière")
    cli.main(["gestes", "--ouvrir", "a_ch"])
    chrome.page = {**PAGE_OK, "consent_visible": True}
    assert cli.main(["gestes", "--verifier", "a_ch"]) == 2
    assert not profile_mod.is_warm("a_ch")
    assert [g.site for g in gestures.pending()] == ["a_ch"]
    assert "bandeau de consentement encore affiché" in capsys.readouterr().out


def test_consentement_bandeau_ferme(chrome):
    gestures.add("a_ch", "consent", "https://a.ch/", "bannière")
    cli.main(["gestes", "--ouvrir", "a_ch"])
    chrome.page = {**PAGE_OK, "consent_visible": False}
    assert cli.main(["gestes", "--verifier", "a_ch"]) == 0
    assert profile_mod.is_warm("a_ch")


def test_defi_passe_bandeau_visible_ne_bloque_pas(chrome):
    """Le défi passé, le site peut montrer son bandeau : le geste demandé est fait."""
    gestures.add("a_ch", "challenge", "https://a.ch/", "403")
    cli.main(["gestes", "--ouvrir", "a_ch"])
    chrome.page = {**PAGE_OK, "consent_visible": True}
    assert cli.main(["gestes", "--verifier", "a_ch"]) == 0
