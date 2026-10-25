"""Lancement de Chrome en CDP : port non fixe par défaut, journal hors chemin /tmp prévisible."""

from __future__ import annotations

import asyncio
import stat

import pytest

from accesspath.browser import cdp


@pytest.fixture
def faux_chrome(monkeypatch, tmp_path):
    chrome = tmp_path / "chrome"
    chrome.write_text("")
    monkeypatch.setattr(cdp, "CHROME_PATH", str(chrome))
    appels: list[dict] = []

    class _Popen:
        def __init__(self, cmd, stdout=None, stderr=None, **kw):
            appels.append({"cmd": cmd, "stderr": stderr, **kw})

        def terminate(self):
            pass

    async def _ok(port, timeout=15.0):
        return True

    async def _rien(port):
        return None

    monkeypatch.setattr(cdp.subprocess, "Popen", _Popen)
    monkeypatch.setattr(cdp, "_wait_for_cdp", _ok)
    monkeypatch.setattr(cdp, "kill_on_port", _rien)
    monkeypatch.delenv("ACCESSPATH_CDP_PORT", raising=False)
    monkeypatch.setenv("ACCESSPATH_CHROME_LOG_DIR", str(tmp_path / "logs"))
    return appels


def _port(cmd):
    return int(next(a for a in cmd if a.startswith("--remote-debugging-port=")).split("=")[1])


def test_port_par_defaut_ni_fixe_ni_9222(faux_chrome, tmp_path):
    p1 = asyncio.run(cdp.launch_chrome(tmp_path / "prof"))
    p2 = asyncio.run(cdp.launch_chrome(tmp_path / "prof"))
    ports = [_port(a["cmd"]) for a in faux_chrome]
    assert 9222 not in ports
    assert all(1024 < p < 65536 for p in ports)
    assert p1.cdp_port == ports[0] and p2.cdp_port == ports[1]


def test_port_par_variable_d_environnement(faux_chrome, tmp_path, monkeypatch):
    monkeypatch.setenv("ACCESSPATH_CDP_PORT", "9333")
    p = asyncio.run(cdp.launch_chrome(tmp_path / "prof"))
    assert _port(faux_chrome[0]["cmd"]) == 9333
    assert p.cdp_port == 9333


def test_port_explicite_conserve(faux_chrome, tmp_path):
    """cli.py passe port=9222 : comportement inchangé pour lui."""
    p = asyncio.run(cdp.launch_chrome(tmp_path / "prof", port=9222))
    assert _port(faux_chrome[0]["cmd"]) == 9222
    assert p.cdp_port == 9222


def test_journal_hors_chemin_tmp_previsible(faux_chrome, tmp_path):
    p = asyncio.run(cdp.launch_chrome(tmp_path / "prof", port=9222))
    log_path = p.chrome_log_path
    assert str(log_path) != "/tmp/chrome_9222.log"
    assert log_path.parent == tmp_path / "logs"
    assert log_path.exists()
    assert stat.S_IMODE(log_path.stat().st_mode) == 0o600


def test_journal_nom_imprevisible(faux_chrome, tmp_path):
    a = asyncio.run(cdp.launch_chrome(tmp_path / "prof", port=9222)).chrome_log_path
    b = asyncio.run(cdp.launch_chrome(tmp_path / "prof", port=9222)).chrome_log_path
    assert a != b


def test_aucun_appelant_ne_fixe_le_port_cdp():
    """cli.py, runner.py et human.py laissent launch_chrome choisir le port et
    se connectent à chrome.cdp_port."""
    import re
    from pathlib import Path

    racine = Path(cdp.__file__).resolve().parent.parent
    fautifs = []
    for f in racine.rglob("*.py"):
        src = f.read_text(encoding="utf-8")
        if re.search(r"launch_chrome\([^)]*port=", src) or re.search(
            r"connect_over_cdp\(\s*f\"http://127\.0\.0\.1:\{CDP_PORT\}", src
        ):
            fautifs.append(str(f.relative_to(racine)))
    assert fautifs == []


def test_chrome_detache_ouvre_l_adresse(faux_chrome, tmp_path):
    """Geste piloté depuis la conversation : Chrome survit à la commande qui l'a lancé."""
    asyncio.run(cdp.launch_chrome(tmp_path / "prof", url="https://a.ch/", detached=True))
    assert faux_chrome[0]["cmd"][-1] == "https://a.ch/"
    assert faux_chrome[0]["start_new_session"] is True


def test_chrome_attache_par_defaut(faux_chrome, tmp_path):
    asyncio.run(cdp.launch_chrome(tmp_path / "prof"))
    assert "start_new_session" not in faux_chrome[0]
    assert faux_chrome[0]["cmd"][-1].startswith("--")


def test_taille_de_fenetre(faux_chrome, tmp_path):
    asyncio.run(cdp.launch_chrome(tmp_path / "prof", headless=True, window_size="1440,900"))
    assert "--window-size=1440,900" in faux_chrome[0]["cmd"]


@pytest.mark.parametrize("headless", [True, False])
def test_trousseau_factice_toujours(faux_chrome, tmp_path, headless):
    """Sans session graphique (SSH, launchd), Chrome n'a pas le trousseau macOS : il
    n'enregistre aucun cookie (« Encryption is not available »), et un profil réchauffé
    ne garde rien. Le trousseau factice chiffre de la même façon avec ou sans session."""
    asyncio.run(cdp.launch_chrome(tmp_path / "prof", headless=headless))
    assert "--use-mock-keychain" in faux_chrome[0]["cmd"]
