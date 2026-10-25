"""M5 — cycle de vie du navigateur de `inspect` (étape 2) avec un navigateur
factice : arrêt garanti même sur exception, arrêt du seul processus lancé
(plus de `pkill -f` global), arguments qui rétablissent l'isolation des sites
et restreignent --remote-allow-origins."""

from __future__ import annotations

import asyncio
import sys
import types
from pathlib import Path

import pytest

from accesspath import sap_inspect as si


@pytest.fixture(autouse=True)
def _allow_local(monkeypatch):
    monkeypatch.setenv("ACCESSPATH_ALLOW_PRIVATE", "1")


@pytest.fixture
def stage1_needs_browser(monkeypatch):
    async def _s1(url, **k):
        return si.Stage1Findings(homepage_status=200, needs_browser=True, decision_rationale="test")

    monkeypatch.setattr(si, "_stage1_cheap_probe", _s1)


class FakeTab:
    def add_handler(self, *a, **k):
        pass

    async def send(self, *a, **k):
        return []

    async def evaluate(self, expr):
        return ""

    async def get_content(self):
        return ""


class FakeBrowser:
    instances: list[FakeBrowser] = []

    def __init__(self, config):
        self.config = config
        self.stopped = False
        FakeBrowser.instances.append(self)

    async def get(self, url):
        return FakeTab()

    def stop(self):
        self.stopped = True


@pytest.fixture
def fake_nodriver(monkeypatch):
    """Module `nodriver` factice : start() rend un FakeBrowser, sans Chrome."""
    import nodriver as real

    FakeBrowser.instances.clear()
    mod = types.ModuleType("nodriver")
    mod.Config = real.Config
    mod.cdp = types.SimpleNamespace(
        network=types.SimpleNamespace(
            enable=lambda: None,
            get_cookies=lambda: None,
            RequestWillBeSent=object,
            ResponseReceived=object,
            LoadingFinished=object,
        )
    )

    async def start(config=None, **kw):
        return FakeBrowser(config)

    mod.start = start
    monkeypatch.setitem(sys.modules, "nodriver", mod)
    return mod


@pytest.fixture
def no_pkill(monkeypatch):
    calls = []
    import subprocess

    real_run = subprocess.run

    def _run(cmd, *a, **k):
        calls.append(cmd)
        if cmd and cmd[0] == "pkill":
            return subprocess.CompletedProcess(cmd, 0)
        return real_run(cmd, *a, **k)

    monkeypatch.setattr(subprocess, "run", _run)
    return calls


def test_browser_stopped_when_stage2_raises(fake_nodriver, stage1_needs_browser, monkeypatch, no_pkill):
    async def _boom(tab):
        raise RuntimeError("panne simulée pendant l'étape 2")

    monkeypatch.setattr(si, "_detect_frameworks", _boom)
    with pytest.raises(RuntimeError):
        asyncio.run(si.inspect("http://127.0.0.1:9/", "site_x", timeout=0, headless=True))
    assert FakeBrowser.instances and FakeBrowser.instances[0].stopped is True


def test_profile_dir_removed_after_inspect(fake_nodriver, stage1_needs_browser, monkeypatch, no_pkill):
    async def _boom(tab):
        raise RuntimeError("panne simulée")

    monkeypatch.setattr(si, "_detect_frameworks", _boom)
    with pytest.raises(RuntimeError):
        asyncio.run(si.inspect("http://127.0.0.1:9/", "site_x", timeout=0, headless=True))
    args = FakeBrowser.instances[0].config()
    udd = next(a.split("=", 1)[1] for a in args if a.startswith("--user-data-dir="))
    assert not Path(udd).exists()


def test_startup_failure_kills_only_own_process(fake_nodriver, stage1_needs_browser, monkeypatch, no_pkill):
    async def start(config=None, **kw):
        raise RuntimeError("Chrome ne démarre pas")

    fake_nodriver.start = start
    killed = []
    monkeypatch.setattr(si, "_kill_browser_processes", lambda marker: killed.append(marker), raising=False)
    report = asyncio.run(si.inspect("http://127.0.0.1:9/", "site_x", timeout=0, headless=True))
    assert report.tier_recommendation.primary == 4
    assert not [c for c in no_pkill if c and c[0] == "pkill"]
    assert killed and all("--user-data-dir=" in m and "sap_inspect_" in m for m in killed)


def test_kill_browser_processes_targets_exact_profile(monkeypatch):
    import os
    import subprocess

    ps = (
        " 101 /Applications/Chrome --user-data-dir=/tmp/sap_inspect_abc --headless\n"
        " 102 /Applications/Chrome --user-data-dir=/tmp/uc_other\n"
        " 103 /Applications/Chrome --user-data-dir=/tmp/sap_inspect_abcdef\n"
    )
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: subprocess.CompletedProcess(a[0], 0, stdout=ps, stderr=""))
    killed = []
    monkeypatch.setattr(os, "kill", lambda pid, sig: killed.append(pid))
    si._kill_browser_processes("--user-data-dir=/tmp/sap_inspect_abc")
    assert killed == [101]


# ── arguments du navigateur ────────────────────────────────────────────────
def test_browser_config_restores_isolation_and_restricts_origins(tmp_path):
    import nodriver as nd

    cfg = si._browser_config(nd, headless=True, profile_dir=str(tmp_path), browser_args=["--window-size=1,1"])
    args = cfg()
    assert "--remote-allow-origins=*" not in args
    assert [a for a in args if a.startswith("--remote-allow-origins=")] == ["--remote-allow-origins=http://127.0.0.1"]
    disabled = ",".join(a for a in args if a.startswith("--disable-features="))
    assert "IsolateOrigins" not in disabled and "site-per-process" not in disabled
    assert "--disable-site-isolation-trials" not in args
    assert "--site-per-process" in args
    assert f"--user-data-dir={tmp_path}" in args
    assert "--window-size=1,1" in args


def test_waits_for_browser_exit_before_removing_profile(fake_nodriver, stage1_needs_browser, monkeypatch, no_pkill):
    events = []

    class Proc:
        async def wait(self):
            events.append("wait")

    async def start(config=None, **kw):
        b = FakeBrowser(config)
        b._process = Proc()
        return b

    fake_nodriver.start = start
    import shutil

    real_rmtree = shutil.rmtree
    monkeypatch.setattr(shutil, "rmtree", lambda p, **k: (events.append("rmtree"), real_rmtree(p, **k)))
    asyncio.run(si.inspect("http://127.0.0.1:9/", "site_x", timeout=0, headless=True))
    assert events[:2] == ["wait", "rmtree"]
