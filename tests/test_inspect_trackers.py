"""inspect relève les traceurs tiers : réseau capturé et HTML rendu (étape 2), HTML seul
(étape 1). `force_browser` ouvre Chrome même quand l'étape 1 suffit à l'accès, car les
traceurs se chargent en JavaScript."""

from __future__ import annotations

import asyncio
import json
import types

from accesspath import cli
from accesspath import sap_inspect as si

from .test_sap_browser_lifecycle import (  # noqa: F401 — fixtures
    FakeBrowser,
    FakeTab,
    _allow_local,
    fake_nodriver,
    no_pkill,
    stage1_needs_browser,
)

HTML = (
    "<html><head><title>Gemeinde</title>"
    '<script src="https://securepubads.g.doubleclick.net/tag/js/gpt.js"></script>'
    "<script>_paq.push(['trackPageView'])</script></head><body>Willkommen</body></html>"
)


class AdTab(FakeTab):
    async def evaluate(self, expr):
        if expr == "document.title":
            return "Gemeinde"
        if "innerText" in expr:
            return "Willkommen"
        return ""

    async def get_content(self):
        return HTML


def _run(**kw):
    return asyncio.run(si.inspect("http://127.0.0.1:9/", "site_x", timeout=0, headless=True, **kw))


def test_etape_2_releve_les_traceurs(fake_nodriver, stage1_needs_browser, monkeypatch, no_pkill):  # noqa: F811
    async def get(self, url):
        return AdTab()

    monkeypatch.setattr(FakeBrowser, "get", get)
    report = _run()
    assert report.trackers["regies"] == ["Google Ad Manager"]
    assert "Matomo (auto-hébergé)" in report.trackers["vendors"]
    md = si.to_markdown(report)
    assert "## Traceurs tiers" in md and "Google Ad Manager" in md and "régie" in md
    assert json.loads(json.dumps(si._to_serializable(report)))["trackers"]["regies"] == ["Google Ad Manager"]


def test_etape_1_seule_lit_le_html(monkeypatch):
    async def s1(url, **k):
        return si.Stage1Findings(homepage_status=200, needs_browser=False, homepage_html_first_kb=HTML)

    monkeypatch.setattr(si, "_stage1_cheap_probe", s1)
    report = _run()
    assert report.skipped_browser_stage2 is True
    assert report.trackers["regies"] == ["Google Ad Manager"]
    assert "HTML seul" in si.to_markdown(report)


def test_force_browser_ouvre_chrome(fake_nodriver, monkeypatch, no_pkill):  # noqa: F811
    async def s1(url, **k):
        return si.Stage1Findings(homepage_status=200, needs_browser=False, homepage_html_first_kb=HTML)

    monkeypatch.setattr(si, "_stage1_cheap_probe", s1)
    report = _run(force_browser=True)
    assert FakeBrowser.instances and report.skipped_browser_stage2 is False


def test_cli_inspect_browser_transmis(monkeypatch):
    seen = {}

    async def fake_inspect(url, name, **kw):
        seen.update(kw)
        raise RuntimeError("arrêt du test")

    monkeypatch.setattr(si, "inspect", fake_inspect)
    rc = cli.main(["sap", "inspect", "https://example.org/", "--browser", "--headless"])
    assert rc == 1 and seen.get("force_browser") is True


class NetworkTab(AdTab):
    """Rejoue une requête de régie vers le gestionnaire `on_req` d'inspect."""

    def __init__(self):
        self.handlers = []

    def add_handler(self, kind, fn):
        self.handlers.append(fn)

    async def get_content(self):
        req = types.SimpleNamespace(url="https://ib.adnxs.com/ut/v3", method="POST", post_data=None)
        for fn in self.handlers:
            if fn.__name__ == "on_req":
                await fn(types.SimpleNamespace(request_id="r1", request=req))
        return "<html><title>Gemeinde</title></html>"


def test_requete_reseau_capturee(fake_nodriver, stage1_needs_browser, monkeypatch, no_pkill):  # noqa: F811
    async def get(self, url):
        return NetworkTab()

    monkeypatch.setattr(FakeBrowser, "get", get)
    report = _run()
    assert report.trackers["regies"] == ["Xandr"]
    assert report.trackers["vendors"]["Xandr"]["source"] == "réseau"


def test_rapport_partiel_sans_chrome(monkeypatch):
    async def s1(url, **k):
        return si.Stage1Findings(homepage_status=200, needs_browser=False, homepage_html_first_kb=HTML)

    monkeypatch.setattr(si, "_stage1_cheap_probe", s1)
    report = si._build_report_from_stage1(asyncio.run(s1("x")), "http://127.0.0.1:9/", "site_x", 0.0)
    report.skipped_browser_stage2 = False  # comme le repli après un échec de Chrome
    assert report.browser_ran is False
    assert "HTML seul" in si.to_markdown(report)


def test_chrome_complet_marque_browser_ran(fake_nodriver, stage1_needs_browser, monkeypatch, no_pkill):  # noqa: F811
    async def get(self, url):
        return AdTab()

    monkeypatch.setattr(FakeBrowser, "get", get)
    report = _run()
    assert report.browser_ran is True
    assert "réseau et HTML" in si.to_markdown(report)


def test_domaines_non_classes_dans_le_rapport(fake_nodriver, stage1_needs_browser, monkeypatch, no_pkill):  # noqa: F811
    class T(AdTab):
        async def get_content(self):
            return HTML + '<script src="https://cdn.unknown-widget.net/w.js"></script>'

    async def get(self, url):
        return T()

    monkeypatch.setattr(FakeBrowser, "get", get)
    md = si.to_markdown(_run())
    assert "Non classés : unknown-widget.net" in md
