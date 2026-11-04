"""A modern single-page application serves an empty shell: a mount element, module scripts, no text. Angular CLI
builds no longer write ``ng-version`` in the served HTML, and inlined CSS can make the shell larger than 200 KB.
The probe must still see a SPA, and a SPA must not be sent to its sitemap: the sitemap lists addresses whose pages
are empty shells. The path is the data API in the application code."""

import asyncio

from accesspath import probe as probe_mod

STYLE = "<style>" + ":root{--c:#fff}" * 15_000 + "</style>"  # inlined CSS, more than 200 KB


def _shell(root: str) -> bytes:
    return (
        f'<!doctype html><html><head><meta charset="utf-8"><title>RPEX</title><base href="/">{STYLE}</head>'
        f'<body>{root}<link rel="modulepreload" href="chunk-EUZTCWZM.js">'
        '<script src="polyfills-ERLYOUQC.js" type="module"></script>'
        '<script src="main-SSOFTLRP.js" type="module"></script></body></html>'
    ).encode()


def _tier2(body: bytes) -> dict:
    return asyncio.run(probe_mod.discover_tier2("https://x.eu/doc", home={"ok": True, "body": body}))


def test_an_angular_shell_without_ng_version_is_a_spa():
    t2 = _tier2(_shell("<app-root></app-root>"))
    assert "angular" in t2["frameworks"]
    assert t2["is_likely_spa"] is True
    assert t2["visible_words"] < 5


def test_an_empty_mount_element_with_module_scripts_is_a_spa():
    assert _tier2(_shell('<div id="app"></div>'))["is_likely_spa"] is True


def test_a_page_with_text_is_not_a_spa():
    texte = "<main>" + "<p>" + "Le texte de la page est servi par le serveur. " * 40 + "</p></main>"
    assert _tier2(_shell("<app-root></app-root>" + texte))["is_likely_spa"] is False


def test_a_spa_goes_to_its_api_and_not_to_its_sitemap():
    r = probe_mod.ProbeReport(url="https://x.eu/doc", timestamp="t")
    r.tier1 = {"sitemap": {"endpoint": "/sitemap.xml", "items": 8}}
    r.tier2 = {"fetched": True, "is_likely_spa": True, "frameworks": ["angular"], "inline_json": []}
    tier, why = probe_mod._decide_tier(r)
    assert tier == 4
    assert "API" in why and "code" in why and "sitemap" in why
