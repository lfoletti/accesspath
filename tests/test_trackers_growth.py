"""Table des traceurs, agrandie à partir des domaines non classés des médias (veille
web-access, point 9), et reclassement d'un lot déjà inspecté sans relancer Chrome."""

from __future__ import annotations

import json

import pytest

from accesspath import batch, cli, trackers


@pytest.mark.parametrize(
    "url, vendor, category",
    [
        ("https://sdk.privacy-center.org/loader.js", "Didomi", "consentement"),
        ("https://cdn.privacy-mgmt.com/wrapper.js", "Sourcepoint", "consentement"),
        ("https://gdpr.privacymanager.io/x.js", "LiveRamp Privacy Manager", "consentement"),
        ("https://quantcast.mgr.consensu.org/cmp.js", "CMP (IAB TCF)", "consentement"),
        ("https://static.axept.io/sdk.js", "Axeptio", "consentement"),
        ("https://cdn.permutive.app/x.js", "Permutive", "profilage"),
        ("https://dpm.demdex.net/id", "Adobe Audience Manager", "profilage"),
        ("https://idsync.rlcdn.com/x", "LiveRamp", "profilage"),
        ("https://scdn.cxense.com/cx.js", "Piano (Cxense)", "profilage"),
        ("https://static.chartbeat.com/js/chartbeat.js", "Chartbeat", "audience"),
        ("https://secure-dcr.imrworldwide.com/x", "Nielsen", "audience"),
        ("https://securepubads.g.doubleclick.net/tag/js/gpt.js", "Google Ad Manager", "régie"),
        ("https://www.googletagservices.com/tag/js/gpt.js", "Google Ad Manager", "régie"),
        ("https://js-sec.indexww.com/ht/p.js", "Index Exchange", "régie"),
        ("https://eu-1-id5-sync.com/x", "ID5", "régie"),
        ("https://ssl.cdne.jwpsrv.com/x", "JW Player", "intégration"),
    ],
)
def test_table_agrandie(url, vendor, category):
    found = trackers.detect_trackers([url], "", "https://journal.ch/")
    assert found["vendors"][vendor]["category"] == category


def test_signature_tcf():
    html = "<script>window.__tcfapi=function(){}</script>"
    found = trackers.detect_trackers([], html, "https://journal.ch/")
    assert found["consent_manager"] == ["CMP (IAB TCF)"]


SAVED = {
    "vendors": {"Google Ad Manager": {"category": "régie", "source": "réseau", "hosts": ["doubleclick.net"]}},
    "categories": {"régie": 1},
    "regies": ["Google Ad Manager"],
    "consent_manager": [],
    "third_party_domains": ["doubleclick.net", "privacy-center.org", "inconnu.example"],
    "unclassified": ["privacy-center.org", "inconnu.example"],
}


def test_reclassement():
    t = trackers.reclassify(SAVED)
    assert t["consent_manager"] == ["Didomi"]
    assert t["regies"] == ["Google Ad Manager"]
    assert t["unclassified"] == ["inconnu.example"]
    assert t["categories"] == {"consentement": 1, "régie": 1}
    assert t["vendors"]["Didomi"]["source"] == "reclassement"


def test_reclassement_garde_les_signatures_html():
    saved = {**SAVED, "vendors": {"Matomo (auto-hébergé)": {"category": "audience", "source": "html", "hosts": []}}}
    assert "Matomo (auto-hébergé)" in trackers.reclassify(saved)["vendors"]


def _lot(tmp_path):
    out = tmp_path / "lot"
    (out / "profils").mkdir(parents=True)
    report = {"trackers": SAVED, "browser_ran": True, "tier_recommendation": {"primary": 1}}
    (out / "profils" / "journal_inspect_2026-10-24.json").write_text(json.dumps(report))
    rows = [
        {
            "name": "journal",
            "url": "https://journal.ch/",
            "status": "ok",
            "tier": 1,
            "regies": ["Google Ad Manager"],
            "consent": [],
        },
        {"name": "sans_profil", "url": "https://autre.ch/", "status": "ok", "tier": 2, "consent": []},
    ]
    (out / "results.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
    return out


def test_lot_reclasse_depuis_les_profils(tmp_path):
    out = _lot(tmp_path)
    assert batch.refresh_trackers(out) == 1
    rows = {r["name"]: r for r in batch.read_results(out / "results.jsonl")}
    assert rows["journal"]["consent"] == ["Didomi"] and rows["journal"]["unclassified"] == ["inconnu.example"]
    assert rows["sans_profil"] == {
        "name": "sans_profil",
        "url": "https://autre.ch/",
        "status": "ok",
        "tier": 2,
        "consent": [],
    }


def test_cli_retrackers(tmp_path, capsys):
    out = _lot(tmp_path)
    lst = tmp_path / "lot.txt"
    lst.write_text("https://journal.ch/\n")
    assert cli.main(["sap", "batch", str(lst), "--retrackers", "--out", str(out)]) == 0
    assert "Didomi" in (out / "summary.md").read_text()
    assert "1 site(s) reclassé(s)" in capsys.readouterr().out


def test_cli_retrackers_sans_lot(tmp_path):
    lst = tmp_path / "lot.txt"
    lst.write_text("https://journal.ch/\n")
    assert cli.main(["sap", "batch", str(lst), "--retrackers", "--out", str(tmp_path / "vide")]) == 3


def test_lot_reclasse_depuis_le_profil_le_plus_recent(tmp_path):
    out = _lot(tmp_path)
    old = {"trackers": {**SAVED, "third_party_domains": ["doubleclick.net"], "unclassified": []}}
    (out / "profils" / "journal_inspect_2026-05-01.json").write_text(json.dumps(old))
    batch.refresh_trackers(out)
    assert batch.read_results(out / "results.jsonl")[0]["consent"] == ["Didomi"]
