"""sap batch et traceurs : colonnes par site, tableaux de synthèse (régies, fournisseurs,
catégories), durée du passage, dossier de sortie choisi (--out), profils copiés dans
<out>/profils, --browser transmis à inspect."""

from __future__ import annotations

import asyncio
import json

from accesspath import batch, cli

REPORT = {
    "tier_recommendation": {"primary": 2},
    "trackers": {
        "vendors": {
            "Google Ad Manager": {"category": "régie", "source": "réseau", "hosts": ["x.doubleclick.net"]},
            "Cookiebot": {"category": "consentement", "source": "réseau", "hosts": ["consent.cookiebot.com"]},
            "Google Analytics": {"category": "audience", "source": "réseau", "hosts": ["www.google-analytics.com"]},
        },
        "categories": {"audience": 1, "consentement": 1, "régie": 1},
        "regies": ["Google Ad Manager"],
        "consent_manager": ["Cookiebot"],
        "third_party_domains": ["cookiebot.com", "doubleclick.net", "google-analytics.com", "x.net"],
    },
}


def test_ligne_inspect_porte_les_traceurs():
    row = batch.inspect_row(REPORT)
    assert row["regies"] == ["Google Ad Manager"]
    assert row["trackers"] == ["Cookiebot", "Google Ad Manager", "Google Analytics"]
    assert row["tracker_categories"] == ["audience", "consentement", "régie"]
    assert row["consent"] == ["Cookiebot"]
    assert row["third_party"] == 4


def test_ligne_inspect_sans_traceurs():
    row = batch.inspect_row({"tier_recommendation": {"primary": 1}})
    assert row["regies"] == [] and row["trackers"] == [] and row["third_party"] == 0


def test_synthese_traceurs_et_duree():
    rows = [
        {"name": "a", "status": "ok", "duration_s": 30.0, **batch.inspect_row(REPORT)},
        {"name": "b", "status": "ok", "duration_s": 10.0, **batch.inspect_row({"tier_recommendation": {}})},
        {"name": "c", "status": "error", "duration_s": 5.0},
    ]
    md = batch.summarize("x", rows, elapsed_s=125.0)
    assert "Durée du passage : 2 min 5 s" in md
    assert "Temps d'audit cumulé : 45 s (15.0 s par site)" in md
    assert "Sites avec une régie : 1 sur 2" in md
    assert "## Régies" in md and "| Google Ad Manager | 1 |" in md
    assert "## Traceurs tiers" in md and "| Google Analytics | 1 |" in md
    assert "## Catégories de traceurs" in md and "| consentement | 1 |" in md
    assert md.index(batch.DATA_BEGIN) < md.index("Google Ad Manager") < md.index(batch.DATA_END)


def test_synthese_sans_duree_ne_l_affiche_pas():
    assert "Durée du passage" not in batch.summarize("x", [])


def test_runner_inspect_browser_et_profils(tmp_path, monkeypatch):
    probes = tmp_path / "probes"
    probes.mkdir()
    monkeypatch.setattr(batch, "PROBES_DIR", probes)
    seen = {}

    async def fake_sub(cmd, *, timeout, stall=None):
        seen["cmd"] = cmd
        (probes / "c1_inspect_2026-10-24.json").write_text(json.dumps({**REPORT, "browser_ran": True}))
        (probes / "c1_inspect_2026-10-24.md").write_text("# rapport")
        return "ok"

    monkeypatch.setattr(batch, "run_subprocess", fake_sub)
    prof = tmp_path / "out" / "profils"
    run = batch.inspect_runner(deadline=60, browser=True, profiles_dir=prof)
    row = asyncio.run(run({"name": "c1", "url": "https://c1.ch/"}))
    assert "--browser" in seen["cmd"]
    assert row["status"] == "ok" and row["regies"] == ["Google Ad Manager"]
    assert (prof / "c1_inspect_2026-10-24.json").exists() and (prof / "c1_inspect_2026-10-24.md").exists()


def test_runner_inspect_sans_browser_par_defaut(tmp_path, monkeypatch):
    monkeypatch.setattr(batch, "PROBES_DIR", tmp_path)
    seen = {}

    async def fake_sub(cmd, *, timeout, stall=None):
        seen["cmd"] = cmd
        return "exit=1"

    monkeypatch.setattr(batch, "run_subprocess", fake_sub)
    asyncio.run(batch.inspect_runner(deadline=60)({"name": "c1", "url": "https://c1.ch/"}))
    assert "--browser" not in seen["cmd"]


def test_cli_out_browser_et_duree(tmp_path, monkeypatch):
    monkeypatch.setattr(batch, "BATCH_DIR", tmp_path / "batch")
    seen = {}

    def fake_runner(**kw):
        seen.update(kw)

        async def run(t):
            await asyncio.sleep(0)
            return {"status": "ok", **batch.inspect_row(REPORT)}

        return run

    monkeypatch.setattr(batch, "inspect_runner", fake_runner)
    monkeypatch.setattr(batch, "clock", iter([100.0, 162.0]).__next__)
    f = tmp_path / "communes.csv"
    f.write_text("url,name\nhttps://a.ch,a\n")
    out = tmp_path / "etude"
    assert cli.main(["sap", "batch", str(f), "--mode", "inspect", "--browser", "--out", str(out)]) == 0
    assert seen["browser"] is True and seen["profiles_dir"] == out / "profils"
    assert (out / "results.jsonl").exists() and not (tmp_path / "batch").exists()
    md = (out / "summary.md").read_text()
    assert "Durée du passage : 1 min 2 s" in md and "| Google Ad Manager | 1 |" in md


def _runner_with(tmp_path, monkeypatch, report, outcome, **kw):
    monkeypatch.setattr(batch, "PROBES_DIR", tmp_path)

    async def fake_sub(cmd, *, timeout, stall=None):
        (tmp_path / "c1_inspect_2026-10-24.json").write_text(json.dumps(report))
        return outcome

    monkeypatch.setattr(batch, "run_subprocess", fake_sub)
    return asyncio.run(batch.inspect_runner(deadline=60, **kw)({"name": "c1", "url": "https://c1.ch/"}))


def test_rapport_apres_delai_est_partiel(tmp_path, monkeypatch):
    row = _runner_with(tmp_path, monkeypatch, {**REPORT, "browser_ran": True}, "timeout_killed")
    assert row["status"] == "partial"


def test_chrome_demande_mais_absent_est_partiel(tmp_path, monkeypatch):
    row = _runner_with(tmp_path, monkeypatch, {**REPORT, "browser_ran": False}, "ok", browser=True)
    assert row["status"] == "partial" and row["browser"] is False


def test_chrome_complet_est_ok(tmp_path, monkeypatch):
    row = _runner_with(tmp_path, monkeypatch, {**REPORT, "browser_ran": True}, "ok", browser=True)
    assert row["status"] == "ok" and row["browser"] is True


def test_sans_browser_demande_le_html_seul_suffit(tmp_path, monkeypatch):
    row = _runner_with(tmp_path, monkeypatch, {**REPORT, "browser_ran": False}, "ok")
    assert row["status"] == "ok"


def test_non_classes_dans_la_ligne_et_la_synthese():
    rep = {**REPORT, "trackers": {**REPORT["trackers"], "unclassified": ["x.net"]}}
    row = batch.inspect_row(rep)
    assert row["unclassified"] == ["x.net"]
    md = batch.summarize("x", [{"name": "a", "status": "ok", **row}])
    assert "## Domaines tiers non classés" in md and "| x.net | 1 |" in md
