"""sap batch : une liste de sites, audités en parallèle, résultats écrits au fil de l'eau
(reprise possible), synthèse agrégée. Mode probe dans le processus ; mode inspect un
processus par site, son groupe entier tué au délai."""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time

import pytest

from accesspath import batch, cli
from accesspath import probe as probe_mod

from ._localserver import LocalServer, body


@pytest.fixture(autouse=True)
def _allow_local(monkeypatch):
    monkeypatch.setenv("ACCESSPATH_ALLOW_PRIVATE", "1")


# ── Lecture de la liste ──────────────────────────────────────────────────
def test_liste_texte_commentaires_doublons_et_invalides(tmp_path):
    f = tmp_path / "sites.txt"
    f.write_text("# communes\nhttps://a.ch\n\nhttps://a.ch/\nftp://x.ch\nhttps://www.b.ch/accueil\n")
    targets, invalid = batch.read_targets(f)
    assert [t["url"] for t in targets] == ["https://a.ch/", "https://www.b.ch/accueil"]
    assert [t["name"] for t in targets] == ["a_ch", "b_ch"]
    assert [i["line"] for i in invalid] == ["ftp://x.ch"]


def test_liste_csv_avec_noms(tmp_path):
    f = tmp_path / "communes.csv"
    f.write_text(
        "name,url,canton\nneuchatel,https://www.neuchatelville.ch,NE\n../x,https://c.ch,VD\n,https://d.ch,VS\n"
    )
    targets, invalid = batch.read_targets(f)
    assert [(t["name"], t["url"]) for t in targets] == [
        ("neuchatel", "https://www.neuchatelville.ch/"),
        ("d_ch", "https://d.ch/"),
    ]
    assert targets[0]["extra"] == {"canton": "NE"}
    assert len(invalid) == 1 and "../x" in invalid[0]["line"]


def test_noms_en_double_departages(tmp_path):
    f = tmp_path / "s.txt"
    f.write_text("https://a.ch/x\nhttps://a.ch/y\n")
    targets, _ = batch.read_targets(f)
    assert [t["name"] for t in targets] == ["a_ch", "a_ch_2"]


def test_nom_du_lot(tmp_path):
    assert batch.batch_name(tmp_path / "Communes Suisses.csv") == "communes_suisses"


# ── Exécution ────────────────────────────────────────────────────────────
def _targets(n):
    return [{"name": f"s{i}", "url": f"https://s{i}.ch/", "extra": {}} for i in range(n)]


def test_parallelisme_borne_et_resultats_au_fil_de_l_eau(tmp_path):
    active = {"now": 0, "max": 0}
    seen_lines = []

    async def runner(t):
        active["now"] += 1
        active["max"] = max(active["max"], active["now"])
        await asyncio.sleep(0.05)
        seen_lines.append(
            len((tmp_path / "results.jsonl").read_text().splitlines()) if (tmp_path / "results.jsonl").exists() else 0
        )
        active["now"] -= 1
        return {"status": "ok", "tier": 1}

    rows = asyncio.run(batch.run_batch(_targets(9), runner=runner, concurrency=3, out_dir=tmp_path))
    assert active["max"] == 3 and len(rows) == 9
    lines = [json.loads(x) for x in (tmp_path / "results.jsonl").read_text().splitlines()]
    assert sorted(r["name"] for r in lines) == [f"s{i}" for i in range(9)]
    assert all({"name", "url", "status", "tier", "duration_s"} <= set(r) for r in lines)
    assert max(seen_lines) > 0  # écrit avant la fin du lot


def test_reprise_saute_les_sites_faits(tmp_path):
    (tmp_path / "results.jsonl").write_text(json.dumps({"name": "s0", "url": "https://s0.ch/", "status": "ok"}) + "\n")
    done = []

    async def runner(t):
        done.append(t["name"])
        return {"status": "ok"}

    asyncio.run(batch.run_batch(_targets(3), runner=runner, concurrency=2, out_dir=tmp_path, resume=True))
    assert sorted(done) == ["s1", "s2"]
    assert len((tmp_path / "results.jsonl").read_text().splitlines()) == 3


def test_exception_d_un_site_n_arrete_pas_le_lot(tmp_path):
    async def runner(t):
        if t["name"] == "s1":
            raise RuntimeError("boum")
        return {"status": "ok"}

    rows = asyncio.run(batch.run_batch(_targets(3), runner=runner, concurrency=2, out_dir=tmp_path))
    bad = next(r for r in rows if r["name"] == "s1")
    assert bad["status"] == "error" and "boum" in bad["error"]
    assert sum(r["status"] == "ok" for r in rows) == 2


def test_colonnes_en_plus_reportees(tmp_path):
    async def runner(t):
        return {"status": "ok"}

    t = [{"name": "a", "url": "https://a.ch/", "extra": {"canton": "NE"}}]
    rows = asyncio.run(batch.run_batch(t, runner=runner, concurrency=1, out_dir=tmp_path))
    assert rows[0]["canton"] == "NE"


# ── Mode probe ───────────────────────────────────────────────────────────
def test_probe_row_de_bout_en_bout():
    feed = b'<?xml version="1.0"?><rss><channel><item><title>a</title></item></channel></rss>'
    page = b"<html><head><title>Commune</title></head><body>" + b"mot " * 300 + b"</body></html>"
    with LocalServer(
        {"/": body(200, page, Content_Type="text/html"), "/feed": body(200, feed, Content_Type="application/rss+xml")}
    ) as s:
        row = asyncio.run(batch.probe_runner(deadline=60, copies=False)({"name": "c", "url": s.url("/"), "extra": {}}))
    assert row["status"] == "ok" and row["tier"] == 1
    assert row["rss"] >= 1 and row["platform"] == "generic"
    assert row["tls"] is None


def test_probe_row_echeance(monkeypatch):
    async def lent(url, *, deadline, copies):
        raise TimeoutError("échéance")

    monkeypatch.setattr(probe_mod, "probe", lent)
    row = asyncio.run(batch.probe_runner(deadline=1, copies=False)({"name": "c", "url": "https://c.ch/", "extra": {}}))
    assert row["status"] == "timeout"


def test_probe_row_porte_le_verdict_tls():
    r = probe_mod.ProbeReport(url="https://c.ch/", timestamp="t", chosen_tier=1, rationale="x")
    r.tls = {
        "tested": True,
        "python_status": 403,
        "chrome_status": 200,
        "impersonate": "chrome",
        "verdict": "empreinte",
    }
    assert batch.probe_row(r)["tls"] == "empreinte"


# ── Mode inspect : un processus par site, groupe tué au délai ────────────
def test_sous_processus_et_ses_enfants_tues_au_delai(tmp_path):
    pidfile = tmp_path / "child.pid"
    code = (
        "import subprocess, sys, time\n"
        f"c = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])\n"
        f"open({str(pidfile)!r}, 'w').write(str(c.pid))\n"
        "time.sleep(60)\n"
    )
    t0 = time.monotonic()
    outcome = asyncio.run(batch.run_subprocess([sys.executable, "-c", code], timeout=1.5))
    assert outcome == "timeout_killed" and time.monotonic() - t0 < 10
    child = int(pidfile.read_text())
    time.sleep(0.3)
    with pytest.raises(ProcessLookupError):
        os.kill(child, 0)


def test_sous_processus_code_de_sortie():
    assert asyncio.run(batch.run_subprocess([sys.executable, "-c", "raise SystemExit(4)"], timeout=10)) == "exit=4"
    assert asyncio.run(batch.run_subprocess([sys.executable, "-c", "pass"], timeout=10)) == "ok"


def test_rapport_inspect_le_plus_recent_apres_le_debut(tmp_path):
    old = tmp_path / "c_inspect_2026-10-23.json"
    old.write_text(json.dumps({"tier_recommendation": {"primary": 4}}))
    os.utime(old, (time.time() - 3600, time.time() - 3600))
    started = time.time() - 1
    assert batch.find_inspect_report(tmp_path, "c", started) is None
    new = tmp_path / "c_inspect_2026-10-24.json"
    new.write_text(json.dumps({"tier_recommendation": {"primary": 2}}))
    assert batch.find_inspect_report(tmp_path, "c", started)["tier_recommendation"]["primary"] == 2


def test_inspect_row_depuis_le_rapport():
    rep = {
        "tier_recommendation": {"primary": 2},
        "anti_bot_stack": {"cloudflare": {"detected": True}, "akamai": {"detected": False}},
        "reachability": {"status": "OK"},
        "scraping_difficulty": 1,
        "sitemap": {"n_urls": 40},
        "frameworks": {"vue": {"detected": True}},
    }
    row = batch.inspect_row(rep)
    assert row == {
        "tier": 2,
        "anti_bot": ["cloudflare"],
        "reachability": "OK",
        "redirected_to": None,
        "human_gate": None,
        "difficulty": 1,
        "sitemap_urls": 40,
        "frameworks": ["vue"],
        "regies": [],
        "trackers": [],
        "tracker_categories": [],
        "consent": [],
        "third_party": 0,
        "unclassified": [],
        "browser": False,
    }


# ── Synthèse ─────────────────────────────────────────────────────────────
def test_synthese_compte_et_neutralise():
    rows = [
        {
            "name": "a",
            "status": "ok",
            "tier": 1,
            "platform": "wordpress",
            "tls": None,
            "rss": 1,
            "api": 0,
            "sitemap": True,
        },
        {
            "name": "b",
            "status": "ok",
            "tier": 2,
            "platform": "generic",
            "tls": "empreinte",
            "rss": 0,
            "api": 0,
            "sitemap": False,
        },
        {"name": "c", "status": "timeout"},
        {"name": "d", "status": "ok", "tier": 4, "anti_bot": ["cloudflare", "\x1b[31mx"], "platform": None},
    ]
    md = batch.summarize("communes", rows, invalid=[{"line": "ftp://x"}])
    assert "# Batch communes" in md
    assert "| 1 | 1 |" in md and "| 2 | 1 |" in md and "| 4 | 1 |" in md
    assert "| timeout | 1 |" in md and "| ok | 3 |" in md
    assert "| wordpress | 1 |" in md and "| empreinte | 1 |" in md and "| cloudflare | 1 |" in md
    assert "Lignes invalides : 1" in md
    assert "\x1b" not in md
    assert md.index(probe_mod.DATA_BEGIN) < md.index("wordpress") < md.index(probe_mod.DATA_END)
    assert "2 sur 3" in md  # sans navigateur (tiers 1-2) parmi les audits réussis


# ── CLI ──────────────────────────────────────────────────────────────────
def _cli_env(tmp_path, monkeypatch):
    monkeypatch.setattr(batch, "BATCH_DIR", tmp_path / "batch")


def test_cli_batch_probe(tmp_path, monkeypatch, capsys):
    _cli_env(tmp_path, monkeypatch)
    page = b"<html><head><title>C</title></head><body>" + b"mot " * 300 + b"</body></html>"
    with LocalServer({"*": body(200, page, Content_Type="text/html")}) as s:
        f = tmp_path / "liste.txt"
        f.write_text(f"{s.url('/a')}\n{s.url('/b')}\nnot a url\n")
        assert cli.main(["sap", "batch", str(f), "--concurrency", "2", "--allow-private"]) == 0
    out_dir = tmp_path / "batch" / "liste"
    rows = [json.loads(x) for x in (out_dir / "results.jsonl").read_text().splitlines()]
    assert len(rows) == 2 and all(r["status"] == "ok" for r in rows)
    assert "# Batch liste" in (out_dir / "summary.md").read_text()
    assert "summary.md" in capsys.readouterr().out


def test_cli_batch_refuse_d_ecraser_sans_reprise(tmp_path, monkeypatch, capsys):
    _cli_env(tmp_path, monkeypatch)
    f = tmp_path / "liste.txt"
    f.write_text("https://a.ch\n")
    d = tmp_path / "batch" / "liste"
    d.mkdir(parents=True)
    (d / "results.jsonl").write_text("{}\n")
    assert cli.main(["sap", "batch", str(f)]) == 3
    assert "--resume" in capsys.readouterr().err


def test_cli_batch_fichier_absent(tmp_path, monkeypatch):
    _cli_env(tmp_path, monkeypatch)
    assert cli.main(["sap", "batch", str(tmp_path / "rien.txt")]) == 3


@pytest.mark.parametrize(
    "mode,n,ok",
    [("probe", 32, True), ("probe", 33, False), ("inspect", 8, True), ("inspect", 9, False), ("probe", 0, False)],
)
def test_cli_batch_borne_le_parallelisme(tmp_path, monkeypatch, mode, n, ok):
    _cli_env(tmp_path, monkeypatch)
    f = tmp_path / "liste.txt"
    f.write_text("")
    code = cli.main(["sap", "batch", str(f), "--mode", mode, "--concurrency", str(n)])
    assert (code == 0) is ok and (code == 3) is (not ok)


def test_cli_batch_limit(tmp_path, monkeypatch):
    _cli_env(tmp_path, monkeypatch)
    seen = []

    def fake_runner(**_kw):
        async def run(t):
            seen.append(t["name"])
            return {"status": "ok"}

        return run

    monkeypatch.setattr(batch, "probe_runner", fake_runner)
    f = tmp_path / "liste.txt"
    f.write_text("https://a.ch\nhttps://b.ch\nhttps://c.ch\n")
    assert cli.main(["sap", "batch", str(f), "--limit", "2"]) == 0
    assert sorted(seen) == ["a_ch", "b_ch"]


def test_rapport_inspect_prend_le_plus_recent(tmp_path):
    started = time.time() - 10
    a = tmp_path / "c_inspect_2026-10-24.json"
    a.write_text(json.dumps({"tier_recommendation": {"primary": 4}}))
    os.utime(a, (time.time() - 5, time.time() - 5))
    b = tmp_path / "c_inspect_2026-10-25.json"
    b.write_text(json.dumps({"tier_recommendation": {"primary": 1}}))
    assert batch.find_inspect_report(tmp_path, "c", started)["tier_recommendation"]["primary"] == 1


def test_synthese_ne_compte_que_les_audits_reussis():
    rows = [{"name": "a", "status": "ok", "tier": 1}, {"name": "b", "status": "error", "tier": 1}]
    assert "Sans navigateur (tiers 1 et 2) : 1 sur 1" in batch.summarize("x", rows)
