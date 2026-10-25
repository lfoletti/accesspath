"""Roulement de configurations d'inspect : un chien de garde tue une inspection muette
(Chrome qui n'avance plus) sans attendre l'échéance, puis le lot essaie la configuration
suivante, jusqu'à un rapport complet. La ligne garde la configuration retenue et le
nombre d'essais."""

from __future__ import annotations

import asyncio
import json
import sys
import time

import pytest

from accesspath import batch, cli


def test_chien_de_garde_tue_une_inspection_muette():
    code = "import sys, time; print('départ', file=sys.stderr, flush=True); time.sleep(20)"
    t0 = time.monotonic()
    out = asyncio.run(batch.run_subprocess([sys.executable, "-c", code], timeout=30, stall=1.0))
    assert out == "stalled" and time.monotonic() - t0 < 8


def test_une_inspection_qui_parle_n_est_pas_tuee():
    code = "import sys, time\nfor i in range(6):\n    print(i, file=sys.stderr, flush=True); time.sleep(0.4)"
    assert asyncio.run(batch.run_subprocess([sys.executable, "-c", code], timeout=30, stall=1.0)) == "ok"


def test_echeance_toujours_active_avec_chien_de_garde():
    code = "import sys, time\nwhile True:\n    print('.', file=sys.stderr, flush=True); time.sleep(0.2)"
    assert asyncio.run(batch.run_subprocess([sys.executable, "-c", code], timeout=1.5, stall=1.0)) == "timeout_killed"


def _rotation(tmp_path, monkeypatch, outcomes):
    """outcomes : par essai, (issue du processus, browser_ran du rapport, ou None sans rapport)."""
    monkeypatch.setattr(batch, "PROBES_DIR", tmp_path)
    calls = []

    async def fake_sub(cmd, *, timeout, stall=None):
        outcome, ran = outcomes[len(calls)]
        calls.append({"cmd": cmd, "stall": stall})
        if ran is not None:
            p = tmp_path / f"c1_inspect_2026-10-2{len(calls)}.json"
            p.write_text(json.dumps({"tier_recommendation": {"primary": 2}, "browser_ran": ran}))
        return outcome

    monkeypatch.setattr(batch, "run_subprocess", fake_sub)
    run = batch.inspect_runner(deadline=90, browser=True, configs=["headless-30", "headless-12", "visible-30"])
    return asyncio.run(run({"name": "c1", "url": "https://c1.ch/"})), calls


def test_rotation_passe_a_la_config_suivante(tmp_path, monkeypatch):
    row, calls = _rotation(tmp_path, monkeypatch, [("stalled", False), ("ok", True)])
    assert row["status"] == "ok" and row["config"] == "headless-12" and row["attempts"] == 2
    assert calls[0]["cmd"][calls[0]["cmd"].index("--timeout") + 1] == "30"
    assert calls[1]["cmd"][calls[1]["cmd"].index("--timeout") + 1] == "12"
    assert "--headless" in calls[1]["cmd"]


def test_rotation_s_arrete_au_premier_succes(tmp_path, monkeypatch):
    row, calls = _rotation(tmp_path, monkeypatch, [("ok", True)])
    assert len(calls) == 1 and row["config"] == "headless-30" and row["attempts"] == 1


def test_rotation_epuisee_garde_le_dernier_resultat(tmp_path, monkeypatch):
    row, calls = _rotation(tmp_path, monkeypatch, [("stalled", None), ("exit=1", None), ("timeout_killed", False)])
    assert len(calls) == 3 and row["attempts"] == 3
    assert row["status"] == "partial" and row["config"] == "visible-30"
    assert "--headless" not in calls[2]["cmd"]


def test_rotation_sans_rapport_du_tout(tmp_path, monkeypatch):
    row, _ = _rotation(tmp_path, monkeypatch, [("stalled", None), ("stalled", None), ("stalled", None)])
    assert row["status"] == "timeout" and row["attempts"] == 3


def test_chien_de_garde_au_dela_de_la_capture(tmp_path, monkeypatch):
    _, calls = _rotation(tmp_path, monkeypatch, [("stalled", None), ("ok", True)])
    assert calls[0]["stall"] == 30 + batch.STALL_GRACE_S and calls[1]["stall"] == 12 + batch.STALL_GRACE_S


def test_un_essai_ne_reprend_pas_le_rapport_du_precedent(tmp_path, monkeypatch):
    monkeypatch.setattr(batch, "PROBES_DIR", tmp_path)
    n = []

    async def fake_sub(cmd, *, timeout, stall=None):
        n.append(1)
        if len(n) == 1:
            (tmp_path / "c1_inspect_a.json").write_text(json.dumps({"browser_ran": False}))
        return "stalled"

    monkeypatch.setattr(batch, "run_subprocess", fake_sub)
    monkeypatch.setattr(batch, "_attempt_start", iter([0.0, time.time() + 3600]).__next__)
    run = batch.inspect_runner(deadline=90, browser=True, configs=["headless-30", "headless-12"])
    row = asyncio.run(run({"name": "c1", "url": "https://c1.ch/"}))
    assert row["status"] == "timeout"  # le rapport du 1er essai n'est pas compté pour le 2e


def test_cli_configs(tmp_path, monkeypatch):
    monkeypatch.setattr(batch, "BATCH_DIR", tmp_path / "batch")
    seen = {}

    def fake_runner(**kw):
        seen.update(kw)

        async def run(t):
            return {"status": "ok"}

        return run

    monkeypatch.setattr(batch, "inspect_runner", fake_runner)
    f = tmp_path / "l.txt"
    f.write_text("https://a.ch\n")
    args = ["sap", "batch", str(f), "--mode", "inspect", "--configs", "headless-12,visible-30"]
    assert cli.main(args) == 0
    assert seen["configs"] == ["headless-12", "visible-30"]


@pytest.mark.parametrize("bad", ["nimporte", "headless-30,", ""])
def test_cli_configs_inconnues_refusees(tmp_path, monkeypatch, bad):
    monkeypatch.setattr(batch, "BATCH_DIR", tmp_path / "batch")
    f = tmp_path / "l.txt"
    f.write_text("https://a.ch\n")
    assert cli.main(["sap", "batch", str(f), "--mode", "inspect", "--configs", bad]) == 3


def test_cli_configs_par_defaut(tmp_path, monkeypatch):
    monkeypatch.setattr(batch, "BATCH_DIR", tmp_path / "batch")
    seen = {}

    def fake_runner(**kw):
        seen.update(kw)

        async def run(t):
            return {"status": "ok"}

        return run

    monkeypatch.setattr(batch, "inspect_runner", fake_runner)
    f = tmp_path / "l.txt"
    f.write_text("https://a.ch\n")
    assert cli.main(["sap", "batch", str(f), "--mode", "inspect"]) == 0
    assert seen["configs"] == list(batch.DEFAULT_ROTATION)


def test_roulement_par_defaut_sans_fenetre():
    assert batch.DEFAULT_ROTATION == ("headless-30", "headless-12")
    assert all(batch.INSPECT_CONFIGS[c]["headless"] for c in batch.DEFAULT_ROTATION)
