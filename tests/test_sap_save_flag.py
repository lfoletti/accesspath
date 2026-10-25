"""M6 — « sans --save, rien n'est écrit » rendu vrai : verify, rehearse,
--emit-yaml ; `show` affiche aussi le dernier audit."""

from __future__ import annotations

import json

import pytest
import yaml

from accesspath import cli, sap_inspect
from accesspath import probe as probe_mod
from accesspath import sap as sap_mod


@pytest.fixture
def data_dir(tmp_path, monkeypatch):
    d = tmp_path / "data"
    d.mkdir()
    monkeypatch.setattr(sap_mod, "AUDITS_FILE", d / "sap_audits.jsonl")
    monkeypatch.setattr(sap_mod, "PROFILES_FILE", d / "site_architecture_profiles.json")
    monkeypatch.setattr(sap_inspect, "SAP_DIR", d / "sap")
    monkeypatch.setattr(sap_inspect, "PROBES_DIR", d / "probes")
    monkeypatch.setattr(probe_mod, "DATA_DIR", d)
    monkeypatch.setattr(probe_mod, "SITES_DIR", tmp_path / "sites")
    return d


def _files(d):
    return {p: p.read_bytes() for p in d.rglob("*") if p.is_file()}


@pytest.fixture
def fake_verify(monkeypatch):
    from accesspath import config

    monkeypatch.setattr(config, "sites_registry", lambda: {"designboom": object()})

    async def _v(name):
        return sap_mod.SapResult(
            site=name, timestamp="2026-10-24T00:00:00+00:00", fetch_url="u", fetch_method="http", overall="pass"
        )

    monkeypatch.setattr(sap_mod, "verify_site", _v)


def test_verify_without_save_writes_nothing(data_dir, fake_verify):
    before = _files(data_dir)
    cli.main(["sap", "verify", "designboom"])
    assert _files(data_dir) == before


def test_verify_with_save_appends_audit(data_dir, fake_verify):
    cli.main(["sap", "verify", "designboom", "--save"])
    assert (data_dir / "sap_audits.jsonl").exists()


def _deferred_shards(data_dir):
    d = data_dir / "sap" / "site_x"
    d.mkdir(parents=True)
    (d / "04_strategy.yaml").write_text(
        yaml.safe_dump({"url": "https://example.com/", "tier_recommendation": {"primary": 3}})
    )
    (d / "02_technical.yaml").write_text(yaml.safe_dump({"url": "https://example.com/"}))
    return d / "04_strategy.yaml"


def test_rehearse_without_save_writes_nothing(data_dir):
    _deferred_shards(data_dir)
    before = _files(data_dir)
    cli.main(["sap", "rehearse", "site_x"])
    assert _files(data_dir) == before


def test_rehearse_with_save_updates_strategy(data_dir):
    p = _deferred_shards(data_dir)
    cli.main(["sap", "rehearse", "site_x", "--save"])
    assert yaml.safe_load(p.read_text())["rehearsal"]["tested"] is True


def test_emit_yaml_requires_save(data_dir, monkeypatch):
    async def _boom(*a, **k):
        raise AssertionError("inspect ne doit pas partir")

    monkeypatch.setattr(sap_inspect, "inspect", _boom)
    before = _files(data_dir)
    assert cli.main(["sap", "inspect", "https://example.com", "--emit-yaml"]) == 3
    assert _files(data_dir) == before


def test_probe_without_save_writes_nothing(data_dir, monkeypatch):
    async def _p(url, **k):
        return probe_mod.ProbeReport(url=url, timestamp="2026-10-24T00:00:00+00:00")

    monkeypatch.setattr(probe_mod, "probe", _p)
    before = _files(data_dir)
    cli.main(["sap", "probe", "https://example.com"])
    assert _files(data_dir) == before
    assert not (data_dir.parent / "sites").exists()


def test_show_prints_last_audit(data_dir, capsys):
    (data_dir / "site_architecture_profiles.json").write_text(json.dumps({"designboom": {"tier": 1}}))
    r = sap_mod.SapResult(
        site="designboom", timestamp="2026-10-24T12:00:00+00:00", fetch_url="u", fetch_method="rss", overall="warn"
    )
    (data_dir / "sap_audits.jsonl").write_text(json.dumps(r.to_dict()) + "\n")
    assert cli.main(["sap", "show", "designboom"]) == 0
    out = capsys.readouterr().out
    assert "Dernier audit" in out and "2026-10-24T12:00:00" in out and "warn" in out.lower()
