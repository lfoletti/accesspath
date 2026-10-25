"""E4 + M1 — validation des noms de site, des URL cibles et des chemins écrits.

Tous les tests sont hors réseau : la sonde n'est jamais lancée, les écritures
se font dans un DATA_DIR temporaire.
"""

from __future__ import annotations

import ast
import asyncio
from pathlib import Path

import pytest

from accesspath import cli, sap_inspect
from accesspath import probe as probe_mod
from accesspath import sap as sap_mod
from accesspath._safe import (
    UnsafeInput,
    name_from_url,
    normalize_target_url,
    safe_path,
    validate_site_name,
)

EVIL_QUERY_URL = 'https://example.com/?q=";__import__("os").system("id");x="'
EVIL_HOST_URL = 'https://ex"+exec("print(1)")+".com/'


# ── Nom de site ────────────────────────────────────────────────────────────
@pytest.mark.parametrize("name", ["designboom", "news_a_com", "a", "x" * 64, "site_2"])
def test_valid_site_names(name):
    assert validate_site_name(name) == name


@pytest.mark.parametrize(
    "name",
    [
        "",
        "../../tests/test_x",
        "a/b",
        "A",
        "x" * 65,
        "nom-avec-tiret",
        "a.b",
        "a b",
        "a\nb",
        'a"b',
        "é",
    ],
)
def test_invalid_site_names(name):
    with pytest.raises(UnsafeInput):
        validate_site_name(name)


# ── URL cible ──────────────────────────────────────────────────────────────
def test_normalize_adds_https_and_keeps_path():
    assert normalize_target_url("example.com/a?b=1") == "https://example.com/a?b=1"


def test_normalize_idna_host():
    assert normalize_target_url("https://bücher.de/") == "https://xn--bcher-kva.de/"


@pytest.mark.parametrize(
    "url",
    [
        "ftp://example.com/",
        "file:///etc/passwd",
        "javascript:alert(1)",
        EVIL_HOST_URL,
        "https://user:pw@example.com/",
        "https:///nohost",
        "https://exa mple.com/",
        "https://example.com/\nX-Injected: 1",
    ],
)
def test_normalize_rejects_bad_urls(url):
    with pytest.raises(UnsafeInput):
        normalize_target_url(url)


def test_normalize_quotes_dangerous_characters_in_query():
    out = normalize_target_url(EVIL_QUERY_URL)
    assert '"' not in out
    assert out.startswith("https://example.com/?q=")


# ── Nom dérivé de l'hôte ───────────────────────────────────────────────────
def test_name_from_url_keeps_full_domain():
    assert name_from_url("https://news.a.com/x") == "news_a_com"
    assert name_from_url("https://news.b.com/x") == "news_b_com"
    assert name_from_url("https://www.designboom.com") == "designboom_com"


def test_name_from_url_is_always_valid():
    for url in ("https://xn--bcher-kva.de", "https://a-b.c-d.example.org:8443/"):
        assert validate_site_name(name_from_url(url))


# ── Chemins ────────────────────────────────────────────────────────────────
def test_safe_path_refuses_traversal(tmp_path):
    with pytest.raises(UnsafeInput):
        safe_path(tmp_path, "../evil.md")
    with pytest.raises(UnsafeInput):
        safe_path(tmp_path, "/etc/passwd")
    assert safe_path(tmp_path, "sub", "ok.md") == (tmp_path / "sub" / "ok.md").resolve()


def test_safe_path_refuses_symlink_escape(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    base = tmp_path / "base"
    base.mkdir()
    (base / "link").symlink_to(outside, target_is_directory=True)
    with pytest.raises(UnsafeInput):
        safe_path(base, "link", "x.md")


# ── Squelette généré : pas d'injection de code ─────────────────────────────
def _report(url: str, rationale: str = "ok") -> probe_mod.ProbeReport:
    return probe_mod.ProbeReport(
        url=url,
        timestamp="2026-10-24T00:00:00+00:00",
        tier1={"wordpress_detected": True, "rss_feeds": [{"endpoint": "/feed"}]},
        chosen_tier=1,
        rationale=rationale,
    )


def _calls(tree: ast.AST) -> set[str]:
    out = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            f = node.func
            out.add(f.id if isinstance(f, ast.Name) else getattr(f, "attr", "?"))
    return out


@pytest.mark.parametrize("url", [EVIL_QUERY_URL, 'https://a"+exec("print(1)")+".com', "https://x.com/'''\"\"\""])
def test_skeleton_is_injection_free(url):
    src = probe_mod.emit_skeleton(_report(url, rationale='"""\nimport os\nos.system("id")\n"""'), "example_com")
    tree = ast.parse(src)
    calls = _calls(tree)
    assert "__import__" not in calls and "system" not in calls and "exec" not in calls
    assigns = {
        n.targets[0].id: n.value.value
        for n in tree.body
        if isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name) and isinstance(n.value, ast.Constant)
    }
    assert assigns["BASE_URL"] == url.rstrip("/")
    # pas de `import os` injecté au niveau module
    imported = {a.name for n in tree.body if isinstance(n, ast.Import) for a in n.names}
    assert "os" not in imported


def test_skeleton_refuses_bad_name():
    with pytest.raises(UnsafeInput):
        probe_mod.emit_skeleton(_report("https://example.com"), 'x"); import os; ("')


# ── Écritures : save_findings / save_report / shards YAML ─────────────────
@pytest.fixture
def data_dir(tmp_path, monkeypatch):
    d = tmp_path / "data"
    d.mkdir()
    sites = tmp_path / "sites"
    sites.mkdir()
    monkeypatch.setattr(probe_mod, "DATA_DIR", d)
    monkeypatch.setattr(probe_mod, "SITES_DIR", sites, raising=False)
    monkeypatch.setattr(sap_inspect, "PROBES_DIR", d / "probes")
    monkeypatch.setattr(sap_inspect, "SAP_DIR", d / "sap")
    return tmp_path


def _all_files(root: Path) -> set[Path]:
    return {p for p in root.rglob("*") if p.is_file()}


def test_save_findings_refuses_traversal(data_dir):
    before = _all_files(data_dir)
    with pytest.raises(UnsafeInput):
        probe_mod.save_findings(_report("https://example.com"), "../../tests/test_x", save_skeleton=True)
    assert _all_files(data_dir) == before


def test_save_findings_writes_inside_base(data_dir):
    out = probe_mod.save_findings(_report("https://example.com"), "example_com", save_skeleton=True)
    assert Path(out["markdown"]).resolve().is_relative_to(data_dir.resolve())
    assert Path(out["skeleton"]).resolve().is_relative_to((data_dir / "sites").resolve())
    ast.parse(Path(out["skeleton"]).read_text())


def _inspect_report(name: str) -> sap_inspect.InspectReport:
    return sap_inspect.InspectReport(
        target_url="https://example.com",
        name=name,
        timestamp="2026-10-24T00:00:00+00:00",
        duration_s=0.0,
        reachability=sap_inspect.Reachability(status="OK"),
        anti_bot_stack={},
        frameworks={},
        endpoints=[],
        graphql_calls=[],
        inline_data_islands=[],
        link_architecture=None,
    )


def test_save_report_refuses_traversal(data_dir):
    with pytest.raises(UnsafeInput):
        sap_inspect.save_report(_inspect_report("../../tests/test_x"))
    assert not (data_dir / "tests").exists()


def test_emit_yaml_refuses_traversal(data_dir):
    with pytest.raises(UnsafeInput):
        sap_inspect.emit_yaml_shards(_inspect_report("../../escape"))
    assert not (data_dir / "escape").exists()


def test_yaml_shard_helpers_refuse_traversal(data_dir):
    with pytest.raises(UnsafeInput):
        sap_inspect._save_yaml_shard("../../escape", "04_strategy.yaml", {"a": 1})
    with pytest.raises(UnsafeInput):
        sap_inspect._save_yaml_shard("ok_name", "../../../x.yaml", {"a": 1})
    with pytest.raises(UnsafeInput):
        sap_inspect._load_yaml_shard("../..", "x.yaml")


def test_rehearse_refuses_bad_name(data_dir):
    with pytest.raises(UnsafeInput):
        sap_inspect.rehearse_strategy("../../etc")


# ── CLI : validation centrale avant toute action ──────────────────────────
@pytest.fixture
def no_network(monkeypatch):
    async def _boom(*a, **k):
        raise AssertionError("la sonde ne doit pas être lancée")

    monkeypatch.setattr(probe_mod, "probe", _boom)
    monkeypatch.setattr(sap_inspect, "inspect", _boom)
    monkeypatch.setattr(sap_mod, "verify_site", _boom)


@pytest.mark.parametrize(
    "argv",
    [
        ["sap", "probe", "https://example.com", "--name", "../../tests/test_x"],
        ["sap", "inspect", "https://example.com", "--name", "../../tests/test_x"],
        ["sap", "probe", EVIL_HOST_URL],
        ["sap", "probe", "file:///etc/passwd"],
        ["sap", "inspect", "ftp://example.com"],
        ["sap", "rehearse", "../../etc"],
        ["sap", "verify", "../../etc"],
        ["sap", "show", "../../etc"],
        ["sap", "diff", "../../etc"],
    ],
)
def test_cli_rejects_unsafe_targets(argv, no_network, data_dir):
    assert cli.main(argv) == 3


def test_cli_verify_refuses_target_absent_from_registry(no_network):
    assert cli.main(["sap", "verify", "site_qui_nexiste_pas"]) == 3


def test_verify_site_refuses_unknown_module():
    r = asyncio.run(sap_mod.verify_site("os"))
    assert r.overall == "fail"
    assert "collecteur" in (r.error or "")
    r = asyncio.run(sap_mod.verify_site("../../x"))
    assert r.overall == "fail"


def test_cli_probe_derives_name_from_full_domain(monkeypatch, data_dir):
    seen = {}

    async def _fake_probe(url, **_k):
        seen["url"] = url
        r = _report(url)
        r.tier2 = {"fetched": True}
        return r

    def _fake_save(report, name, *, save_skeleton=False):
        seen["name"] = name
        return {}

    monkeypatch.setattr(probe_mod, "probe", _fake_probe)
    monkeypatch.setattr(probe_mod, "save_findings", _fake_save)
    assert cli.main(["sap", "probe", "news.a.com", "--save"]) == 0
    assert seen == {"url": "https://news.a.com", "name": "news_a_com"}
