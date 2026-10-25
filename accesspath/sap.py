"""Site Architecture Profile (SAP) — portrait-robot exécutable par site.

Concept : chaque site décrit son architecture (rendering, endpoints, selectors,
auth, anti-bot…) ET expose une fonction `sap_verify()` qui auto-teste le profil
contre une page sample. Le diff entre 2 audits successifs détecte les refontes
silencieuses (selectors morts, API qui change, anti-bot durci).

Usage CLI :
  accesspath sap show <site>           # imprime le profil + dernier audit
  accesspath sap verify <site>         # auto-test live, retourne PASS/WARN/FAIL
  accesspath sap verify --all          # tous les sites
  accesspath sap diff <site>           # compare le dernier audit au précédent

Audit history : data/sap_audits.jsonl (append-only, dédup par (site, hash) à read).
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

from .config import DATA_DIR

PROFILES_FILE = DATA_DIR / "site_architecture_profiles.json"
AUDITS_FILE = DATA_DIR / "sap_audits.jsonl"

CheckStatus = Literal["pass", "warn", "fail"]


@dataclass
class CheckResult:
    name: str
    status: CheckStatus
    detail: str = ""
    measured: Any = None  # valeur observée (count, sample, etc.)
    expected: Any = None


@dataclass
class SapResult:
    site: str
    timestamp: str  # ISO
    fetch_url: str
    fetch_method: str  # "http" | "rss" | "chrome"
    overall: CheckStatus  # worst of all checks
    checks: list[CheckResult] = field(default_factory=list)
    duration_s: float = 0.0
    error: str | None = None

    def to_dict(self) -> dict:
        d = asdict(self)
        return d

    @classmethod
    def from_dict(cls, d: dict) -> SapResult:
        checks = [CheckResult(**c) for c in d.pop("checks", [])]
        return cls(checks=checks, **d)


def _aggregate(checks: list[CheckResult]) -> CheckStatus:
    if not checks:
        return "fail"
    if any(c.status == "fail" for c in checks):
        return "fail"
    if any(c.status == "warn" for c in checks):
        return "warn"
    return "pass"


def make_check(
    name: str,
    measured: Any,
    expected: Any,
    *,
    fail_if_below: int | None = None,
    warn_if_below: int | None = None,
    must_be_truthy: bool = False,
) -> CheckResult:
    """Helper : crée un CheckResult avec les seuils standard."""
    if must_be_truthy:
        status: CheckStatus = "pass" if bool(measured) else "fail"
        detail = "ok" if bool(measured) else "absent/None/empty"
    elif fail_if_below is not None:
        if measured < fail_if_below:
            status = "fail"
            detail = f"{measured} < {fail_if_below} (seuil critique)"
        elif warn_if_below is not None and measured < warn_if_below:
            status = "warn"
            detail = f"{measured} < {warn_if_below} (seuil warn)"
        else:
            status = "pass"
            detail = f"{measured} ≥ {fail_if_below}"
    else:
        status = "pass" if measured == expected else "fail"
        detail = f"got {measured!r}, expected {expected!r}"
    return CheckResult(name=name, status=status, detail=detail, measured=measured, expected=expected)


def load_profiles() -> dict[str, dict]:
    """Lit data/site_architecture_profiles.json. Retourne dict ou {}."""
    if not PROFILES_FILE.exists():
        return {}
    try:
        data = json.loads(PROFILES_FILE.read_text())
    except json.JSONDecodeError:
        return {}
    return {k: v for k, v in data.items() if not k.startswith("_")}


async def verify_site(site_name: str) -> SapResult:
    """Appelle `sap_verify()` du module site si défini, sinon retourne fail.

    Refuse tout nom hors `^[a-z0-9_]{1,64}$` ou absent du registre des sites :
    aucun module arbitraire n'est importé.
    """
    from ._safe import SITE_NAME_RE

    t0 = time.monotonic()
    known = bool(SITE_NAME_RE.fullmatch(site_name or ""))
    if known:
        from .config import sites_registry

        known = site_name in sites_registry()
    if not known:
        return SapResult(
            site=site_name,
            timestamp=datetime.now(UTC).isoformat(),
            fetch_url="",
            fetch_method="?",
            overall="fail",
            error=f"site {site_name!r} sans collecteur branché (ACCESSPATH_SITES)",
            duration_s=time.monotonic() - t0,
        )
    try:
        from .config import site_module

        mod = site_module(site_name)
    except ImportError as e:
        return SapResult(
            site=site_name,
            timestamp=datetime.now(UTC).isoformat(),
            fetch_url="",
            fetch_method="?",
            overall="fail",
            error=f"site module not found: {e}",
            duration_s=time.monotonic() - t0,
        )

    fn = getattr(mod, "sap_verify", None)
    if fn is None or not callable(fn):
        return SapResult(
            site=site_name,
            timestamp=datetime.now(UTC).isoformat(),
            fetch_url="",
            fetch_method="?",
            overall="warn",
            error=f"site {site_name} does not expose sap_verify() — profile not enforced",
            duration_s=time.monotonic() - t0,
        )

    try:
        result = await fn()
    except Exception as e:
        return SapResult(
            site=site_name,
            timestamp=datetime.now(UTC).isoformat(),
            fetch_url="",
            fetch_method="?",
            overall="fail",
            error=f"sap_verify raised: {type(e).__name__}: {e}",
            duration_s=time.monotonic() - t0,
        )
    result.duration_s = time.monotonic() - t0
    return result


def save_audit(result: SapResult) -> None:
    """Append-only audit log."""
    AUDITS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with AUDITS_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(result.to_dict(), ensure_ascii=False) + "\n")


def load_audits(site_name: str | None = None) -> list[SapResult]:
    """Read all audits (filtered by site if provided), most recent last."""
    if not AUDITS_FILE.exists():
        return []
    out: list[SapResult] = []
    with AUDITS_FILE.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
                r = SapResult.from_dict(d)
                if site_name and r.site != site_name:
                    continue
                out.append(r)
            except (json.JSONDecodeError, TypeError):
                continue
    return out


def diff_results(prev: SapResult, curr: SapResult) -> str:
    """Texte diff lisible entre 2 audits."""
    lines = [
        f"Diff [{curr.site}] — {prev.timestamp[:19]} → {curr.timestamp[:19]}",
        f"  overall: {prev.overall} → {curr.overall}",
    ]
    prev_checks = {c.name: c for c in prev.checks}
    curr_checks = {c.name: c for c in curr.checks}

    new_checks = set(curr_checks) - set(prev_checks)
    removed_checks = set(prev_checks) - set(curr_checks)

    for name in sorted(removed_checks):
        lines.append(f"  - REMOVED check: {name}")
    for name in sorted(new_checks):
        c = curr_checks[name]
        lines.append(f"  + NEW check: {name} → {c.status} ({c.detail})")
    for name in sorted(set(prev_checks) & set(curr_checks)):
        p, c = prev_checks[name], curr_checks[name]
        if p.status != c.status:
            lines.append(f"  Δ {name}: {p.status} → {c.status}  ({c.detail})")
        elif p.measured != c.measured:
            lines.append(f"  Δ {name} measured: {p.measured!r} → {c.measured!r}")
    if len(lines) == 2:
        lines.append("  (no change)")
    return "\n".join(lines)


def print_result(result: SapResult) -> None:
    """Pretty print pour le terminal."""
    flags = {"pass": "✅", "warn": "⚠️", "fail": "❌"}
    print(f"\n  {flags[result.overall]} SAP [{result.site}] — {result.overall.upper()} en {result.duration_s:.1f}s")
    print(f"     fetch  : {result.fetch_method} {result.fetch_url}")
    if result.error:
        print(f"     error  : {result.error}")
    for c in result.checks:
        flag = flags[c.status]
        meas = f" (got {c.measured!r})" if c.measured is not None and c.expected != c.measured else ""
        print(f"     {flag} {c.name:<40} {c.detail}{meas}")
