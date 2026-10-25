"""sap.print_result : une valeur mesurée qui diffère de l'attendue est affichée."""

from accesspath.sap import CheckResult, SapResult, print_result


def _result(*checks):
    return SapResult(
        site="x",
        timestamp="2026-10-24T00:00:00+00:00",
        fetch_url="https://x.test",
        fetch_method="http",
        overall="warn",
        checks=list(checks),
    )


def test_valeur_mesuree_differente_affichee(capsys):
    print_result(_result(CheckResult("articles", "warn", "trop peu", measured=3, expected=20)))
    assert "(got 3)" in capsys.readouterr().out


def test_valeur_mesuree_egale_non_repetee(capsys):
    print_result(_result(CheckResult("articles", "pass", "ok", measured=20, expected=20)))
    assert "(got" not in capsys.readouterr().out
