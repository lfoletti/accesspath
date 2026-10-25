"""Hook pre-push versionné : refuse les termes privés, lance les tests touchés."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

HOOK = Path(__file__).parent.parent / ".githooks" / "pre-push"
ZERO = "0" * 40

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git absent")


def _git(cwd, *args):
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=True).stdout.strip()


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "r"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@example.invalid")
    _git(r, "config", "user.name", "t")
    (r / "a.txt").write_text("début\n")
    _git(r, "add", "a.txt")
    _git(r, "commit", "-q", "-m", "a")
    return r


def _push(repo, base):
    head = _git(repo, "rev-parse", "HEAD")
    return subprocess.run(
        ["bash", str(HOOK), "origin", "x"],
        cwd=repo,
        input=f"refs/heads/main {head} refs/heads/main {base}\n",
        capture_output=True,
        text=True,
    )


def _commit(repo, name, text):
    (repo / name).parent.mkdir(parents=True, exist_ok=True)
    (repo / name).write_text(text)
    _git(repo, "add", name)
    _git(repo, "commit", "-q", "-m", name)


def test_terme_prive_refuse(repo):
    base = _git(repo, "rev-parse", "HEAD")
    (repo / ".git" / "info" / "private-terms").write_text("# privé\nNomDeCode\n")
    _commit(repo, "b.txt", "on parle du projet nomdecode ici\n")
    r = _push(repo, base)
    assert r.returncode == 1 and "nomdecode" in r.stderr.lower() and "refusée" in r.stderr


def test_sans_terme_prive_la_poussee_passe(repo):
    base = _git(repo, "rev-parse", "HEAD")
    (repo / ".git" / "info" / "private-terms").write_text("NomDeCode\n")
    _commit(repo, "b.txt", "rien de privé\n")
    assert _push(repo, base).returncode == 0


def test_terme_retire_n_est_pas_un_ajout(repo):
    _commit(repo, "b.txt", "nomdecode\n")
    base = _git(repo, "rev-parse", "HEAD")
    (repo / ".git" / "info" / "private-terms").write_text("NomDeCode\n")
    _commit(repo, "b.txt", "propre\n")
    assert _push(repo, base).returncode == 0


def test_tests_touches_lances_et_echec_refuse(repo):
    base = _git(repo, "rev-parse", "HEAD")
    _commit(repo, "accesspath/outil.py", "X = 1\n")
    _commit(repo, "tests/test_outil.py", "def test_x():\n    assert False\n")
    r = _push(repo, base)
    assert r.returncode == 1 and "tests/test_outil.py" in r.stderr and "tests en échec" in r.stderr


def test_tests_touches_qui_passent(repo):
    base = _git(repo, "rev-parse", "HEAD")
    _commit(repo, "tests/test_outil.py", "def test_x():\n    assert True\n")
    assert _push(repo, base).returncode == 0


def test_suppression_de_branche_ignoree(repo):
    r = subprocess.run(
        ["bash", str(HOOK), "origin", "x"],
        cwd=repo,
        input=f"refs/heads/old {ZERO} refs/heads/old {_git(repo, 'rev-parse', 'HEAD')}\n",
        capture_output=True,
        text=True,
    )
    assert r.returncode == 0


def test_fichier_de_test_modifie_seul_est_lance(repo):
    base = _git(repo, "rev-parse", "HEAD")
    _commit(repo, "tests/test_seul.py", "def test_x():\n    assert False\n")
    assert _push(repo, base).returncode == 1
