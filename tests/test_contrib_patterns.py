"""Les contributions de motifs reçues par pull request respectent le format."""

from pathlib import Path

import pytest
import yaml

from accesspath.acquisition import learn

CONTRIB = Path(__file__).parent.parent / "contrib" / "patterns"


@pytest.mark.parametrize("path", sorted(CONTRIB.glob("*.yaml")), ids=lambda p: p.name)
def test_contribution_valide(path):
    assert learn.validate_contribution(yaml.safe_load(path.read_text(encoding="utf-8"))) == []
