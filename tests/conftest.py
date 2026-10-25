from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def _archives_hors_reseau(monkeypatch):
    """Aucun test ne joint les vraies archives : une sonde sans porte interroge
    les copies tierces, qui pointent ici vers un port local fermé. Les tests
    des copies remplacent ces adresses par leur faux serveur."""
    from accesspath import probe as probe_mod

    monkeypatch.setattr(probe_mod, "WAYBACK_CDX", "http://127.0.0.1:9/cdx/search/cdx")
    monkeypatch.setattr(probe_mod, "CC_COLLINFO", "http://127.0.0.1:9/collinfo.json")
    monkeypatch.setattr(probe_mod, "MEMENTO_TIMETRAVEL", "http://127.0.0.1:9/api/json")
    from accesspath import robots_history as rh_mod

    monkeypatch.setattr(rh_mod, "WAYBACK_CDX", "http://127.0.0.1:9/cdx")
    monkeypatch.setattr(rh_mod, "WAYBACK_WEB", "http://127.0.0.1:9/web")


@pytest.fixture(autouse=True)
def _motifs_appris_hors_du_dossier_personnel(tmp_path, monkeypatch):
    """Les lots des tests apprennent des motifs : dans un dataset jetable, jamais dans
    ~/.accesspath, et la base de plateformes est relue sans eux."""
    from accesspath.acquisition import contents as pp
    from accesspath.acquisition import learn
    from accesspath.acquisition import platforms as pf

    monkeypatch.setattr(learn, "LOCAL_FILE", tmp_path / "patterns.local.yaml")
    monkeypatch.setattr(pf, "_DOC", None)
    monkeypatch.setattr(pp, "_DOC", None)
