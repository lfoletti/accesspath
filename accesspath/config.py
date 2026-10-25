"""Chemins et branchement des collecteurs.

Le moteur écrit dans le dossier `data/` du projet qui l'appelle (le dossier courant), ou
dans `ACCESSPATH_DATA`. Il n'écrit rien sans `--save`.

Un projet de collecte peut brancher ses collecteurs : `ACCESSPATH_SITES` nomme un paquet
Python qui expose `REGISTRY` (nom → configuration) et un module par site. `sap verify` et
`warmup` s'en servent ; sans ce paquet, le moteur audite seul.
"""

from __future__ import annotations

import importlib
import os
from enum import StrEnum
from pathlib import Path
from types import ModuleType

DATA_DIR = Path(os.environ.get("ACCESSPATH_DATA") or Path.cwd() / "data")
PROFILES_DIR = DATA_DIR / "profiles"
# Corpus de sites annotés pour le prior kNN de `inspect` ; facultatif.
CORPUS_FILE = Path(os.environ.get("ACCESSPATH_CORPUS") or DATA_DIR / "sap_training_corpus.json")
SITES_PACKAGE = os.environ.get("ACCESSPATH_SITES", "")


class BrowserMode(StrEnum):
    PROXY_ROTATION = "proxy_rotation"
    PERSISTENT_PROFILE = "persistent_profile"


def sites_registry() -> dict:
    """Collecteurs branchés (`ACCESSPATH_SITES`), ou rien."""
    if not SITES_PACKAGE:
        return {}
    return getattr(importlib.import_module(SITES_PACKAGE), "REGISTRY", {})


def site_module(name: str) -> ModuleType:
    """Module du collecteur `name` ; le nom est validé par l'appelant."""
    if not SITES_PACKAGE:
        raise ImportError("aucun collecteur branché (ACCESSPATH_SITES)")
    return importlib.import_module(f"{SITES_PACKAGE}.{name}")
