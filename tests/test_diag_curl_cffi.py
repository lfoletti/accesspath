"""Diagnostic temporaire (branche curl-cffi-017-ua, à retirer) : en-têtes reçus selon la cible et les en-têtes passés."""

from __future__ import annotations

import asyncio
import json

import pytest

from accesspath import _http

from ._localserver import LocalServer, _send

cc = pytest.importorskip("curl_cffi")


@pytest.fixture(autouse=True)
def _allow_local(monkeypatch):
    monkeypatch.setenv("ACCESSPATH_ALLOW_PRIVATE", "1")


def test_diagnostic():
    out = {"version": cc.__version__}
    for target in ("chrome", "chrome150", "chrome146", "chrome152_macos"):
        for hdrs in (None, {"Accept": "text/html"}):
            seen = {}

            def h(req, seen=seen):
                seen.update(req.headers)
                _send(req, 200, b"ok", {"Content-Type": "text/plain"})

            with LocalServer({"/": h}) as s:
                try:
                    asyncio.run(_http.aimpersonate_get(s.url("/"), headers=hdrs, impersonate=target))
                except Exception as e:  # noqa: BLE001
                    seen["ERR"] = repr(e)
            out[f"{target}|{bool(hdrs)}"] = {k: v[:60] for k, v in seen.items()}
    pytest.fail(json.dumps(out, indent=1))
