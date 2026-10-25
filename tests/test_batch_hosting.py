"""Un lot ne visite pas en même temps plusieurs sites du même hébergeur.

Cas d'origine (bureaux étrangers, octobre 2026) : huit sites à la fois, dont plusieurs
chez le même hébergeur mutualisé (Strato, 81.169.145.x) ; l'hébergeur a coupé les
connexions de notre adresse, et douze sites lus la veille sont sortis « injoignables ».
Les sites sont groupés par bloc d'adresses (IPv4 /24, IPv6 /48) ; un bloc ne reçoit
qu'un site à la fois (`per_block`), les autres blocs avancent en parallèle.
"""

from __future__ import annotations

import asyncio
import socket

import pytest

from accesspath import batch, cli


# ── Bloc d'adresses ──────────────────────────────────────────────────────
def _fixed(table):
    async def resolve(host):
        if host not in table:
            raise socket.gaierror("inconnu")
        return table[host]

    return resolve


@pytest.mark.parametrize(
    ("address", "expected"),
    [
        ("81.169.145.149", "81.169.145.0/24"),
        ("81.169.145.86", "81.169.145.0/24"),
        ("2a01:238:20a:202:1149::1", "2a01:238:20a::/48"),
    ],
)
def test_bloc_d_une_adresse(address, expected):
    resolve = _fixed({"a.de": address})
    assert asyncio.run(batch.host_block("https://a.de/x", resolve)) == expected


def test_hote_sans_adresse_forme_son_propre_bloc():
    assert asyncio.run(batch.host_block("https://www.perdu.de/", _fixed({}))) == "www.perdu.de"


def test_resolveur_par_defaut_lit_le_systeme(monkeypatch):
    def fake_getaddrinfo(host, port, *args, **kw):
        assert host == "a.de"
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("81.169.145.10", 443))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    assert asyncio.run(batch.host_block("https://a.de/")) == "81.169.145.0/24"


# ── Lot ──────────────────────────────────────────────────────────────────
def _run(tmp_path, per_block, table):
    active: dict[str, int] = {}
    peak: dict[str, int] = {}
    overall = {"now": 0, "max": 0}

    async def runner(t):
        block = t["name"][0]  # « s » pour l'hébergeur partagé, « o » pour les autres
        active[block] = active.get(block, 0) + 1
        peak[block] = max(peak.get(block, 0), active[block])
        overall["now"] += 1
        overall["max"] = max(overall["max"], overall["now"])
        await asyncio.sleep(0.03)
        active[block] -= 1
        overall["now"] -= 1
        return {"status": "ok"}

    targets = [{"name": f"s{i}", "url": f"https://s{i}.de/", "extra": {}} for i in range(4)]
    targets += [{"name": f"o{i}", "url": f"https://o{i}.ch/", "extra": {}} for i in range(3)]
    rows = asyncio.run(
        batch.run_batch(
            targets, runner=runner, concurrency=6, out_dir=tmp_path, per_block=per_block, resolve=_fixed(table)
        )
    )
    return rows, peak, overall


TABLE = {
    **{f"s{i}.de": f"81.169.145.{10 + i}" for i in range(4)},
    "o0.ch": "1.1.1.1",
    "o1.ch": "2.2.2.2",
    "o2.ch": "3.3.3.3",
}


def test_un_site_a_la_fois_par_hebergeur(tmp_path):
    rows, peak, overall = _run(tmp_path, 1, TABLE)
    assert len(rows) == 7
    assert peak["s"] == 1  # les quatre sites de l'hébergeur passent l'un après l'autre
    assert peak["o"] == 3 and overall["max"] >= 4  # les autres ne les attendent pas


def test_limite_par_hebergeur_reglable(tmp_path):
    _rows, peak, _overall = _run(tmp_path, 2, TABLE)
    assert peak["s"] == 2


def test_sans_limite_par_hebergeur(tmp_path):
    _rows, peak, _overall = _run(tmp_path, None, TABLE)
    assert peak["s"] == 4


def test_ligne_porte_le_bloc(tmp_path):
    rows, _peak, _overall = _run(tmp_path, 1, TABLE)
    assert {r["name"]: r["host_block"] for r in rows}["s0"] == "81.169.145.0/24"


def test_un_site_en_attente_ne_prend_pas_de_place(tmp_path):
    # Quatre sites du même hébergeur et deux places : un autre site passe tout de suite.
    order = []

    async def runner(t):
        order.append(t["name"])
        await asyncio.sleep(0.03)
        return {"status": "ok"}

    targets = [{"name": f"s{i}", "url": f"https://s{i}.de/", "extra": {}} for i in range(4)]
    targets.append({"name": "o0", "url": "https://o0.ch/", "extra": {}})
    asyncio.run(
        batch.run_batch(targets, runner=runner, concurrency=2, out_dir=tmp_path, per_block=1, resolve=_fixed(TABLE))
    )
    assert order.index("o0") <= 1


# ── Ligne de commande ────────────────────────────────────────────────────
def test_option_de_la_ligne_de_commande():
    parser = cli.build_parser()
    args = parser.parse_args(["sap", "batch", "liste.csv", "--per-host-block", "2"])
    assert args.per_host_block == 2
    assert parser.parse_args(["sap", "batch", "liste.csv"]).per_host_block == batch.PER_HOST_BLOCK
    assert batch.PER_HOST_BLOCK == 1


@pytest.mark.parametrize(
    ("argv", "expected"), [([], 1), (["--per-host-block", "3"], 3), (["--per-host-block", "0"], 1)]
)
def test_la_commande_transmet_la_limite(tmp_path, monkeypatch, argv, expected):
    from .test_sap_batch import _cli_env

    _cli_env(tmp_path, monkeypatch)
    seen = {}

    async def fake_run_batch(targets, **kw):
        seen.update(kw)
        kw["out_dir"].mkdir(parents=True, exist_ok=True)
        (kw["out_dir"] / "results.jsonl").write_text("")
        return []

    monkeypatch.setattr(batch, "run_batch", fake_run_batch)
    f = tmp_path / "liste.txt"
    f.write_text("https://a.ch/\n")
    assert cli.main(["sap", "batch", str(f), *argv]) == 0
    assert seen["per_block"] == expected
