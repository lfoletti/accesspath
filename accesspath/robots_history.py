"""Histoire du robots.txt d'un site, lue dans la Wayback Machine.

L'index CDX donne une ligne par contenu distinct (`collapse=digest`) ; chaque version est
relue telle qu'archivée (`id_`, sans la barre de navigation de l'archive). Pour chaque
version, la position des robots d'IA (`usage_prefs.ai_crawler_rules`) ; entre deux
versions, les changements datés. Une date « ≤AAAA-MM-JJ » dit qu'un robot était déjà
bloqué à la première version archivée : le blocage est antérieur.

Les dates sont celles des captures, pas des modifications : un changement a eu lieu
entre la capture précédente et celle-ci. Un échantillon réparti couvre la période ;
entre deux versions lues qui diffèrent, une dichotomie retrouve la première version
changée (log2 de l'écart en relectures). Une archive qui ralentit (429, 503, connexion
refusée) est reprise après une pause ; un refus (403) ne l'est pas. Une connexion
encore refusée après les reprises arrête le site : l'archive a fermé la porte, insister
n'y change rien (`unavailable`).
"""

from __future__ import annotations

import asyncio
import json
from urllib.parse import urlencode

from . import usage_prefs

WAYBACK_CDX = "https://web.archive.org/cdx/search/cdx"
WAYBACK_WEB = "https://web.archive.org/web"
MAX_VERSIONS = 16  # échantillon ; la dichotomie précise ensuite les dates
MAX_FETCHES = 80  # relectures par site, échantillon et dichotomie compris
BACKOFF_S = (10.0, 30.0, 60.0)
RETRY_STATUS = {-1, 429, 502, 503, 504}
DEFAULT_SINCE = "2020"
DEFAULT_DELAY_S = 4.0  # quinze lectures par minute au plus
BLOCKED = "bloqué"


def parse_cdx(payload: bytes) -> list[tuple[str, str]]:
    """Réponse CDX (JSON, première ligne = en-têtes) → [(horodatage, empreinte)]."""
    try:
        rows = json.loads(payload or b"[]")
    except ValueError:
        return []
    if not isinstance(rows, list) or len(rows) < 2:
        return []
    head = rows[0]
    try:
        i_ts, i_dg = head.index("timestamp"), head.index("digest")
    except ValueError:
        return []
    return [(r[i_ts], r[i_dg]) for r in rows[1:] if len(r) > max(i_ts, i_dg)]


def sample(versions: list, limit: int) -> list:
    """Au plus `limit` versions réparties sur la période, première et dernière comprises."""
    if len(versions) <= limit:
        return list(versions)
    step = (len(versions) - 1) / (limit - 1)
    return [versions[round(i * step)] for i in range(limit)]


def _date(ts: str) -> str:
    return f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}"


def events(snapshots: list[tuple[str, str]]) -> list[dict]:
    """[(date, robots.txt)] dans l'ordre → changements de position des robots d'IA."""
    out: list[dict] = []
    prev: dict[str, str] | None = None
    for date, text in snapshots:
        cur = usage_prefs.ai_crawler_rules(text)
        if prev is not None:
            out += [{"date": date, "bot": b, "from": prev[b], "to": v} for b, v in cur.items() if v != prev[b]]
        prev = cur
    return out


def first_blocked(evts: list[dict]) -> dict[str, str]:
    out: dict[str, str] = {}
    for e in evts:
        if e["to"] == BLOCKED:
            out.setdefault(e["bot"], e["date"])
    return out


def reopened(evts: list[dict]) -> dict[str, str]:
    out: dict[str, str] = {}
    for e in evts:
        if e["from"] == BLOCKED:  # un événement est toujours un changement
            out.setdefault(e["bot"], e["date"])
    return out


def summarize_snapshots(snapshots: list[tuple[str, str]]) -> dict:
    evts = events(snapshots)
    first = {}
    if snapshots:
        initial = usage_prefs.ai_crawler_rules(snapshots[0][1])
        first = {b: f"≤{snapshots[0][0]}" for b, v in initial.items() if v == BLOCKED}
    first.update({b: d for b, d in first_blocked(evts).items() if b not in first})
    return {
        "events": evts,
        "first_blocked": dict(sorted(first.items())),
        "reopened": dict(sorted(reopened(evts).items())),
        "current": usage_prefs.ai_crawler_rules(snapshots[-1][1]) if snapshots else {},
    }


async def _sleep(seconds: float) -> None:
    await asyncio.sleep(seconds)


async def _get(url: str) -> dict:
    """GET d'archive avec identité déclarée ; reprise après une pause si l'archive ralentit."""
    from .probe import _third_party_get

    r = await _third_party_get(url)
    for wait in BACKOFF_S:
        if r["status"] not in RETRY_STATUS:
            break
        await _sleep(wait)
        r = await _third_party_get(url)
    return r


# Seul un refus de connexion dit que l'archive ferme la porte ; une connexion coupée en
# cours de route est un incident : la version est illisible, le site continue.
CLOSED_ERRORS = ("ConnectError", "ConnectTimeout")


def _closed(r: dict) -> bool:
    return r["status"] == -1 and str(r.get("error") or "").startswith(CLOSED_ERRORS)


def _stance(text: str) -> tuple:
    """Robots bloqués : la dichotomie ne précise que les blocages et les réouvertures ;
    les autres changements (permis ↔ partiel) gardent la précision de l'échantillon."""
    return tuple(sorted(b for b, v in usage_prefs.ai_crawler_rules(text).items() if v == BLOCKED))


async def robots_history(
    netloc: str, *, since: str = DEFAULT_SINCE, limit: int = MAX_VERSIONS, delay: float = DEFAULT_DELAY_S
) -> dict:
    """Versions archivées de https://<netloc>/robots.txt et changements des robots d'IA."""
    target = f"https://{netloc}/robots.txt"
    q = (
        WAYBACK_CDX
        + "?"
        + urlencode(
            {
                "url": f"{netloc}/robots.txt",
                "output": "json",
                "fl": "timestamp,digest,statuscode",
                "filter": "statuscode:200",
                "collapse": "digest",
                "from": since,
            }
        )
    )
    r = await _get(q)
    if not r["ok"]:
        return {**_empty(q, r["error"]), "unavailable": _closed(r)}
    versions = parse_cdx(r["body"])
    read: dict[int, str | None] = {}  # rang → robots.txt, None si illisible

    class Closed(Exception):
        pass

    async def fetch(i: int) -> None:
        if read and delay:
            await asyncio.sleep(delay)
        v = await _get(f"{WAYBACK_WEB}/{versions[i][0]}id_/{target}")
        if _closed(v):
            raise Closed(v["error"])
        text = v["body"].decode("utf-8", "replace") if v["ok"] else ""
        # page d'erreur, ou HTML archivé à la place du fichier
        read[i] = text if v["ok"] and text.lstrip()[:1] != "<" else None

    index = {ts: i for i, (ts, _d) in enumerate(versions)}
    try:
        await _walk(versions, index, read, fetch, limit)
    except Closed as e:
        return {**_empty(q, f"archive indisponible : {e}"), "unavailable": True}
    snaps = [(_date(versions[i][0]), read[i]) for i in sorted(read) if read[i] is not None]
    return {"versions": len(versions), "fetched": len(snaps), **summarize_snapshots(snaps), "query": q, "error": None}


def _empty(query: str, error: str | None) -> dict:
    return {
        "versions": None,
        "fetched": 0,
        "events": [],
        "first_blocked": {},
        "reopened": {},
        "current": {},
        "query": query,
        "error": error,
    }


async def _walk(versions, index, read, fetch, limit) -> None:
    """Échantillon réparti, puis dichotomie entre deux versions lues qui diffèrent."""
    for ts, _d in sample(versions, min(limit, MAX_FETCHES)):
        await fetch(index[ts])
    while len(read) < MAX_FETCHES:
        good = sorted(i for i, t in read.items() if t is not None)
        gap = next(
            (
                (a, b)
                for a, b in zip(good, good[1:], strict=False)
                if _stance(read[a]) != _stance(read[b]) and any(m not in read for m in range(a + 1, b))
            ),
            None,
        )
        if gap is None:
            break
        a, b = gap
        await fetch(min((m for m in range(a + 1, b) if m not in read), key=lambda m: abs(m - (a + b) / 2)))


def history_row(h: dict) -> dict:
    """Résultat d'histoire → ligne de lot."""
    if h.get("versions") is None:
        return {"status": "error", "error": str(h.get("error"))[:200]}
    return {
        "status": "ok",
        "versions": h["versions"],
        "first_blocked": h["first_blocked"],
        "reopened": h["reopened"],
        "changes": len(h["events"]),
        "ai_blocked_now": sorted(b for b, v in h["current"].items() if v == BLOCKED),
    }
