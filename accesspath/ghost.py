"""Mode fantôme : la navigation du porteur devient une spécification d'appels rejouables.

Le porteur parcourt le site dans son navigateur et exporte la session en HAR (outils de
développement, onglet Réseau, « Enregistrer au format HAR »). Ce module, sans navigateur
ni réseau :

1. lit le HAR (`load_har`), corps décodés ;
2. écarte le bruit (statique, mesure d'audience, publicité) et classe les appels de
   données : par la part de leur JSON qui se retrouve dans le texte affiché quand on
   le donne, sinon par la présence d'une liste d'objets (`rank_data_calls`) ;
3. généralise chaque appel en gabarit (`build_spec`) : paramètre de pagination,
   curseur repris d'une réponse précédente, constante, secret ;
4. expurge les secrets (cookies, jetons, signatures) en `{secret:nom}` : la
   spécification ne garde que la forme des appels et la liste des champs, jamais les
   valeurs des réponses.

Le rejeu (`replay`) refait ces appels sans navigateur, page après page : pas de pagination,
curseur repris de la réponse précédente, secrets lus à l'environnement
(`ACCESSPATH_SECRET_<NOM>`) ou dans un HAR frais, jamais écrits sur disque.
"""

from __future__ import annotations

import base64
import json
import os
import re
import time
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit

from .sap_inspect import SAP_DIR, _categorize_url, _normalize_path_pattern

HAR_MAX_BYTES = 200 * 1024 * 1024
NOISE = {"static", "ad-tech", "telemetry"}
SECRET_NAME = re.compile(
    r"cookie|authori[sz]ation|token|csrf|xsrf|secret|session|sig(nature)?$|^sig|api[-_]?key|^key$|auth|hash", re.I
)
# Un décalage avance du nombre d'éléments reçus ; une page, de un.
OFFSET_NAME = re.compile(r"^(offset|start|skip|from)$", re.I)
PAGE_NAME = re.compile(r"^(page|p|pg|offset|start|skip|from|page_?num(ber)?)$", re.I)
# En-têtes que tout navigateur envoie : le rejeu les fournit lui-même.
BROWSER_HEADERS = {
    "user-agent",
    "accept-encoding",
    "accept-language",
    "connection",
    "host",
    "content-length",
    "referer",
    "origin",
    "pragma",
    "cache-control",
    "priority",
    "upgrade-insecure-requests",
    "dnt",
}


def load_har(path: str | Path) -> list[dict]:
    """Appels du HAR : méthode, adresse, statut, type, corps décodé, corps envoyé, en-têtes."""
    p = Path(path)
    if p.stat().st_size > HAR_MAX_BYTES:
        raise ValueError(f"HAR trop gros (> {HAR_MAX_BYTES // 2**20} Mo)")
    log = json.loads(p.read_text(encoding="utf-8", errors="replace")).get("log", {})
    calls = []
    for e in log.get("entries", []):
        req, resp = e.get("request", {}), e.get("response", {})
        content = resp.get("content", {})
        body = content.get("text") or ""
        if body and content.get("encoding") == "base64":
            try:
                body = base64.b64decode(body).decode("utf-8", errors="replace")
            except ValueError:
                body = ""
        calls.append(
            {
                "method": (req.get("method") or "GET").upper(),
                "url": req.get("url") or "",
                "status": resp.get("status") or 0,
                "mime": (content.get("mimeType") or "").lower(),
                "body": body,
                "post": (req.get("postData") or {}).get("text") or "",
                "headers": {h["name"]: h.get("value", "") for h in req.get("headers", []) if h.get("name")},
            }
        )
    return calls


def _json(text: str):
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None


def _strings(obj) -> list[str]:
    if isinstance(obj, str):
        return [obj]
    if isinstance(obj, dict):
        return [s for v in obj.values() for s in _strings(v)]
    if isinstance(obj, list):
        return [s for v in obj for s in _strings(v)]
    return []


def _has_object_list(obj) -> bool:
    if isinstance(obj, list):
        return any(isinstance(v, dict) for v in obj) or any(_has_object_list(v) for v in obj)
    if isinstance(obj, dict):
        return any(_has_object_list(v) for v in obj.values())
    return False


def _squash(text: str) -> str:
    return " ".join(text.casefold().split())


def rank_data_calls(calls: list[dict], visible: str | None) -> list[tuple[float, dict]]:
    """Appels de données, du plus probant au moins probant.

    Avec le texte affiché : nombre de chaînes du JSON (3 caractères au moins) qu'on y
    retrouve ; un appel dont rien ne s'affiche est écarté. Sans lui : les réponses qui
    portent une liste d'objets, par taille."""
    seen = _squash(visible) if visible else None
    ranked = []
    for c in calls:
        if not 200 <= c["status"] < 300 or _categorize_url(c["url"]) in NOISE:
            continue
        data = _json(c["body"])
        if not isinstance(data, (dict, list)):
            continue
        if seen is not None:
            score = float(sum(1 for s in _strings(data) if len(s) >= 3 and _squash(s) in seen))
        else:
            score = float(len(c["body"])) if _has_object_list(data) else 0.0
        if score > 0:
            ranked.append((score, c))
    ranked.sort(key=lambda sc: -sc[0])
    return ranked


def _fields(obj, prefix: str = "") -> set[str]:
    out: set[str] = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = f"{prefix}.{k}" if prefix else str(k)
            sub = _fields(v, path)
            out |= sub or {path}
    elif isinstance(obj, list):
        for v in obj:
            out |= _fields(v, f"{prefix}[]")
    return out


def _find_key(obj, value: str, prefix: str = "") -> str | None:
    """Chemin de la clé qui porte `value` dans une réponse, ou None."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = f"{prefix}.{k}" if prefix else str(k)
            if v == value:
                return path
            if (hit := _find_key(v, value, path)) is not None:
                return hit
    elif isinstance(obj, list):
        for v in obj:
            if (hit := _find_key(v, value, f"{prefix}[]")) is not None:
                return hit
    return None


def _roles(name: str, values: list, earlier: list) -> dict:
    """Rôle d'un paramètre d'après ses valeurs dans les appels du gabarit."""
    if SECRET_NAME.search(name):
        return {"role": "secret", "value": f"{{secret:{name.lower()}}}"}
    for v in values:
        if isinstance(v, str) and len(v) >= 3:
            for resp in earlier:
                if (key := _find_key(resp, v)) is not None:
                    return {"role": "curseur", "from": key}
    distinct = list(dict.fromkeys(json.dumps(v) for v in values))
    digits = all(isinstance(v, int) or (isinstance(v, str) and v.isdigit()) for v in values)
    if digits and (len(distinct) > 1 or PAGE_NAME.match(name)):
        ints = sorted({int(v) for v in values})
        gaps = [b - a for a, b in zip(ints, ints[1:], strict=False)]
        step = min(gaps) if gaps else ("items" if OFFSET_NAME.match(name) else 1)
        return {"role": "pagination", "start": ints[0], "step": step}
    if len(distinct) == 1 and len(values) >= 1:
        return {"role": "constante", "value": values[0]}
    return {"role": "variable"}


def _headers(headers: dict) -> dict:
    out = {}
    for name, value in headers.items():
        low = name.lower()
        if low in BROWSER_HEADERS or low.startswith("sec-") or low.startswith(":"):
            continue
        out[name] = f"{{secret:{low}}}" if SECRET_NAME.search(low) else value
    return out


def build_spec(site: str, calls: list[dict], visible: str | None) -> dict:
    """Gabarits des appels de données, rangés du plus probant au moins probant."""
    ranked = rank_data_calls(calls, visible)
    order = {id(c): i for i, c in enumerate(calls)}
    groups: dict[tuple, list[dict]] = {}
    best: dict[tuple, float] = {}
    for score, c in ranked:
        u = urlsplit(c["url"])
        post = _json(c["post"]) if c["post"] else None
        op = post.get("operationName") if isinstance(post, dict) else None
        key = (c["method"], u.netloc, _normalize_path_pattern(u.path), op)
        groups.setdefault(key, []).append(c)
        best[key] = max(best.get(key, 0.0), score)
    templates = []
    for key in sorted(groups, key=lambda k: -best[k]):
        method, host, path, op = key
        members = sorted(groups[key], key=lambda c: order[id(c)])
        queries = [dict(parse_qsl(urlsplit(c["url"]).query, keep_blank_values=True)) for c in members]
        names = list(dict.fromkeys(n for q in queries for n in q))
        prior = [d for c in calls if order[id(c)] < order[id(members[-1])] for d in [_json(c["body"])] if d is not None]
        params = {n: _roles(n, [q[n] for q in queries if n in q], prior) for n in names}
        t = {
            "method": method,
            "url": f"{urlsplit(members[0]['url']).scheme}://{host}{urlsplit(members[0]['url']).path}",
            "path": path,
            "score": best[key],
            "samples": len(members),
            "params": params,
            "headers": _headers(members[0]["headers"]),
            "fields": sorted(set().union(*(_fields(_json(c["body"])) for c in members))),
        }
        posts = [p for c in members if isinstance(p := _json(c["post"]), dict)]
        if posts:
            if op:
                t["operation"] = op
            if posts[0].get("query"):
                t["query"] = posts[0]["query"]
            variables = [p.get("variables") or {} for p in posts]
            vnames = list(dict.fromkeys(n for v in variables for n in v))
            t["variables"] = {n: _roles(n, [v[n] for v in variables if n in v], prior) for n in vnames}
        templates.append(t)
    return {"site": site, "calls": templates}


def summary_lines(spec: dict) -> list[str]:
    lines = []
    for t in spec["calls"]:
        head = f"{t['method']} {t['path']}" + (f" ({t['operation']})" if t.get("operation") else "")
        lines.append(f"{head} — score {t['score']:.0f}, {t['samples']} appel(s), {len(t['fields'])} champ(s)")
        for kind in ("params", "variables"):
            for n, r in (t.get(kind) or {}).items():
                extra = f" ← {r['from']}" if r.get("from") else ""
                lines.append(f"    {n} : {r['role']}{extra}")
    return lines


def save_spec(spec: dict) -> Path:
    import yaml

    out = SAP_DIR / spec["site"] / "ghost_spec.yaml"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(yaml.safe_dump(spec, allow_unicode=True, sort_keys=False), encoding="utf-8")
    return out


# ── Rejeu ────────────────────────────────────────────────────────────────
SECRET_REF = re.compile(r"\{secret:([^}]+)\}")
DEFAULT_DELAY_S = 1.0


def env_name(secret: str) -> str:
    return "ACCESSPATH_SECRET_" + re.sub(r"[^A-Z0-9]", "_", secret.upper())


def needed_secrets(t: dict) -> list[str]:
    """Noms des secrets qu'un gabarit attend, triés."""
    refs = [r.get("value", "") for k in ("params", "variables") for r in (t.get(k) or {}).values()]
    refs += list((t.get("headers") or {}).values())
    return sorted({m for v in refs if isinstance(v, str) for m in SECRET_REF.findall(v)})


def resolve_secrets(t: dict, har_calls: list[dict] | None, env=None) -> tuple[dict, list[str]]:
    """Valeurs des secrets : l'environnement d'abord, puis le premier appel du HAR au même
    chemin (en-tête ou paramètre du même nom). Rend (trouvés, manquants)."""
    env = os.environ if env is None else env
    path = urlsplit(t["url"]).path
    same = [c for c in har_calls or [] if urlsplit(c["url"]).path == path]
    got, missing = {}, []
    for name in needed_secrets(t):
        value = env.get(env_name(name))
        for c in same:
            if value is not None:
                break
            hdr = {k.lower(): v for k, v in c["headers"].items()}
            value = hdr.get(name) or dict(parse_qsl(urlsplit(c["url"]).query)).get(name)
        if value is None:
            missing.append(name)
        else:
            got[name] = value
    return got, missing


def _get_path(obj, path: str):
    """Valeur au chemin `a.b[].c` ; dans une liste, le dernier élément (pagination par clé)."""
    for part in path.split("."):
        is_list = part.endswith("[]")
        key = part[:-2] if is_list else part
        if key:
            obj = obj.get(key) if isinstance(obj, dict) else None
        if is_list:
            obj = obj[-1] if isinstance(obj, list) and obj else None
        if obj is None:
            return None
    return obj


def _fill(roles: dict, state: dict, secrets: dict) -> dict | None:
    """Valeurs des paramètres pour la page `state["page"]` ; None si un curseur attendu manque."""
    out = {}
    for name, r in roles.items():
        role = r.get("role")
        if role == "constante":
            out[name] = r["value"]
        elif role == "secret":
            out[name] = secrets[SECRET_REF.search(r["value"]).group(1)]
        elif role == "pagination":
            step = r.get("step", 1)
            out[name] = r["start"] + (state["items"] if step == "items" else state["page"] * step)
        elif role == "curseur" and state["prev"] is not None:
            value = _get_path(state["prev"], r["from"])
            if value is None:
                return None
            out[name] = value
    return out


def plan_request(t: dict, state: dict, secrets: dict):
    """(méthode, adresse, en-têtes, corps) de la requête de la page `state["page"]`, ou None."""
    params = _fill(t.get("params") or {}, state, secrets)
    if params is None:
        return None
    url = t["url"] + ("?" + urlencode(params) if params else "")
    headers = {k: SECRET_REF.sub(lambda m: secrets[m.group(1)], v) for k, v in (t.get("headers") or {}).items()}
    body = None
    if "variables" in t or t.get("query"):
        variables = _fill(t.get("variables") or {}, state, secrets)
        if variables is None:
            return None
        payload = {"operationName": t.get("operation"), "query": t.get("query"), "variables": variables}
        body = json.dumps({k: v for k, v in payload.items() if v is not None})
        headers["Content-Type"] = "application/json"
    return t["method"], url, headers, body


def _item_count(obj) -> int:
    """Taille de la plus grande liste d'objets de la réponse."""
    if isinstance(obj, list):
        own = sum(1 for v in obj if isinstance(v, dict))
        return max([own, *(_item_count(v) for v in obj)])
    if isinstance(obj, dict):
        return max([0, *(_item_count(v) for v in obj.values())])
    return 0


def replay(t: dict, client, secrets: dict, *, pages: int = 3, delay: float = DEFAULT_DELAY_S, sleep=time.sleep):
    """Rejoue un gabarit page après page. S'arrête au plafond `pages`, sur un statut hors 2xx,
    une réponse non JSON, une page vide, un curseur absent ou une réponse déjà vue."""
    from . import _http

    out: list[dict] = []
    state = {"page": 0, "items": 0, "prev": None}
    seen: set[bytes] = set()
    while len(out) < pages:
        planned = plan_request(t, state, secrets)
        if planned is None:
            break
        if out:
            sleep(delay)
        method, url, headers, body = planned
        r = _http.request(client, method, url, headers=headers, content=body)
        data = _json(r.text) if 200 <= r.status_code < 300 else None
        page = {
            "page": state["page"] + 1,
            "status": r.status_code,
            "items": _item_count(data),
            "repeated": r.content in seen,
            "data": data,
        }
        out.append(page)
        if data is None or page["repeated"] or page["items"] == 0:
            break
        seen.add(r.content)
        state = {"page": state["page"] + 1, "items": state["items"] + page["items"], "prev": data}
    return out


# ── Export OpenAPI ─────────────────────────────────────────────────────────
OPENAPI_VERSION = "3.1.0"
_TOKEN = re.compile(r"<([^>]+)>")


def _openapi_path(path: str) -> tuple[str, list[str]]:
    """`/v1/products/<N>/reviews` → (`/v1/products/{n1}/reviews`, ["n1"])."""
    names: list[str] = []

    def sub(m: re.Match) -> str:
        names.append(f"{re.sub(r'[^a-z0-9]+', '', m.group(1).lower()) or 'p'}{len(names) + 1}")
        return "{" + names[-1] + "}"

    return _TOKEN.sub(sub, path), names


def _schema_for(value) -> dict:
    kind = (
        "boolean"
        if isinstance(value, bool)
        else "integer"
        if isinstance(value, int)
        else "number"
        if isinstance(value, float)
        else "string"
    )
    return {"type": kind, "default": value}


def _openapi_param(name: str, where: str, role: dict) -> dict:
    p = {"name": name, "in": where, "x-accesspath-role": role["role"]}
    if role["role"] == "secret":
        ref = SECRET_REF.search(str(role.get("value", "")))
        p["schema"] = {"type": "string"}
        p["x-accesspath-env"] = env_name(ref.group(1) if ref else name)
        p["description"] = "secret de session : variable d'environnement ou HAR frais"
    elif role["role"] == "pagination":
        p["schema"] = {"type": "integer", "minimum": role.get("start", 0)}
        p["x-accesspath-step"] = role.get("step")
    elif role["role"] == "curseur":
        p["schema"] = {"type": "string"}
        p["x-accesspath-from"] = role.get("from")
    elif role["role"] == "constante":
        p["schema"] = _schema_for(role.get("value"))
    else:
        p["schema"] = {"type": "string"}
    return p


def _header_role(value: str) -> dict:
    return {"role": "secret", "value": value} if SECRET_REF.search(value) else {"role": "constante", "value": value}


def to_openapi(spec: dict) -> dict:
    """Gabarits du mode fantôme → document OpenAPI 3.1, inféré d'une session observée.
    Un chemin et une méthode ne donnent qu'une opération : la plus probante."""
    paths: dict[str, dict] = {}
    for t in spec["calls"]:
        path, path_params = _openapi_path(t["path"])
        method = t["method"].lower()
        item = paths.setdefault(path, {})
        if method in item:
            continue
        u = urlsplit(t["url"])
        item.setdefault("servers", [{"url": f"{u.scheme}://{u.netloc}"}])
        params = [{"name": n, "in": "path", "required": True, "schema": {"type": "string"}} for n in path_params]
        params += [_openapi_param(n, "query", r) for n, r in (t.get("params") or {}).items()]
        params += [_openapi_param(n, "header", _header_role(str(v))) for n, v in (t.get("headers") or {}).items()]
        op = {
            "operationId": t.get("operation") or f"{method}_{re.sub(r'[^a-z0-9]+', '_', path.lower()).strip('_')}",
            "parameters": params,
            "responses": {"200": {"description": "réponse observée", "x-accesspath-fields": t.get("fields", [])}},
            "x-accesspath-score": t.get("score"),
            "x-accesspath-samples": t.get("samples"),
        }
        if t.get("query") or t.get("variables"):
            variables = {
                n: r["value"] if r["role"] == "constante" else r["start"]
                for n, r in (t.get("variables") or {}).items()
                if r["role"] in ("constante", "pagination")
            }
            example = {"operationName": t.get("operation"), "query": t.get("query"), "variables": variables}
            op["requestBody"] = {"content": {"application/json": {"schema": {"type": "object"}, "example": example}}}
        item[method] = op
    return {
        "openapi": OPENAPI_VERSION,
        "info": {
            "title": f"{spec['site']} — inféré par accesspath (mode fantôme)",
            "version": "0.1.0",
            "description": "Inféré d'une session de navigateur (HAR) : à vérifier avant tout usage.",
        },
        "paths": paths,
    }


def save_openapi(spec: dict) -> Path:
    out = SAP_DIR / spec["site"] / "openapi.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(to_openapi(spec), indent=2, ensure_ascii=False), encoding="utf-8")
    return out
