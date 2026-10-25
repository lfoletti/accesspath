"""Préférences d'usage qu'un site déclare aux machines.

- AIPREF (IETF) : en-tête `Content-Usage` (dictionnaire structuré, ex. `train-ai=n`) et
  règle `Content-Usage:` dans robots.txt, avec un chemin facultatif ;
- TDMRep (W3C) : `tdm-reservation` et `tdm-policy`, en en-tête, en métadonnée HTML ou
  dans `/.well-known/tdmrep.json` ;
- `/llms.txt` : page d'entrée pour les modèles de langue ;
- robots d'IA connus : ce que robots.txt leur permet à la racine ;
- accès payant : HTTP 402 ou en-tête `crawler-price` (Pay Per Crawl).

Les déclarations sont rapportées, pas interprétées : leur portée juridique dépend du pays
et de l'usage (`--purpose`).
"""

from __future__ import annotations

import json
import re
from urllib.robotparser import RobotFileParser

# Robots d'IA les plus répandus (entraînement, recherche, agents à la demande).
AI_CRAWLERS = (
    "GPTBot",
    "OAI-SearchBot",
    "ChatGPT-User",
    "ClaudeBot",
    "Claude-SearchBot",
    "Claude-User",
    "anthropic-ai",
    "CCBot",
    "Google-Extended",
    "PerplexityBot",
    "Perplexity-User",
    "Bytespider",
    "Applebot-Extended",
    "Meta-ExternalAgent",
    "Amazonbot",
)
TDM_FIELDS = ("tdm-reservation", "tdm-policy")
WELL_KNOWN_TDMREP = "/.well-known/tdmrep.json"
LLMS_TXT = "/llms.txt"

_META = re.compile(r"<meta\b[^>]*>", re.I)
_ATTR = re.compile(r"""\b(name|content)\s*=\s*["']([^"']*)["']""", re.I)
_CONTENT_USAGE_LINE = re.compile(r"^\s*content-usage\s*:\s*(.+?)\s*$", re.I)


def parse_content_usage(value: str | None) -> dict[str, str]:
    """`train-ai=n, search=y` → {"train-ai": "n", "search": "y"} ; paramètres (`;q=1`) ignorés."""
    out: dict[str, str] = {}
    for item in (value or "").split(","):
        key, _, val = item.split(";", 1)[0].partition("=")
        if key.strip() and val.strip():
            out[key.strip().lower()] = val.strip()
    return out


def robots_content_usage(robots_txt: str) -> list[dict]:
    """Règles `Content-Usage:` de robots.txt, avec leur chemin (« / » par défaut)."""
    rules = []
    for line in robots_txt.splitlines():
        m = _CONTENT_USAGE_LINE.match(line.split("#", 1)[0])
        if not m:
            continue
        value = m.group(1)
        path = "/"
        if value.startswith("/"):
            path, _, value = value.partition(" ")
        prefs = parse_content_usage(value)
        if prefs:
            rules.append({"path": path, "prefs": prefs})
    return rules


def ai_crawler_rules(robots_txt: str) -> dict[str, str]:
    """Par robot d'IA : « bloqué » (racine interdite), « partiel » (une partie interdite),
    « permis »."""
    rp = RobotFileParser()
    rp.parse(robots_txt.splitlines())
    groups = _disallows_by_agent(robots_txt)
    out = {}
    for bot in AI_CRAWLERS:
        if not rp.can_fetch(bot, "/"):
            out[bot] = "bloqué"
        elif groups.get(bot.lower(), groups.get("*", [])):
            out[bot] = "partiel"
        else:
            out[bot] = "permis"
    return out


def _disallows_by_agent(robots_txt: str) -> dict[str, list[str]]:
    """Chemins Disallow non vides, par agent (en minuscules)."""
    groups: dict[str, list[str]] = {}
    agents: list[str] = []
    in_rules = False
    for raw in robots_txt.splitlines():
        line = raw.split("#", 1)[0].strip()
        key, _, val = line.partition(":")
        key, val = key.strip().lower(), val.strip()
        if key == "user-agent":
            if in_rules:
                agents, in_rules = [], False
            agents.append(val.lower())
            groups.setdefault(val.lower(), [])
        elif key in ("allow", "disallow"):
            in_rules = True
            if key == "disallow" and val:
                for a in agents:
                    groups[a].append(val)
    return groups


def tdm_from_html(html: str) -> dict[str, str]:
    out = {}
    for tag in _META.findall(html or ""):
        attrs = {k.lower(): v for k, v in _ATTR.findall(tag)}
        if attrs.get("name", "").lower() in TDM_FIELDS and "content" in attrs:
            out[attrs["name"].lower()] = attrs["content"]
    return out


def tdm_from_headers(headers: dict) -> dict[str, str]:
    return {k.lower(): v for k, v in headers.items() if k.lower() in TDM_FIELDS}


def pay_per_crawl(status: int, headers: dict) -> dict | None:
    """Accès payant annoncé : HTTP 402 ou en-têtes `crawler-*` de Pay Per Crawl."""
    price = {k.lower(): v for k, v in headers.items() if k.lower() in ("crawler-price", "crawler-charged")}
    if status != 402 and not price:
        return None
    return {"status": status, **price}


def parse_tdmrep_json(body: bytes) -> list | None:
    try:
        data = json.loads(body.decode("utf-8", "replace"))
    except ValueError:
        return None
    return data if isinstance(data, list) else None


def llms_title(body: bytes) -> str:
    for line in body.decode("utf-8", "replace").splitlines():
        if line.startswith("# "):
            return line[2:].strip()[:120]
    return ""
