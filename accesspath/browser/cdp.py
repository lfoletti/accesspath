"""Lance Chrome en remote-debugging et attache Playwright via CDP.

Détails importants :
- L'URL CDP utilise 127.0.0.1 (pas localhost) : sur macOS récents, localhost
  résout en ::1 (IPv6), mais Chrome ne bind QUE IPv4 sur --remote-debugging-port.
- La détection de readiness poll `/json/version` jusqu'à 15 s au lieu d'un
  sleep fixe — ça supprime les faux-positifs sur machines lentes.
- Le path Chrome est configurable via env var `ACCESSPATH_CHROME_PATH`.
- Port CDP : `port` explicite, sinon `ACCESSPATH_CDP_PORT`, sinon un port libre
  tiré par l'OS (jamais 9222 fixe : un autre process local pourrait s'y
  attacher ou être tué par `kill_on_port`). Le port retenu est exposé en
  `popen.cdp_port`.
- stderr de Chrome va dans un fichier créé par `tempfile.mkstemp` (nom
  imprévisible, mode 0600) dans `ACCESSPATH_CHROME_LOG_DIR` ou le dossier
  temporaire de l'utilisateur ; chemin exposé en `popen.chrome_log_path`.
"""

from __future__ import annotations

import asyncio
import os
import signal as _signal
import socket
import subprocess
import tempfile
from pathlib import Path

CHROME_MACOS_DEFAULT = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
CHROME_PATH = os.environ.get("ACCESSPATH_CHROME_PATH", CHROME_MACOS_DEFAULT)
CDP_HOST = "127.0.0.1"  # pas "localhost" — évite le bug IPv6 ::1


def cdp_url(port: int) -> str:
    return f"http://{CDP_HOST}:{port}"


async def kill_on_port(port: int) -> None:
    """Tue tout process écoutant sur ce port (idempotent)."""
    try:
        result = subprocess.run(["lsof", "-ti", f"tcp:{port}"], capture_output=True, text=True, timeout=5)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return
    pids = [p for p in result.stdout.strip().split() if p]
    for pid in pids:
        try:
            os.kill(int(pid), _signal.SIGTERM)
        except (ProcessLookupError, ValueError):
            pass
    if pids:
        await asyncio.sleep(1.0)


async def _wait_for_cdp(port: int, timeout: float = 15.0) -> bool:
    """Poll http://127.0.0.1:port/json/version jusqu'à réponse 200."""
    import socket

    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        # Check TCP port ouvert d'abord
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.3)
            try:
                s.connect((CDP_HOST, port))
                return True
            except (TimeoutError, ConnectionRefusedError, OSError):
                pass
        await asyncio.sleep(0.2)
    return False


def free_port() -> int:
    """Port TCP libre sur 127.0.0.1, choisi par l'OS."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((CDP_HOST, 0))
        return s.getsockname()[1]


def resolve_port(port: int | None = None) -> int:
    """`port` explicite > `ACCESSPATH_CDP_PORT` > port libre aléatoire."""
    if port is not None:
        return port
    env = os.environ.get("ACCESSPATH_CDP_PORT")
    if env:
        return int(env)
    return free_port()


def _open_chrome_log(port: int) -> tuple[int, Path]:
    log_dir = os.environ.get("ACCESSPATH_CHROME_LOG_DIR") or None
    if log_dir:
        Path(log_dir).mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f"chrome_{port}_", suffix=".log", dir=log_dir)
    return fd, Path(name)


async def launch_chrome(
    profile_dir: Path,
    port: int | None = None,
    *,
    headless: bool = False,
    timeout: float = 15.0,
    url: str | None = None,
    detached: bool = False,
    window_size: str | None = None,
) -> subprocess.Popen:
    """Lance Chrome avec CDP activé. Poll le port jusqu'à readiness.
    Lève `RuntimeError` si Chrome ne bind pas le port dans `timeout` secondes.
    Sans `port`, voir `resolve_port` ; le port retenu est `popen.cdp_port`.
    `url` : page ouverte au lancement. `detached` : Chrome dans sa propre session,
    il survit à la commande qui l'a lancé (geste piloté depuis la conversation).
    """
    port = resolve_port(port)
    if not Path(CHROME_PATH).exists():
        raise FileNotFoundError(f"Chrome introuvable : {CHROME_PATH}. Override via env var ACCESSPATH_CHROME_PATH.")
    profile_dir.mkdir(parents=True, exist_ok=True)
    await kill_on_port(port)

    cmd = [
        CHROME_PATH,
        f"--remote-debugging-port={port}",
        f"--user-data-dir={profile_dir}",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-background-networking",
        # Trousseau macOS inaccessible sans session graphique (SSH, launchd) : sans ce
        # drapeau, aucun cookie n'est enregistré. Même chiffrement avec ou sans session.
        "--use-mock-keychain",
    ]
    if headless:
        cmd.append("--headless=new")
    if window_size:
        cmd.append(f"--window-size={window_size}")
    if url:
        cmd.append(url)

    # Log stderr pour debug (fichier neuf à chaque launch, mode 0600)
    log_fd, log_path = _open_chrome_log(port)
    try:
        extra = {"start_new_session": True} if detached else {}
        popen = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=log_fd, **extra)
    finally:
        os.close(log_fd)  # le fils garde sa copie du descripteur
    popen.cdp_port = port  # type: ignore[attr-defined]
    popen.chrome_log_path = log_path  # type: ignore[attr-defined]

    if not await _wait_for_cdp(port, timeout=timeout):
        # Chrome n'a pas bindé le port — tue et remonte l'erreur
        try:
            popen.terminate()
        except Exception:
            pass
        raise RuntimeError(f"Chrome n'a pas ouvert le port CDP {port} après {timeout}s. Voir {log_path} pour stderr.")
    return popen
