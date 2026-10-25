"""Accès HTTP partagé du moteur SAP (probe, inspect, rehearse).

Une seule porte vers le réseau pour les sondes : garde de destination (pas
d'adresse interne, à chaque requête et à chaque redirection), lecture en flux
bornée sur le fil, décompression bornée (gzip, deflate, br), réponse rendue
sous une forme simple (`Response`). Le corps n'est jamais décodé par httpx : on lit les octets
bruts et on les décompresse nous-mêmes, avec une limite de sortie.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json as _json
import os
import re
import socket
import time
import zlib
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

import httpx

MiB = 1 << 20
MAX_WIRE_BYTES = 10 * MiB  # octets reçus sur le fil, par réponse
MAX_DECODED_BYTES = 50 * MiB  # octets après décompression, par réponse
_BR_STEP = 64 * 1024
REQUEST_DEADLINE_S = 30.0  # échéance totale d'une requête, lecture du corps comprise


class ResponseTooLarge(Exception):
    """Réponse trop volumineuse (sur le fil ou après décompression)."""


class TooManyRedirects(Exception):
    """Plus de `MAX_REDIRECTS` redirections."""


class BlockedDestination(Exception):
    """Destination refusée : schéma autre que http/https ou adresse non publique."""


# ── Garde de destination ───────────────────────────────────────────────────
# Levée explicitement par `--allow-private` (CLI) ou ACCESSPATH_ALLOW_PRIVATE=1
# (tests sur 127.0.0.1). Par défaut, toute adresse interne est refusée.
_ALLOW_PRIVATE = False


def set_allow_private(value: bool) -> None:
    global _ALLOW_PRIVATE
    _ALLOW_PRIVATE = bool(value)


def private_allowed() -> bool:
    return _ALLOW_PRIVATE or os.environ.get("ACCESSPATH_ALLOW_PRIVATE") == "1"


def _ip_is_public(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Vrai seulement pour une adresse routable publique (unicast global)."""
    # ipaddress classe déjà comme non globales les formes IPv6 qui embarquent
    # une IPv4 (::ffff:0:0/96, 6to4 2002::/16) : pas de dépliage nécessaire.
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
        or not ip.is_global
    )


def _split_target(url: str) -> tuple[str, int]:
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise BlockedDestination(f"schéma refusé {scheme!r} : {url}")
    host = parts.hostname
    if not host:
        raise BlockedDestination(f"URL sans hôte : {url}")
    return host, parts.port or (443 if scheme == "https" else 80)


def _check_addresses(host: str, infos) -> None:
    addrs = {info[4][0] for info in infos}
    if not addrs:
        raise BlockedDestination(f"{host} ne se résout pas")
    for a in addrs:
        ip = ipaddress.ip_address(a.split("%", 1)[0])
        if not _ip_is_public(ip):
            raise BlockedDestination(
                f"destination interne refusée : {host} → {ip} (utiliser --allow-private pour l'autoriser)"
            )


def assert_public(url: str) -> None:
    """Lève BlockedDestination si `url` n'est pas http(s) vers une adresse publique."""
    host, port = _split_target(url)
    if private_allowed():
        return
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise BlockedDestination(f"{host} ne se résout pas : {e}") from None
    _check_addresses(host, infos)


async def assert_public_async(url: str) -> None:
    host, port = _split_target(url)
    if private_allowed():
        return
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as e:
        raise BlockedDestination(f"{host} ne se résout pas : {e}") from None
    _check_addresses(host, infos)


async def _guard_request_async(request: httpx.Request) -> None:
    await assert_public_async(str(request.url))


def _guard_request(request: httpx.Request) -> None:
    assert_public(str(request.url))


class DeadlineExceeded(TimeoutError):
    """Échéance totale de la requête dépassée (serveur trop lent ou goutte-à-goutte)."""


class UnsupportedEncoding(Exception):
    """Content-Encoding que le moteur n'a pas demandé et ne décode pas."""


class BoundedDecoder:
    """Décompresse en flux sans jamais produire plus de `max_out` octets."""

    def __init__(self, encoding: str, *, max_out: int = MAX_DECODED_BYTES):
        enc = (encoding or "").strip().lower()
        self.encoding = enc
        self.max_out = max_out
        self.produced = 0
        self._first = True
        if enc in ("", "identity"):
            self._kind = "identity"
        elif enc in ("gzip", "x-gzip"):
            self._kind = "zlib"
            self._d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        elif enc == "deflate":
            self._kind = "deflate"
            self._d = zlib.decompressobj(zlib.MAX_WBITS)
        elif enc == "br":
            try:
                import brotli  # type: ignore
            except ImportError:
                raise UnsupportedEncoding("br reçu mais brotli absent") from None
            self._kind = "br"
            self._d = brotli.Decompressor()
        else:
            raise UnsupportedEncoding(f"Content-Encoding non pris en charge : {encoding!r}")

    def _account(self, data: bytes) -> bytes:
        self.produced += len(data)
        if self.produced > self.max_out:
            raise ResponseTooLarge(f"réponse trop volumineuse après décompression (> {self.max_out} octets)")
        return data

    def _room(self) -> int:
        # +1 pour détecter le dépassement sans le laisser grossir
        return max(self.max_out - self.produced, 0) + 1

    def _zlib_feed(self, data: bytes) -> bytes:
        out = []
        buf = data
        while True:
            chunk = self._d.decompress(buf, self._room())
            out.append(self._account(chunk))
            buf = self._d.unconsumed_tail
            if not buf:
                break
        return b"".join(out)

    def feed(self, data: bytes) -> bytes:
        if not data:
            return b""
        if self._kind == "identity":
            return self._account(data)
        if self._kind == "deflate" and self._first:
            self._first = False
            try:
                return self._zlib_feed(data)
            except zlib.error:
                # deflate « brut » (sans en-tête zlib), comme le tolèrent les navigateurs
                self._d = zlib.decompressobj(-zlib.MAX_WBITS)
                return self._zlib_feed(data)
        if self._kind in ("zlib", "deflate"):
            return self._zlib_feed(data)
        # brotli : output_buffer_limit borne chaque appel (brotli >= 1.2) ; le tampon
        # peut dépasser d'un cran la limite demandée, d'où des pas de 64 Kio.
        out = []
        step = lambda: min(self._room(), _BR_STEP)  # noqa: E731
        try:
            chunk = self._d.process(data, output_buffer_limit=step())
        except TypeError:
            raise UnsupportedEncoding("brotli trop ancien (sans output_buffer_limit) : brotli>=1.2 requis") from None
        out.append(self._account(chunk))
        # Vider la sortie en attente : appels à entrée vide tant qu'ils produisent.
        while not self._d.is_finished():
            chunk = self._d.process(b"", output_buffer_limit=step())
            out.append(self._account(chunk))
            if not chunk and self._d.can_accept_more_data():
                break
        return b"".join(out)

    def flush(self) -> bytes:
        if self._kind in ("zlib", "deflate"):
            return self._account(self._d.flush())
        return b""


_CHARSET_RE = re.compile(r"charset=[\"']?([\w.:-]+)", re.I)


@dataclass
class Response:
    """Réponse lue en entier mais bornée. Interface proche de httpx.Response."""

    status_code: int
    headers: httpx.Headers
    content: bytes
    url: str
    history: list[str] = field(default_factory=list)

    @property
    def text(self) -> str:
        m = _CHARSET_RE.search(self.headers.get("content-type", ""))
        enc = m.group(1) if m else "utf-8"
        try:
            return self.content.decode(enc, errors="replace")
        except LookupError:
            return self.content.decode("utf-8", errors="replace")

    def json(self):
        return _json.loads(self.content)


def _check_wire(n: int, max_wire: int) -> None:
    if n > max_wire:
        raise ResponseTooLarge(f"réponse trop volumineuse sur le fil (> {max_wire} octets)")


async def aget(
    client: httpx.AsyncClient,
    url: str,
    *,
    headers: dict | None = None,
    max_wire: int = MAX_WIRE_BYTES,
    max_decoded: int = MAX_DECODED_BYTES,
    total_timeout: float | None = None,
) -> Response:
    """GET asynchrone, corps lu en flux et borné, échéance totale `total_timeout`."""
    total = REQUEST_DEADLINE_S if total_timeout is None else total_timeout
    try:
        async with asyncio.timeout(total):
            async with client.stream("GET", url, headers=headers) as r:
                dec = BoundedDecoder(r.headers.get("content-encoding", ""), max_out=max_decoded)
                wire = 0
                parts: list[bytes] = []
                async for chunk in r.aiter_raw():
                    wire += len(chunk)
                    _check_wire(wire, max_wire)
                    parts.append(dec.feed(chunk))
                parts.append(dec.flush())
                return Response(
                    r.status_code,
                    r.headers,
                    b"".join(parts),
                    str(r.url),
                    [str(h.url) for h in r.history],
                )
    except TimeoutError as e:
        if isinstance(e, DeadlineExceeded):
            raise
        raise DeadlineExceeded(f"échéance de requête dépassée ({total:g} s) : {url}") from None


# ── Imitation d'un navigateur (curl_cffi) ─────────────────────────────────
IMPERSONATE_TARGET = "chrome"  # dernière empreinte Chrome connue de curl_cffi
MAX_REDIRECTS = 5
_REDIRECT_STATUSES = (301, 302, 303, 307, 308)


# Chrome annonce l'échange de clés post-quantique X25519MLKEM768 depuis la version 131.
PQ_CHROME_MIN = 131


def _resolve_target(target: str) -> str:
    """Alias curl_cffi (« chrome ») → profil précis (« chrome150 »)."""
    try:
        from curl_cffi.requests import impersonate as imp
    except ImportError:
        return target
    return getattr(imp, f"DEFAULT_{target.upper()}", target)


def impersonation_profile(target: str = IMPERSONATE_TARGET) -> dict:
    """Profil réellement imité et annonce post-quantique (None hors Chrome)."""
    resolved = _resolve_target(target)
    m = re.match(r"chrome(\d+)", resolved)
    version = int(m.group(1)) if m else None
    return {
        "target": target,
        "resolved": resolved,
        "version": version,
        "post_quantum": None if version is None else version >= PQ_CHROME_MIN,
    }


def impersonation_available() -> bool:
    try:
        import curl_cffi.requests  # noqa: F401
    except ImportError:
        return False
    return True


async def aimpersonate_get(
    url: str,
    *,
    headers: dict | None = None,
    impersonate: str = IMPERSONATE_TARGET,
    max_decoded: int = MAX_DECODED_BYTES,
    total_timeout: float | None = None,
) -> Response:
    """GET asynchrone qui imite l'empreinte TLS et HTTP/2 d'un navigateur (curl_cffi).

    Même garde que les clients httpx : chaque adresse, redirections comprises, passe
    par `assert_public_async` avant de partir ; les redirections sont donc suivies
    ici, `MAX_REDIRECTS` au plus. curl décompresse lui-même : le corps est borné
    après décompression, fragment par fragment. Échéance totale `total_timeout`.
    """
    from curl_cffi.requests import AsyncSession

    total = REQUEST_DEADLINE_S if total_timeout is None else total_timeout
    history: list[str] = []
    try:
        async with asyncio.timeout(total), AsyncSession(impersonate=impersonate) as session:
            for _ in range(MAX_REDIRECTS + 1):
                await assert_public_async(url)
                r = await session.request("GET", url, headers=headers, allow_redirects=False, stream=True)
                try:
                    location = r.headers.get("location")
                    if r.status_code in _REDIRECT_STATUSES and location:
                        history.append(url)
                        url = urljoin(url, location)
                        continue
                    parts: list[bytes] = []
                    size = 0
                    async for chunk in r.aiter_content():
                        size += len(chunk)
                        if size > max_decoded:
                            raise ResponseTooLarge(f"réponse décompressée > {max_decoded} octets : {url}")
                        parts.append(chunk)
                    return Response(
                        r.status_code, httpx.Headers(list(r.headers.items())), b"".join(parts), url, history
                    )
                finally:
                    await r.aclose()
    except TimeoutError as e:
        if isinstance(e, DeadlineExceeded):
            raise
        raise DeadlineExceeded(f"échéance de requête dépassée ({total:g} s) : {url}") from None
    raise TooManyRedirects(f"plus de {MAX_REDIRECTS} redirections : {url}")


def get(
    client: httpx.Client,
    url: str,
    *,
    headers: dict | None = None,
    max_wire: int = MAX_WIRE_BYTES,
    max_decoded: int = MAX_DECODED_BYTES,
    total_timeout: float | None = None,
) -> Response:
    """GET synchrone, corps lu en flux et borné, échéance totale `total_timeout`.

    L'échéance est vérifiée à chaque fragment reçu ; l'attente d'un fragment
    reste bornée par le délai par opération du client.
    """
    return request(
        client, "GET", url, headers=headers, max_wire=max_wire, max_decoded=max_decoded, total_timeout=total_timeout
    )


def request(
    client: httpx.Client,
    method: str,
    url: str,
    *,
    headers: dict | None = None,
    content: bytes | str | None = None,
    max_wire: int = MAX_WIRE_BYTES,
    max_decoded: int = MAX_DECODED_BYTES,
    total_timeout: float | None = None,
) -> Response:
    """Comme `get`, pour toute méthode, avec un corps envoyé facultatif."""
    total = REQUEST_DEADLINE_S if total_timeout is None else total_timeout
    deadline = time.monotonic() + total
    with client.stream(method, url, headers=headers, content=content) as r:
        dec = BoundedDecoder(r.headers.get("content-encoding", ""), max_out=max_decoded)
        wire = 0
        parts: list[bytes] = []
        for chunk in r.iter_raw():
            if time.monotonic() > deadline:
                raise DeadlineExceeded(f"échéance de requête dépassée ({total:g} s) : {url}")
            wire += len(chunk)
            _check_wire(wire, max_wire)
            parts.append(dec.feed(chunk))
        parts.append(dec.flush())
        return Response(
            r.status_code,
            r.headers,
            b"".join(parts),
            str(r.url),
            [str(h.url) for h in r.history],
        )


def async_client(*, timeout: float = 10.0, follow_redirects: bool = True) -> httpx.AsyncClient:
    """Client asynchrone gardé : chaque requête, redirections comprises, passe
    par `assert_public_async` avant de partir."""
    return httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=follow_redirects,
        event_hooks={"request": [_guard_request_async]},
    )


def client(*, timeout: float = 10.0, follow_redirects: bool = True) -> httpx.Client:
    """Client synchrone gardé (même règle que `async_client`)."""
    return httpx.Client(
        timeout=timeout,
        follow_redirects=follow_redirects,
        event_hooks={"request": [_guard_request]},
    )
