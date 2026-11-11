"""Direct network probes: TCP connect, QUIC liveness, TLS handshake.

Everything here uses plain sockets created by this process, so no proxy can
ever be involved.
"""

from __future__ import annotations

import asyncio
import errno
import hashlib
import json
import os
import random
import socket
import ssl
import time
from dataclasses import dataclass

from .results import Stage

_UNREACHABLE = {errno.EHOSTUNREACH, errno.ENETUNREACH, errno.ENETDOWN, errno.EHOSTDOWN}


def _ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)


def _classify_oserror(exc: OSError) -> tuple[str, str]:
    if isinstance(exc, ConnectionRefusedError) or exc.errno == errno.ECONNREFUSED:
        return "tcp_refused", "ECONNREFUSED"
    if isinstance(exc, ConnectionResetError) or exc.errno == errno.ECONNRESET:
        return "tcp_reset", "ECONNRESET"
    if exc.errno in _UNREACHABLE:
        return "net_unreachable", errno.errorcode.get(exc.errno, str(exc.errno))
    if exc.errno == errno.ETIMEDOUT:
        return "tcp_timeout", "ETIMEDOUT"
    return "tcp_error", errno.errorcode.get(exc.errno or 0, exc.__class__.__name__)


# ── TCP ─────────────────────────────────────────────────────────────────────

async def tcp_connect(ip: str, port: int, timeout: float) -> Stage:
    started = time.monotonic()
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
    except asyncio.TimeoutError:
        return Stage("tcp", False, "tcp_timeout", f"{timeout:g} с", _ms(started), ip)
    except OSError as exc:
        code, detail = _classify_oserror(exc)
        return Stage("tcp", False, code, detail, _ms(started), ip)
    elapsed = _ms(started)
    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), 1)
    except (asyncio.TimeoutError, OSError):
        pass
    return Stage("tcp", True, "ok", "", elapsed, ip)


async def tcp_probe(ip: str, port: int, timeout: float, attempts: int = 2, pause: float = 1.0) -> Stage:
    """TCP connect with in-check retries, so one lost SYN is not a failure."""
    stage = await tcp_connect(ip, port, timeout)
    for _ in range(max(0, attempts - 1)):
        if stage.ok:
            break
        await asyncio.sleep(pause)
        stage = await tcp_connect(ip, port, timeout)
    return stage


# ── QUIC (UDP) ──────────────────────────────────────────────────────────────

def _quic_probe_packet() -> bytes:
    """Long-header packet with a reserved version: forces Version Negotiation (RFC 9000 §6)."""
    dcid, scid = os.urandom(8), os.urandom(8)
    packet = bytes([0xC0 | (os.urandom(1)[0] & 0x3F)]) + bytes.fromhex("1a2a3a4a")
    packet += bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid
    return packet + os.urandom(1200 - len(packet))


class _UdpProtocol(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self.future: asyncio.Future = asyncio.get_running_loop().create_future()

    def datagram_received(self, data: bytes, addr) -> None:  # noqa: ANN001
        if not self.future.done():
            self.future.set_result(data)

    def error_received(self, exc: Exception) -> None:
        if not self.future.done():
            self.future.set_exception(exc)


async def quic_probe(ip: str, port: int, timeout: float, attempts: int = 3) -> Stage:
    """Stateless liveness probe of a QUIC endpoint (Hysteria2 without obfuscation).

    Any datagram in reply proves the service is alive. Silence is ambiguous for
    obfuscated protocols, which the caller must take into account.
    """
    started = time.monotonic()
    loop = asyncio.get_running_loop()
    try:
        transport, protocol = await loop.create_datagram_endpoint(_UdpProtocol, remote_addr=(ip, port))
    except OSError as exc:
        code, detail = _classify_oserror(exc)
        return Stage("quic", False, "net_unreachable" if code == "net_unreachable" else "udp_no_reply",
                     detail, _ms(started), ip)
    try:
        per_try = timeout / attempts
        for _ in range(attempts):
            transport.sendto(_quic_probe_packet())
            try:
                data = await asyncio.wait_for(asyncio.shield(protocol.future), per_try)
            except asyncio.TimeoutError:
                continue
            except ConnectionRefusedError:
                return Stage("quic", False, "udp_unreachable", "ICMP port unreachable", _ms(started), ip)
            except OSError as exc:
                code, detail = _classify_oserror(exc)
                return Stage("quic", False, "net_unreachable" if code == "net_unreachable" else "udp_no_reply",
                             detail, _ms(started), ip)
            kind = "version negotiation" if len(data) > 6 and data[1:5] == b"\0\0\0\0" else "ответ получен"
            return Stage("quic", True, "ok", kind, _ms(started), ip)
        return Stage("quic", False, "udp_no_reply", f"{attempts} датаграммы без ответа", _ms(started), ip)
    finally:
        transport.close()


# ── TLS ─────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class Fragment:
    """Client-side ClientHello fragmentation (Xray ``finalmask``/``fragment``)."""
    length: tuple[int, int]
    interval_ms: tuple[int, int]
    first: int = 1
    last: int = 1


def _range(value, default: tuple[int, int]) -> tuple[int, int]:  # noqa: ANN001
    try:
        low, _, high = str(value).partition("-")
        low_i = int(low)
        high_i = int(high) if high else low_i
        return (min(low_i, high_i), max(low_i, high_i))
    except (TypeError, ValueError):
        return default


def parse_fragment(fm: str | dict | None) -> Fragment | None:
    """Extract TCP fragmentation settings from an Xray ``finalmask`` object."""
    if not fm:
        return None
    try:
        data = json.loads(fm) if isinstance(fm, str) else fm
        for mask in data.get("tcp") or []:
            if mask.get("type") != "fragment":
                continue
            settings = mask.get("settings") or {}
            packets = str(settings.get("packets", "tlshello"))
            first, last = (1, 1) if packets == "tlshello" else _range(packets, (1, 1))
            length = _range(settings.get("length"), (10, 20))
            return Fragment((max(1, length[0]), max(1, length[1])),
                            _range(settings.get("interval"), (10, 20)), max(1, first), max(1, last))
    except (ValueError, AttributeError, TypeError):
        return None
    return None


def _tls_context(alpn: list[str] | None) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE   # reachability probe; authenticity is not the question here
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    if alpn:
        try:
            context.set_alpn_protocols(alpn)
        except (ssl.SSLError, NotImplementedError):
            pass
    return context


async def _send(writer: asyncio.StreamWriter, data: bytes, fragment: Fragment | None) -> None:
    if fragment is None:
        writer.write(data)
        await writer.drain()
        return
    offset = 0
    while offset < len(data):
        size = random.randint(*fragment.length)
        writer.write(data[offset:offset + size])
        await writer.drain()
        offset += size
        if offset < len(data):
            await asyncio.sleep(random.randint(*fragment.interval_ms) / 1000)


async def tls_probe(ip: str, port: int, sni: str, timeout: float, alpn: list[str] | None = None,
                    fragment: Fragment | None = None) -> Stage:
    """TLS handshake with the configured SNI.

    For REALITY the server relays an ordinary ClientHello to its cover site, so
    a completed handshake proves the path and the listening service. With
    ``fragment`` the ClientHello is split the way the real client does it.
    The leaf certificate hash is returned in ``detail`` as ``sha256=<hex>``.
    """
    started = time.monotonic()
    deadline = started + timeout
    writer = None
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
        sock = writer.get_extra_info("socket")
        if sock is not None:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        hostname = sni if sni and not _is_ip_literal(sni) else None
        tls = _tls_context(alpn).wrap_bio(incoming, outgoing, server_hostname=hostname)
        flight = 0
        while True:
            try:
                tls.do_handshake()
                done = True
            except ssl.SSLWantReadError:
                done = False
            pending = outgoing.read()
            if pending:
                flight += 1
                use = fragment if fragment and fragment.first <= flight <= fragment.last else None
                await asyncio.wait_for(_send(writer, pending, use), max(0.1, deadline - time.monotonic()))
            if done:
                break
            chunk = await asyncio.wait_for(reader.read(16384), max(0.1, deadline - time.monotonic()))
            if not chunk:
                return Stage("tls", False, "tls_eof", "соединение закрыто сервером", _ms(started), ip)
            incoming.write(chunk)
        certificate = tls.getpeercert(binary_form=True)
        digest = hashlib.sha256(certificate).hexdigest() if certificate else ""
        detail = f"{tls.version()} alpn={tls.selected_alpn_protocol() or '-'} sha256={digest}"
        return Stage("tls", True, "ok", detail, _ms(started), ip)
    except asyncio.TimeoutError:
        return Stage("tls", False, "tls_timeout", f"{timeout:g} с", _ms(started), ip)
    except ConnectionResetError:
        return Stage("tls", False, "tls_reset", "ECONNRESET", _ms(started), ip)
    except ssl.SSLError as exc:
        return Stage("tls", False, "tls_error", (exc.reason or str(exc))[:120], _ms(started), ip)
    except OSError as exc:
        code, detail = _classify_oserror(exc)
        return Stage("tls", False, "tls_reset" if code == "tcp_reset" else "tls_error", detail, _ms(started), ip)
    finally:
        if writer is not None:
            writer.close()


def _is_ip_literal(value: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET6 if ":" in value else socket.AF_INET, value)
        return True
    except OSError:
        return False


def cert_digest(stage: Stage | None) -> str:
    """SHA-256 of the leaf certificate recorded by :func:`tls_probe`."""
    if stage is None or not stage.ok:
        return ""
    _, _, digest = stage.detail.partition("sha256=")
    return digest.strip()
