"""The check pipeline for one server: DNS → TCP/QUIC → TLS → end-to-end.

Verdict rules:

* the end-to-end check, when it can run, is authoritative: it is the only one
  that exercises the VPN protocol the way a client does;
* without it the lower layers decide, and anything they cannot prove either
  way is reported as "no verdict" rather than guessed;
* problems of the monitor's own DNS never become a server failure.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
from dataclasses import dataclass, field
from typing import Any, Callable

from . import dns as dnsmod
from .dns import DnsResolver
from .e2e import E2EChecker
from .net import cert_digest, parse_fragment, quic_probe, tcp_probe, tls_probe
from .results import CheckResult, Stage
from .xraycfg import Unsupported, build_outbound

log = logging.getLogger(__name__)


@dataclass
class Target:
    id: int
    name: str
    address: str
    port: int
    l4: str
    protocol: str
    transport: str
    security: str
    sni: str = ""
    host: str = ""
    path: str = ""
    params: dict[str, Any] = field(default_factory=dict)
    extra_addresses: list[str] = field(default_factory=list)
    cached_ips: list[str] = field(default_factory=list)
    secret: Callable[[], dict[str, Any]] | None = None
    e2e: bool = True
    data_probe: bool = False

    def as_server(self) -> dict[str, Any]:
        return {
            "address": self.address, "port": self.port, "protocol": self.protocol,
            "transport": self.transport, "security": self.security, "sni": self.sni,
            "host": self.host, "path": self.path, "params": self.params,
        }


@dataclass
class Timeouts:
    dns: float = 4.0
    tcp: float = 5.0
    tls: float = 8.0
    udp: float = 4.0
    e2e: float = 12.0


@dataclass
class _IpProbe:
    ip: str
    l2: Stage
    l3: Stage | None = None

    @property
    def passed(self) -> bool:
        return bool(self.l2.ok) and (self.l3 is None or bool(self.l3.ok))


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _default_alpn(transport: str) -> list[str]:
    if transport in ("grpc", "xhttp", "h2"):
        return ["h2"]
    if transport in ("ws", "httpupgrade"):
        return ["http/1.1"]
    return ["h2", "http/1.1"]


class Checker:
    def __init__(self, resolver: DnsResolver, e2e: E2EChecker, ipv6: bool = False, max_ips: int = 4,
                 retry_pause: float = 1.0, tcp_attempts: int = 2) -> None:
        self.resolver = resolver
        self.e2e = e2e
        self.ipv6 = ipv6
        self.max_ips = max_ips
        self.retry_pause = retry_pause
        self.tcp_attempts = tcp_attempts

    # ── layers ──────────────────────────────────────────────────────────────

    async def _probe_ip(self, target: Target, ip: str, timeouts: Timeouts) -> _IpProbe:
        if target.l4 == "udp":
            return _IpProbe(ip, await quic_probe(ip, target.port, timeouts.udp))
        probe = _IpProbe(ip, await tcp_probe(ip, target.port, timeouts.tcp, attempts=self.tcp_attempts,
                                             pause=self.retry_pause))
        if probe.l2.ok and target.security in ("tls", "reality"):
            sni = target.sni or ("" if _is_ip(target.address) else target.address)
            alpn = [item.strip() for item in str(target.params.get("alpn") or "").split(",") if item.strip()]
            fragment = parse_fragment(target.params.get("fm"))
            probe.l3 = await tls_probe(ip, target.port, sni, timeouts.tls, alpn or _default_alpn(target.transport), fragment)
            if not probe.l3.ok:
                await asyncio.sleep(self.retry_pause)
                probe.l3 = await tls_probe(ip, target.port, sni, timeouts.tls, alpn or _default_alpn(target.transport), fragment)
        return probe

    def _family_ok(self, ip: str) -> bool:
        return self.ipv6 or ":" not in ip

    async def _run_e2e(self, target: Target, candidates: list[_IpProbe], timeouts: Timeouts) -> Stage:
        try:
            secret = target.secret() if target.secret else {}
        except Exception as exc:  # noqa: BLE001 - a broken secret must not crash the check
            return Stage("e2e", None, "e2e_unavailable", f"не удалось прочитать параметры сервера: {exc.__class__.__name__}")
        stage = Stage("e2e", None, "e2e_unavailable", "нет адреса для проверки")
        for probe in candidates[:2]:
            try:
                outbound = build_outbound(target.as_server(), secret, ip=probe.ip, cert_sha256=cert_digest(probe.l3))
            except Unsupported as exc:
                return Stage("e2e", None, "e2e_unavailable", str(exc), None, probe.ip)
            except Exception as exc:  # noqa: BLE001
                log.warning("cannot build xray outbound for server %s: %s", target.id, exc.__class__.__name__)
                return Stage("e2e", None, "e2e_unavailable", "не удалось собрать конфигурацию Xray", None, probe.ip)
            stage = await self.e2e.check(outbound, timeouts.e2e, target.data_probe, probe.ip,
                                         quick=not probe.passed)
            if stage.ok is not False:
                break
        return stage

    # ── main entry ──────────────────────────────────────────────────────────

    async def check(self, target: Target, timeouts: Timeouts, use_e2e: bool = True) -> CheckResult:
        result = CheckResult(ok=None)
        addresses = list(dict.fromkeys([target.address, *target.extra_addresses]))
        ip_list: list[str] = []
        dns_negative: list[Stage] = []
        dns_unavailable = False
        used_cache = False

        for address in addresses:
            if _is_ip(address):
                ip_list.append(address)
                continue
            answer = await self.resolver.resolve(address, timeouts.dns)
            if answer.status == dnsmod.OK:
                stage = Stage("dns", True, "ok", ("резервный резолвер; " + answer.detail) if answer.degraded else "",
                              answer.ms, address)
                if answer.degraded:
                    result.notes.append("системный DNS-резолвер не ответил, использован резервный")
                ip_list.extend(answer.ips)
            elif answer.status in (dnsmod.NXDOMAIN, dnsmod.NODATA):
                stage = Stage("dns", False, f"dns_{answer.status}", answer.detail, answer.ms, address)
                dns_negative.append(stage)
            else:
                stage = Stage("dns", None, "dns_unavailable", answer.detail, answer.ms, address)
                dns_unavailable = True
                if address == target.address and target.cached_ips:
                    ip_list.extend(target.cached_ips)
                    used_cache = True
                    result.notes.append("DNS недоступен, проверены последние известные IP-адреса")
            result.stages.append(stage)

        ip_list = [ip for ip in dict.fromkeys(ip_list) if self._family_ok(ip)][: self.max_ips]
        result.ips = ip_list

        if not ip_list:
            if dns_negative and not dns_unavailable:
                first = dns_negative[0]
                result.ok, result.code, result.stage = False, first.code, "dns"
            else:
                result.ok, result.code, result.stage = None, "dns_unavailable", "dns"
            return result

        probes = list(await asyncio.gather(*(self._probe_ip(target, ip, timeouts) for ip in ip_list)))
        for probe in probes:
            result.stages.append(probe.l2)
            if probe.l3 is not None:
                result.stages.append(probe.l3)
        l2_ok = [probe for probe in probes if probe.l2.ok]
        passed = [probe for probe in probes if probe.passed]
        result.good_ips = [probe.ip for probe in l2_ok]

        e2e_stage: Stage | None = None
        want_e2e = use_e2e and target.e2e
        if want_e2e:
            if target.l4 == "udp":
                candidates = l2_ok + [probe for probe in probes if not probe.l2.ok]
            else:
                candidates = passed + [probe for probe in l2_ok if not probe.passed]
            if candidates:
                e2e_stage = await self._run_e2e(target, candidates, timeouts)
                result.stages.append(e2e_stage)
                result.e2e_ran = e2e_stage.ok is not None
                result.data_probe = target.data_probe and e2e_stage.ok is not None
                if e2e_stage.ok is None:
                    result.notes.append(f"сквозная проверка не выполнена: {e2e_stage.detail}")

        if e2e_stage is not None and e2e_stage.ok is True:
            result.ok, result.code = True, "ok"
            result.latency_ms = e2e_stage.ms
            if e2e_stage.target and e2e_stage.target not in result.good_ips:
                result.good_ips.append(e2e_stage.target)
            tested = next((probe for probe in probes if probe.ip == e2e_stage.target), None)
            if tested is not None and tested.l3 is not None and not tested.l3.ok:
                result.notes.append("упрощённая TLS-проба не прошла, но туннель работает")
            elif tested is not None and not tested.l2.ok:
                result.notes.append("сервер не ответил на QUIC-пробу, но туннель работает")
        elif e2e_stage is not None and e2e_stage.ok is False:
            result.ok = False
            failed_l3 = next((probe.l3 for probe in probes if probe.l3 is not None and not probe.l3.ok), None)
            failed_l2 = next((probe.l2 for probe in probes if not probe.l2.ok), None)
            if target.l4 == "tcp" and not passed and failed_l3 is not None:
                result.code, result.stage = failed_l3.code, "tls"
            elif target.l4 == "udp" and not l2_ok and failed_l2 is not None:
                result.code, result.stage = failed_l2.code, "quic"
            else:
                result.code, result.stage = e2e_stage.code, "e2e"
        else:
            self._verdict_without_e2e(target, probes, l2_ok, passed, result)

        if used_cache and result.ok is False:
            # DNS is broken on our side and the cached addresses fail: the server may simply have moved.
            result.ok, result.code, result.stage = None, "dns_unavailable", "dns"
        if result.ok:
            self._partial(result, probes, dns_negative, bool(e2e_stage is not None and e2e_stage.ok))
            if result.latency_ms is None:
                first = passed[0] if passed else (l2_ok[0] if l2_ok else None)
                if first is not None:
                    result.latency_ms = (first.l3.ms if first.l3 is not None else first.l2.ms)
        return result

    @staticmethod
    def _verdict_without_e2e(target: Target, probes: list[_IpProbe], l2_ok: list[_IpProbe],
                             passed: list[_IpProbe], result: CheckResult) -> None:
        if target.l4 == "udp":
            obfuscated = target.transport == "kcp" or bool(target.params.get("obfs"))
            if l2_ok:
                result.ok, result.code = True, "ok"
            elif obfuscated:
                result.ok, result.code, result.stage = None, "udp_unverifiable", "quic"
            else:
                result.ok, result.code, result.stage = False, probes[0].l2.code, "quic"
            return
        if passed:
            result.ok, result.code = True, "ok"
        elif l2_ok:
            stage = next(probe.l3 for probe in l2_ok if probe.l3 is not None)
            result.ok, result.code, result.stage = False, stage.code, "tls"
        else:
            result.ok, result.code, result.stage = False, probes[0].l2.code, "tcp"

    @staticmethod
    def _partial(result: CheckResult, probes: list[_IpProbe], dns_negative: list[Stage], e2e_ok: bool) -> None:
        bad = [f"{probe.ip} ({probe.l2.code})" for probe in probes if not probe.l2.ok and probe.ip not in result.good_ips]
        if not e2e_ok:
            bad += [f"{probe.ip} ({probe.l3.code})" for probe in probes
                    if probe.l2.ok and probe.l3 is not None and not probe.l3.ok]
        bad += [f"{stage.target} ({stage.code})" for stage in dns_negative]
        if bad:
            result.partial = True
            result.partial_note = "не отвечают " + ", ".join(bad[:4])
