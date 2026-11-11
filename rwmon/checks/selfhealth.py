"""Self-check of the monitor's own connectivity.

Before server failures are trusted, the monitor proves that it can reach
well-known hosts itself. If it cannot, results are discarded ("no verdict")
and the owner is told about the monitor's problem instead of server failures.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import time
from dataclasses import dataclass, field

from . import dns as dnsmod
from .dns import DnsResolver
from .net import tcp_connect

log = logging.getLogger(__name__)


@dataclass
class Health:
    checked_at: float = 0.0
    foreign_ok: bool = True
    ru_ok: bool = True
    dns_ok: bool = True
    details: list[str] = field(default_factory=list)

    @property
    def network_ok(self) -> bool:
        """Results of server checks can be trusted."""
        return self.foreign_ok

    @property
    def problem(self) -> str:
        if not self.foreign_ok and not self.ru_ok:
            return "у сервера мониторинга нет связи с интернетом"
        if not self.foreign_ok:
            return "с сервера мониторинга недоступны зарубежные контрольные узлы"
        if not self.dns_ok:
            return "системный DNS-резолвер сервера мониторинга не отвечает"
        return ""

    @property
    def kind(self) -> str:
        if not self.foreign_ok:
            return "network"
        if not self.dns_ok:
            return "dns"
        return ""


def parse_targets(raw: list[str]) -> list[tuple[str, int]]:
    targets = []
    for item in raw:
        host, _, port = item.strip().rpartition(":")
        if host and port.isdigit():
            targets.append((host.strip("[]"), int(port)))
    return targets


class SelfHealth:
    def __init__(self, resolver: DnsResolver, ru: list[str], foreign: list[str], dns_name: str,
                 timeout: float = 4.0, cache_seconds: float = 15.0, retry_pause: float = 2.0) -> None:
        self.resolver = resolver
        self.ru = parse_targets(ru)
        self.foreign = parse_targets(foreign)
        self.dns_name = dns_name
        self.timeout = timeout
        self.cache_seconds = cache_seconds
        self.retry_pause = retry_pause
        self.last = Health()
        self._lock = asyncio.Lock()

    async def _target_ok(self, host: str, port: int) -> bool:
        ips = [host]
        try:
            ipaddress.ip_address(host)
        except ValueError:
            answer = await self.resolver.resolve(host, self.timeout)
            if answer.status != dnsmod.OK:
                return False
            ips = [ip for ip in answer.ips if ":" not in ip][:2] or answer.ips[:1]
        for ip in ips:
            if (await tcp_connect(ip, port, self.timeout)).ok:
                return True
        return False

    async def _group_ok(self, targets: list[tuple[str, int]]) -> tuple[bool, int]:
        """A group is fine when at least one of its targets answers."""
        if not targets:
            return True, 0
        results = await asyncio.gather(*(self._target_ok(host, port) for host, port in targets))
        return any(results), sum(results)

    async def check(self, force: bool = False) -> Health:
        async with self._lock:
            if not force and time.monotonic() - self.last.checked_at < self.cache_seconds and self.last.checked_at:
                return self.last
            health = await self._check_once()
            if not health.foreign_ok or not health.dns_ok:
                await asyncio.sleep(self.retry_pause)   # one retry: a blip must not freeze monitoring
                health = await self._check_once()
            self.last = health
            return health

    async def _check_once(self) -> Health:
        (foreign_ok, foreign_n), (ru_ok, ru_n), (dns_ok, dns_detail) = await asyncio.gather(
            self._group_ok(self.foreign), self._group_ok(self.ru),
            self.resolver.system_ok(self.dns_name, self.timeout) if self.dns_name else _true(),
        )
        details = [
            f"зарубежные узлы: {foreign_n}/{len(self.foreign)}",
            f"российские узлы: {ru_n}/{len(self.ru)}",
            f"DNS: {'ок' if dns_ok else dns_detail}",
        ]
        return Health(time.monotonic(), foreign_ok, ru_ok, dns_ok, details)


async def _true() -> tuple[bool, str]:
    return True, ""
