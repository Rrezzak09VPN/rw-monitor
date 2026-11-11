"""DNS resolution with independent resolvers and precise failure classes.

A resolver that does not answer is a problem of the monitor, not of the
server. A negative answer counts only when it is confirmed.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
import time
from dataclasses import dataclass, field

import dns.asyncresolver
import dns.exception
import dns.resolver

log = logging.getLogger(__name__)

OK = "ok"
NXDOMAIN = "nxdomain"
NODATA = "nodata"
UNAVAILABLE = "unavailable"


@dataclass
class DnsResult:
    status: str
    ips: list[str] = field(default_factory=list)
    detail: str = ""
    degraded: bool = False   # the system resolver failed, a fallback resolver answered
    ms: int = 0


def detect_ipv6() -> bool:
    """True when the host has a global IPv6 route (no packets are sent)."""
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
            sock.connect(("2001:4860:4860::8888", 53))
            return ipaddress.ip_address(sock.getsockname()[0]).is_global
    except OSError:
        return False


class DnsResolver:
    def __init__(self, fallback_servers: list[str], want_v4: bool = True, want_v6: bool = False) -> None:
        self.want_v4 = want_v4
        self.want_v6 = want_v6
        self._resolvers: list[tuple[str, dns.asyncresolver.Resolver]] = []
        try:
            system = dns.asyncresolver.Resolver()
            system.cache = None
            self._resolvers.append(("system", system))
        except dns.resolver.NoResolverConfiguration:
            log.warning("system DNS configuration not found; only fallback resolvers will be used")
        for server in fallback_servers:
            resolver = dns.asyncresolver.Resolver(configure=False)
            resolver.nameservers = [server]
            resolver.cache = None
            self._resolvers.append((server, resolver))
        if not self._resolvers:
            raise RuntimeError("нет ни одного DNS-резолвера: проверьте /etc/resolv.conf и DNS_RESOLVERS")

    @property
    def names(self) -> list[str]:
        return [name for name, _ in self._resolvers]

    async def _query_type(self, resolver: dns.asyncresolver.Resolver, name: str, rdtype: str,
                          timeout: float) -> tuple[str, list[str], str]:
        try:
            answer = await resolver.resolve(
                name, rdtype, lifetime=timeout, raise_on_no_answer=False, search=False)
        except dns.resolver.NXDOMAIN:
            return NXDOMAIN, [], "NXDOMAIN"
        except dns.resolver.NoNameservers:
            return UNAVAILABLE, [], "SERVFAIL/REFUSED"
        except dns.exception.Timeout:
            return UNAVAILABLE, [], "таймаут"
        except (dns.exception.DNSException, OSError) as exc:
            return UNAVAILABLE, [], exc.__class__.__name__
        ips = [item.address for item in answer.rrset] if answer.rrset is not None else []
        return (OK, ips, "") if ips else (NODATA, [], "нет записей")

    async def _query(self, resolver: dns.asyncresolver.Resolver, name: str,
                     timeout: float) -> tuple[str, list[str], str]:
        types = (["A"] if self.want_v4 else []) + (["AAAA"] if self.want_v6 else [])
        answers = await asyncio.gather(*(self._query_type(resolver, name, t, timeout) for t in types))
        ips = [ip for _, found, _ in answers for ip in found]
        if ips:
            return OK, ips, ""
        statuses = {status for status, _, _ in answers}
        if statuses == {NXDOMAIN}:
            return NXDOMAIN, [], "NXDOMAIN"
        if UNAVAILABLE in statuses:
            return UNAVAILABLE, [], "; ".join(dict.fromkeys(d for _, _, d in answers if d))
        return NODATA, [], "нет A/AAAA-записей"

    async def resolve(self, name: str, timeout: float = 4.0) -> DnsResult:
        started = time.monotonic()
        outcomes: list[tuple[str, str, str]] = []
        for index, (label, resolver) in enumerate(self._resolvers):
            status, ips, detail = await self._query(resolver, name, timeout)
            if status == OK:
                note = ""
                if index > 0:
                    note = "; ".join(f"{n}: {d}" for n, _, d in outcomes)
                return DnsResult(OK, list(dict.fromkeys(ips)), note, degraded=index > 0,
                                 ms=int((time.monotonic() - started) * 1000))
            outcomes.append((label, status, detail))
        elapsed = int((time.monotonic() - started) * 1000)
        detail = "; ".join(f"{label}: {text}" for label, _, text in outcomes)
        definitive = [status for _, status, _ in outcomes if status in (NXDOMAIN, NODATA)]
        # A negative answer is trusted when two resolvers agree, or all configured ones do.
        if definitive and (len(definitive) >= 2 or len(definitive) == len(outcomes)):
            status = NXDOMAIN if all(item == NXDOMAIN for item in definitive) else NODATA
            return DnsResult(status, [], detail, ms=elapsed)
        return DnsResult(UNAVAILABLE, [], detail, ms=elapsed)

    async def system_ok(self, name: str, timeout: float = 4.0) -> tuple[bool, str]:
        """Health probe of the primary (system) resolver only."""
        label, resolver = self._resolvers[0]
        status, _, detail = await self._query(resolver, name, timeout)
        return status == OK, f"{label}: {detail or status}"
