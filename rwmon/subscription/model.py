"""Normalised description of a proxy server extracted from a subscription."""

from __future__ import annotations

import hashlib
import ipaddress
import os
import re
from dataclasses import dataclass, field
from typing import Any

PROXY_PROTOCOLS = ("vless", "trojan", "shadowsocks", "hysteria2", "vmess")
UDP_TRANSPORTS = ("kcp", "hysteria", "quic")
ZERO_UUID = "00000000-0000-0000-0000-000000000000"
# Loopback addresses in a subscription are informational stubs, never real servers.
# The test suite turns this off (also via RWMON_ALLOW_LOOPBACK=1) to run against a local stand.
LOOPBACK_IS_PLACEHOLDER = os.environ.get("RWMON_ALLOW_LOOPBACK") != "1"

_PROTOCOL_ALIASES = {
    "ss": "shadowsocks", "shadowsocks": "shadowsocks",
    "hysteria": "hysteria2", "hysteria2": "hysteria2", "hy2": "hysteria2",
    "vless": "vless", "trojan": "trojan", "vmess": "vmess",
}
_TRANSPORT_ALIASES = {
    "": "tcp", "tcp": "tcp", "raw": "tcp", "none": "tcp",
    "ws": "ws", "websocket": "ws",
    "grpc": "grpc", "gun": "grpc",
    "httpupgrade": "httpupgrade", "http-upgrade": "httpupgrade",
    "xhttp": "xhttp", "splithttp": "xhttp",
    "kcp": "kcp", "mkcp": "kcp",
    "h2": "h2", "http": "h2",
    "quic": "quic", "hysteria": "hysteria", "hysteria2": "hysteria",
}
_SECURITY_ALIASES = {"": "none", "none": "none", "tls": "tls", "xtls": "tls", "reality": "reality"}
_DEDUP_SUFFIX_RE = re.compile(r"\s*\^~\d+~\^\s*$")


def norm_protocol(value: Any) -> str:
    return _PROTOCOL_ALIASES.get(str(value or "").strip().lower(), "")


def norm_transport(value: Any) -> str:
    key = str(value or "").strip().lower()
    return _TRANSPORT_ALIASES.get(key, key)


def norm_security(value: Any) -> str:
    key = str(value or "").strip().lower()
    return _SECURITY_ALIASES.get(key, key)


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def norm_host(value: Any) -> str:
    """Lower-case host without brackets or trailing dot; IPs in canonical form."""
    host = str(value or "").strip().strip("[]").rstrip(".").lower()
    try:
        return ipaddress.ip_address(host).compressed
    except ValueError:
        return host


def norm_name(value: Any) -> str:
    """Remark without Remnawave's duplicate suffix (`` ^~2~^``) and extra spaces."""
    name = _DEDUP_SUFFIX_RE.sub("", str(value or ""))
    return " ".join(name.split())


@dataclass
class ServerConfig:
    name: str
    address: str
    port: int
    protocol: str
    transport: str = "tcp"
    security: str = "none"
    sni: str = ""
    host: str = ""
    path: str = ""
    params: dict[str, Any] = field(default_factory=dict)   # non-secret extras
    secrets: dict[str, Any] = field(default_factory=dict)  # credentials and keys
    outbound: dict[str, Any] | None = None                 # original Xray outbound, if known
    source: str = ""
    name_rank: int = 1                                      # lower wins when picking the name
    aliases: list[str] = field(default_factory=list)
    outbound_rank: int = 99                                 # lower = outbound from a simpler config
    group_name: str = ""                                    # remark of a multi-server (balancer) config

    def __post_init__(self) -> None:
        self.name = norm_name(self.name)
        self.address = norm_host(self.address)
        self.port = int(self.port)
        self.protocol = norm_protocol(self.protocol)
        self.transport = norm_transport(self.transport)
        self.security = norm_security(self.security)
        self.sni = norm_host(self.sni)
        self.host = str(self.host or "").strip().lower()
        self.path = str(self.path or "").strip()
        if self.protocol == "hysteria2":
            self.transport = "hysteria"
            if self.security == "none":
                self.security = "tls"
        if not self.name:
            self.name = f"{self.address}:{self.port}"

    @property
    def l4(self) -> str:
        return "udp" if self.transport in UDP_TRANSPORTS else "tcp"

    @property
    def node_key(self) -> str:
        return self.address

    @property
    def endpoint(self) -> str:
        host = f"[{self.address}]" if ":" in self.address else self.address
        return f"{host}:{self.port}"

    @property
    def fingerprint(self) -> str:
        """Identity of a technical configuration (names and credentials excluded)."""
        key = "|".join((
            self.address, str(self.port), self.protocol, self.transport,
            self.security, self.sni, self.host, self.path,
        ))
        return hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]

    @property
    def soft_key(self) -> tuple:
        """Used to recognise the same host when its address or SNI is randomised."""
        return (self.port, self.protocol, self.transport, self.security, self.name)

    @property
    def is_placeholder(self) -> bool:
        """Remnawave's informational pseudo-hosts (expired, HWID, no hosts...)."""
        if self.address in ("", "0", "localhost"):
            return LOOPBACK_IS_PLACEHOLDER or self.address != "localhost"
        try:
            ip = ipaddress.ip_address(self.address)
        except ValueError:
            ip = None
        if ip is not None and (ip.is_unspecified or (ip.is_loopback and LOOPBACK_IS_PLACEHOLDER)):
            return True
        if not 1 < self.port <= 65535:
            return True
        return self.secrets.get("id") == ZERO_UUID

    @property
    def kind_label(self) -> str:
        return describe_kind(self.protocol, self.transport, self.security)

    def public_params(self) -> dict[str, Any]:
        return {key: value for key, value in self.params.items() if value not in ("", None, [], {})}


_PROTOCOL_LABELS = {
    "vless": "VLESS", "trojan": "Trojan", "shadowsocks": "Shadowsocks",
    "hysteria2": "Hysteria2", "vmess": "VMess",
}
_TRANSPORT_LABELS = {
    "tcp": "TCP", "ws": "WebSocket", "grpc": "gRPC", "httpupgrade": "HTTPUpgrade",
    "xhttp": "XHTTP", "kcp": "mKCP (UDP)", "h2": "HTTP/2", "quic": "QUIC (UDP)",
    "hysteria": "QUIC (UDP)",
}
_SECURITY_LABELS = {"none": "без TLS", "tls": "TLS", "reality": "REALITY"}


def describe_kind(protocol: str, transport: str, security: str) -> str:
    return " · ".join((
        _PROTOCOL_LABELS.get(protocol, protocol.upper()),
        _TRANSPORT_LABELS.get(transport, transport.upper()),
        _SECURITY_LABELS.get(security, security.upper()),
    ))


RANK_NORMAL = 1   # a link or a single-server config
RANK_GROUP = 4    # the entry that represents a multi-server (balancer) config
RANK_MEMBER = 5   # a server found only inside a multi-server config


def merge_servers(groups: list[list[ServerConfig]]) -> list[ServerConfig]:
    """Union of several parsed lists, de-duplicated by fingerprint.

    The first occurrence keeps its position. The best-ranked name becomes the
    display name and the remaining meaningful names become aliases. Names of
    balancer configs ("auto-select") are demoted: such an entry points at an
    ordinary server that normally has its own name elsewhere in the list.
    """
    group_names = {item.group_name for group in groups for item in group if item.group_name}
    merged: dict[str, ServerConfig] = {}
    names: dict[str, list[tuple[int, int, str]]] = {}
    order = 0
    for group in groups:
        for item in group:
            order += 1
            rank = item.name_rank
            if rank == RANK_NORMAL and item.name in group_names:
                rank = RANK_GROUP
            key = item.fingerprint
            names.setdefault(key, []).append((rank, order, item.name))
            current = merged.get(key)
            if current is None:
                merged[key] = item
                continue
            if item.outbound is not None and item.outbound_rank < current.outbound_rank:
                current.outbound, current.outbound_rank = item.outbound, item.outbound_rank
            for name, value in item.secrets.items():
                current.secrets.setdefault(name, value)
            for name, value in item.params.items():
                if current.params.get(name) in ("", None, [], {}):
                    current.params[name] = value
    for key, item in merged.items():
        ranked = sorted(names[key])
        item.name_rank, _, item.name = ranked[0]
        seen = {item.name}
        item.aliases = []
        for rank, _, name in ranked[1:]:
            if rank < RANK_MEMBER and name and name not in seen:
                seen.add(name)
                item.aliases.append(name)
    return list(merged.values())
