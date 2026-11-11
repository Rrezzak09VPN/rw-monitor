"""Subscription format detection and parsing.

Supported: share links (plain or base64), Xray JSON, Mihomo/Clash/Stash YAML,
sing-box JSON. The format is detected from the body, never from Content-Type.
"""

from __future__ import annotations

import base64
import binascii
import copy
import json
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, unquote

import yaml

from .model import (
    PROXY_PROTOCOLS,
    RANK_MEMBER,
    RANK_NORMAL,
    ServerConfig,
    norm_protocol,
    norm_transport,
)

try:
    _YamlLoader = yaml.CSafeLoader
except AttributeError:  # pragma: no cover - pure-python fallback
    _YamlLoader = yaml.SafeLoader

LINK_SCHEMES = ("vless", "trojan", "ss", "vmess", "hysteria2", "hy2")
_LINK_RE = re.compile(r"(?im)^\s*(vless|trojan|ss|vmess|hysteria2|hy2)://")
_ANY_LINK_RE = re.compile(r"(?im)^\s*[a-z][a-z0-9+.-]{1,15}://\S")

# Outbound/proxy types that are not servers and are skipped silently.
_XRAY_SERVICE = {"freedom", "blackhole", "dns", "loopback", "block", "direct"}
_SINGBOX_SERVICE = {"direct", "block", "dns", "selector", "urltest"}


@dataclass
class ParseResult:
    format: str  # links | xray_json | mihomo | singbox | html | encrypted | unsupported | empty | unknown
    servers: list[ServerConfig] = field(default_factory=list)
    placeholders: list[str] = field(default_factory=list)  # remarks of informational pseudo-hosts
    skipped: Counter = field(default_factory=Counter)        # reason -> count
    is_base64: bool = False

    @property
    def has_servers(self) -> bool:
        return bool(self.servers)

    @property
    def format_label(self) -> str:
        labels = {
            "links": "список ссылок (base64)" if self.is_base64 else "список ссылок",
            "xray_json": "Xray JSON", "mihomo": "Mihomo / Clash YAML", "singbox": "sing-box JSON",
            "html": "HTML-страница", "encrypted": "зашифрованный ответ",
            "unsupported": "неподдерживаемый формат", "empty": "пустой ответ", "unknown": "не распознан",
        }
        return labels.get(self.format, self.format)

    def add(self, server: ServerConfig | None, reason: str = "") -> None:
        if server is None:
            if reason:
                self.skipped[reason] += 1
        elif server.is_placeholder:
            self.placeholders.append(server.name)
        else:
            self.servers.append(server)


class _Skip(Exception):
    """Entry cannot be turned into a server; message is the reason."""


# ── helpers ─────────────────────────────────────────────────────────────────

def _b64decode(text: str) -> bytes | None:
    compact = "".join(text.split())
    if not compact or not re.fullmatch(r"[A-Za-z0-9+/_=-]+", compact):
        return None
    compact = compact.replace("-", "+").replace("_", "/").rstrip("=")
    compact += "=" * (-len(compact) % 4)
    try:
        return base64.b64decode(compact, validate=False)
    except (binascii.Error, ValueError):
        return None


def _first(value: Any) -> str:
    """Scalar or first element of a list, as a string."""
    if isinstance(value, (list, tuple)):
        value = value[0] if value else ""
    return "" if value is None else str(value)


def _csv(value: Any) -> str:
    if isinstance(value, (list, tuple)):
        return ",".join(str(item) for item in value)
    return "" if value is None else str(value)


def _port(value: Any) -> int:
    """First port of ``443``, ``"443"`` or ``"443,5000-6000"``."""
    match = re.match(r"\s*(\d{1,5})", str(value))
    if not match:
        raise _Skip("некорректный порт")
    return int(match.group(1))


def _truthy(value: Any) -> bool:
    return str(value).strip().lower() in ("1", "true", "yes")


def _clean(mapping: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in mapping.items() if value not in ("", None, [], {}, False)}


# ── share links ─────────────────────────────────────────────────────────────

def _split_hostport(text: str) -> tuple[str, Any]:
    text = text.strip().rstrip("/")
    if text.startswith("["):
        host, _, rest = text[1:].partition("]")
        return host, rest.lstrip(":")
    host, sep, port = text.rpartition(":")
    if not sep:
        raise _Skip("в ссылке нет порта")
    return host, port


def parse_link(line: str) -> ServerConfig:
    """Parse one share link. Raises ``_Skip`` when it is not a usable server."""
    scheme, sep, rest = line.strip().partition("://")
    scheme = scheme.lower()
    if not sep or scheme not in LINK_SCHEMES:
        raise _Skip(f"схема {scheme or '?'}:// не поддерживается")
    rest, _, fragment = rest.partition("#")
    # Remnawave appends "?serverDescription=..." after the remark for some clients.
    name = unquote(fragment.split("?serverDescription=", 1)[0])
    if scheme == "vmess":
        return _parse_vmess(rest, name)
    main, _, query = rest.partition("?")
    query = dict(parse_qsl(query, keep_blank_values=True))
    if scheme == "ss":
        return _parse_ss(main, query, name)
    userinfo, sep, hostport = main.rpartition("@")
    if not sep:
        raise _Skip("в ссылке нет учётных данных")
    host, port = _split_hostport(hostport)
    credential = unquote(userinfo)
    if scheme in ("hysteria2", "hy2"):
        return ServerConfig(
            name=name, address=host, port=_port(port), protocol="hysteria2", transport="hysteria",
            security="tls", sni=query.get("sni", ""),
            params=_clean({
                "alpn": query.get("alpn", ""), "obfs": query.get("obfs", ""),
                "insecure": _truthy(query.get("insecure", "")), "fm": query.get("fm", ""),
            }),
            secrets=_clean({
                "auth": credential, "obfs_password": query.get("obfs-password", ""),
                "pin": query.get("pinSHA256", ""),
            }),
            source="links",
        )
    transport = norm_transport(query.get("type", "tcp"))
    security = query.get("security", "tls" if scheme == "trojan" else "none")
    path = query.get("serviceName", "") if transport == "grpc" else query.get("path", "")
    host_header = query.get("authority", "") if transport == "grpc" else query.get("host", "")
    secrets = {"id": credential} if scheme == "vless" else {"password": credential}
    secrets.update({
        "pbk": query.get("pbk", ""), "sid": query.get("sid", ""), "spx": query.get("spx", ""),
        "pqv": query.get("pqv", ""), "pin": query.get("pcs", ""),
    })
    params = {
        "alpn": query.get("alpn", ""), "fp": query.get("fp", ""), "flow": query.get("flow", ""),
        "encryption": query.get("encryption", ""), "header_type": query.get("headerType", ""),
        "mode": query.get("mode", ""), "fm": query.get("fm", ""), "extra": query.get("extra", ""),
        "insecure": _truthy(query.get("allowInsecure", query.get("insecure", ""))),
    }
    return ServerConfig(
        name=name, address=host, port=_port(port), protocol=scheme, transport=transport,
        security=security, sni=query.get("sni", query.get("peer", "")), host=host_header, path=path,
        params=_clean(params), secrets=_clean(secrets), source="links",
    )


def _parse_ss(main: str, query: dict[str, str], name: str) -> ServerConfig:
    main = main.rstrip("/")
    if "@" not in main:  # legacy: base64(method:password@host:port)
        decoded = _b64decode(main)
        if decoded is None:
            raise _Skip("некорректная ссылка ss://")
        main = decoded.decode("utf-8", "replace")
        userinfo, _, hostport = main.rpartition("@")
    else:
        userinfo, _, hostport = main.rpartition("@")
        decoded = _b64decode(unquote(userinfo))
        if decoded is not None and b":" in decoded:
            userinfo = decoded.decode("utf-8", "replace")
        else:
            userinfo = unquote(userinfo)
    method, sep, password = userinfo.partition(":")
    if not sep:
        raise _Skip("некорректные учётные данные ss://")
    host, port = _split_hostport(hostport)
    return ServerConfig(
        name=name, address=host, port=_port(port), protocol="shadowsocks", transport="tcp",
        security="none", params=_clean({"plugin": query.get("plugin", "")}),
        secrets={"method": method, "password": password}, source="links",
    )


def _parse_vmess(rest: str, name: str) -> ServerConfig:
    decoded = _b64decode(rest.partition("?")[0])
    try:
        data = json.loads(decoded.decode("utf-8")) if decoded else None
    except (ValueError, UnicodeDecodeError):
        data = None
    if not isinstance(data, dict):
        raise _Skip("некорректная ссылка vmess://")
    transport = norm_transport(data.get("net", "tcp"))
    return ServerConfig(
        name=name or str(data.get("ps", "")), address=str(data.get("add", "")),
        port=_port(data.get("port", "")), protocol="vmess", transport=transport,
        security="tls" if str(data.get("tls", "")).lower() == "tls" else "none",
        sni=str(data.get("sni", "")), host=str(data.get("host", "")), path=str(data.get("path", "")),
        params=_clean({"alpn": str(data.get("alpn", "")), "fp": str(data.get("fp", "")),
                       "header_type": str(data.get("type", ""))}),
        secrets=_clean({"id": str(data.get("id", "")), "alter_id": str(data.get("aid", "0")),
                        "cipher": str(data.get("scy", "auto"))}),
        source="links",
    )


def parse_links(text: str, is_base64: bool = False) -> ParseResult:
    result = ParseResult("links", is_base64=is_base64)
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "://" not in line:
            continue
        try:
            result.add(parse_link(line))
        except _Skip as exc:
            result.add(None, str(exc))
        except Exception:  # noqa: BLE001 - one bad line must not break the import
            result.add(None, "ошибка разбора ссылки")
    return result


# ── Xray JSON ───────────────────────────────────────────────────────────────

def parse_xray_outbound(outbound: dict[str, Any], name: str, rank: int = RANK_NORMAL,
                        group_name: str = "") -> ServerConfig:
    protocol = norm_protocol(outbound.get("protocol"))
    if protocol not in PROXY_PROTOCOLS:
        raise _Skip(f"протокол {outbound.get('protocol')} не поддерживается")
    settings = outbound.get("settings") or {}
    stream = outbound.get("streamSettings") or {}
    node = settings
    for key in ("vnext", "servers"):
        if isinstance(settings.get(key), list) and settings[key]:
            node = settings[key][0]
            break
    user = (node.get("users") or [{}])[0] if isinstance(node.get("users"), list) else node
    transport = norm_transport(stream.get("network") or stream.get("method") or "tcp")
    security = stream.get("security") or "none"
    tls = stream.get("tlsSettings") or {}
    reality = stream.get("realitySettings") or {}
    sec = reality if security == "reality" else tls
    host = path = ""
    extra: dict[str, Any] = {}
    if transport == "ws":
        opts = stream.get("wsSettings") or {}
        path, host = opts.get("path", ""), opts.get("host") or (opts.get("headers") or {}).get("Host", "")
    elif transport == "httpupgrade":
        opts = stream.get("httpupgradeSettings") or {}
        path, host = opts.get("path", ""), opts.get("host") or (opts.get("headers") or {}).get("Host", "")
    elif transport == "grpc":
        opts = stream.get("grpcSettings") or {}
        path, host = opts.get("serviceName", ""), opts.get("authority", "")
        extra["mode"] = "multi" if opts.get("multiMode") else ""
    elif transport == "xhttp":
        opts = stream.get("xhttpSettings") or stream.get("splithttpSettings") or {}
        path, host = opts.get("path", ""), opts.get("host", "")
        extra["mode"] = opts.get("mode", "")
    elif transport == "h2":
        opts = stream.get("httpSettings") or {}
        path, host = opts.get("path", ""), _first(opts.get("host"))
    elif transport == "tcp":
        header = (stream.get("tcpSettings") or stream.get("rawSettings") or {}).get("header") or {}
        if header.get("type") == "http":
            request = header.get("request") or {}
            path = _first(request.get("path"))
            host = _first((request.get("headers") or {}).get("Host"))
            extra["header_type"] = "http"
    finalmask = stream.get("finalmask") or {}
    obfs = ""
    obfs_password = ""
    for mask in finalmask.get("udp") or []:
        if isinstance(mask, dict) and mask.get("type") == "salamander":
            obfs = "salamander"
            obfs_password = (mask.get("settings") or {}).get("password", "")
    hysteria = stream.get("hysteriaSettings") or {}
    params = {
        "alpn": _csv(sec.get("alpn")), "fp": sec.get("fingerprint", ""), "flow": user.get("flow", ""),
        "encryption": user.get("encryption", ""), "obfs": obfs,
        "insecure": bool(tls.get("allowInsecure")),
        "fm": json.dumps(finalmask, separators=(",", ":")) if finalmask else "",
        **extra,
    }
    secrets = {
        "id": user.get("id", ""), "password": node.get("password", ""), "method": node.get("method", ""),
        "auth": hysteria.get("auth", ""), "obfs_password": obfs_password,
        "pbk": reality.get("publicKey", ""), "sid": reality.get("shortId", ""),
        "spx": reality.get("spiderX", ""), "pin": _csv(tls.get("pinnedPeerCertSha256")),
    }
    return ServerConfig(
        name=name, address=str(node.get("address", "")), port=_port(node.get("port", "")),
        protocol=protocol, transport=transport, security=security,
        sni=sec.get("serverName", "") or "", host=host or "", path=path or "",
        params=_clean(params), secrets=_clean(secrets), outbound=copy.deepcopy(outbound),
        source="xray_json", name_rank=rank, outbound_rank=rank, group_name=group_name,
    )


def parse_xray_json(data: Any) -> ParseResult:
    result = ParseResult("xray_json")
    configs = data if isinstance(data, list) else [data]
    for config in configs:
        if not isinstance(config, dict):
            result.add(None, "элемент не является конфигурацией")
            continue
        outbounds = [ob for ob in config.get("outbounds") or [] if isinstance(ob, dict)]
        proxies = [ob for ob in outbounds if str(ob.get("protocol", "")).lower() not in _XRAY_SERVICE]
        remarks = str(config.get("remarks") or "")
        multi = len(proxies) > 1
        for outbound in proxies:
            tag = str(outbound.get("tag") or "")
            name = f"{remarks} · {tag}" if multi else (remarks or tag)
            try:
                result.add(parse_xray_outbound(
                    outbound, name, RANK_MEMBER if multi else RANK_NORMAL, remarks if multi else "",
                ))
            except _Skip as exc:
                result.add(None, str(exc))
            except Exception:  # noqa: BLE001
                result.add(None, "ошибка разбора outbound")
    return result


# ── Mihomo / Clash / Stash ──────────────────────────────────────────────────

def parse_mihomo_proxy(proxy: dict[str, Any]) -> ServerConfig:
    protocol = norm_protocol(proxy.get("type"))
    if protocol not in PROXY_PROTOCOLS:
        raise _Skip(f"тип {proxy.get('type')} не поддерживается")
    network = str(proxy.get("network") or "tcp").lower()
    ws = proxy.get("ws-opts") or {}
    reality = proxy.get("reality-opts") or {}
    host = path = ""
    extra: dict[str, Any] = {}
    if network == "ws":
        path, host = ws.get("path", ""), (ws.get("headers") or {}).get("Host", "")
        if ws.get("v2ray-http-upgrade"):
            network = "httpupgrade"
    elif network == "grpc":
        path = (proxy.get("grpc-opts") or {}).get("grpc-service-name", "")
    elif network in ("http", "h2"):
        opts = proxy.get("h2-opts") or proxy.get("http-opts") or {}
        path, host = _first(opts.get("path")), _first(opts.get("host") or (opts.get("headers") or {}).get("Host"))
    elif network == "xhttp":
        opts = proxy.get("xhttp-opts") or {}
        path, host, extra["mode"] = opts.get("path", ""), opts.get("host", ""), opts.get("mode", "")
    if reality:
        security = "reality"
    elif protocol in ("trojan", "hysteria2") or proxy.get("tls"):
        security = "tls"
    else:
        security = "none"
    params = {
        "alpn": _csv(proxy.get("alpn")), "fp": proxy.get("client-fingerprint", ""),
        "flow": proxy.get("flow", ""), "obfs": proxy.get("obfs", "") if protocol == "hysteria2" else "",
        "insecure": bool(proxy.get("skip-cert-verify")), **extra,
    }
    secrets = {
        "id": proxy.get("uuid", ""), "method": proxy.get("cipher", "") if protocol == "shadowsocks" else "",
        "pbk": reality.get("public-key", ""), "sid": reality.get("short-id", ""),
        "obfs_password": proxy.get("obfs-password", ""), "pin": proxy.get("fingerprint", ""),
    }
    password = str(proxy.get("password", "") or "")
    secrets["auth" if protocol == "hysteria2" else "password"] = password
    return ServerConfig(
        name=str(proxy.get("name") or ""), address=str(proxy.get("server") or ""),
        port=_port(proxy.get("port", "")), protocol=protocol, transport=network, security=security,
        sni=str(proxy.get("servername") or proxy.get("sni") or ""), host=host or "", path=path or "",
        params=_clean(params), secrets=_clean(secrets), source="mihomo",
    )


def parse_mihomo(data: dict[str, Any]) -> ParseResult:
    result = ParseResult("mihomo")
    for proxy in data.get("proxies") or []:
        if not isinstance(proxy, dict):
            result.add(None, "элемент proxies не является объектом")
            continue
        try:
            result.add(parse_mihomo_proxy(proxy))
        except _Skip as exc:
            result.add(None, str(exc))
        except Exception:  # noqa: BLE001
            result.add(None, "ошибка разбора proxy")
    return result


# ── sing-box ────────────────────────────────────────────────────────────────

def parse_singbox_outbound(outbound: dict[str, Any]) -> ServerConfig:
    protocol = norm_protocol(outbound.get("type"))
    if protocol not in PROXY_PROTOCOLS:
        raise _Skip(f"тип {outbound.get('type')} не поддерживается")
    tls = outbound.get("tls") or {}
    reality = tls.get("reality") or {}
    transport = outbound.get("transport") or {}
    ttype = str(transport.get("type") or "tcp").lower()
    path = transport.get("service_name", "") if ttype == "grpc" else transport.get("path", "")
    host = _first(transport.get("host")) or (transport.get("headers") or {}).get("Host", "")
    if reality.get("enabled"):
        security = "reality"
    elif tls.get("enabled") or protocol == "hysteria2":
        security = "tls"
    else:
        security = "none"
    obfs = outbound.get("obfs") or {}
    if isinstance(obfs, str):
        obfs = {"type": obfs, "password": outbound.get("obfs_password", "")}
    params = {
        "alpn": _csv(tls.get("alpn")), "fp": (tls.get("utls") or {}).get("fingerprint", ""),
        "flow": outbound.get("flow", ""), "obfs": obfs.get("type", ""),
        "insecure": bool(tls.get("insecure")),
    }
    secrets = {
        "id": outbound.get("uuid", ""), "method": outbound.get("method", ""),
        "pbk": reality.get("public_key", ""), "sid": reality.get("short_id", ""),
        "obfs_password": obfs.get("password", ""),
    }
    password = str(outbound.get("password", "") or "")
    secrets["auth" if protocol == "hysteria2" else "password"] = password
    return ServerConfig(
        name=str(outbound.get("tag") or ""), address=str(outbound.get("server") or ""),
        port=_port(outbound.get("server_port", "")), protocol=protocol, transport=ttype,
        security=security, sni=str(tls.get("server_name") or ""), host=host or "", path=path or "",
        params=_clean(params), secrets=_clean(secrets), source="singbox",
    )


def parse_singbox(data: dict[str, Any]) -> ParseResult:
    result = ParseResult("singbox")
    for outbound in data.get("outbounds") or []:
        if not isinstance(outbound, dict):
            continue
        if str(outbound.get("type", "")).lower() in _SINGBOX_SERVICE:
            continue
        try:
            result.add(parse_singbox_outbound(outbound))
        except _Skip as exc:
            result.add(None, str(exc))
        except Exception:  # noqa: BLE001
            result.add(None, "ошибка разбора outbound")
    return result


# ── detection ───────────────────────────────────────────────────────────────

def _looks_like_singbox(data: dict[str, Any]) -> bool:
    outbounds = data.get("outbounds")
    if not isinstance(outbounds, list):
        return False
    return any(isinstance(ob, dict) and "type" in ob and "protocol" not in ob for ob in outbounds)


def _from_json(data: Any) -> ParseResult | None:
    if isinstance(data, list):
        if not data:
            return ParseResult("empty")
        if all(isinstance(item, dict) for item in data):
            return parse_xray_json(data)
        return None
    if isinstance(data, dict):
        if _looks_like_singbox(data):
            return parse_singbox(data)
        if isinstance(data.get("outbounds"), list):
            return parse_xray_json(data)
        if isinstance(data.get("proxies"), list):
            return parse_mihomo(data)
    return None


def parse_subscription(body: bytes | str) -> ParseResult:
    """Detect the format of a subscription body and extract servers."""
    if isinstance(body, bytes):
        text = body.decode("utf-8-sig", "replace")
    else:
        text = body.lstrip("\ufeff")
    stripped = text.strip()
    if not stripped:
        return ParseResult("empty")
    head = stripped[:300].lower()
    if head.startswith(("<!doctype", "<html", "<head", "<?xml")) or "<html" in head:
        return ParseResult("html")
    if "age-encryption.org/v1" in head or "begin age encrypted file" in head:
        return ParseResult("encrypted")
    if head.startswith("happ://"):
        return ParseResult("unsupported")
    if stripped[0] in "[{":
        try:
            parsed = _from_json(json.loads(stripped))
        except ValueError:
            parsed = None
        if parsed is not None:
            return parsed
    if _LINK_RE.search(stripped):
        return parse_links(stripped)
    decoded = _b64decode(stripped)
    if decoded:
        inner = decoded.decode("utf-8", "replace").strip()
        if _LINK_RE.search(inner):
            return parse_links(inner, is_base64=True)
        if inner[:1] in "[{":  # base64-wrapped JSON is unusual but harmless to accept
            try:
                parsed = _from_json(json.loads(inner))
            except ValueError:
                parsed = None
            if parsed is not None:
                parsed.is_base64 = True
                return parsed
        if inner.startswith("happ://") or "age-encryption.org/v1" in inner[:200]:
            return ParseResult("encrypted")
        if _ANY_LINK_RE.search(inner):
            return parse_links(inner, is_base64=True)
    if "proxies" in stripped:
        try:
            data = yaml.load(stripped, Loader=_YamlLoader)  # noqa: S506 - safe loader
        except yaml.YAMLError:
            data = None
        if isinstance(data, dict) and isinstance(data.get("proxies"), list):
            return parse_mihomo(data)
    if _ANY_LINK_RE.search(stripped):
        return parse_links(stripped)
    return ParseResult("unknown")
