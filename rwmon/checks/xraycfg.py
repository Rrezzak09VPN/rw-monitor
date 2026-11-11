"""Build a one-shot Xray client configuration for the end-to-end check.

The original outbound from the subscription is preferred (it is exactly what
real clients run). When the subscription was only available as links or
Mihomo/sing-box configs, an equivalent outbound is assembled from the
normalised fields.
"""

from __future__ import annotations

import copy
import ipaddress
import json
from typing import Any


class Unsupported(Exception):
    """This server cannot be checked end-to-end; the message explains why."""


_XRAY_NETWORK = {
    "tcp": "raw", "ws": "ws", "grpc": "grpc", "httpupgrade": "httpupgrade",
    "xhttp": "xhttp", "kcp": "kcp", "hysteria": "hysteria",
}


def _csv(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if item]
    return [item.strip() for item in str(value or "").split(",") if item.strip()]


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _from_fields(server: dict[str, Any], secrets: dict[str, Any]) -> dict[str, Any]:
    params = server.get("params") or {}
    protocol, transport, security = server["protocol"], server["transport"], server["security"]
    address, port = server["address"], int(server["port"])
    if transport not in _XRAY_NETWORK:
        raise Unsupported(f"транспорт {transport} не поддерживается текущим Xray-core")
    if protocol == "vless":
        if not secrets.get("id"):
            raise Unsupported("в подписке нет UUID пользователя")
        user = {"id": secrets["id"], "encryption": params.get("encryption") or "none"}
        if params.get("flow"):
            user["flow"] = params["flow"]
        outbound = {"protocol": "vless", "settings": {"vnext": [{"address": address, "port": port, "users": [user]}]}}
    elif protocol == "vmess":
        if not secrets.get("id"):
            raise Unsupported("в подписке нет UUID пользователя")
        user = {"id": secrets["id"], "alterId": int(secrets.get("alter_id") or 0),
                "security": secrets.get("cipher") or "auto"}
        outbound = {"protocol": "vmess", "settings": {"vnext": [{"address": address, "port": port, "users": [user]}]}}
    elif protocol == "trojan":
        if not secrets.get("password"):
            raise Unsupported("в подписке нет пароля")
        outbound = {"protocol": "trojan",
                    "settings": {"servers": [{"address": address, "port": port, "password": secrets["password"]}]}}
    elif protocol == "shadowsocks":
        if not secrets.get("password") or not secrets.get("method"):
            raise Unsupported("в подписке нет метода шифрования или пароля")
        if params.get("plugin"):
            raise Unsupported("Shadowsocks с плагином не поддерживается Xray-core")
        outbound = {"protocol": "shadowsocks", "settings": {"servers": [{
            "address": address, "port": port, "method": secrets["method"], "password": secrets["password"]}]}}
    elif protocol == "hysteria2":
        if not secrets.get("auth"):
            raise Unsupported("в подписке нет пароля Hysteria2")
        outbound = {"protocol": "hysteria", "settings": {"version": 2, "address": address, "port": port}}
    else:
        raise Unsupported(f"протокол {protocol} не поддерживается")

    stream: dict[str, Any] = {"network": _XRAY_NETWORK[transport], "security": security}
    host, path = server.get("host") or "", server.get("path") or ""
    if transport == "ws":
        stream["wsSettings"] = {key: value for key, value in (("path", path), ("host", host)) if value}
    elif transport == "httpupgrade":
        stream["httpupgradeSettings"] = {key: value for key, value in (("path", path), ("host", host)) if value}
    elif transport == "grpc":
        settings: dict[str, Any] = {"serviceName": path}
        if host:
            settings["authority"] = host
        if params.get("mode") == "multi":
            settings["multiMode"] = True
        stream["grpcSettings"] = settings
    elif transport == "xhttp":
        settings = {key: value for key, value in (("path", path), ("host", host), ("mode", params.get("mode"))) if value}
        if params.get("extra"):
            try:
                settings["extra"] = json.loads(params["extra"]) if isinstance(params["extra"], str) else params["extra"]
            except ValueError as exc:
                raise Unsupported("некорректный параметр extra транспорта XHTTP") from exc
        stream["xhttpSettings"] = settings
    elif transport == "tcp" and params.get("header_type") == "http":
        request: dict[str, Any] = {"path": [path or "/"]}
        if host:
            request["headers"] = {"Host": _csv(host)}
        stream["rawSettings"] = {"header": {"type": "http", "request": request}}
    elif transport == "hysteria":
        stream["hysteriaSettings"] = {"version": 2, "auth": secrets["auth"]}
        stream["security"] = security = "tls"

    server_name = server.get("sni") or ("" if _is_ip(address) else address)
    if security == "tls":
        tls: dict[str, Any] = {}
        if server_name:
            tls["serverName"] = server_name
        alpn = _csv(params.get("alpn")) or (["h3"] if transport == "hysteria" else [])
        if alpn:
            tls["alpn"] = alpn
        if params.get("fp") and transport != "hysteria":
            tls["fingerprint"] = params["fp"]
        if secrets.get("pin") and _looks_like_sha256(secrets["pin"]):
            tls["pinnedPeerCertSha256"] = _normalise_pin(secrets["pin"])
        stream["tlsSettings"] = tls
    elif security == "reality":
        if not secrets.get("pbk"):
            raise Unsupported("в подписке нет публичного ключа REALITY")
        reality: dict[str, Any] = {
            "serverName": server_name, "publicKey": secrets["pbk"], "shortId": secrets.get("sid", ""),
            "fingerprint": params.get("fp") or "chrome",
        }
        if secrets.get("spx"):
            reality["spiderX"] = secrets["spx"]
        if secrets.get("pqv"):
            reality["mldsa65Verify"] = secrets["pqv"]
        stream["realitySettings"] = reality
    elif security != "none":
        raise Unsupported(f"тип защиты {security} не поддерживается")

    finalmask: dict[str, Any] = {}
    if params.get("fm"):
        try:
            finalmask = json.loads(params["fm"]) if isinstance(params["fm"], str) else dict(params["fm"])
        except ValueError:
            finalmask = {}
    if transport == "hysteria" and params.get("obfs") == "salamander" and not finalmask.get("udp"):
        finalmask["udp"] = [{"type": "salamander", "settings": {"password": secrets.get("obfs_password", "")}}]
    if finalmask:
        stream["finalmask"] = finalmask
    outbound["streamSettings"] = stream
    return outbound


def _looks_like_sha256(value: str) -> bool:
    text = _normalise_pin(value)
    return len(text) == 64 and all(char in "0123456789abcdef" for char in text)


def _normalise_pin(value: str) -> str:
    return str(value).split(",")[0].strip().lower().replace(":", "")


def _set_address(outbound: dict[str, Any], ip: str) -> None:
    settings = outbound.get("settings") or {}
    for key in ("vnext", "servers"):
        for node in settings.get(key) or []:
            if isinstance(node, dict) and "address" in node:
                node["address"] = ip
    if "address" in settings:
        settings["address"] = ip


def _original_address(outbound: dict[str, Any]) -> str:
    settings = outbound.get("settings") or {}
    for key in ("vnext", "servers"):
        for node in settings.get(key) or []:
            if isinstance(node, dict) and node.get("address"):
                return str(node["address"])
    return str(settings.get("address") or "")


def build_outbound(server: dict[str, Any], secret: dict[str, Any], ip: str | None = None,
                   cert_sha256: str = "") -> dict[str, Any]:
    """Return the Xray outbound for one server.

    ``server`` holds address, port, protocol, transport, security, sni, host,
    path and params. ``ip`` pins the connection to the address verified by the
    lower-level probes. ``cert_sha256`` is the leaf certificate seen by the TLS
    probe; it replaces the "skip certificate verification" flag, which current
    Xray versions no longer accept.
    """
    original = secret.get("outbound")
    if isinstance(original, dict) and original.get("protocol"):
        outbound = copy.deepcopy(original)
    else:
        outbound = _from_fields(server, secret.get("secrets") or {})
    outbound["tag"] = "proxy"
    if not (outbound.get("mux") or {}).get("enabled"):
        outbound.pop("mux", None)
    stream = outbound.setdefault("streamSettings", {})
    sockopt = stream.get("sockopt")
    if isinstance(sockopt, dict):
        if sockopt.get("dialerProxy"):
            raise Unsupported("конфигурация использует цепочку прокси (dialerProxy)")
        for key in ("mark", "interface", "tproxy"):
            sockopt.pop(key, None)

    address = _original_address(outbound)
    security = stream.get("security") or "none"
    section = stream.get("tlsSettings") if security == "tls" else stream.get("realitySettings") if security == "reality" else None
    if isinstance(section, dict):
        if not section.get("serverName") and address and not _is_ip(address):
            section["serverName"] = address
    if security == "tls":
        tls = stream.setdefault("tlsSettings", {})
        insecure = bool(tls.pop("allowInsecure", False)) or bool((server.get("params") or {}).get("insecure"))
        if insecure and not tls.get("pinnedPeerCertSha256"):
            if not cert_sha256:
                raise Unsupported("сервер использует непроверяемый сертификат, а получить его отпечаток не удалось")
            tls["pinnedPeerCertSha256"] = cert_sha256
    if ip:
        _set_address(outbound, ip)
    return outbound


def build_config(outbound: dict[str, Any], socks_port: int) -> dict[str, Any]:
    return {
        "log": {"loglevel": "info"},   # connection errors are reported at this level
        "inbounds": [{
            "tag": "in", "listen": "127.0.0.1", "port": socks_port, "protocol": "socks",
            "settings": {"auth": "noauth", "udp": False},
        }],
        "outbounds": [outbound],
    }
