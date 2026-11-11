"""Subscription formats. Fixtures are real Remnawave responses with hosts and keys replaced."""

import base64
import json
from pathlib import Path

import pytest

from rwmon.subscription.model import merge_servers
from rwmon.subscription.parsers import parse_subscription

FIX = Path(__file__).resolve().parent.parent / "fixtures" / "sub"


def load(name: str) -> bytes:
    return (FIX / name).read_bytes()


@pytest.mark.parametrize("name,fmt,count", [
    ("links.b64", "links", 16), ("xray.json", "xray_json", 28), ("mihomo.yaml", "mihomo", 16), ("singbox.json", "singbox", 16)])
def test_every_format_is_detected_by_content(name, fmt, count):
    parsed = parse_subscription(load(name))
    assert parsed.format == fmt and parsed.has_servers
    assert len(parsed.servers) == count
    assert not parsed.placeholders


def test_all_formats_describe_the_same_physical_servers():
    prints = {}
    for name in ("links.b64", "xray.json", "mihomo.yaml", "singbox.json"):
        prints[name] = {server.fingerprint for server in parse_subscription(load(name)).servers}
    assert len(prints["links.b64"]) == 15                 # 16 entries, one is a duplicate "auto-select"
    assert prints["links.b64"] == prints["xray.json"] == prints["mihomo.yaml"] == prints["singbox.json"]


def test_extracted_fields():
    servers = parse_subscription(load("links.b64")).servers
    first = next(server for server in servers if server.address == "node01.vpn-example.org")
    assert (first.port, first.protocol, first.transport, first.security) == (443, "vless", "tcp", "reality")
    assert first.sni == "node01.vpn-example.org" and first.l4 == "tcp"
    assert first.params["flow"] == "xtls-rprx-vision" and first.params["fp"] == "firefox"
    assert first.secrets["id"].startswith("5d2f7c1e") and first.secrets["pbk"] and first.secrets["sid"]
    assert "id" not in first.public_params() and "pbk" not in first.public_params()      # secrets stay out of the open part
    assert first.kind_label == "VLESS · TCP · REALITY"


def test_merge_dedups_and_prefers_real_names():
    groups = [parse_subscription(load(name)).servers for name in ("links.b64", "xray.json", "mihomo.yaml")]
    merged = merge_servers(groups)
    assert len(merged) == 15
    poland = next(server for server in merged if server.address == "node01.vpn-example.org")
    assert "Автовыбор" not in poland.name and any("Автовыбор" in alias for alias in poland.aliases)
    assert poland.outbound is not None and poland.outbound["protocol"] == "vless"         # original Xray outbound kept for E2E
    assert all(server.outbound is not None for server in merged)


@pytest.mark.parametrize("name", ["placeholder_links.b64", "placeholder_xray.json", "placeholder_mihomo.yaml",
                                  "placeholder_singbox.json"])
def test_panel_stub_entries_are_not_servers(name):
    parsed = parse_subscription(load(name))
    assert not parsed.has_servers and parsed.placeholders
    assert any("не поддерживается" in remark for remark in parsed.placeholders)      # the panel's own message is kept


def test_plain_links_without_base64_and_mixed_protocols():
    body = "\n".join([
        "vless://5d2f7c1e-3b6a-4c8d-9e0f-000000000001@de.example.org:8443?type=ws&security=tls&sni=cdn.example.org"
        "&host=cdn.example.org&path=%2Fws%3Fed%3D2048#DE%20WS",
        "trojan://secret-pass@nl.example.org:443?type=grpc&serviceName=grpc-svc&sni=nl.example.org#NL%20gRPC",
        "ss://" + base64.urlsafe_b64encode(b"chacha20-ietf-poly1305:pw").decode().rstrip("=") + "@fi.example.org:8388#FI%20SS",
        "hysteria2://hy-pass@se.example.org:8443?sni=se.example.org&obfs=salamander&obfs-password=x#SE%20HY2",
        "vless://5d2f7c1e-3b6a-4c8d-9e0f-000000000001@[2001:db8::1]:443?type=xhttp&security=reality&sni=a.example.org"
        "&pbk=AAAA&sid=01&path=%2Fx&mode=auto#V6%20XHTTP",
        "wireguard://unsupported@host:51820#WG",
        "garbage line",
    ]).encode()
    parsed = parse_subscription(body)
    assert parsed.format == "links" and not parsed.is_base64
    by_name = {server.name: server for server in parsed.servers}
    assert set(by_name) == {"DE WS", "NL gRPC", "FI SS", "SE HY2", "V6 XHTTP"}
    assert (by_name["DE WS"].transport, by_name["DE WS"].host, by_name["DE WS"].path) == ("ws", "cdn.example.org", "/ws?ed=2048")
    assert (by_name["NL gRPC"].protocol, by_name["NL gRPC"].security, by_name["NL gRPC"].path) == ("trojan", "tls", "grpc-svc")
    assert by_name["FI SS"].secrets == {"method": "chacha20-ietf-poly1305", "password": "pw"}
    assert by_name["SE HY2"].l4 == "udp" and by_name["SE HY2"].params["obfs"] == "salamander"
    assert by_name["V6 XHTTP"].address == "2001:db8::1" and by_name["V6 XHTTP"].transport == "xhttp"
    assert dict(parsed.skipped) == {"схема wireguard:// не поддерживается": 1}     # reported to the owner, not fatal


def test_same_server_with_different_transports_is_one_node_many_configs():
    body = "\n".join([
        "vless://5d2f7c1e-3b6a-4c8d-9e0f-000000000001@de.example.org:443?type=tcp&security=reality&sni=x.org&pbk=A&sid=1#DE",
        "vless://5d2f7c1e-3b6a-4c8d-9e0f-000000000001@de.example.org:443?type=tcp&security=reality&sni=x.org&pbk=A&sid=1#DE%20copy",
        "vless://5d2f7c1e-3b6a-4c8d-9e0f-000000000001@de.example.org:8443?type=ws&security=tls&sni=de.example.org&path=%2Fw#DE%20WS",
        "hysteria2://pw@de.example.org:443?sni=de.example.org#DE%20HY2",
    ]).encode()
    merged = merge_servers([parse_subscription(body).servers])
    assert len(merged) == 3                                    # exact duplicate collapsed, real variants kept
    assert len({server.node_key for server in merged}) == 1    # one physical machine
    assert {server.l4 for server in merged} == {"tcp", "udp"}


@pytest.mark.parametrize("body,fmt", [
    (b"", "empty"), (b"   \n", "empty"),
    (b"<!DOCTYPE html><html><head><title>Sub</title></head><body></body></html>", "html"),
    (b"just some text that is not a subscription", "unknown"),
])
def test_non_subscription_bodies(body, fmt):
    parsed = parse_subscription(body)
    assert parsed.format == fmt and not parsed.has_servers


def test_xray_json_single_object_and_array():
    configs = json.loads(load("xray.json"))
    single = parse_subscription(json.dumps(configs[1]).encode())
    assert single.format == "xray_json" and len(single.servers) == 1
