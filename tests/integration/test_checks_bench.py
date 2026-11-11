"""Real checks against real Xray servers on loopback, with DPI-like faults injected on the path.

Needs the Xray binary (XRAY_BIN, /usr/local/bin/xray or /tmp/xray/xray); skipped without it.
"""

import asyncio
import dataclasses
import os
import time

import pytest
import pytest_asyncio

from rwmon.checks import net
from rwmon.checks.dns import DnsResolver
from rwmon.checks.e2e import E2EChecker
from rwmon.checks.pipeline import Checker, Target, Timeouts
from rwmon.checks.selfhealth import SelfHealth
from rwmon.checks.xraycfg import Unsupported, build_outbound
from rwmon.subscription.parsers import parse_subscription

from ..fakes.xray_bench import Bench, find_xray

pytestmark = pytest.mark.skipif(find_xray() is None, reason="xray binary not found")
T = Timeouts(dns=3, tcp=2, tls=3, udp=1.5, e2e=5)


@pytest_asyncio.fixture
async def bench():
    stand = await Bench.start()
    try:
        yield stand
    finally:
        await stand.stop()


@pytest_asyncio.fixture
async def checker(bench):
    e2e = E2EChecker(bench.xray, [bench.test_url], bench.data_url(), 131072, concurrency=3)
    assert await e2e.probe_binary() and e2e.version.startswith("Xray")
    return Checker(DnsResolver([]), e2e, retry_pause=0.2)


def servers(bench, via_relay: bool = False, names=None):
    parsed = parse_subscription(bench.subscription_body(names, via_relay))
    return {server.name.split()[-1].lower(): server for server in parsed.servers}


def target(cfg, data: bool = False, **changes) -> Target:
    cfg = dataclasses.replace(cfg, **changes) if changes else cfg
    return Target(
        id=1, name=cfg.name, address=cfg.address, port=cfg.port, l4=cfg.l4, protocol=cfg.protocol,
        transport=cfg.transport, security=cfg.security, sni=cfg.sni, host=cfg.host, path=cfg.path,
        params=cfg.public_params(), secret=lambda: {"secrets": cfg.secrets, "outbound": cfg.outbound}, data_probe=data)


def stage(result, name):
    return next((item for item in result.stages if item.name == name), None)


async def test_every_protocol_passes_end_to_end(bench, checker):
    for name, cfg in servers(bench).items():
        result = await checker.check(target(cfg, data=True), T)
        assert result.ok is True and result.code == "ok", (name, result.summary)
        assert result.e2e_ran and stage(result, "e2e").ok and result.data_probe, name
        assert result.latency_ms is not None and result.good_ips == ["127.0.0.1"]
        if cfg.l4 == "udp":
            assert stage(result, "quic").ok
        else:
            assert stage(result, "tcp").ok
        if cfg.security in ("tls", "reality") and cfg.l4 == "tcp":
            assert stage(result, "tls").ok and "sha256=" in stage(result, "tls").detail
    assert bench.hits >= 5                                   # requests really travelled through the tunnels


async def test_open_port_is_not_a_working_tunnel(bench, checker):
    """Wrong credentials: TCP and TLS are fine, only the end-to-end check sees the failure."""
    cfg = servers(bench)["reality"]
    broken = dataclasses.replace(cfg, secrets={**cfg.secrets, "id": "11111111-2222-4333-8444-555555555555"})
    result = await checker.check(target(broken), T)
    assert result.ok is False and result.code == "e2e_failed" and result.stage == "e2e"
    assert stage(result, "tcp").ok and stage(result, "tls").ok
    without = await checker.check(target(broken), T, use_e2e=False)
    assert without.ok is True                                 # exactly what a TCP/TLS-only monitor would report


@pytest.mark.parametrize("mode,code,failing", [
    ("freeze_after", "e2e_stall", "e2e"),     # data stops after ~16 KB: the "16-20 KB" throttling pattern
    ("drop", "tls_timeout", "tls"),           # silence after ClientHello
    ("reset", "tls_reset", "tls"),            # RST after ClientHello
])
async def test_dpi_like_interference_is_classified(bench, checker, mode, code, failing):
    cfg = servers(bench, via_relay=True, names=["reality"])["reality"]
    bench.relay.mode = "pass"
    assert (await checker.check(target(cfg, data=True), T)).ok is True
    bench.relay.mode = mode
    result = await checker.check(target(cfg, data=True), T)
    assert result.ok is False and result.code == code and result.stage == failing, result.summary
    assert stage(result, "tcp").ok                            # the port itself stays "open" in every case
    if mode == "freeze_after":
        assert stage(result, "tls").ok and "из 131072 байт" in stage(result, "e2e").detail


async def test_stopped_server_and_recovery(bench, checker):
    cfgs = servers(bench)
    bench.stop_xray()
    await asyncio.sleep(0.3)
    tcp = await checker.check(target(cfgs["reality"]), T)
    assert tcp.ok is False and tcp.code == "tcp_refused" and stage(tcp, "e2e") is None    # no pointless tunnel attempt
    udp = await checker.check(target(cfgs["hy2"]), T)
    assert udp.ok is False and udp.code == "udp_unreachable"
    await bench.restart_xray()
    assert (await checker.check(target(cfgs["reality"]), T)).ok is True


async def test_timeout_takes_bounded_time(checker, bench):
    cfg = servers(bench)["ws"]
    started = time.monotonic()
    result = await checker.check(target(cfg, address="10.255.255.1"), T)     # blackholed private address
    elapsed = time.monotonic() - started
    assert result.ok is False and result.code == "tcp_timeout"
    assert 3.5 < elapsed < 6.5                                               # 2 attempts × 2 s + pause, no more


async def test_without_xray_lower_layers_still_work(bench):
    e2e = E2EChecker("/nonexistent/xray", [bench.test_url], "", 0)
    assert not await e2e.probe_binary() and "не найден" in e2e.problem
    plain = Checker(DnsResolver([]), e2e, retry_pause=0.2)
    cfgs = servers(bench)
    result = await plain.check(target(cfgs["reality"]), T)
    assert result.ok is True and not result.e2e_ran and any("сквозная проверка не выполнена" in note for note in result.notes)
    bench.stop_xray()
    await asyncio.sleep(0.3)
    assert (await plain.check(target(cfgs["reality"]), T)).code == "tcp_refused"


async def test_obfuscated_udp_without_tunnel_check_is_unknown_not_down(bench):
    e2e = E2EChecker("/nonexistent/xray", [bench.test_url], "", 0)
    await e2e.probe_binary()
    plain = Checker(DnsResolver([]), e2e, retry_pause=0.2)
    cfg = servers(bench)["hy2"]
    obfuscated = dataclasses.replace(cfg, port=9, params={**cfg.params, "obfs": "salamander"})   # nothing answers there
    result = await plain.check(target(obfuscated), T)
    assert result.ok is None and result.code in ("udp_unverifiable", "udp_unreachable")
    plain_hy2 = dataclasses.replace(cfg, port=9)
    result = await plain.check(target(plain_hy2), T)
    assert result.ok is False                                                 # plain QUIC must answer a probe


async def test_partial_availability_is_not_an_outage(bench, checker):
    cfg = servers(bench)["ws"]
    item = target(cfg)
    item.extra_addresses = ["127.0.0.2"]                       # second address of the same server: nothing listens
    result = await checker.check(item, T)
    assert result.ok is True and result.partial and "127.0.0.2" in result.partial_note


async def test_xray_config_details(bench):
    cfgs = servers(bench)
    as_server = lambda cfg: {"address": cfg.address, "port": cfg.port, "protocol": cfg.protocol,  # noqa: E731
                             "transport": cfg.transport, "security": cfg.security, "sni": cfg.sni,
                             "host": cfg.host, "path": cfg.path, "params": cfg.public_params()}
    reality = build_outbound(as_server(cfgs["reality"]), {"secrets": cfgs["reality"].secrets, "outbound": None}, ip="127.0.0.9")
    assert reality["settings"]["vnext"][0]["address"] == "127.0.0.9"                 # pinned to the verified IP
    assert reality["streamSettings"]["realitySettings"]["serverName"] == "bench.test"
    trojan = cfgs["trojan"]
    with pytest.raises(Unsupported):                                                  # "insecure" needs a pinned certificate
        build_outbound(as_server(trojan), {"secrets": trojan.secrets, "outbound": None})
    pinned = build_outbound(as_server(trojan), {"secrets": trojan.secrets, "outbound": None}, cert_sha256="ab" * 32)
    assert pinned["streamSettings"]["tlsSettings"]["pinnedPeerCertSha256"] == "ab" * 32
    assert "allowInsecure" not in pinned["streamSettings"]["tlsSettings"]
    chained = {"protocol": "vless", "settings": {"vnext": [{"address": "h", "port": 1, "users": []}]},
               "streamSettings": {"sockopt": {"dialerProxy": "fragment"}}}
    with pytest.raises(Unsupported):
        build_outbound({}, {"outbound": chained})


async def test_no_secrets_on_disk_or_in_process_list(bench, checker):
    """The one-shot Xray client gets its configuration on stdin."""
    cfg = servers(bench, via_relay=True, names=["reality"])["reality"]
    bench.relay.mode = "drop"
    task = asyncio.create_task(checker.check(target(cfg), T))
    seen = []
    while not task.done() and not seen:                        # catch the short-lived client process
        await asyncio.sleep(0.2)
        for pid in filter(str.isdigit, os.listdir("/proc")):
            try:
                cmdline = open(f"/proc/{pid}/cmdline", "rb").read().split(b"\0")
            except OSError:
                continue
            if cmdline and cmdline[0].endswith(b"xray") and b"stdin:" in cmdline:
                seen.append(cmdline)
    await task
    bench.relay.mode = "pass"
    assert seen, "the client process was not observed"
    assert all(bench.uuid.encode() not in b" ".join(line) for line in seen)


async def test_tls_probe_fragmentation_and_raw_helpers(bench):
    port = bench.ports["trojan"]
    plain = await net.tls_probe("127.0.0.1", port, "bench.test", 3, ["http/1.1"], None)
    fragment = net.parse_fragment('{"tcp":[{"type":"fragment","settings":{"length":"10-20","packets":"1-3","interval":"1-2"}}]}')
    assert fragment is not None
    fragmented = await net.tls_probe("127.0.0.1", port, "bench.test", 5, ["http/1.1"], fragment)
    assert plain.ok and fragmented.ok and net.cert_digest(plain) == bench.cert_sha256 == net.cert_digest(fragmented)
    assert net.parse_fragment("") is None and net.parse_fragment("{broken") is None
    refused = await net.tcp_probe("127.0.0.1", 9, 1, pause=0.1)
    assert refused.ok is False and refused.code == "tcp_refused"
    assert (await net.quic_probe("127.0.0.1", bench.ports["hy2"], 1.5)).ok


@pytest.mark.network
async def test_dns_layer_with_real_resolvers():
    resolver = DnsResolver(["8.8.8.8", "1.1.1.1"])
    good = await resolver.resolve("example.com", 4)
    assert good.status == "ok" and good.ips
    missing = await resolver.resolve("no-such-host-rwmon-test.invalid", 4)
    assert missing.status == "nxdomain" and "NXDOMAIN" in missing.detail          # confirmed by more than one resolver
    ok, _ = await resolver.system_ok("example.com", 4)
    assert ok


async def test_dns_outage_is_not_a_server_failure(bench):
    """A resolver that does not answer gives "no verdict"; cached addresses keep the check going."""
    resolver = DnsResolver([])
    for _, item in resolver._resolvers:
        item.nameservers, item.port, item.timeout, item.lifetime = ["127.0.0.1"], 9, 0.5, 0.5
    e2e = E2EChecker(bench.xray, [bench.test_url], "", 0)
    await e2e.probe_binary()
    checker = Checker(resolver, e2e, retry_pause=0.2)
    cfg = servers(bench)["ws"]
    blind = target(cfg, address="vpn.example.org")
    result = await checker.check(blind, T)
    assert result.ok is None and result.code == "dns_unavailable"
    blind.cached_ips = ["127.0.0.1"]
    result = await checker.check(blind, T)
    assert result.ok is True and any("последние известные IP" in note for note in result.notes)
    bench.stop_xray()
    await asyncio.sleep(0.3)
    result = await checker.check(blind, T)
    assert result.ok is None                                   # cached address fails + DNS is blind → still no verdict


async def test_self_health_groups(bench):
    resolver = DnsResolver([])
    alive, dead = f"127.0.0.1:{bench.ports['web']}", "127.0.0.1:9"
    health = SelfHealth(resolver, [alive], [dead, alive], "", timeout=1, retry_pause=0.1)
    state = await health.check(force=True)
    assert state.network_ok and state.ru_ok and state.problem == ""          # one live target per group is enough
    health = SelfHealth(resolver, [alive], [dead], "", timeout=1, retry_pause=0.1)
    state = await health.check(force=True)
    assert not state.network_ok and "зарубежные" in state.problem
    health = SelfHealth(resolver, [dead], [dead], "", timeout=1, retry_pause=0.1)
    assert "нет связи с интернетом" in (await health.check(force=True)).problem
