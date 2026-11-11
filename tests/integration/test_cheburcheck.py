"""Cheburcheck integration against a fake API replaying real recorded responses."""

import time

import pytest_asyncio

from rwmon.cheburcheck import service as cc_service
from rwmon.cheburcheck import summary as sm
from rwmon.cheburcheck.client import CheburcheckClient
from rwmon.cheburcheck.service import CheburcheckService
from rwmon.monitor.alerts import Alerts

from ..fakes.cheburcheck import FakeCheburcheck

A, B, C, D = "a.example.com", "b.example.com", "c.example.com", "d.example.com"


@pytest_asyncio.fixture
async def cc(env, monkeypatch):
    """The env with Cheburcheck switched on and pointed at the fake service (no pacing delays)."""
    fake = await FakeCheburcheck().start()
    object.__setattr__(env.config, "cheburcheck_enabled", True)
    object.__setattr__(env.config, "cheburcheck_check_interval", 0.0)
    object.__setattr__(env.config, "cheburcheck_probe_interval", 0.0)
    object.__setattr__(env.config, "cheburcheck_wait", 10)
    await env.cc.stop()
    await env.alerts.stop()
    env.cc = CheburcheckService(env.config, env.db, env.settings, CheburcheckClient(fake.base_url, timeout=3, probe_timeout=5))
    env.alerts = Alerts(env.config, env.db, env.settings, env.outbox, env.cc)
    env.monitor.alerts = env.alerts
    await env.cc.start()
    await env.alerts.start()
    env.fake_cc = fake
    try:
        yield env
    finally:
        await fake.stop()


async def take_down(env, clock, *hosts):
    env.checker.fail(*hosts)
    clock.advance(180)
    await env.cycle(); clock.advance(31); await env.rechecks(); clock.advance(61); await env.rechecks()


async def test_not_called_for_healthy_or_suspect_servers(cc, clock):
    await cc.add_servers(A, B)
    for _ in range(3):
        await cc.cycle()
        clock.advance(180)
    cc.checker.fail(A)
    await cc.cycle()                                  # SUSPECT
    cc.checker.heal(A)
    clock.advance(31); await cc.rechecks()            # cleared
    assert cc.fake_cc.check_calls == [] and cc.fake_cc.probe_calls == 0


async def test_down_notification_carries_cheburcheck_data(cc, clock):
    await cc.add_servers(A, B)
    await cc.cycle()
    await take_down(cc, clock, A)
    assert sorted(cc.fake_cc.check_calls) == ["93.184.216.34", A]       # IP and domain, once each
    down = (await cc.messages("down"))[0]["text"]
    assert "Cheburcheck" in down and "✅ данные получены" in down
    assert "Замеры у операторов" in down and "Блокировка на ТСПУ: <b>" in down
    assert "Наличие в списках" in down and "справочно, это не замер" in down       # static vs dynamic kept apart
    assert "AS13335" in down and "Вероятная причина: блокировка IP на ТСПУ" in down
    incident = await cc.db.fetchone("SELECT * FROM incidents")
    assert incident["cc_status"] == "complete" and "ТСПУ" in incident["assessment"]
    assert await cc.db.scalar("SELECT COUNT(*) FROM cheburcheck_results") == 2
    # nothing more is requested while the server stays down
    for _ in range(3):
        clock.advance(180)
        await cc.cycle()
    assert len(cc.fake_cc.check_calls) == 2


async def test_probes_see_no_block_changes_the_hypothesis(cc, clock):
    cc.fake_cc.blocked_share = 0.05
    await cc.add_servers(A)
    await cc.cycle()
    await take_down(cc, clock, A)
    down = (await cc.messages("down"))[0]["text"]
    assert "Вероятная причина: отказ сервера или сети хостера" in down and "сканеры не видят" in down


async def test_cache_prevents_repeated_requests(cc, clock):
    await cc.add_servers(A)
    await cc.cycle()
    await take_down(cc, clock, A)
    calls = len(cc.fake_cc.check_calls)
    cc.checker.heal(A)
    clock.advance(180); await cc.cycle(); clock.advance(31); await cc.rechecks(); clock.advance(31); await cc.rechecks()
    clock.advance(700); await cc.cycle()
    await take_down(cc, clock, A)                       # second incident within the cache lifetime
    assert len(await cc.messages("down")) == 2
    assert len(cc.fake_cc.check_calls) == calls       # served from the local cache
    assert "запрошено в" in (await cc.messages("down"))[1]["text"]


async def test_unavailable_service_does_not_block_or_mislabel(cc, clock, monkeypatch):
    monkeypatch.setattr(cc_service, "RETRY_PAUSES", (60, 60, 60, 60, 60))
    cc.fake_cc.mode = "down"
    await cc.add_servers(A)
    await cc.cycle()
    started = time.monotonic()
    await take_down(cc, clock, A)
    assert time.monotonic() - started < 8               # the alert is not held up by the dead service
    down = (await cc.messages("down"))[0]
    assert "СЕРВЕР НЕДОСТУПЕН" in down["text"] and "нет ответа на TCP-соединение" in down["text"]
    assert "запрашиваются" in down["text"] or "временно недоступен" in down["text"]
    assert "ТСПУ" not in down["text"].split("Cheburcheck")[0].split("Причина:")[1].replace("блокировки IP", "")
    incident = await cc.db.fetchone("SELECT * FROM incidents")
    assert incident["cc_status"] in ("pending", "unavailable") and incident["assessment"] == ""
    assert (await cc.states())[A] == "DOWN"
    queue = await cc.db.fetchall("SELECT * FROM cheburcheck_queue")
    assert queue and all(row["status"] == "pending" for row in queue)

    # no hammering: the breaker opens after three failures in a row
    calls = len(cc.fake_cc.check_calls)
    for _ in range(4):
        clock.advance(61)
        cc.cc._wake.set()
        await _settle(cc)
    assert cc.cc.backing_off and len(cc.fake_cc.check_calls) <= calls + 3
    blocked_calls = len(cc.fake_cc.check_calls)
    clock.advance(120); cc.cc._wake.set(); await _settle(cc)
    assert len(cc.fake_cc.check_calls) == blocked_calls   # silent while backing off

    # the service returns: queued lookups are completed and the incident is updated
    cc.fake_cc.mode = "ok"
    clock.advance(4000); cc.cc._wake.set()
    await _settle(cc, until=lambda: cc.db.scalar("SELECT COUNT(*) FROM cheburcheck_queue WHERE status='pending'"), want=0)
    await _settle(cc, until=lambda: cc.db.scalar("SELECT COUNT(*) FROM notifications WHERE kind='cc_followup'"), want=1)
    incident = await cc.db.fetchone("SELECT * FROM incidents")
    assert incident["cc_status"] == "complete" and "ТСПУ" in incident["assessment"]
    edits = await cc.messages("down_edit")
    assert len(edits) == 1 and edits[0]["edit_of"] == down["id"] and "✅ данные получены" in edits[0]["text"]
    followups = await cc.messages("cc_followup")
    assert len(followups) == 1 and followups[0]["reply_to"] == down["id"]
    assert len(await cc.messages("cc_back")) == 1
    assert len(await cc.messages("down")) == 1


async def test_static_part_survives_probe_outage(cc, clock):
    cc.fake_cc.mode = "probe_down"
    await cc.add_servers(A)
    await cc.cycle()
    await take_down(cc, clock, A)
    down = (await cc.messages("down"))[0]["text"]
    assert "Наличие в списках" in down and "AS13335" in down
    assert "Вероятная причина" not in down                 # lists alone are not evidence of a block


async def test_mass_failure_limits_lookups(cc, clock):
    hosts = [f"h{i}.example.com" for i in range(8)]
    await cc.add_servers(*hosts)
    await cc.cycle()
    await take_down(cc, clock, *hosts)
    assert len(await cc.messages("down")) == 1
    await _settle(cc, until=lambda: cc.db.scalar("SELECT COUNT(*) FROM cheburcheck_queue WHERE status='pending'"), want=0)
    assert len(set(cc.fake_cc.check_calls)) <= 10


async def test_daily_limit_and_disable(cc, clock):
    await cc.settings.set("cheburcheck_daily_limit", "1")
    result = await cc.cc.lookup_now("198.51.100.7", "ip")
    assert result.static_status == "ok" and result.probe_status == "skipped"
    second = await cc.cc.lookup_now("198.51.100.8", "ip")
    assert second.static_status == "skipped" and second.reliability == sm.UNAVAILABLE
    await cc.settings.set("cheburcheck_enabled", "off")
    calls = len(cc.fake_cc.check_calls)
    await cc.add_servers(A)
    await cc.cycle()
    await take_down(cc, clock, A)
    assert len(cc.fake_cc.check_calls) == calls
    assert "Cheburcheck" not in (await cc.messages("down"))[0]["text"]


async def test_changed_api_is_reported_once(cc, clock):
    cc.fake_cc.mode = "garbage"
    for index in range(4):
        result = await cc.cc.lookup_now(f"198.51.100.{index}", "ip", use_cache=False)
        assert result.static_status == "unavailable"
    assert len(await cc.messages("cc_api")) == 1


async def test_rate_limit_is_respected_without_tripping_the_breaker(cc, clock):
    cc.fake_cc.mode = "rate_limit"
    await cc.add_servers(A)
    await cc.cycle()
    await take_down(cc, clock, A)
    assert len(await cc.messages("down")) == 1                       # the alert does not wait for the service
    assert not cc.cc.backing_off                                     # 429 is "slow down", not "service is dead"
    rows = await cc.db.fetchall("SELECT * FROM cheburcheck_queue")
    assert rows and all(row["status"] == "pending" and row["attempts"] == 0 for row in rows)
    cc.fake_cc.mode = "ok"
    clock.advance(5); cc.cc._wake.set()
    await _settle(cc, until=lambda: cc.db.scalar("SELECT COUNT(*) FROM cheburcheck_queue WHERE status='pending'"), want=0)
    await _settle(cc, until=lambda: cc.db.scalar("SELECT COUNT(*) FROM notifications WHERE kind='down_edit'"), want=1)
    assert (await cc.db.fetchone("SELECT cc_status FROM incidents"))["cc_status"] == "complete"
    assert len(await cc.messages("down_edit")) == 1


async def test_broken_probe_stream_keeps_partial_data(cc):
    cc.fake_cc.mode = "cut_stream"
    result = await cc.cc.lookup_now("198.51.100.20", "ip")
    assert result.static_status == "ok" and result.probe_status == "partial"
    assert 1 <= result.probes["responses"] <= 5 and result.reliability == sm.PARTIAL
    from rwmon.telegram import texts
    block = "\n".join(texts.cc_block([result], []))
    assert "◐ данные частичные" in block and "ответили" in block


async def _settle(env, until=None, want=None, timeout: float = 6.0):
    import asyncio
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        await asyncio.sleep(0.05)
        if until is not None and await until() == want:
            return
    if until is None:
        return
