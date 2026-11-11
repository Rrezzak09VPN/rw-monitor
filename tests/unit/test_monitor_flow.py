"""State machine + scheduler + notifications, driven end to end with scripted check results."""

import pytest

pytestmark = pytest.mark.asyncio

A, B, C, D = "a.example.com", "b.example.com", "c.example.com", "d.example.com"


async def test_single_failure_never_notifies(env, clock):
    await env.add_servers(A, B)
    await env.cycle()
    assert await env.states() == {A: "OK", B: "OK"}

    env.checker.fail(A)
    clock.advance(180)
    await env.cycle()
    assert (await env.states())[A] == "SUSPECT"
    env.checker.heal(A)
    clock.advance(31)
    await env.rechecks()
    assert (await env.states())[A] == "OK"
    assert await env.messages("down") == []
    assert await env.db.scalar("SELECT COUNT(*) FROM incidents") == 0


async def test_down_after_n_failures_then_recovery(env, clock):
    await env.add_servers(A, B)
    await env.cycle()
    env.checker.fail(A)
    clock.advance(180)
    await env.cycle()                       # failure 1 → SUSPECT
    assert await env.rechecks() is None     # the first recheck is not due yet
    clock.advance(31)
    await env.rechecks()                    # failure 2
    assert (await env.states())[A] == "SUSPECT"
    assert await env.messages("down") == []
    clock.advance(61)
    await env.rechecks()                    # failure 3 → DOWN
    assert await env.states() == {A: "DOWN", B: "OK"}

    downs = await env.messages("down")
    assert len(downs) == 1
    text = downs[0]["text"]
    assert "СЕРВЕР НЕДОСТУПЕН" in text and "Srv-1" in text and A in text and "443" in text
    assert "VLESS" in text and "REALITY" in text and "DOWN" in text and "МСК" in text
    assert "подтверждено 3 проверками" in text and "TCP" in text

    # staying down produces nothing new
    clock.advance(180)
    await env.cycle()
    assert len(await env.messages("down")) == 1

    # recovery needs M consecutive successes
    env.checker.heal(A)
    clock.advance(180)
    await env.cycle()
    assert (await env.states())[A] == "DOWN"
    clock.advance(31)
    await env.rechecks()
    assert (await env.states())[A] == "DOWN"
    assert await env.messages("recovered") == []
    clock.advance(31)
    await env.rechecks()
    assert (await env.states())[A] == "RECOVERED"
    ups = await env.messages("recovered")
    assert len(ups) == 1 and "СЕРВЕР ВОССТАНОВЛЕН" in ups[0]["text"] and "3 успешными проверками" in ups[0]["text"]
    assert ups[0]["reply_to"] == downs[0]["id"]

    incident = await env.db.fetchone("SELECT * FROM incidents")
    assert incident["recovered_at"] and incident["resolved_at"] and incident["resolved_at"] <= incident["recovered_at"]

    # after the observation period the server is plain OK again, silently
    clock.advance(700)
    await env.cycle()
    assert (await env.states())[A] == "OK"
    assert len(await env.messages()) == 2


async def test_failed_recovery_attempt_resets_counter(env, clock):
    await env.add_servers(A)
    await env.cycle()
    env.checker.fail(A)
    clock.advance(180)
    await env.cycle(); clock.advance(31); await env.rechecks(); clock.advance(61); await env.rechecks()
    assert (await env.states())[A] == "DOWN"
    env.checker.heal(A)
    clock.advance(180); await env.cycle()               # success 1
    env.checker.fail(A)
    clock.advance(31); await env.rechecks()             # failure → counter resets
    env.checker.heal(A)
    clock.advance(180); await env.cycle()               # success 1 again
    clock.advance(31); await env.rechecks()             # success 2
    assert (await env.states())[A] == "DOWN"
    assert await env.messages("recovered") == []
    clock.advance(31); await env.rechecks()             # success 3
    assert (await env.states())[A] == "RECOVERED"


async def test_no_verdict_changes_nothing(env, clock):
    from tests.fakes.checks import unknown_result
    await env.add_servers(A)
    await env.cycle()
    env.checker.set(A, lambda: unknown_result())
    for _ in range(6):
        clock.advance(180)
        await env.cycle()
    assert (await env.states())[A] == "OK"
    assert await env.messages("down") == []


async def test_monitor_own_outage_freezes_everything(env, clock):
    await env.add_servers(A, B, C)
    await env.cycle()
    env.checker.fail(A, B, C)
    clock.advance(180)
    env.health.foreign_ok = False          # the VPS itself lost connectivity
    for _ in range(5):
        summary = await env.cycle()
        assert summary.frozen
        clock.advance(180)
    assert set((await env.states()).values()) == {"OK"}
    assert await env.messages("down") == []
    problems = await env.messages("monitor_problem")
    assert len(problems) == 1 and "ПРОБЛЕМА МОНИТОРИНГА" in problems[0]["text"]

    env.health.foreign_ok = True
    env.checker.heal(A, B, C)
    clock.advance(180)
    await env.cycle()
    assert len(await env.messages("monitor_restored")) == 1
    assert set((await env.states()).values()) == {"OK"}


async def test_network_lost_during_round_discards_failures(env, clock):
    await env.add_servers(A, B)
    await env.cycle()

    async def check_and_break(target, timeouts, use_e2e=True):
        env.health.foreign_ok = False      # connectivity disappears while checks are running
        from tests.fakes.checks import fail_result
        return fail_result()
    env.monitor.checker.check = check_and_break
    clock.advance(180)
    summary = await env.cycle()
    assert summary.frozen
    assert set((await env.states()).values()) == {"OK"}
    assert await env.db.scalar("SELECT COUNT(*) FROM checks WHERE ok=0") == 0


async def test_mass_failure_is_one_digest(env, clock):
    await env.add_servers(A, B, C, D)
    await env.cycle()
    env.checker.fail(A, B, C)
    clock.advance(180)
    await env.cycle(); clock.advance(31); await env.rechecks(); clock.advance(61); await env.rechecks()
    assert await env.states() == {A: "DOWN", B: "DOWN", C: "DOWN", D: "OK"}
    downs = await env.messages("down")
    assert len(downs) == 1
    assert "МАССОВАЯ НЕДОСТУПНОСТЬ" in downs[0]["text"] and "3 сервера из 4" in downs[0]["text"]
    assert await env.db.scalar("SELECT COUNT(*) FROM monitor_events WHERE kind='mass_failure'") == 1

    env.checker.heal(A, B, C)
    clock.advance(180); await env.cycle(); clock.advance(31); await env.rechecks(); clock.advance(31); await env.rechecks()
    ups = await env.messages("recovered")
    assert len(ups) == 1 and "СЕРВЕРЫ ВОССТАНОВЛЕНЫ" in ups[0]["text"]


async def test_muted_server_is_checked_but_silent(env, clock):
    servers = await env.add_servers(A, B)
    await env.db.update("servers", {"id": servers[0]["id"]}, notify_muted=1)
    await env.cycle()
    env.checker.fail(A)
    clock.advance(180)
    await env.cycle(); clock.advance(31); await env.rechecks(); clock.advance(61); await env.rechecks()
    assert (await env.states())[A] == "DOWN"
    assert await env.db.scalar("SELECT COUNT(*) FROM incidents") == 1
    assert await env.messages() == []


async def test_excluded_and_paused_servers_are_not_checked(env, clock):
    import time
    servers = await env.add_servers(A, B, C)
    await env.db.update("servers", {"id": servers[0]["id"]}, monitor_enabled=0)
    await env.db.update("servers", {"id": servers[1]["id"]}, paused_until=int(time.time()) + 3600)
    await env.cycle()
    assert [address for address, _ in env.checker.calls] == [C]
    clock.advance(3700)                    # the pause expires on its own
    env.checker.calls.clear()
    await env.cycle()
    assert sorted(address for address, _ in env.checker.calls) == [B, C]


async def test_manual_checks_cannot_force_down(env, clock):
    servers = await env.add_servers(A)
    await env.cycle()
    env.checker.fail(A)
    clock.advance(180)
    for _ in range(6):                      # the owner hammers "check now"
        await env.monitor.check_now(servers[0]["id"])
    await env.alerts.drain()
    assert (await env.states())[A] in ("OK", "SUSPECT")
    assert await env.messages("down") == []


async def test_restart_keeps_state_and_does_not_repeat_notifications(env, clock):
    from rwmon.monitor.alerts import Alerts
    await env.add_servers(A)
    await env.cycle()
    env.checker.fail(A)
    clock.advance(180)
    await env.cycle(); clock.advance(31); await env.rechecks(); clock.advance(61); await env.rechecks()
    assert len(await env.messages("down")) == 1
    # "restart": new alert processor over the same database
    await env.alerts.stop()
    alerts = Alerts(env.config, env.db, env.settings, env.outbox, env.cc)
    await alerts.start()
    await alerts.drain()
    env.monitor.alerts = env.alerts = alerts
    assert len(await env.messages("down")) == 1
    assert (await env.states())[A] == "DOWN"


async def test_interrupted_notification_is_sent_after_restart(env, clock):
    from rwmon.monitor.alerts import Alerts
    await env.add_servers(A)
    await env.cycle()
    env.checker.fail(A)
    await env.alerts.stop()                 # the process dies right after DOWN was confirmed
    clock.advance(180)
    await env.monitor._round(await env.monitor.active_servers(), "scheduled")
    clock.advance(31); await env.monitor._round(await env.monitor.active_servers(), "recheck")
    clock.advance(61); await env.monitor._round(await env.monitor.active_servers(), "recheck")
    assert (await env.states())[A] == "DOWN" and await env.messages("down") == []
    alerts = Alerts(env.config, env.db, env.settings, env.outbox, env.cc)
    await alerts.start()
    await alerts.drain()
    env.alerts = alerts
    assert len(await env.messages("down")) == 1


async def test_flapping_server_is_reported_once(env, clock):
    await env.add_servers(A)
    await env.cycle()
    for _ in range(4):
        env.checker.fail(A)
        clock.advance(180); await env.cycle(); clock.advance(31); await env.rechecks(); clock.advance(61); await env.rechecks()
        assert (await env.states())[A] == "DOWN"
        env.checker.heal(A)
        clock.advance(180); await env.cycle(); clock.advance(31); await env.rechecks(); clock.advance(31); await env.rechecks()
        assert (await env.states())[A] == "RECOVERED"
    assert len(await env.messages("down")) == 2          # the first two incidents are reported normally
    assert len(await env.messages("recovered")) == 2
    assert len(await env.messages("flapping")) == 1      # then a single "unstable" message
    clock.advance(3700)
    await env.alerts.check_flapping()
    assert len(await env.messages("stable")) == 1


async def test_dns_problem_of_the_monitor_is_reported_separately(env, clock):
    await env.add_servers(A, B)
    await env.cycle()
    env.health.dns_ok = False                       # resolver of the VPS is broken, connectivity is fine
    for _ in range(4):
        clock.advance(180)
        summary = await env.cycle()
        assert not summary.frozen                   # checks keep running through fallback resolvers
    assert set((await env.states()).values()) == {"OK"}
    problems = await env.messages("monitor_problem")
    assert len(problems) == 1 and "Проблема DNS на сервере мониторинга" in problems[0]["text"]
    env.health.dns_ok = True
    clock.advance(180)
    await env.cycle()
    assert len(await env.messages("monitor_restored")) == 1


async def test_partial_availability_is_a_warning_not_an_outage(env, clock):
    from tests.fakes.checks import ok_result

    def partial():
        result = ok_result()
        result.partial, result.partial_note = True, "не отвечают 198.51.100.2 (tcp_timeout)"
        return result

    await env.add_servers(A)
    await env.cycle()
    env.checker.set(A, partial)
    for _ in range(2):
        clock.advance(180)
        await env.cycle()
    assert await env.messages("partial") == []                      # needs the same confirmation as a failure
    clock.advance(180)
    await env.cycle()
    warnings = await env.messages("partial")
    assert len(warnings) == 1 and "Частичная недоступность" in warnings[0]["text"] and "198.51.100.2" in warnings[0]["text"]
    for _ in range(3):
        clock.advance(180)
        await env.cycle()
    assert len(await env.messages("partial")) == 1                  # not repeated
    assert (await env.states())[A] == "OK" and await env.messages("down") == []
    env.checker.heal(A)
    for _ in range(3):
        clock.advance(180)
        await env.cycle()
    assert len(await env.messages("partial_ok")) == 1


async def test_global_pause_stops_checks_and_resumes(env, clock):
    await env.add_servers(A, B)
    await env.settings.set_pause(True)
    env.monitor.next_cycle_at = 0
    for _ in range(3):
        assert await env.monitor._tick() == 5.0
    assert env.checker.calls == []
    await env.settings.set_pause(False)
    await env.monitor._tick()
    assert sorted(address for address, _ in env.checker.calls) == [A, B]
    # a timed pause ends on its own
    import time
    await env.settings.set_pause(True, int(time.time()) + 600)
    env.checker.calls.clear()
    env.monitor.next_cycle_at = 0
    await env.monitor._tick()
    assert env.checker.calls == []
    clock.advance(601)
    await env.monitor._tick()
    assert len(env.checker.calls) == 2


async def test_scheduler_runs_cycles_and_due_rechecks(env, clock):
    await env.add_servers(A, B)
    await env.monitor._tick()                                       # first cycle
    assert (await env.states()) == {A: "OK", B: "OK"}
    env.checker.fail(A)
    clock.advance(181)
    await env.monitor._tick()                                       # cycle: first failure
    assert (await env.states())[A] == "SUSPECT"
    env.checker.calls.clear()
    clock.advance(10)
    await env.monitor._tick()                                       # too early for the recheck
    assert env.checker.calls == []
    clock.advance(21)
    await env.monitor._tick()                                       # recheck of the suspect only
    assert [address for address, _ in env.checker.calls] == [A]
    clock.advance(61)
    await env.monitor._tick()
    await env.alerts.drain()
    assert (await env.states())[A] == "DOWN" and len(await env.messages("down")) == 1
    assert env.monitor.last_cycle is not None and env.monitor.last_cycle.checked == 2


async def test_start_after_long_downtime_drops_unconfirmed_suspicions(env, clock):
    import time
    servers = await env.add_servers(A, B, C)
    await env.cycle()
    env.checker.fail(A, B)
    clock.advance(180)
    await env.cycle(); clock.advance(31); await env.rechecks(); clock.advance(61); await env.rechecks()
    env.checker.fail(C)
    clock.advance(180)
    await env.cycle()                                               # C: one unconfirmed failure
    assert await env.states() == {A: "DOWN", B: "DOWN", C: "SUSPECT"}
    await env.settings.set_raw("runtime.alive", int(time.time()))
    clock.advance(2 * 3600)                                         # the VPS was off for two hours
    env.checker.heal(A, B, C)
    env.health.foreign_ok = False                                   # ...and the network is not up yet at start
    env.monitor.ready_poll = 0.05
    await env.monitor.start()
    try:
        import asyncio
        await asyncio.sleep(0.4)
        assert env.checker.calls[-1][0] == C and len([c for c in env.checker.calls]) > 0
        calls_before = len(env.checker.calls)
        await asyncio.sleep(0.3)
        assert len(env.checker.calls) == calls_before               # no checks until our own network works
        states = await env.states()
        assert states == {A: "DOWN", B: "DOWN", C: "OK"}            # confirmed stays, suspicion is dropped
        started = (await env.messages("started"))[0]["text"]
        assert "Не работал: 2 ч (" in started and "недоступных на момент остановки: 2" in started
        env.health.foreign_ok = True
        await asyncio.sleep(0.5)
        assert len(env.checker.calls) >= calls_before + 3           # the first cycle ran once the network was back
    finally:
        await env.monitor.stop()
    assert servers and len(await env.messages("down")) == 2          # the two old alerts; nothing new after the restart


async def test_recheck_pause_counts_from_the_end_of_the_check(env, clock):
    """A slow round must not eat the pause between observations."""
    import time

    from tests.fakes.checks import fail_result

    servers = await env.add_servers(A)
    await env.cycle()

    def slow_fail():
        clock.advance(40)                    # the check itself (timeouts, a long round) takes 40 s
        return fail_result()

    env.checker.set(A, slow_fail)
    clock.advance(180)
    started = int(time.time())
    await env.cycle()
    row = await env.monitor.get_server(servers[0]["id"])
    assert row["state"] == "SUSPECT"
    assert row["next_check_at"] >= started + 40 + 30         # first recheck pause (30 s) after the check finished
    assert row["first_fail_at"] >= started + 40
    assert await env.rechecks() is None                      # nothing is due right after the slow round


async def test_several_configs_of_one_host_make_one_alert(env, clock):
    """VLESS on 443 and Trojan on 8443 of the same machine: one DOWN message, one RECOVERED message."""
    from tests.fakes.panel import vless_link
    env.panel.links = [
        vless_link("DE reality", A, port=443),
        f"trojan://secret@{A}:8443?type=ws&security=tls&sni={A}&path=%2Fws#DE%20trojan",
        vless_link("Other", B),
    ]
    assert (await env.subs.add(env.panel.url)).total == 3
    await env.cycle()
    env.checker.fail(A)
    clock.advance(180)
    await env.cycle(); clock.advance(31); await env.rechecks(); clock.advance(61); await env.rechecks()
    downs = await env.messages("down")
    assert len(downs) == 1 and await env.db.scalar("SELECT COUNT(*) FROM incidents") == 2
    text = downs[0]["text"]
    assert "Недоступны конфигурации" in text and "443 · VLESS · TCP · REALITY" in text and "8443 · Trojan · WebSocket · TLS" in text
    env.checker.heal(A)
    clock.advance(180); await env.cycle(); clock.advance(31); await env.rechecks(); clock.advance(31); await env.rechecks()
    ups = await env.messages("recovered")
    assert len(ups) == 1 and "Восстановлены конфигурации" in ups[0]["text"] and ups[0]["reply_to"] == downs[0]["id"]
    assert await env.db.scalar("SELECT COUNT(*) FROM incidents WHERE up_notif_id IS NULL") == 0


async def test_recovery_is_reported_after_unmute_or_stabilisation(env, clock):
    servers = await env.add_servers(A, B)
    await env.cycle()
    await env.monitor.mute_server(servers[0]["id"], True)
    env.checker.fail(A)
    clock.advance(180)
    await env.cycle(); clock.advance(31); await env.rechecks(); clock.advance(61); await env.rechecks()
    assert (await env.states())[A] == "DOWN" and await env.messages("down") == []      # muted: silent
    await env.monitor.mute_server(servers[0]["id"], False)                             # the owner unmutes it
    env.checker.heal(A)
    clock.advance(180); await env.cycle(); clock.advance(31); await env.rechecks(); clock.advance(31); await env.rechecks()
    ups = await env.messages("recovered")
    assert len(ups) == 1 and ups[0]["reply_to"] is None and "Был недоступен" in ups[0]["text"]

    # a server that was flapping and then stayed down: the owner is told, and hears about the recovery
    clock.advance(700); await env.cycle()
    for _ in range(3):
        env.checker.fail(B)
        clock.advance(180); await env.cycle(); clock.advance(31); await env.rechecks(); clock.advance(61); await env.rechecks()
        if _ < 2:
            env.checker.heal(B)
            clock.advance(180); await env.cycle(); clock.advance(31); await env.rechecks(); clock.advance(31); await env.rechecks()
    assert len(await env.messages("flapping")) == 1 and (await env.states())[B] == "DOWN"
    clock.advance(3700)
    await env.cycle()
    await env.alerts.check_flapping()                                                  # done by the scheduler after each cycle
    stable = await env.messages("stable")
    assert len(stable) == 1 and "остаётся <b>недоступным</b>" in stable[0]["text"]
    before = len(await env.messages("recovered"))
    env.checker.heal(B)
    clock.advance(180); await env.cycle(); clock.advance(31); await env.rechecks(); clock.advance(31); await env.rechecks()
    assert len(await env.messages("recovered")) == before + 1
