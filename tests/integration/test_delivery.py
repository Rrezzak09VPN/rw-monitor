"""Notification delivery and the Telegram route (proxy), against fake servers."""

import asyncio

from rwmon.telegram import notifier as notifier_module

from ..conftest import OWNER, TOKEN
from ..fakes.socks import Socks5Proxy
from .conftest import build_tg

A, B = "a.example.com", "b.example.com"


async def take_down(env, clock, *hosts):
    env.checker.fail(*hosts)
    clock.advance(180)
    await env.cycle(); clock.advance(31); await env.rechecks(); clock.advance(61); await env.rechecks()


async def test_down_and_recovered_reach_the_owner(tg, clock):
    await tg.add_servers(A, B)
    await tg.cycle()
    await take_down(tg, clock, A)
    await tg.flush()
    down = tg.api.sent[-1]
    assert down["chat_id"] == OWNER and "СЕРВЕР НЕДОСТУПЕН" in down["text"] and not down["silent"]
    assert down["buttons"][0][0]["callback_data"].startswith("srv:")
    tg.checker.heal(A)
    clock.advance(180); await tg.cycle(); clock.advance(31); await tg.rechecks(); clock.advance(31); await tg.rechecks()
    await tg.flush()
    up = tg.api.sent[-1]
    assert "СЕРВЕР ВОССТАНОВЛЕН" in up["text"] and up["reply_to"] == down["message_id"]
    assert "Был недоступен" in up["text"]
    rows = await tg.db.fetchall("SELECT status, tg_message_id FROM notifications ORDER BY id")
    assert [row["status"] for row in rows] == ["sent", "sent"] and all(row["tg_message_id"] for row in rows)


async def test_telegram_outage_delays_but_never_loses(tg, clock, monkeypatch, caplog):
    import logging
    monkeypatch.setattr(notifier_module, "RETRY_PAUSES", (0.2, 0.2, 0.2))
    await tg.add_servers(A)
    await tg.cycle()
    for mode in ("502", "drop"):                      # a gateway error page, then a dropped connection
        tg.api.fail = mode
        caplog.clear()
        await tg.outbox.add("probe", f"проверка режима {mode}")
        await asyncio.sleep(0.7)
        assert "нет связи с Telegram" in tg.notifier.last_error, mode
        assert not [r for r in caplog.records if r.name == "rwmon.telegram.notifier" and r.levelno >= logging.ERROR], mode
        await tg.db.execute("DELETE FROM notifications")
    tg.api.fail = "502"                               # Telegram (or the proxy) is unreachable
    await take_down(tg, clock, A)
    await tg.alerts.drain()
    await asyncio.sleep(0.8)
    assert tg.api.sent == []
    assert await tg.outbox.pending_count() == 1
    assert (await tg.states())[A] == "DOWN"            # monitoring itself is unaffected
    clock.advance(900)
    tg.api.fail = ""
    await tg.flush()
    assert len(tg.api.sent) == 1
    text = tg.api.sent[0]["text"]
    assert "СЕРВЕР НЕДОСТУПЕН" in text and "Доставлено с задержкой" in text
    assert "Обнаружено:" in text                       # the original detection time is in the message


async def test_rate_limit_bad_markup_and_forbidden(tg, monkeypatch):
    monkeypatch.setattr(notifier_module, "RETRY_PAUSES", (0.2,))
    tg.api.fail = "429"
    await tg.outbox.add("test", "первое")
    await asyncio.sleep(2.6)                           # retry_after = 1 s is honoured
    assert [item["text"] for item in tg.api.sent] == ["первое"]
    await tg.outbox.add("test", "<bad>сломанная</bad> разметка <b>текст</b>")
    await tg.flush()
    assert tg.api.sent[-1]["text"] == "сломанная разметка текст"       # resent as plain text, not lost
    await tg.outbox.add("test", "x", dedup_key="once")
    assert await tg.outbox.add("test", "x", dedup_key="once") is None  # same event is never queued twice


async def test_restart_delivers_pending_messages(tmp_path, clock):
    env, close = await build_tg(tmp_path)
    try:
        env.api.fail = "502"
        await env.add_servers(A)
        await env.cycle()
        await take_down(env, clock, A)
        await env.alerts.drain()
        assert await env.outbox.pending_count() == 1
        token_holder = env.api
    finally:
        await close()
    # a new process over the same data directory
    env2, close2 = await build_tg(tmp_path)
    try:
        await env2.flush()
        assert len(env2.api.sent) == 1 and "СЕРВЕР НЕДОСТУПЕН" in env2.api.sent[0]["text"]
        assert (await env2.states())[A] == "DOWN"
        assert await env2.db.scalar("SELECT COUNT(*) FROM incidents") == 1
        assert token_holder is not env2.api
    finally:
        await close2()


async def test_telegram_goes_through_proxy_and_checks_do_not(tmp_path, clock):
    proxy = await Socks5Proxy("tguser", "tgpass").start()
    env, close = await build_tg(tmp_path, proxy_url=proxy.url)
    try:
        assert await env.botman.ensure_reachable()
        await env.say("/start")
        assert "Мониторинг серверов" in env.api.last_text()
        assert proxy.targets and all(target == ("127.0.0.1", env.api.port) for target in proxy.targets)
        # subscription download and Cheburcheck never use the Telegram proxy
        seen = len(proxy.targets)
        await env.add_servers(A)
        assert env.panel.requests and all(port != env.panel.port for _, port in proxy.targets)
        await env.press("st")
        assert "Telegram: socks5://***@127.0.0.1" in env.api.last_text()
        assert "tgpass" not in env.api.last_text()
        assert len(proxy.targets) >= seen

        # the proxy dies: monitoring continues, notifications wait, nothing is lost
        await proxy.go_down()
        await env.cycle()
        env.checker.fail(A)
        clock.advance(180)
        await env.cycle(); clock.advance(31); await env.rechecks(); clock.advance(61); await env.rechecks()
        await env.alerts.drain()
        assert (await env.states())[A] == "DOWN" and await env.outbox.pending_count() == 1
        proxy.enabled = True
        env.notifier._failures = 0
        await env.flush()
        assert "СЕРВЕР НЕДОСТУПЕН" in env.api.sent[-1]["text"]
    finally:
        await close()
        await proxy.stop()


async def test_proxy_change_is_tested_before_it_is_applied(tmp_path):
    good = await Socks5Proxy().start()
    dead = await Socks5Proxy().start()
    await dead.stop()
    env, close = await build_tg(tmp_path)
    try:
        await env.say("/start")
        await env.press("set:c:telegram_proxy_url")
        await env.say("ftp://bad")
        assert "схема прокси" in env.api.last_text() and env.botman.proxy_url == ""
        await env.press("set:c:telegram_proxy_url")
        await env.say(dead.url)
        assert "не изменена" in await env.wait_text("прокси не работает")
        assert env.botman.proxy_url == "" and not env.settings.is_overridden("telegram_proxy_url")
        await env.say("/start")                           # the bot is still reachable the old way
        assert "Мониторинг серверов" in env.api.last_text()

        await env.press("set:c:telegram_proxy_url")
        await env.say(good.url)
        assert "прокси применён" in await env.wait_text("прокси применён")
        assert env.botman.proxy_url == good.url and env.settings.get("telegram_proxy_url") == good.url
        assert len(env.api.deleted) >= 3                  # messages with proxy addresses are removed from the chat
        before = len(good.targets)
        await env.say("/status")
        assert len(good.targets) > before                 # traffic really flows through the new proxy
        stored = await env.db.scalar("SELECT value FROM settings WHERE key='telegram_proxy_url'")
        assert stored.startswith("enc:")                  # encrypted at rest
        await env.press("set:r:telegram_proxy_url")
        await env.wait_text("из файла конфигурации")
        assert env.botman.proxy_url == "" and not env.settings.is_overridden("telegram_proxy_url")
    finally:
        await close()
        await good.stop()


async def test_broken_saved_proxy_falls_back_to_config_on_start(tmp_path):
    dead = await Socks5Proxy().start()
    await dead.stop()
    env, close = await build_tg(tmp_path)
    try:
        await env.settings.set("telegram_proxy_url", dead.url)      # a proxy saved earlier that no longer works
        from rwmon.telegram.bot import BotManager
        manager = BotManager(env.config, env.settings)
        assert manager.proxy_url == dead.url
        assert await manager.ensure_reachable()
        assert manager.proxy_url == "" and manager.reverted and not env.settings.is_overridden("telegram_proxy_url")
        await manager.close()
    finally:
        await close()


async def test_token_never_appears_in_logs(tg, caplog):
    import logging

    from rwmon.logging_setup import MaskingFormatter
    formatter = MaskingFormatter("%(message)s")
    record = logging.LogRecord("x", logging.ERROR, "", 0, "request to https://api.telegram.org/bot%s/getMe failed", (TOKEN,), None)
    assert TOKEN not in formatter.format(record) and "***" in formatter.format(record)


async def test_dead_proxy_is_handled_quietly_everywhere(tmp_path, caplog, monkeypatch):
    """A refused proxy connection raises aiohttp-socks' own exception types; none of them may escape."""
    import logging

    from rwmon.cheburcheck.client import UNAVAILABLE, CheburcheckClient, CheburcheckError
    from rwmon.subscription.fetcher import SubscriptionFetcher

    monkeypatch.setattr(notifier_module, "RETRY_PAUSES", (0.2, 0.2, 0.2))
    dead = await Socks5Proxy().start()
    await dead.stop()                                   # nothing listens there any more: ECONNREFUSED
    env, close = await build_tg(tmp_path)
    try:
        await env.botman._swap(dead.url)                # the Telegram proxy has just died
        caplog.set_level(logging.WARNING)
        await env.outbox.add("test", "важное сообщение")
        await asyncio.sleep(1.0)
        assert await env.outbox.pending_count() == 1    # kept for later
        assert "нет связи с Telegram" in env.notifier.last_error
        row = await env.db.fetchone("SELECT attempts, last_error FROM notifications WHERE status='pending'")
        assert row["attempts"] >= 2 and "нет связи" in row["last_error"]
        assert not [r for r in caplog.records if r.name == "rwmon.telegram.notifier" and r.levelno >= logging.ERROR]
        await env.botman._swap("")                      # the route is back
        await env.flush()
        assert env.api.sent[-1]["text"] == "важное сообщение"

        client = CheburcheckClient("http://127.0.0.1:9", proxy_url=dead.url, timeout=3)
        try:
            await client.check("1.1.1.1")
            raise AssertionError("an error was expected")
        except CheburcheckError as exc:
            assert exc.kind == UNAVAILABLE and exc.service_down
        finally:
            await client.close()

        object.__setattr__(env.config, "subscription_proxy_url", dead.url)
        fetcher = SubscriptionFetcher(env.config, lambda: "hwid")
        try:
            response = await fetcher.request(env.panel.url, "rw-monitor/1.0", False)
            assert response.error == "proxy" and "прокси" in response.error_text
        finally:
            await fetcher.close()
    finally:
        await close()


async def test_queue_is_flushed_as_soon_as_telegram_is_reachable_again(tg, monkeypatch):
    """No waiting out a long retry pause once a probe has shown that the route works."""
    monkeypatch.setattr(notifier_module, "RETRY_PAUSES", (30, 30, 30))      # the next retry would be far away
    tg.botman.on_reachable = tg.notifier.kick                               # wired the same way in the application
    tg.api.fail = "502"
    await tg.outbox.add("test", "сообщение из очереди")
    await asyncio.sleep(0.5)
    assert await tg.outbox.pending_count() == 1 and "нет связи с Telegram" in tg.notifier.last_error
    tg.api.fail = ""
    assert await tg.botman.ensure_reachable()                               # e.g. the periodic probe succeeds
    await asyncio.sleep(1.0)
    assert await tg.outbox.pending_count() == 0
    assert tg.api.sent[-1]["text"] == "сообщение из очереди"
