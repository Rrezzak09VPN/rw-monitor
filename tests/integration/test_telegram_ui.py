"""The real aiogram bot against a fake Bot API: access control, menus, flows."""

import time

from ..conftest import OWNER
from ..fakes.panel import vless_link

STRANGER = 555000999
A, B, C = "a.example.com", "b.example.com", "c.example.com"


async def test_owner_gets_menu(tg):
    await tg.say("/start")
    assert "Мониторинг серверов Remnawave" in tg.api.last_text()
    labels = [button["text"] for row in tg.api.sent[-1]["buttons"] for button in row]
    assert labels == [
        "📊 Статус мониторинга", "🖥 Список серверов", "➕ Добавить подписку", "⚙️ Настройки мониторинга",
        "🔕 Управление исключениями", "📋 История событий", "🔄 Проверить все серверы"]
    assert tg.api.sent[-1]["chat_id"] == OWNER and tg.api.sent[-1]["parse_mode"] == "HTML"


async def test_strangers_are_ignored_completely(tg):
    await tg.say("/start")
    menu_id = tg.api.sent[-1]["message_id"]
    before = (len(tg.api.sent), len(tg.api.edits), len(tg.api.answers), len(tg.api.deleted))
    await tg.say("/start", user=STRANGER)
    await tg.say("/status", user=STRANGER)
    await tg.say("https://panel.example.com/sub/stolen", user=STRANGER)
    await tg.press("all", user=STRANGER, message_id=menu_id)
    await tg.press("set:pause:0", user=STRANGER, message_id=menu_id)
    await tg.press("srv:1:off", user=STRANGER, message_id=menu_id)
    # the owner writing in a group, or pressing a button there, is ignored too
    await tg.say("/start", user=OWNER, chat_type="group", chat_id=-100123)
    await tg.press("all", user=OWNER, message_id=menu_id, chat_type="supergroup")
    after = (len(tg.api.sent), len(tg.api.edits), len(tg.api.answers), len(tg.api.deleted))
    assert after == before                       # no reply, no callback answer, nothing
    assert tg.gate.dropped == 8
    assert await tg.db.scalar("SELECT COUNT(*) FROM subscriptions") == 0
    assert tg.settings.pause_state() == (False, 0)
    assert tg.checker.calls == []


async def test_subscription_added_from_link_and_message_deleted(tg):
    tg.panel.links = [vless_link("Germany", A), vless_link("Poland", B)]
    await tg.say(f"вот ссылка {tg.panel.url}")
    assert len(tg.api.deleted) == 1                                   # the message with the secret link is removed
    text = tg.api.last_text()
    assert "Подписка добавлена" in text and "Серверов: <b>2</b>" in text and "Germany" in text
    assert tg.panel.token not in "".join(item["text"] for item in tg.api.sent + tg.api.edits)   # full URL never echoed
    assert await tg.db.scalar("SELECT COUNT(*) FROM servers WHERE archived=0") == 2

    # sending the same link again refreshes: new servers appear, missing ones are removed
    tg.panel.links = [vless_link("Germany", A), vless_link("France", C)]
    await tg.say(tg.panel.url)
    text = tg.api.last_text()
    assert "Подписка обновлена" in text and "Добавлены (1): France" in text and "Удалены (1): Poland" in text
    rows = await tg.db.fetchall("SELECT name, archived FROM servers ORDER BY id")
    assert [(row["name"], row["archived"]) for row in rows] == [("Germany", 0), ("Poland", 1), ("France", 0)]


async def test_add_via_button_and_bad_input(tg):
    await tg.say("/start")
    await tg.press("sub")
    await tg.press("sub:add")
    assert "Пришлите ссылку" in tg.api.last_text()
    await tg.say("это не ссылка")
    assert "не похоже на ссылку" in tg.api.last_text()
    tg.panel.mode = "error500"
    await tg.say(tg.panel.url)
    assert "загрузить не удалось" in tg.api.last_text() and "HTTP 500" in tg.api.last_text()
    assert await tg.db.scalar("SELECT COUNT(*) FROM subscriptions") == 0


async def test_hwid_requires_explicit_consent(tg):
    tg.panel.links = [vless_link("Germany", A)]
    tg.panel.mode = "hwid"
    await tg.say(tg.panel.url)
    assert "идентификатор устройства" in tg.api.last_text()
    assert all(not request["hwid"] for request in tg.panel.requests)   # nothing sent before consent
    assert await tg.db.scalar("SELECT COUNT(*) FROM subscriptions") == 0
    await tg.press("sub:hwid:yes")
    assert "Подписка добавлена" in tg.api.last_text()
    assert tg.panel.requests[-1]["hwid"]
    sub = await tg.db.fetchone("SELECT use_hwid FROM subscriptions")
    assert sub["use_hwid"] == 1


async def test_list_card_and_manual_check(tg, clock):
    servers = await tg.add_servers(A, B)
    await tg.cycle()
    await tg.say("/start")
    await tg.press("ls:a:0")
    text = tg.api.last_text()
    assert "Srv-1" in text and f"{A}:443" in text and "доступен, 42 мс" in text and "🟢" in text
    sid = servers[0]["id"]
    await tg.press(f"srv:{sid}")
    card = tg.api.last_text()
    assert "VLESS · TCP · REALITY" in card and "OK" in card and "Мониторинг: включён" in card
    assert set(tg.api.last_buttons()) >= {f"srv:{sid}:chk", f"srv:{sid}:off", f"srv:{sid}:exc", f"srv:{sid}:det",
                                          f"srv:{sid}:his", f"srv:{sid}:cc"}
    tg.checker.fail(A)
    clock.advance(180)
    await tg.press(f"srv:{sid}:chk")
    text = tg.api.last_text()
    assert "❌" in text and "нет ответа на TCP-соединение" in text and "ещё не падение" in text
    await tg.press(f"srv:{sid}:det")
    assert "Последняя проверка" in tg.api.last_text() and "Подписка:" in tg.api.last_text()
    await tg.press(f"srv:{sid}:his")
    assert "Доля доступности" in tg.api.last_text()
    await tg.press("ls:p:0")
    assert "Srv-1" in tg.api.last_text() and "Srv-2" not in tg.api.last_text()


async def test_exclusions_are_separate_from_muting(tg, clock):
    servers = await tg.add_servers(A, B)
    sid = servers[0]["id"]
    await tg.cycle()
    await tg.say("/start")
    await tg.press(f"srv:{sid}:mute")
    row = await tg.monitor.get_server(sid)
    assert row["notify_muted"] == 1 and row["monitor_enabled"] == 1      # muted, still checked
    await tg.press(f"srv:{sid}:unmute")
    await tg.press(f"srv:{sid}:off")
    row = await tg.monitor.get_server(sid)
    assert row["monitor_enabled"] == 0 and row["notify_muted"] == 0 and row["state"] == "UNKNOWN"
    tg.checker.calls.clear()
    clock.advance(180)
    await tg.cycle()
    assert [address for address, _ in tg.checker.calls] == [B]
    await tg.press("exc:0")
    assert "Srv-1" in tg.api.last_text() and "исключён" in tg.api.last_text()
    await tg.press(f"exc:on:{sid}:0")
    assert (await tg.monitor.get_server(sid))["monitor_enabled"] == 1
    # temporary pause, including a custom duration typed by the owner
    await tg.press(f"srv:{sid}:p:3600")
    assert (await tg.monitor.get_server(sid))["paused_until"] > time.time() + 3500
    await tg.press(f"srv:{sid}:on")
    await tg.press(f"srv:{sid}:pc")
    await tg.say("ерунда")
    assert "Укажите срок" in tg.api.last_text()
    await tg.say("2h")
    paused = (await tg.monitor.get_server(sid))["paused_until"]
    assert 7100 < paused - time.time() < 7300


async def test_excluding_a_down_server_closes_incident_silently(tg, clock):
    servers = await tg.add_servers(A)
    await tg.cycle()
    tg.checker.fail(A)
    clock.advance(180)
    await tg.cycle(); clock.advance(31); await tg.rechecks(); clock.advance(61); await tg.rechecks()
    await tg.flush()
    assert (await tg.states())[A] == "DOWN"
    await tg.say("/start")
    await tg.press(f"srv:{servers[0]['id']}:off")
    incident = await tg.db.fetchone("SELECT * FROM incidents")
    assert incident["close_reason"] == "excluded"
    await tg.flush()
    assert await tg.messages("recovered") == []


async def test_settings_from_telegram_persist(tg):
    await tg.say("/start")
    await tg.press("set")
    assert "Интервал проверки: <b>3 мин</b>" in tg.api.last_text()
    await tg.press("set:k:check_interval")
    assert set(tg.api.last_buttons()) >= {"set:v:check_interval:1m", "set:v:check_interval:3m",
                                          "set:v:check_interval:5m", "set:v:check_interval:10m", "set:c:check_interval"}
    await tg.press("set:v:check_interval:10m")
    assert tg.settings.get("check_interval") == 600
    await tg.press("set:c:check_interval")
    await tg.say("7")                                   # below the allowed minimum
    assert "минимум" in tg.api.last_text() and tg.settings.get("check_interval") == 600
    await tg.say("45s")
    assert tg.settings.get("check_interval") == 45
    await tg.press("set:v:fail_threshold:4")
    await tg.press("set:v:recovery_threshold:2")
    await tg.press("set:c:recheck_intervals")
    await tg.say("20, 40, 80")
    await tg.press("set:v:tcp_timeout:8s")
    await tg.press("set:v:cheburcheck_enabled:on")
    await tg.press("set:pause:3600")
    # a fresh Settings object over the same database = state after a restart
    from rwmon.settings import Settings
    restarted = Settings(tg.config, tg.db)
    await restarted.load()
    assert restarted.get("check_interval") == 45 and restarted.get("fail_threshold") == 4
    assert restarted.get("recovery_threshold") == 2 and restarted.recheck_intervals == [20, 40, 80]
    assert restarted.get("tcp_timeout") == 8 and restarted.get("cheburcheck_enabled") is True
    assert restarted.pause_state()[0] is True
    await tg.press("set:pause:off")
    await tg.press("set:r:check_interval")
    assert tg.settings.get("check_interval") == 180 and tg.settings.pause_state()[0] is False
    await tg.press("set:reset:ok")
    assert tg.settings.get("fail_threshold") == 3


async def test_status_history_and_check_all(tg, clock):
    await tg.add_servers(A, B, C)
    await tg.cycle()
    tg.checker.fail(B)
    clock.advance(180)
    await tg.say("/start")
    await tg.press("all")
    text = tg.api.last_text()
    assert "Проверка завершена" in text and "Проверено: 3" in text and "Srv-2" in text and "SUSPECT" in text
    await tg.press("st")
    text = tg.api.last_text()
    assert "Статус мониторинга" in text and "Проверки серверов: напрямую" in text and "Telegram: без прокси" in text
    await tg.press("ev:a:0")
    assert "OK → SUSPECT" in tg.api.last_text()
    await tg.press("ev:m:0")
    await tg.press("set:backup")
    assert "Резервная копия создана" in tg.api.last_text()
    assert len(tg.ctx.maintenance.list_backups()) == 1


async def test_cheburcheck_button_in_server_card(tmp_path, clock):
    from ..fakes.cheburcheck import FakeCheburcheck
    from .conftest import build_tg

    fake = await FakeCheburcheck().start()
    env, close = await build_tg(tmp_path, cheburcheck_enabled=True, cheburcheck_base_url=fake.base_url)
    object.__setattr__(env.config, "cheburcheck_check_interval", 0.0)
    object.__setattr__(env.config, "cheburcheck_probe_interval", 0.0)
    try:
        servers = await env.add_servers(A)
        await env.cycle()
        await env.say("/start")
        await env.press(f"srv:{servers[0]['id']}:cc")
        text = await env.wait_text("Наличие в списках")
        assert "Cheburcheck: Srv-1" in text and "Замеры у операторов" in text and "✅ данные получены" in text
        assert "Состояние сервера определяют только собственные проверки бота" in text
        assert sorted(fake.check_calls) == ["93.184.216.34", A]            # the checked IP and the domain
        await env.press(f"srv:{servers[0]['id']}:cc")                      # again: answered from the local cache
        await env.wait_text("повторно не запрашивалось")
        assert len(fake.check_calls) == 2
        assert (await env.states())[A] == "OK"                             # a lookup never touches the state
    finally:
        await close()
        await fake.stop()
