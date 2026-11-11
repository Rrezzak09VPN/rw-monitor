"""Telegram handlers. Only the owner ever reaches this code (see OwnerOnlyMiddleware)."""

from __future__ import annotations

import logging
import re
import time
from typing import Any

from aiogram import F, Router
from aiogram.exceptions import TelegramAPIError, TelegramBadRequest
from aiogram.filters import Command, CommandStart
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.types import CallbackQuery, Message

from ..settings import SPEC_BY_KEY, SettingError
from ..subscription import fetcher
from ..subscription.model import is_ip
from ..timeutil import fmt_duration, fmt_short, fmt_time, parse_duration
from . import screens
from .context import Ctx
from .texts import code, h

log = logging.getLogger(__name__)

URL_RE = re.compile(r"https?://\S+", re.IGNORECASE)
MAX_PAUSE = 30 * 86400


class Input(StatesGroup):
    sub_url = State()
    setting = State()
    pause = State()


# ── helpers ─────────────────────────────────────────────────────────────────

async def show(target: Message | CallbackQuery, screen: screens.Screen) -> Message | None:
    """Render a screen: edit the message under the pressed button, or send a new one."""
    text, markup = screen
    if isinstance(target, CallbackQuery) and target.message is not None:
        try:
            return await target.message.edit_text(text, reply_markup=markup)  # type: ignore[union-attr]
        except TelegramBadRequest as exc:
            if "not modified" in str(exc).lower():
                return None
            log.debug("edit failed, sending a new message: %s", exc)
            return await target.message.answer(text, reply_markup=markup)
    message = target if isinstance(target, Message) else None
    if message is None:
        return None
    return await message.answer(text, reply_markup=markup)


async def answer(cb: CallbackQuery, text: str = "", alert: bool = False) -> None:
    try:
        await cb.answer(text[:190] if text else None, show_alert=alert)
    except TelegramAPIError:
        pass


async def delete_quietly(message: Message) -> bool:
    try:
        await message.delete()
        return True
    except TelegramAPIError:
        return False


def _int(value: str, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


async def _missing(cb: CallbackQuery, ctx: Ctx) -> None:
    await answer(cb, "Объект не найден — возможно, он удалён из подписки.", alert=True)
    await show(cb, await screens.home(ctx))


# ── commands ────────────────────────────────────────────────────────────────

async def cmd_menu(message: Message, state: FSMContext, ctx: Ctx) -> None:
    await state.set_state(None)
    await show(message, await screens.home(ctx))


async def cmd_status(message: Message, state: FSMContext, ctx: Ctx) -> None:
    await state.set_state(None)
    await show(message, await screens.status(ctx))


async def cmd_help(message: Message, ctx: Ctx) -> None:
    await message.answer(screens.HELP_TEXT, reply_markup=screens.kb([screens.HOME_ROW]))


async def cmd_cancel(message: Message, state: FSMContext, ctx: Ctx) -> None:
    had = await state.get_state()
    await state.set_state(None)
    await message.answer("Ввод отменён." if had else "Отменять нечего.", reply_markup=screens.kb([screens.HOME_ROW]))


# ── subscriptions: adding by URL ────────────────────────────────────────────

async def _report_sync(target: Message, ctx: Ctx, result: Any) -> None:
    rows: list[list[tuple[str, str]]] = []
    if result.status == "needs_confirm" and result.sub_id:
        rows.append([("✅ Подтвердить удаление серверов", f"sub:{result.sub_id}:force")])
    if result.ok:
        rows.append([("🖥 Список серверов", "ls:a:0")])
    rows.append([("📥 Подписки", "sub"), *screens.HOME_ROW])
    await target.edit_text(screens.sync_report(result), reply_markup=screens.kb(rows))


async def _add_subscription(message: Message, state: FSMContext, ctx: Ctx, url: str, allow_hwid: bool = False) -> None:
    progress = await message.answer("⏳ Загружаю подписку…")
    try:
        result = await ctx.subs.add(url, allow_hwid=allow_hwid)
    except ValueError as exc:
        await progress.edit_text(f"⚠️ {h(exc)}", reply_markup=screens.kb([[("📥 Подписки", "sub"), *screens.HOME_ROW]]))
        return
    except Exception:  # noqa: BLE001
        log.exception("adding a subscription failed")
        await progress.edit_text("⚠️ Внутренняя ошибка при загрузке подписки. Подробности — в журнале сервиса.",
                                 reply_markup=screens.kb([screens.HOME_ROW]))
        return
    if result.status == fetcher.NEEDS_HWID and not allow_hwid:
        await state.update_data(pending_url=url)
        await progress.edit_text(
            "🔐 <b>Панель требует идентификатор устройства (HWID)</b>\n\n"
            f"{h(result.message)}\n\n"
            "Чтобы получить список серверов, бот должен представиться панели как устройство с постоянным "
            "идентификатором. Это займёт <b>одно место</b> в лимите устройств подписки; идентификатор "
            "создаётся один раз и больше не меняется.\n\nРазрешить?",
            reply_markup=screens.kb([[("✅ Разрешить", "sub:hwid:yes")], [("Отмена", "sub:hwid:no")]]))
        return
    if result.sub_id:
        await ctx.monitor.subscription_refreshed(result.sub_id, result, interactive=True)
    await _report_sync(progress, ctx, result)


async def on_sub_url(message: Message, state: FSMContext, ctx: Ctx) -> None:
    found = URL_RE.search(message.text or "")
    if not found:
        await message.answer("Это не похоже на ссылку. Пришлите адрес вида https://… или /cancel для отмены.")
        return
    await state.set_state(None)
    await delete_quietly(message)
    await _add_subscription(message, state, ctx, found.group(0))


# ── settings: typed values ──────────────────────────────────────────────────

async def _apply_setting(ctx: Ctx, key: str, raw: str) -> tuple[bool, str]:
    spec = SPEC_BY_KEY[key]
    try:
        if key == "telegram_proxy_url":
            applied, text = await ctx.botman.change_proxy(raw)
            if applied:
                await ctx.monitor.note("settings", "прокси Telegram изменён")
            return applied, ("✅ " if applied else "⚠️ ") + h(text)
        await ctx.settings.set(key, raw)
    except SettingError as exc:
        return False, f"⚠️ {h(exc)}"
    await ctx.monitor.note("settings", f"{spec.title}: {ctx.settings.display(key)}")
    ctx.monitor.wake()
    return True, f"✅ Сохранено: {h(ctx.settings.display(key))}"


async def on_setting_value(message: Message, state: FSMContext, ctx: Ctx) -> None:
    data = await state.get_data()
    key = data.get("setting_key", "")
    if key not in SPEC_BY_KEY:
        await state.set_state(None)
        return
    if key == "telegram_proxy_url":
        await delete_quietly(message)       # the address may contain a password
        progress = await message.answer("⏳ Проверяю прокси…")
        ok, note = await _apply_setting(ctx, key, (message.text or "").strip())
        await state.set_state(None)
        screen = await screens.setting_screen(ctx, key, note)
        await progress.edit_text(screen[0], reply_markup=screen[1])
        return
    ok, note = await _apply_setting(ctx, key, (message.text or "").strip())
    if ok:
        await state.set_state(None)
    else:
        note += "\nПришлите другое значение или /cancel."
    screen = await screens.setting_screen(ctx, key, note)
    await message.answer(screen[0], reply_markup=screen[1])


async def on_pause_value(message: Message, state: FSMContext, ctx: Ctx) -> None:
    data = await state.get_data()
    server_id = _int(data.get("pause_server"))
    seconds = parse_duration(message.text or "")
    if seconds is None or not 60 <= seconds <= MAX_PAUSE:
        await message.answer("Укажите срок от 1 минуты до 30 дней, например: 90m, 3h, 2d. /cancel — отмена.")
        return
    await state.set_state(None)
    until = await ctx.monitor.pause_server(server_id, seconds)
    screen = await screens.server_card(ctx, server_id, f"⏸ Пауза до {fmt_short(until)} МСК.")
    if screen:
        await message.answer(screen[0], reply_markup=screen[1])


async def on_text(message: Message, state: FSMContext, ctx: Ctx) -> None:
    """A bare link is treated as a subscription; anything else brings up the menu."""
    found = URL_RE.search(message.text or "")
    if found:
        await delete_quietly(message)
        await _add_subscription(message, state, ctx, found.group(0))
        return
    await show(message, await screens.home(ctx))


async def on_other(message: Message, ctx: Ctx) -> None:
    await show(message, await screens.home(ctx))


# ── callbacks ───────────────────────────────────────────────────────────────

async def cb_home(cb: CallbackQuery, state: FSMContext, ctx: Ctx) -> None:
    await state.set_state(None)
    await answer(cb)
    await show(cb, await screens.home(ctx))


async def cb_status(cb: CallbackQuery, ctx: Ctx) -> None:
    await answer(cb)
    await show(cb, await screens.status(ctx))


async def cb_list(cb: CallbackQuery, state: FSMContext, ctx: Ctx) -> None:
    parts = (cb.data or "").split(":")
    if parts[1] == "b":
        data = await state.get_data()
        flt, page = data.get("list_filter", "a"), _int(data.get("list_page"))
    else:
        flt, page = parts[1], _int(parts[2] if len(parts) > 2 else "0")
    await state.update_data(list_filter=flt, list_page=page)
    await answer(cb)
    await show(cb, await screens.server_list(ctx, flt, page))


async def cb_server(cb: CallbackQuery, state: FSMContext, ctx: Ctx) -> None:
    parts = (cb.data or "").split(":")
    server_id = _int(parts[1])
    action = parts[2] if len(parts) > 2 else ""
    if action == "":
        screen = await screens.server_card(ctx, server_id)
    elif action == "chk":
        await _check_now(cb, ctx, server_id)
        return
    elif action == "det":
        screen = await screens.server_details(ctx, server_id)
    elif action == "his":
        screen = await screens.server_history(ctx, server_id)
    elif action == "exc":
        screen = await screens.server_exclusions(ctx, server_id)
    elif action in ("cc", "ccf"):
        await _cheburcheck(cb, ctx, server_id, force=action == "ccf")
        return
    elif action == "off":
        await ctx.monitor.exclude_server(server_id)
        screen = await screens.server_card(ctx, server_id, "🚫 Сервер исключён из мониторинга.")
    elif action == "on":
        await ctx.monitor.resume_server(server_id)
        screen = await screens.server_card(ctx, server_id, "▶️ Мониторинг возобновлён, проверка запущена.")
    elif action == "p":
        seconds = min(MAX_PAUSE, max(60, _int(parts[3] if len(parts) > 3 else "3600", 3600)))
        until = await ctx.monitor.pause_server(server_id, seconds)
        screen = await screens.server_card(ctx, server_id, f"⏸ Пауза до {fmt_short(until)} МСК.")
    elif action == "pc":
        await state.set_state(Input.pause)
        await state.update_data(pause_server=server_id)
        await answer(cb)
        if cb.message is not None:
            await cb.message.answer("На какой срок приостановить мониторинг сервера? Например: 90m, 3h, 2d.\n/cancel — отмена.")
        return
    elif action in ("mute", "unmute"):
        await ctx.monitor.mute_server(server_id, action == "mute")
        screen = await screens.server_exclusions(ctx, server_id)
    else:
        screen = await screens.server_card(ctx, server_id)
    if screen is None:
        await _missing(cb, ctx)
        return
    await answer(cb)
    await show(cb, screen)


async def _check_now(cb: CallbackQuery, ctx: Ctx, server_id: int) -> None:
    await answer(cb, "Проверяю…")
    outcome = await ctx.monitor.check_now(server_id)
    if outcome is None:
        await _missing(cb, ctx)
        return
    row, result, state_name = outcome
    lines = [f"🔄 <b>Проверка в {fmt_time(time.time())}</b>"]
    mark = "✅" if result.ok else ("➖" if result.ok is None else "❌")
    lines.append(f"{mark} {h(result.summary)}" + (f", {result.latency_ms} мс" if result.ok and result.latency_ms is not None else ""))
    lines.extend(screens.stage_lines(result.detail()))
    if result.ok is False and state_name != "DOWN":
        lines.append("<i>Одна неудача — ещё не падение: бот перепроверит сервер и сообщит, только если отказ подтвердится.</i>")
    screen = await screens.server_card(ctx, server_id, "\n".join(lines))
    if screen is None:
        await _missing(cb, ctx)
        return
    await show(cb, screen)


async def _cheburcheck(cb: CallbackQuery, ctx: Ctx, server_id: int, force: bool) -> None:
    row = await ctx.monitor.get_server(server_id)
    if row is None:
        await _missing(cb, ctx)
        return
    if not ctx.cc.enabled:
        await answer(cb, "Cheburcheck выключен в настройках.", alert=True)
        return
    await answer(cb)
    from ..db.database import jload
    targets: list[tuple[str, str]] = []
    if is_ip(row["address"]):
        targets.append((row["address"], "ip"))
    else:
        ips = jload(row["good_ips_json"], [])
        state = await ctx.db.fetchone("SELECT last_detail_json FROM server_state WHERE server_id=?", (server_id,))
        ips = (jload(state["last_detail_json"], {}).get("ips") if state else None) or ips
        targets += [(ip, "ip") for ip in ips[:1]]
        targets.append((row["address"], "domain"))
    await show(cb, screens.cheburcheck_screen(
        row, [], f"⏳ Запрашиваю данные по {len(targets)} целям. Сервис ограничивает частоту запросов, "
                 "это займёт до минуты…"))
    results = []
    for target, kind in targets:
        results.append(await ctx.cc.lookup_now(target, kind, use_cache=not force))
    await show(cb, screens.cheburcheck_screen(row, results))


async def cb_subscriptions(cb: CallbackQuery, state: FSMContext, ctx: Ctx) -> None:
    parts = (cb.data or "").split(":")
    if len(parts) == 1:
        await state.set_state(None)
        await answer(cb)
        await show(cb, await screens.subscriptions(ctx))
        return
    if parts[1] == "add":
        await state.set_state(Input.sub_url)
        await answer(cb)
        await show(cb, ("➕ <b>Добавление подписки</b>\n\nПришлите ссылку на подписку Remnawave одним сообщением.\n"
                        "Сообщение со ссылкой бот сразу удалит из чата, сама ссылка хранится в зашифрованном виде.\n\n"
                        "/cancel — отмена.", screens.kb([[("◀️ К подпискам", "sub")]])))
        return
    if parts[1] == "hwid":
        data = await state.get_data()
        url = data.get("pending_url")
        await state.update_data(pending_url=None)
        await answer(cb)
        if len(parts) > 2 and parts[2] == "yes" and url and cb.message is not None:
            await cb.message.edit_text("🔐 Отправка идентификатора устройства разрешена.")
            await _add_subscription(cb.message, state, ctx, url, allow_hwid=True)  # type: ignore[arg-type]
        else:
            await show(cb, await screens.subscriptions(ctx, "Добавление отменено."))
        return
    sub_id = _int(parts[1])
    action = parts[2] if len(parts) > 2 else ""
    if action in ("ref", "force"):
        await answer(cb, "Обновляю…")
        result = await ctx.subs.refresh(sub_id, force=action == "force", interactive=True)
        await ctx.monitor.subscription_refreshed(sub_id, result, interactive=True)
        note = screens.sync_report(result)
        screen = await screens.subscription_card(ctx, sub_id, note)
        if screen is not None and result.status == "needs_confirm":
            text, _ = screen
            screen = (text, screens.kb([[("✅ Подтвердить удаление серверов", f"sub:{sub_id}:force")],
                                        [("◀️ К подпискам", "sub"), *screens.HOME_ROW]]))
    elif action == "auto":
        sub = await ctx.subs.get(sub_id)
        if sub is not None:
            await ctx.subs.set_auto_refresh(sub_id, not sub["auto_refresh"])
        screen = await screens.subscription_card(ctx, sub_id)
    elif action == "del":
        sub = await ctx.subs.get(sub_id)
        if sub is None:
            await _missing(cb, ctx)
            return
        await answer(cb)
        await show(cb, screens.confirm_screen(
            f"🗑 Удалить подписку <b>{h(sub['title'] or sub['url_hint'])}</b>?\n\n"
            "Её серверы, которых нет в других подписках, перестанут отслеживаться. История сохранится.",
            ("🗑 Да, удалить", f"sub:{sub_id}:delok"), ("Отмена", f"sub:{sub_id}")))
        return
    elif action == "delok":
        archived = await ctx.subs.delete(sub_id)
        await ctx.monitor.note("subscription", f"подписка удалена, серверов снято с наблюдения: {len(archived)}")
        await answer(cb)
        await show(cb, await screens.subscriptions(ctx, f"🗑 Подписка удалена. Снято с наблюдения серверов: {len(archived)}."))
        return
    else:
        screen = await screens.subscription_card(ctx, sub_id)
    if screen is None:
        await _missing(cb, ctx)
        return
    await answer(cb)
    await show(cb, screen)


async def cb_settings(cb: CallbackQuery, state: FSMContext, ctx: Ctx) -> None:
    parts = (cb.data or "").split(":", 3)
    action = parts[1] if len(parts) > 1 else ""
    await state.set_state(None)
    if action == "":
        screen: screens.Screen | None = await screens.settings_root(ctx)
    elif action == "g":
        screen = await screens.settings_group(ctx, parts[2])
    elif action == "k":
        screen = await screens.setting_screen(ctx, parts[2])
    elif action == "v" and len(parts) > 3 and parts[2] in SPEC_BY_KEY:
        await answer(cb)
        _, note = await _apply_setting(ctx, parts[2], parts[3])
        await show(cb, await screens.setting_screen(ctx, parts[2], note))  # type: ignore[arg-type]
        return
    elif action == "c" and parts[2] in SPEC_BY_KEY:
        spec = SPEC_BY_KEY[parts[2]]
        await state.set_state(Input.setting)
        await state.update_data(setting_key=spec.key)
        await answer(cb)
        hint = spec.hint or {
            "duration": "Пришлите значение: число секунд или с единицей — 45s, 3m, 1h.",
            "int": "Пришлите целое число.", "intervals": "Пришлите секунды через запятую, например 30,60.",
        }.get(spec.kind, "Пришлите новое значение.")
        if cb.message is not None:
            await cb.message.answer(f"✏️ <b>{h(spec.title)}</b>\n{h(hint)}\n/cancel — отмена.")
        return
    elif action == "r" and parts[2] in SPEC_BY_KEY:
        await answer(cb)
        if parts[2] == "telegram_proxy_url":
            ok, text = await ctx.botman.reset_proxy()
            note = ("✅ " if ok else "⚠️ ") + h(text)
        else:
            await ctx.settings.reset(parts[2])
            note = "↩️ Возвращено значение из файла конфигурации."
        await ctx.monitor.note("settings", f"{SPEC_BY_KEY[parts[2]].title}: возвращено значение из конфигурации")
        ctx.monitor.wake()
        await show(cb, await screens.setting_screen(ctx, parts[2], note))  # type: ignore[arg-type]
        return
    elif action == "pause":
        if len(parts) == 2:
            screen = await screens.pause_screen(ctx)
        else:
            if parts[2] == "off":
                await ctx.settings.set_pause(False)
                await ctx.monitor.note("settings", "общая пауза снята")
                note = "▶️ Пауза снята, мониторинг возобновлён."
            else:
                seconds = max(0, _int(parts[2]))
                until = int(time.time()) + seconds if seconds else 0
                await ctx.settings.set_pause(True, until)
                await ctx.monitor.note("settings", "общая пауза включена" + (f" на {fmt_duration(seconds)}" if seconds else ""))
                note = "⏸ Мониторинг поставлен на паузу" + (f" на {fmt_duration(seconds)}." if seconds else " до ручного снятия.")
            ctx.monitor.wake()
            screen = await screens.settings_root(ctx, note)
    elif action == "reset":
        if len(parts) > 2 and parts[2] == "ok":
            keep_proxy = ctx.settings.is_overridden("telegram_proxy_url")
            proxy = ctx.settings.get("telegram_proxy_url") if keep_proxy else None
            count = await ctx.settings.reset_all()
            if keep_proxy:      # dropping the working Telegram route would cut the owner off
                await ctx.settings.set("telegram_proxy_url", proxy or "-")
                count -= 1
            await ctx.monitor.note("settings", "настройки сброшены к значениям из конфигурации")
            ctx.monitor.wake()
            screen = await screens.settings_root(ctx, f"♻️ Сброшено настроек: {count}. Прокси Telegram не менялся.")
        else:
            screen = screens.confirm_screen(
                "♻️ Вернуть все настройки к значениям из файла конфигурации?\n\nПрокси Telegram останется прежним.",
                ("♻️ Да, сбросить", "set:reset:ok"), ("Отмена", "set"))
    elif action == "backup":
        await answer(cb, "Создаю копию…")
        try:
            path = await ctx.maintenance.backup()
            await ctx.monitor.note("backup", f"создана копия {path.name}")
            copies = ctx.maintenance.list_backups()
            note = (f"💾 Резервная копия создана: {code(str(path))} ({path.stat().st_size // 1024} КБ).\n"
                    f"Всего копий: {len(copies)}. Восстановление — командой <code>rwmon restore</code> (см. README).")
        except Exception:  # noqa: BLE001
            log.exception("backup failed")
            note = "⚠️ Не удалось создать резервную копию. Подробности — в журнале сервиса."
        await show(cb, await screens.settings_root(ctx, note))
        return
    else:
        screen = await screens.settings_root(ctx)
    if screen is None:
        await _missing(cb, ctx)
        return
    await answer(cb)
    await show(cb, screen)


async def cb_exclusions(cb: CallbackQuery, ctx: Ctx) -> None:
    parts = (cb.data or "").split(":")
    page = 0
    if parts[1] in ("on", "unmute") and len(parts) > 2:
        server_id, page = _int(parts[2]), _int(parts[3] if len(parts) > 3 else "0")
        if parts[1] == "on":
            await ctx.monitor.resume_server(server_id)
        else:
            await ctx.monitor.mute_server(server_id, False)
    else:
        page = _int(parts[1])
    await answer(cb)
    await show(cb, await screens.exclusions(ctx, page))


async def cb_events(cb: CallbackQuery, ctx: Ctx) -> None:
    parts = (cb.data or "").split(":")
    await answer(cb)
    await show(cb, await screens.events(ctx, parts[1], _int(parts[2] if len(parts) > 2 else "0")))


async def cb_check_all(cb: CallbackQuery, ctx: Ctx) -> None:
    if ctx.monitor.manual_lock.locked():
        await answer(cb, "Проверка уже выполняется.", alert=True)
        return
    paused, _ = ctx.settings.pause_state()
    await answer(cb, "Мониторинг на паузе — выполняю разовую проверку." if paused else "")
    async with ctx.monitor.manual_lock:
        servers = await ctx.monitor.active_servers()
        if not servers:
            await show(cb, ("Серверов для проверки нет. Добавьте подписку.", screens.kb([screens.HOME_ROW])))
            return
        await show(cb, (screens.check_all_progress(0, len(servers)), screens.kb([])))
        last_edit = 0.0

        async def progress(done: int, total: int) -> None:
            nonlocal last_edit
            now = time.monotonic()
            if now - last_edit < 2.0 or done == total:
                return
            last_edit = now
            await show(cb, (screens.check_all_progress(done, total), screens.kb([])))

        summary = await ctx.monitor.check_all(progress)
        await show(cb, screens.check_all_report(summary))


async def cb_unknown(cb: CallbackQuery, ctx: Ctx) -> None:
    await answer(cb)
    await show(cb, await screens.home(ctx))


def build_router() -> Router:
    """Handlers in priority order: commands, typed input, plain text, then buttons."""
    router = Router(name="owner")
    router.message.register(cmd_menu, CommandStart())
    router.message.register(cmd_menu, Command("menu"))
    router.message.register(cmd_status, Command("status"))
    router.message.register(cmd_help, Command("help"))
    router.message.register(cmd_cancel, Command("cancel"))
    router.message.register(on_sub_url, Input.sub_url, F.text)
    router.message.register(on_setting_value, Input.setting, F.text)
    router.message.register(on_pause_value, Input.pause, F.text)
    router.message.register(on_text, F.text)
    router.message.register(on_other)
    router.callback_query.register(cb_home, F.data == "home")
    router.callback_query.register(cb_status, F.data == "st")
    router.callback_query.register(cb_list, F.data.startswith("ls:"))
    router.callback_query.register(cb_server, F.data.startswith("srv:"))
    router.callback_query.register(cb_subscriptions, F.data.startswith("sub"))
    router.callback_query.register(cb_settings, F.data.startswith("set"))
    router.callback_query.register(cb_exclusions, F.data.startswith("exc:"))
    router.callback_query.register(cb_events, F.data.startswith("ev:"))
    router.callback_query.register(cb_check_all, F.data == "all")
    router.callback_query.register(cb_unknown)
    return router
