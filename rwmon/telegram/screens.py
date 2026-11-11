"""Screens of the inline interface: each function returns (text, keyboard)."""

from __future__ import annotations

import time
from typing import Any

from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup

from ..checks.results import reason_text, short_reason
from ..db.database import Row, jload
from ..monitor import fsm
from ..security import mask_proxy
from ..settings import GROUP_TITLES, SPEC_BY_KEY, SPECS
from ..subscription.model import describe_kind
from ..timeutil import fmt_datetime, fmt_duration, fmt_interval, fmt_short, fmt_time
from . import texts
from .context import Ctx
from .texts import STATE_ICONS, STATE_NAMES, code, h

Screen = tuple[str, InlineKeyboardMarkup]
PAGE = 8
EVENTS_PAGE = 10
STATE_ORDER = {fsm.DOWN: 0, fsm.SUSPECT: 1, fsm.UNKNOWN: 2, fsm.RECOVERED: 3, fsm.OK: 4}
STAGE_TITLES = {"dns": "DNS", "tcp": "TCP", "quic": "QUIC/UDP", "tls": "TLS", "e2e": "Туннель"}
PAUSE_PRESETS = (("1 ч", 3600), ("6 ч", 6 * 3600), ("24 ч", 24 * 3600))


def kb(rows: list[list[tuple[str, str]]]) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text=text, callback_data=data) for text, data in row] for row in rows if row])


HOME_ROW = [("🏠 Меню", "home")]


def endpoint(row: Row) -> str:
    host = f"[{row['address']}]" if ":" in row["address"] else row["address"]
    return f"{host}:{row['port']}"


def flags(row: Row, now: int | None = None) -> str:
    now = now or int(time.time())
    marks = ""
    if not row["monitor_enabled"]:
        marks += " 🚫"
    elif row["paused_until"] and row["paused_until"] > now:
        marks += " ⏸"
    if row["notify_muted"]:
        marks += " 🔕"
    return marks


def state_icon(row: Row) -> str:
    if not row["monitor_enabled"]:
        return "⚫️"
    return STATE_ICONS.get(row["state"], "⚪️")


def last_result(row: Row) -> str:
    if not row["last_check_at"]:
        return "ещё не проверялся"
    if row["last_code"] == "ok":
        latency = f", {row['last_latency_ms']} мс" if row["last_latency_ms"] is not None else ""
        return ("доступен частично" if str(row["last_summary"]).startswith("доступен частично") else "доступен") + latency
    return short_reason(row["last_code"])


# ── home ────────────────────────────────────────────────────────────────────

async def home(ctx: Ctx) -> Screen:
    snap = await ctx.monitor.snapshot()
    counts = snap["counts"]
    total = sum(counts.values())
    lines = ["🛰 <b>Мониторинг серверов Remnawave</b>", ""]
    if not total:
        lines.append("Серверов пока нет. Пришлите ссылку на подписку или нажмите «➕ Добавить подписку».")
    else:
        lines.append(f"Под наблюдением: <b>{total}</b> — 🟢 {counts.get('OK', 0) + counts.get('RECOVERED', 0)}"
                     f" · 🟡 {counts.get('SUSPECT', 0)} · 🔴 {counts.get('DOWN', 0)} · ⚪️ {counts.get('UNKNOWN', 0)}")
        cycle = snap["last_cycle"]
        if cycle is not None:
            lines.append(f"Последний цикл: {fmt_time(cycle.started_at)}")
    lines.append(_mode_line(snap))
    return "\n".join(lines), kb([
        [("📊 Статус мониторинга", "st"), ("🖥 Список серверов", "ls:a:0")],
        [("➕ Добавить подписку", "sub"), ("⚙️ Настройки мониторинга", "set")],
        [("🔕 Управление исключениями", "exc:0"), ("📋 История событий", "ev:a:0")],
        [("🔄 Проверить все серверы", "all")],
    ])


def _mode_line(snap: dict[str, Any]) -> str:
    if snap["paused"]:
        until = f" до {fmt_short(snap['paused_until'])} МСК" if snap["paused_until"] else ""
        return f"⏸ Мониторинг на паузе{until}"
    if snap["frozen_since"]:
        return f"⚠️ Результаты не учитываются с {fmt_time(snap['frozen_since'])}: {h(snap['frozen_problem'])}"
    return "▶️ Мониторинг работает"


# ── status ──────────────────────────────────────────────────────────────────

async def status(ctx: Ctx) -> Screen:
    snap = await ctx.monitor.snapshot()
    counts = snap["counts"]
    get = ctx.settings.get
    now = time.time()
    lines = ["📊 <b>Статус мониторинга</b>", "", _mode_line(snap), ""]
    lines.append(f"Серверы под наблюдением: <b>{sum(counts.values())}</b>")
    for state in (fsm.OK, fsm.RECOVERED, fsm.SUSPECT, fsm.DOWN, fsm.UNKNOWN):
        if counts.get(state):
            lines.append(f"  {STATE_ICONS[state]} {STATE_NAMES[state]}: {counts[state]}")
    lines.append(f"Исключено: {snap['excluded']} · на паузе: {snap['server_paused']} · "
                 f"без уведомлений: {snap['muted']}")
    lines.append(f"Открытых инцидентов: {snap['open_incidents']}")
    lines.append("")
    cycle = snap["last_cycle"]
    if cycle is None:
        lines.append("Последний цикл: ещё не выполнялся")
    elif cycle.frozen:
        lines.append(f"Последний цикл: {fmt_time(cycle.started_at)} — не учтён ({h(cycle.problem)})")
    else:
        lines.append(f"Последний цикл: {fmt_time(cycle.started_at)}, {fmt_duration(cycle.duration)}; "
                     f"проверено {cycle.checked}: успешно {cycle.ok}, отказов {cycle.failed}, "
                     f"без вердикта {cycle.unknown}")
    if snap["cycle_running"]:
        lines.append("Следующий цикл: выполняется сейчас")
    elif not snap["paused"]:
        lines.append(f"Следующий цикл: через {fmt_duration(max(0, snap['next_cycle_at'] - now))}")
    lines.append(f"Интервал: {fmt_interval(get('check_interval'))} · до DOWN: {get('fail_threshold')} неудач · "
                 f"до восстановления: {get('recovery_threshold')} успехов")
    lines.append("")
    health = snap["health"]
    if health.checked_at:
        mark = "✅" if health.network_ok and health.dns_ok else "⚠️"
        lines.append(f"Самоконтроль: {mark} " + h("; ".join(health.details)))
    else:
        lines.append("Самоконтроль: ещё не выполнялся")
    if not ctx.settings.e2e_enabled:
        lines.append("Сквозная проверка: выключена в настройках")
    elif snap["e2e"]:
        lines.append(f"Сквозная проверка: ✅ {h(snap['xray'])}")
    else:
        lines.append(f"Сквозная проверка: ⚠️ не работает — {h(snap['e2e_problem'])}")
    cc = await ctx.cc.status()
    if not cc["enabled"]:
        lines.append("Cheburcheck: выключен в настройках")
    else:
        if cc["open_until"]:
            state = f"⚠️ недоступен, следующая попытка в {fmt_short(cc['open_until'])}"
        elif cc["last_error"]:
            state = f"⚠️ последняя ошибка: {h(cc['last_error'])}"
        else:
            state = "✅ доступен" if cc["last_ok_at"] else "ещё не запрашивался"
        lines.append(f"Cheburcheck: {state} · запросов сегодня {cc['used_today']}/{cc['limit']} · в очереди {cc['queue']}")
    lines.append("")
    lines.append("<b>Маршруты</b>")
    lines.append(f"Telegram: {h(ctx.botman.proxy_label)}")
    lines.append("Проверки серверов: напрямую с этого сервера")
    lines.append(f"Cheburcheck: {h(mask_proxy(ctx.config.cheburcheck_proxy_url)) if ctx.config.cheburcheck_proxy_url else 'напрямую'}")
    lines.append(f"Подписки: {h(mask_proxy(ctx.config.subscription_proxy_url)) if ctx.config.subscription_proxy_url else 'напрямую'}")
    pending = await ctx.outbox.pending_count()
    lines.append("")
    lines.append(f"Очередь уведомлений: {pending}" + (f" ({h(ctx.notifier.last_error)})" if ctx.notifier.last_error else ""))
    lines.append(f"Работает с {fmt_datetime(snap['started_at'])}")
    return "\n".join(lines), kb([[("🔄 Обновить", "st")], HOME_ROW])


# ── server list ─────────────────────────────────────────────────────────────

LIST_FILTERS = {"a": "все", "p": "проблемные", "x": "исключённые"}


async def _list_rows(ctx: Ctx, flt: str) -> list[Row]:
    from ..monitor.service import SERVER_SQL
    now = int(time.time())
    where = "WHERE s.archived=0"
    if flt == "p":
        where += (" AND s.monitor_enabled=1 AND (st.state IN ('SUSPECT','DOWN') OR st.partial_notified=1 "
                  "OR (st.state='UNKNOWN' AND st.last_check_at IS NOT NULL))")
    elif flt == "x":
        where += f" AND (s.monitor_enabled=0 OR s.notify_muted=1 OR (s.paused_until IS NOT NULL AND s.paused_until>{now}))"
    rows = await ctx.db.fetchall(SERVER_SQL + where)
    rows.sort(key=lambda row: (STATE_ORDER.get(row["state"], 5) if row["monitor_enabled"] else 6, row["id"]))
    return rows


async def server_list(ctx: Ctx, flt: str = "a", page: int = 0) -> Screen:
    flt = flt if flt in LIST_FILTERS else "a"
    rows = await _list_rows(ctx, flt)
    pages = max(1, (len(rows) + PAGE - 1) // PAGE)
    page = min(max(0, page), pages - 1)
    chunk = rows[page * PAGE:(page + 1) * PAGE]
    now = int(time.time())
    lines = [f"🖥 <b>Серверы</b> — {LIST_FILTERS[flt]}: {len(rows)}"
             + (f" · стр. {page + 1}/{pages}" if pages > 1 else ""), ""]
    if not rows:
        lines.append("Пусто." if flt != "a" else "Серверов нет. Добавьте подписку.")
    for row in chunk:
        lines.append(f"{state_icon(row)} <b>{h(row['name'])}</b>{flags(row, now)}")
        lines.append(f"     {code(endpoint(row))} · {fmt_short(row['last_check_at'], now)} · {h(last_result(row))}")
    buttons: list[list[tuple[str, str]]] = []
    pair: list[tuple[str, str]] = []
    for row in chunk:
        pair.append((f"{state_icon(row)} {row['name'][:24]}", f"srv:{row['id']}"))
        if len(pair) == 2:
            buttons.append(pair)
            pair = []
    if pair:
        buttons.append(pair)
    nav = []
    if page > 0:
        nav.append(("◀️", f"ls:{flt}:{page - 1}"))
    if page < pages - 1:
        nav.append(("▶️", f"ls:{flt}:{page + 1}"))
    buttons.append(nav)
    buttons.append([(("• " if key == flt else "") + title.capitalize(), f"ls:{key}:0") for key, title in LIST_FILTERS.items()])
    buttons.append([("🔄 Обновить", f"ls:{flt}:{page}"), *HOME_ROW])
    return "\n".join(lines), kb(buttons)


# ── server card ─────────────────────────────────────────────────────────────

def _monitoring_line(row: Row, now: int) -> str:
    if not row["monitor_enabled"]:
        return "Мониторинг: 🚫 отключён (сервер исключён)"
    if row["paused_until"] and row["paused_until"] > now:
        return f"Мониторинг: ⏸ пауза до {fmt_short(row['paused_until'], now)} МСК"
    return "Мониторинг: включён"


async def server_card(ctx: Ctx, server_id: int, note: str = "") -> Screen | None:
    row = await ctx.monitor.get_server(server_id)
    if row is None or row["archived"]:
        return None
    now = int(time.time())
    lines = [f"🖥 <b>{h(row['name'])}</b>"]
    aliases = jload(row["aliases_json"], [])
    if aliases:
        lines.append("Также в подписке: " + h(", ".join(aliases[:3])))
    lines.append("")
    lines.append(f"Адрес: {code(endpoint(row))}")
    lines.append(f"Тип: {h(describe_kind(row['protocol'], row['transport'], row['security']))}")
    if not row["monitor_enabled"]:
        lines.append("Состояние: ⚫️ не отслеживается")
    else:
        since = f" с {fmt_short(row['state_since'], now)}" if row["state_since"] else ""
        lines.append(f"Состояние: {STATE_ICONS[row['state']]} <b>{row['state']}</b> — {STATE_NAMES[row['state']]}{since}")
        if row["state"] == fsm.SUSPECT:
            lines.append(f"Неудач подряд: {row['fail_streak']} из {ctx.settings.get('fail_threshold')}")
        elif row["state"] == fsm.DOWN and row["ok_streak"]:
            lines.append(f"Успехов подряд: {row['ok_streak']} из {ctx.settings.get('recovery_threshold')}")
        if row["flapping"]:
            lines.append("⚠️ Нестабилен: уведомления по серверу приостановлены")
    if row["last_check_at"]:
        lines.append(f"Последняя проверка: {fmt_time(row['last_check_at'])}")
        lines.append(f"Результат: {h(row['last_summary'] or reason_text(row['last_code']))}"
                     + (f", {row['last_latency_ms']} мс" if row["last_code"] == "ok" and row["last_latency_ms"] is not None else ""))
    else:
        lines.append("Последняя проверка: ещё не выполнялась")
    lines.append(_monitoring_line(row, now))
    lines.append("Уведомления: " + ("🔕 отключены (проверки продолжаются)" if row["notify_muted"] else "включены"))
    if note:
        lines += ["", note]
    toggle = ("✅ Включить мониторинг", f"srv:{server_id}:on") if not row["monitor_enabled"] else (
        "⏯ Отключить мониторинг", f"srv:{server_id}:off")
    return "\n".join(lines), kb([
        [("🔄 Проверить сейчас", f"srv:{server_id}:chk"), toggle],
        [("🔕 Исключения", f"srv:{server_id}:exc"), ("ℹ️ Подробности", f"srv:{server_id}:det")],
        [("📈 История доступности", f"srv:{server_id}:his"), ("🔍 Cheburcheck", f"srv:{server_id}:cc")],
        [("◀️ К списку", "ls:b"), *HOME_ROW],
    ])


async def server_exclusions(ctx: Ctx, server_id: int) -> Screen | None:
    row = await ctx.monitor.get_server(server_id)
    if row is None or row["archived"]:
        return None
    now = int(time.time())
    paused = bool(row["paused_until"] and row["paused_until"] > now)
    lines = [
        f"🔕 <b>Исключения: {h(row['name'])}</b>", "",
        _monitoring_line(row, now),
        "Уведомления: " + ("🔕 отключены" if row["notify_muted"] else "включены"), "",
        "• <b>Исключить</b> — сервер не проверяется, пока вы его не вернёте.",
        "• <b>Пауза</b> — проверки возобновятся сами по истечении срока.",
        "• <b>Отключить уведомления</b> — проверки и история продолжаются, сообщения не приходят.",
    ]
    rows: list[list[tuple[str, str]]] = []
    if row["monitor_enabled"]:
        rows.append([("🚫 Исключить полностью", f"srv:{server_id}:off")])
        rows.append([(f"⏸ {title}", f"srv:{server_id}:p:{seconds}") for title, seconds in PAUSE_PRESETS]
                    + [("⏸ Свой срок", f"srv:{server_id}:pc")])
    if not row["monitor_enabled"] or paused:
        rows.append([("▶️ Возобновить мониторинг", f"srv:{server_id}:on")])
    rows.append([("🔔 Включить уведомления", f"srv:{server_id}:unmute")] if row["notify_muted"]
                else [("🔕 Отключить уведомления", f"srv:{server_id}:mute")])
    rows.append([("◀️ К серверу", f"srv:{server_id}"), *HOME_ROW])
    return "\n".join(lines), kb(rows)


def stage_lines(detail: dict[str, Any]) -> list[str]:
    lines = []
    for stage in detail.get("stages") or []:
        mark = "✅" if stage.get("ok") else ("➖" if stage.get("ok") is None else "❌")
        title = STAGE_TITLES.get(stage.get("s"), stage.get("s"))
        target = f" {code(stage['t'])}" if stage.get("t") else ""
        ms = f" · {stage['ms']} мс" if stage.get("ms") is not None else ""
        text = "" if stage.get("ok") else f" — {h(short_reason(stage.get('c', '')))}"
        extra = f" [{h(str(stage['d'])[:120])}]" if stage.get("d") and not stage.get("ok") else ""
        lines.append(f"{mark} {title}{target}{ms}{text}{extra}")
    for note in detail.get("notes") or []:
        lines.append(f"ℹ️ {h(note)}")
    return lines


async def server_details(ctx: Ctx, server_id: int) -> Screen | None:
    row = await ctx.monitor.get_server(server_id)
    if row is None:
        return None
    state = await ctx.db.fetchone("SELECT last_detail_json FROM server_state WHERE server_id=?", (server_id,))
    detail = jload(state["last_detail_json"], {}) if state else {}
    params = jload(row["params_json"], {})
    lines = [f"ℹ️ <b>{h(row['name'])}</b> — подробности", ""]
    lines.append(f"Адрес: {code(row['address'])}")
    lines.append(f"Порт: {row['port']} ({row['l4'].upper()})")
    lines.append(f"Протокол: {h(describe_kind(row['protocol'], row['transport'], row['security']))}")
    if row["sni"]:
        lines.append(f"SNI: {code(row['sni'])}")
    if row["host"]:
        lines.append(f"Host: {code(row['host'])}")
    if row["path"]:
        lines.append(f"Путь: {code(row['path'])}")
    shown = {"flow": "Flow", "fp": "Отпечаток TLS", "alpn": "ALPN", "mode": "Режим", "obfs": "Обфускация",
             "header_type": "Заголовок", "encryption": "Шифрование"}
    for key, title in shown.items():
        if params.get(key) and params[key] != "none":
            lines.append(f"{title}: {code(params[key])}")
    if params.get("fm"):
        lines.append("Фрагментация ClientHello: задана в подписке (учитывается при проверке)")
    if params.get("insecure"):
        lines.append("Проверка сертификата: отключена в подписке")
    ips = detail.get("ips") or jload(row["good_ips_json"], [])
    lines.append("IP: " + (", ".join(code(ip) for ip in ips[:6]) if ips else "ещё не определены"))
    extra = await ctx.db.fetchall(
        "SELECT address FROM server_addresses WHERE server_id=? AND address<>? ORDER BY last_seen DESC LIMIT 5",
        (server_id, row["address"]))
    if extra:
        lines.append("Другие адреса из подписки: " + ", ".join(code(item["address"]) for item in extra))
    subs = await ctx.db.fetchall(
        "SELECT u.title, u.url_hint, ss.remark FROM server_subscriptions ss JOIN subscriptions u "
        "ON u.id=ss.subscription_id WHERE ss.server_id=?", (server_id,))
    for sub in subs:
        lines.append(f"Подписка: {h(sub['title'] or sub['url_hint'])} ({code(sub['url_hint'])})")
    lines.append(f"Добавлен: {fmt_datetime(row['created_at'])}")
    lines.append("")
    if row["last_check_at"]:
        lines.append(f"<b>Последняя проверка</b> — {fmt_time(row['last_check_at'])}")
        lines.extend(stage_lines(detail) or ["нет данных по уровням"])
        if detail.get("partial"):
            lines.append(f"⚠️ {h(detail['partial'])}")
    else:
        lines.append("Проверок ещё не было.")
    return texts.clip("\n".join(lines)), kb([[("◀️ К серверу", f"srv:{server_id}"), *HOME_ROW]])


async def _availability(ctx: Ctx, server_id: int, created_at: int, window: int, now: int) -> tuple[float, int]:
    start = max(now - window, created_at)
    span = max(1, now - start)
    rows = await ctx.db.fetchall(
        "SELECT started_at, COALESCE(resolved_at, recovered_at) AS ended, close_reason FROM incidents "
        "WHERE server_id=? AND COALESCE(resolved_at, recovered_at, ?) > ?", (server_id, now, start))
    down = 0
    for row in rows:
        end = row["ended"] or now
        down += max(0, min(end, now) - max(row["started_at"], start))
    return max(0.0, 100.0 * (1 - down / span)), len(rows)


async def server_history(ctx: Ctx, server_id: int) -> Screen | None:
    row = await ctx.monitor.get_server(server_id)
    if row is None:
        return None
    now = int(time.time())
    lines = [f"📈 <b>{h(row['name'])}</b> — история доступности", ""]
    lines.append("<b>Доля доступности</b> (по подтверждённым инцидентам):")
    for title, window in (("24 часа", 86400), ("7 дней", 7 * 86400), ("30 дней", 30 * 86400)):
        share, count = await _availability(ctx, server_id, row["created_at"], window, now)
        lines.append(f"• {title}: <b>{share:.2f}%</b>" + (f", инцидентов: {count}" if count else ""))
    stats = await ctx.db.fetchone(
        "SELECT COUNT(*) AS n, SUM(ok=1) AS good, SUM(ok=0) AS bad, SUM(ok IS NULL) AS unknown, "
        "CAST(AVG(CASE WHEN ok=1 THEN latency_ms END) AS INTEGER) AS latency "
        "FROM checks WHERE server_id=? AND ts>=?", (server_id, now - 86400))
    if stats and stats["n"]:
        lines.append(f"Проверок за 24 ч: {stats['n']} — успешных {stats['good'] or 0}, неудачных {stats['bad'] or 0}, "
                     f"без вердикта {stats['unknown'] or 0}"
                     + (f"; средний отклик {stats['latency']} мс" if stats["latency"] is not None else ""))
    lines.append("")
    incidents = await ctx.db.fetchall(
        "SELECT * FROM incidents WHERE server_id=? ORDER BY started_at DESC LIMIT 8", (server_id,))
    if incidents:
        lines.append("<b>Последние инциденты</b>")
        for item in incidents:
            ended = item["resolved_at"] or item["recovered_at"]
            if ended:
                span = f"{fmt_short(item['started_at'], now)} – {fmt_short(ended, now)}, {fmt_duration(ended - item['started_at'])}"
            elif item["close_reason"]:
                span = f"{fmt_short(item['started_at'], now)}, закрыт (сервер удалён из подписки)"
            else:
                span = f"с {fmt_short(item['started_at'], now)}, продолжается {fmt_duration(now - item['started_at'])}"
            lines.append(f"🔴 {span}")
            lines.append(f"     {h(short_reason(item['code']))}")
    else:
        lines.append("Подтверждённых инцидентов не было.")
    events = await ctx.db.fetchall(
        "SELECT * FROM state_events WHERE server_id=? ORDER BY id DESC LIMIT 8", (server_id,))
    if events:
        lines += ["", "<b>Последние смены состояния</b>"]
        for event in events:
            lines.append(f"{fmt_short(event['ts'], now)}  {event['from_state']} → {event['to_state']}"
                         + (f" · {h(short_reason(event['code']))}" if event["code"] not in ("ok", "", "stale") else ""))
    return texts.clip("\n".join(lines)), kb([[("◀️ К серверу", f"srv:{server_id}"), *HOME_ROW]])


def cheburcheck_screen(row: Row, results: list[Any], note: str = "") -> Screen:
    lines = [f"🔍 <b>Cheburcheck: {h(row['name'])}</b>", ""]
    if note:
        lines.append(note)
    if results:
        lines.extend(texts.cc_block(results, [])[1:])
        lines += ["", "<i>Сканеры Cheburcheck проверяют путь до 443-го порта, блокировку по SNI и DNS — "
                      "не порт и не протокол самого сервера. Состояние сервера определяют только собственные проверки бота.</i>"]
    return texts.clip("\n".join(lines)), kb([
        [("🔄 Запросить заново", f"srv:{row['id']}:ccf")], [("◀️ К серверу", f"srv:{row['id']}"), *HOME_ROW]])


# ── subscriptions ───────────────────────────────────────────────────────────

SUB_STATUS = {
    "ok": "✅ обновляется", "": "ещё не загружалась", "needs_confirm": "❓ ждёт подтверждения изменений",
}


def _sub_status(sub: Row) -> str:
    if sub["last_status"] in SUB_STATUS:
        return SUB_STATUS[sub["last_status"]]
    return "⚠️ " + (sub["last_error"] or sub["last_status"])


async def subscriptions(ctx: Ctx, note: str = "") -> Screen:
    subs = await ctx.subs.list()
    now = int(time.time())
    lines = ["➕ <b>Подписки</b>", ""]
    if note:
        lines += [note, ""]
    if not subs:
        lines.append("Подписок нет.")
    for sub in subs:
        lines.append(f"<b>{h(sub['title'] or sub['url_hint'])}</b> — {code(sub['url_hint'])}")
        lines.append(f"     серверов: {sub['server_count']} · {h(_sub_status(sub))}")
        tail = f"обновлена {fmt_short(sub['last_ok_at'], now)}" if sub["last_ok_at"] else "не обновлялась"
        if sub["expire_at"]:
            tail += f" · действует до {fmt_short(sub['expire_at'], now)}" + (" ⚠️ истекла" if sub["expire_at"] < now else "")
        lines.append(f"     {tail}")
    lines += ["", "Чтобы добавить или обновить подписку, нажмите кнопку и пришлите ссылку. "
                  "Сообщение со ссылкой бот удалит из чата."]
    rows = [[(f"⚙️ {(sub['title'] or sub['url_hint'])[:28]}", f"sub:{sub['id']}")] for sub in subs]
    rows.append([("➕ Добавить подписку", "sub:add")])
    rows.append(HOME_ROW)
    return "\n".join(lines), kb(rows)


async def subscription_card(ctx: Ctx, sub_id: int, note: str = "") -> Screen | None:
    sub = await ctx.subs.get(sub_id)
    if sub is None:
        return None
    now = int(time.time())
    count = int(await ctx.db.scalar(
        "SELECT COUNT(*) FROM server_subscriptions ss JOIN servers s ON s.id=ss.server_id "
        "WHERE ss.subscription_id=? AND s.archived=0", (sub_id,)) or 0)
    lines = [f"📥 <b>{h(sub['title'] or sub['url_hint'])}</b>", "",
             f"Ссылка: {code(sub['url_hint'])} (хранится в зашифрованном виде)",
             f"Серверов: {count}", f"Состояние: {h(_sub_status(sub))}",
             f"Последнее успешное обновление: {fmt_datetime(sub['last_ok_at'])}",
             f"Форматы: {h(sub['last_formats'] or '—')}",
             f"Запрос: User-Agent {code(sub['user_agent'] or ctx.config.subscription_user_agent)}"
             + (", с идентификатором устройства (HWID)" if sub["use_hwid"] else "")]
    if sub["expire_at"]:
        lines.append(f"Срок действия: до {fmt_datetime(sub['expire_at'])}" + (" — <b>истёк</b>" if sub["expire_at"] < now else ""))
    interval = int(ctx.settings.get("subscription_refresh_interval"))
    auto = "выключено" if not sub["auto_refresh"] else (
        f"каждые {fmt_interval(interval)}" if interval else "выключено в настройках")
    lines.append(f"Автообновление: {auto}")
    if (sub["e2e_suspended_until"] or 0) > now:
        lines.append("⚠️ Сквозная проверка приостановлена: подписка не выдаёт серверы")
    if note:
        lines += ["", note]
    return "\n".join(lines), kb([
        [("🔄 Обновить сейчас", f"sub:{sub_id}:ref")],
        [("🔁 Автообновление: " + ("вкл" if sub["auto_refresh"] else "выкл"), f"sub:{sub_id}:auto")],
        [("🗑 Удалить подписку", f"sub:{sub_id}:del")],
        [("◀️ К подпискам", "sub"), *HOME_ROW],
    ])


def sync_report(result: Any) -> str:
    """Owner-facing report about adding or refreshing a subscription."""
    name = h(result.title or result.hint)
    if result.ok:
        head = "✅ <b>Подписка добавлена</b>" if result.is_new else "✅ <b>Подписка обновлена</b>"
        lines = [head, "", f"{name} ({code(result.hint)})", f"Форматы ответа: {h(', '.join(result.formats) or '—')}",
                 f"Серверов: <b>{result.total}</b>"]
        for caption, names in (("Добавлены", result.added), ("Возвращены", result.restored), ("Удалены", result.archived)):
            if names:
                lines.append(f"{caption} ({len(names)}): " + h(", ".join(names[:15])) + (" …" if len(names) > 15 else ""))
        if not result.is_new and not result.changed:
            lines.append("Состав серверов не изменился.")
        if result.skipped:
            lines.append("Пропущено: " + h("; ".join(f"{reason} — {count}" for reason, count in result.skipped.items())))
        if result.expire_at:
            lines.append(f"Действует до {fmt_datetime(result.expire_at)}")
        if result.is_new:
            lines.append("\nМониторинг новых серверов уже запущен.")
        return "\n".join(lines)
    if result.status == "needs_confirm":
        return "\n".join([
            "❓ <b>Подписка сильно изменилась</b>", "", f"{name} ({code(result.hint)})",
            f"Новый ответ не содержит {len(result.pending_removal)} отслеживаемых серверов: "
            + h(", ".join(result.pending_removal[:10])) + (" …" if len(result.pending_removal) > 10 else ""),
            "Список оставлен без изменений. Подтвердите, если серверы действительно удалены.",
        ])
    return "\n".join(["⚠️ <b>Подписку загрузить не удалось</b>", "", f"{name} ({code(result.hint)})" if result.hint else "",
                      h(result.message or "неизвестная ошибка")])


# ── settings ────────────────────────────────────────────────────────────────

async def settings_root(ctx: Ctx, note: str = "") -> Screen:
    paused, until = ctx.settings.pause_state()
    lines = ["⚙️ <b>Настройки мониторинга</b>", ""]
    if note:
        lines += [note, ""]
    lines.append("Значения, изменённые здесь, хранятся в базе и переживают перезапуск. "
                 "Отмечены ✏️; остальные берутся из файла конфигурации.")
    lines.append("")
    for group, title in GROUP_TITLES.items():
        lines.append(f"<b>{title}</b>")
        for spec in SPECS:
            if spec.group == group:
                mark = " ✏️" if ctx.settings.is_overridden(spec.key) else ""
                lines.append(f"  {h(spec.title)}: <b>{h(ctx.settings.display(spec.key))}</b>{mark}")
    lines.append("")
    lines.append("Общая пауза: " + ("⏸ включена" + (f" до {fmt_short(until)} МСК" if until else "") if paused else "выключена"))
    rows = [[(title, f"set:g:{group}")] for group, title in GROUP_TITLES.items()]
    rows = [sum(rows[index:index + 2], []) for index in range(0, len(rows), 2)]
    rows.append([("▶️ Снять паузу" if paused else "⏸ Общая пауза", "set:pause")])
    rows.append([("💾 Резервная копия", "set:backup"), ("♻️ Сбросить всё", "set:reset")])
    rows.append(HOME_ROW)
    return "\n".join(lines), kb(rows)


async def settings_group(ctx: Ctx, group: str) -> Screen:
    title = GROUP_TITLES.get(group, group)
    lines = [f"⚙️ <b>{title}</b>", ""]
    rows = []
    for spec in SPECS:
        if spec.group != group:
            continue
        mark = " ✏️" if ctx.settings.is_overridden(spec.key) else ""
        lines.append(f"{h(spec.title)}: <b>{h(ctx.settings.display(spec.key))}</b>{mark}")
        rows.append([(f"{spec.title}: {ctx.settings.display(spec.key)}"[:60], f"set:k:{spec.key}")])
    rows.append([("◀️ Настройки", "set"), *HOME_ROW])
    return "\n".join(lines), kb(rows)


async def setting_screen(ctx: Ctx, key: str, note: str = "") -> Screen | None:
    spec = SPEC_BY_KEY.get(key)
    if spec is None:
        return None
    default = getattr(ctx.config, key)
    lines = [f"⚙️ <b>{h(spec.title)}</b>", "", f"Сейчас: <b>{h(ctx.settings.display(key))}</b>"
             + (" ✏️ (изменено здесь)" if ctx.settings.is_overridden(key) else " (из файла конфигурации)")]
    if ctx.settings.is_overridden(key):
        from ..settings import _plain
        lines.append(f"В файле конфигурации: {h(_plain(spec, default))}")
    if spec.hint:
        lines += ["", h(spec.hint)]
    if note:
        lines += ["", note]
    rows: list[list[tuple[str, str]]] = []
    if spec.kind in ("bool", "choice"):
        options = ("on", "off") if spec.kind == "bool" else spec.choices
        rows.append([(ctx.settings.preset_label(key, option).capitalize(), f"set:v:{key}:{option}") for option in options])
    else:
        if spec.presets:
            rows.append([(ctx.settings.preset_label(key, preset), f"set:v:{key}:{preset}") for preset in spec.presets])
        rows.append([("✏️ Своё значение", f"set:c:{key}")])
    if ctx.settings.is_overridden(key):
        rows.append([("↩️ Вернуть значение из конфигурации", f"set:r:{key}")])
    rows.append([("◀️ Назад", f"set:g:{spec.group}"), *HOME_ROW])
    return "\n".join(lines), kb(rows)


async def pause_screen(ctx: Ctx) -> Screen:
    paused, until = ctx.settings.pause_state()
    lines = ["⏸ <b>Общая пауза мониторинга</b>", ""]
    if paused:
        lines.append("Сейчас: <b>на паузе</b>" + (f" до {fmt_datetime(until)}" if until else " до ручного снятия"))
    else:
        lines.append("Сейчас: мониторинг работает.")
    lines += ["", "На паузе серверы не проверяются и уведомления не отправляются. "
                  "После длительной паузы счётчики неудач начинаются заново."]
    rows = [[("1 ч", "set:pause:3600"), ("6 ч", "set:pause:21600"), ("24 ч", "set:pause:86400")],
            [("⏸ До ручного снятия", "set:pause:0")]]
    if paused:
        rows.insert(0, [("▶️ Снять паузу", "set:pause:off")])
    rows.append([("◀️ Настройки", "set"), *HOME_ROW])
    return "\n".join(lines), kb(rows)


def confirm_screen(text: str, yes: tuple[str, str], no: tuple[str, str]) -> Screen:
    return text, kb([[yes], [no]])


# ── exclusions overview ─────────────────────────────────────────────────────

async def exclusions(ctx: Ctx, page: int = 0) -> Screen:
    rows = await _list_rows(ctx, "x")
    now = int(time.time())
    pages = max(1, (len(rows) + PAGE - 1) // PAGE)
    page = min(max(0, page), pages - 1)
    chunk = rows[page * PAGE:(page + 1) * PAGE]
    lines = ["🔕 <b>Управление исключениями</b>" + (f" · стр. {page + 1}/{pages}" if pages > 1 else ""), ""]
    if not rows:
        lines.append("Исключений нет: все серверы проверяются, уведомления включены.")
        lines.append("")
        lines.append("Исключить сервер, поставить его на паузу или отключить уведомления можно в карточке сервера.")
    buttons: list[list[tuple[str, str]]] = []
    for row in chunk:
        states = []
        if not row["monitor_enabled"]:
            states.append("🚫 исключён")
        elif row["paused_until"] and row["paused_until"] > now:
            states.append(f"⏸ пауза до {fmt_short(row['paused_until'], now)}")
        if row["notify_muted"]:
            states.append("🔕 без уведомлений")
        lines.append(f"<b>{h(row['name'])}</b> — {code(endpoint(row))}")
        lines.append(f"     {', '.join(states)}")
        line = [(f"⚙️ {row['name'][:20]}", f"srv:{row['id']}:exc")]
        if not row["monitor_enabled"] or (row["paused_until"] and row["paused_until"] > now):
            line.append(("▶️ Возобновить", f"exc:on:{row['id']}:{page}"))
        if row["notify_muted"]:
            line.append(("🔔 Уведомления", f"exc:unmute:{row['id']}:{page}"))
        buttons.append(line)
    nav = []
    if page > 0:
        nav.append(("◀️", f"exc:{page - 1}"))
    if page < pages - 1:
        nav.append(("▶️", f"exc:{page + 1}"))
    buttons.append(nav)
    buttons.append([("🖥 Выбрать сервер", "ls:a:0"), *HOME_ROW])
    return "\n".join(lines), kb(buttons)


# ── event history ───────────────────────────────────────────────────────────

EVENT_FILTERS = {"a": "все", "s": "серверы", "m": "мониторинг", "u": "подписки"}
MONITOR_ICONS = {
    "started": "▶️", "frozen": "⚠️", "unfrozen": "✅", "mass_failure": "🚨", "overrun": "⚠️",
    "dns_problem": "⚠️", "dns_ok": "✅", "credentials": "🔑", "subscription": "🔁", "error": "❗️",
    "settings": "⚙️", "exclusion": "🔕", "backup": "💾",
}
MONITOR_TITLES = {
    "started": "мониторинг запущен", "frozen": "результаты не учитываются", "unfrozen": "мониторинг восстановлен",
    "mass_failure": "массовый отказ", "overrun": "цикл не укладывается в интервал",
    "dns_problem": "системный DNS не отвечает", "dns_ok": "системный DNS снова отвечает",
    "credentials": "подписка", "subscription": "подписка", "error": "ошибка", "settings": "настройки",
    "exclusion": "исключения", "backup": "резервная копия",
}


async def events(ctx: Ctx, flt: str = "a", page: int = 0) -> Screen:
    flt = flt if flt in EVENT_FILTERS else "a"
    parts = []
    if flt in ("a", "s"):
        parts.append(
            "SELECT e.ts AS ts, 'state' AS kind, s.name AS title, e.from_state || '>' || e.to_state AS a, "
            "e.code AS b, e.id AS ord FROM state_events e JOIN servers s ON s.id=e.server_id")
    if flt in ("a", "m"):
        parts.append("SELECT ts, kind, text AS title, '' AS a, '' AS b, id AS ord FROM monitor_events "
                     "WHERE kind NOT IN ('subscription','credentials')")
    if flt in ("a", "u"):
        parts.append("SELECT ts, kind, text AS title, '' AS a, '' AS b, id AS ord FROM monitor_events "
                     "WHERE kind IN ('subscription','credentials')")
    union = " UNION ALL ".join(parts)
    total = int(await ctx.db.scalar(f"SELECT COUNT(*) FROM ({union})") or 0)
    pages = max(1, (total + EVENTS_PAGE - 1) // EVENTS_PAGE)
    page = min(max(0, page), pages - 1)
    rows = await ctx.db.fetchall(
        f"SELECT * FROM ({union}) ORDER BY ts DESC, ord DESC LIMIT ? OFFSET ?", (EVENTS_PAGE, page * EVENTS_PAGE))
    now = int(time.time())
    lines = [f"📋 <b>История событий</b> — {EVENT_FILTERS[flt]}" + (f" · стр. {page + 1}/{pages}" if pages > 1 else ""), ""]
    if not rows:
        lines.append("Событий пока нет.")
    for row in rows:
        when = fmt_short(row["ts"], now)
        if row["kind"] == "state":
            before, after = row["a"].split(">")
            reason = f" · {h(short_reason(row['b']))}" if row["b"] not in ("ok", "", "stale") else ""
            lines.append(f"{when}  {STATE_ICONS.get(after, '⚪️')} <b>{h(row['title'])}</b>: {before} → {after}{reason}")
        else:
            icon = MONITOR_ICONS.get(row["kind"], "•")
            title = MONITOR_TITLES.get(row["kind"], row["kind"])
            lines.append(f"{when}  {icon} {h(title)}" + (f": {h(row['title'])}" if row["title"] else ""))
    nav = []
    if page > 0:
        nav.append(("◀️ Новее", f"ev:{flt}:{page - 1}"))
    if page < pages - 1:
        nav.append(("Старее ▶️", f"ev:{flt}:{page + 1}"))
    return texts.clip("\n".join(lines)), kb([
        nav,
        [(("• " if key == flt else "") + title.capitalize(), f"ev:{key}:0") for key, title in EVENT_FILTERS.items()],
        HOME_ROW,
    ])


# ── check all ───────────────────────────────────────────────────────────────

def check_all_progress(done: int, total: int) -> str:
    filled = int(10 * done / total) if total else 10
    return f"🔄 <b>Проверяю серверы</b>\n\n{'▰' * filled}{'▱' * (10 - filled)} {done}/{total}"


def check_all_report(summary: Any) -> Screen:
    if summary.frozen:
        text = ("🔄 <b>Проверка не выполнена</b>\n\n"
                f"У сервера мониторинга проблемы с сетью: {h(summary.problem)}.\nРезультаты не учитываются.")
        return text, kb([HOME_ROW])
    lines = ["🔄 <b>Проверка завершена</b>", "",
             f"Проверено: {summary.checked} за {fmt_duration(summary.duration)}",
             f"🟢 доступны: {summary.ok} · ❌ отказов: {summary.failed} · ➖ без вердикта: {summary.unknown}"]
    problems = [(row, result, state) for row, result, state in summary.results if result.ok is not True]
    if problems:
        lines += ["", "<b>Требуют внимания</b>"]
        for row, result, state in problems[:15]:
            lines.append(f"{STATE_ICONS.get(state, '⚪️')} <b>{h(row['name'])}</b> ({state}) — {h(short_reason(result.code))}")
        if len(problems) > 15:
            lines.append(f"… и ещё {len(problems) - 15}")
        lines += ["", "Отказ в ручной проверке — это одно наблюдение: DOWN объявляется только после "
                      "подтверждения повторными проверками."]
    rows = [[(f"{STATE_ICONS.get(state, '⚪️')} {row['name'][:24]}", f"srv:{row['id']}")] for row, _, state in problems[:6]]
    rows.append([("🖥 Список серверов", "ls:a:0"), *HOME_ROW])
    return texts.clip("\n".join(lines)), kb(rows)


HELP_TEXT = "\n".join([
    "🛰 <b>Мониторинг серверов Remnawave</b>", "",
    "Бот проверяет доступность серверов из подписки с этого сервера в российской сети и сообщает "
    "о подтверждённых падениях и восстановлениях.", "",
    "<b>Как пользоваться</b>",
    "• Пришлите ссылку на подписку — серверы добавятся и начнут проверяться.",
    "• Всё управление — кнопками меню.",
    "• Команды: /menu — меню, /status — статус, /cancel — отменить ввод, /help — эта справка.", "",
    "<b>Состояния</b>",
    "🟢 OK — доступен · 🟡 SUSPECT — была неудача, идут перепроверки · 🔴 DOWN — недоступность подтверждена · "
    "🟢 RECOVERED — восстановлен, идёт наблюдение · ⚪️ UNKNOWN — достоверного результата нет.", "",
    "Уведомление о падении приходит только после нескольких неудач подряд, о восстановлении — "
    "после нескольких успехов подряд.",
])
