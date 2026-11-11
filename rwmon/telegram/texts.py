"""Texts of notifications (HTML parse mode). Pure functions: data in, string out."""

from __future__ import annotations

from html import escape
from typing import Any

from ..cheburcheck import summary as sm
from ..timeutil import _plural, fmt_datetime, fmt_duration, fmt_short, fmt_time, to_msk

STATE_ICONS = {"OK": "🟢", "SUSPECT": "🟡", "DOWN": "🔴", "RECOVERED": "🟢", "UNKNOWN": "⚪️"}
STATE_NAMES = {
    "OK": "доступен", "SUSPECT": "перепроверяется", "DOWN": "недоступен",
    "RECOVERED": "восстановлен, под наблюдением", "UNKNOWN": "нет данных",
}
MAX_MESSAGE = 3900


def h(value: Any) -> str:
    return escape(str(value), quote=False)


def code(value: Any) -> str:
    return f"<code>{h(value)}</code>"


def clip(text: str, limit: int = MAX_MESSAGE) -> str:
    """Cut on a line boundary so that HTML tags are never split."""
    if len(text) <= limit:
        return text
    lines, size = [], 0
    for line in text.split("\n"):
        if size + len(line) + 1 > limit - 40:
            break
        lines.append(line)
        size += len(line) + 1
    return "\n".join(lines) + "\n… (сообщение сокращено)"


def checks_word(count: int) -> str:
    return f"{count} {_plural(count, 'проверкой', 'проверками', 'проверками')}"


def servers_word(count: int) -> str:
    return f"{count} {_plural(count, 'сервер', 'сервера', 'серверов')}"


def period(start: int | None, end: int | None) -> str:
    """``12:34 – 12:51 МСК`` with dates when the period crosses midnight."""
    if not start or not end:
        return "—"
    a, b = to_msk(start), to_msk(end)
    if a.date() == b.date():
        return f"{a:%H:%M} – {b:%H:%M} МСК"
    return f"{a:%d.%m %H:%M} – {b:%d.%m %H:%M} МСК"


# ── Cheburcheck block ───────────────────────────────────────────────────────

_KIND_TITLES = {"ip": "IP", "domain": "Домен", "sni": "SNI"}


def _static_lines(static: dict[str, Any]) -> list[str]:
    registry = f"да ({h(static['rkn_domain'])})" if static.get("rkn_domain") else ("да" if static.get("listed") else "нет")
    subnets = ", ".join(h(item) for item in static.get("blocked_subnets") or []) or "нет"
    parts = [f"Списки блокировок: {registry}", f"Подсети РКН: {subnets}"]
    cdn = static.get("cdn") or []
    if cdn:
        parts.append("CDN/хостинг: " + ", ".join(
            h(f"{item['provider']} {item['cidr']}".strip()) for item in cdn[:2]))
    lines = ["• " + " · ".join(parts)]
    origin = " ".join(part for part in (static.get("asn"), static.get("org")) if part)
    place = ", ".join(part for part in (static.get("country"), static.get("location")) if part)
    if origin or place:
        lines.append("• " + h(", ".join(part for part in (origin, place) if part)))
    extras = []
    if static.get("asn_blocked_prefixes"):
        extras.append(f"заблокированных префиксов AS: {static['asn_blocked_prefixes']} из {static.get('asn_prefixes', '?')}")
    if static.get("whitelisted"):
        extras.append("есть в «белом списке»")
    if static.get("complaints_7d"):
        extras.append(f"жалоб пользователей за 7 дней: {static['complaints_7d']}")
    if extras:
        lines.append("• " + h("; ".join(extras)))
    return lines


def _probe_lines(probes: dict[str, Any]) -> list[str]:
    lines = []
    counts = probes.get("counts") or {}
    places = probes.get("places") or {}
    for verdict in sm.PRIORITY:
        count = counts.get(verdict)
        if not count:
            continue
        line = f"• {sm.LABELS[verdict]}: <b>{count}</b>"
        where = places.get(verdict)
        if where:
            line += " — " + h(", ".join(where["shown"]))
            if where.get("more"):
                line += f" и ещё {where['more']}"
        lines.append(line)
    if counts.get("cdn_block"):
        lines.append(f"<i>{sm.CDN_NOTE}</i>")
    return lines


STALE_AFTER = 300   # a result requested this long before the incident is shown with its time


def cc_target_lines(result: Any, compact: bool = False, reference_ts: int | None = None) -> list[str]:
    """Lines describing one Cheburcheck result (``CcResult``)."""
    title = f"{_KIND_TITLES.get(result.kind, result.kind)} {code(result.target)}"
    status = sm.RELIABILITY[result.reliability]
    age = ""
    if result.from_cache or (reference_ts and reference_ts - result.requested_at > STALE_AFTER):
        age = f" (запрошено в {fmt_short(result.requested_at)}, повторно не запрашивалось)"
    lines = [f"🔎 {title} — {status}{age}"]
    if result.static_status == "rejected":
        return lines
    if result.static_status != "ok":
        if result.error:
            lines.append(f"• {h(result.error)}")
        return lines
    probes = result.probes
    if result.probe_status in ("ok", "partial") and probes.get("responses"):
        note = f"ответили {probes['responses']} из {probes.get('online') or '?'} сканеров"
        if probes.get("cached"):
            note += f", {probes['cached']} — из кеша сервиса"
        if compact:
            counts = probes.get("counts") or {}
            brief = ", ".join(f"{sm.LABELS[v].lower()}: {counts[v]}" for v in sm.PRIORITY if counts.get(v))
            lines.append(f"• Замеры ({note}): {h(brief)}")
        else:
            lines.append(f"<i>Замеры у операторов</i> ({note}):")
            lines.extend(_probe_lines(probes))
    elif result.probe_status == "skipped":
        lines.append("<i>Замеры у операторов</i>: не запрашивались")
    elif result.probe_status == "rejected":
        lines.append("<i>Замеры у операторов</i>: для этой цели не выполняются")
    else:
        lines.append(f"<i>Замеры у операторов</i>: не получены ({h(result.error or 'нет ответа')})")
    if compact:
        static = result.static
        listed = "есть в списках блокировок" if static.get("listed") else "в списках блокировок нет"
        origin = " ".join(part for part in (static.get("asn"), static.get("org")) if part)
        lines.append("• " + h(", ".join(part for part in (listed, origin) if part)))
    else:
        lines.append("<i>Наличие в списках</i> (справочно, это не замер):")
        lines.extend(_static_lines(result.static))
    return lines


def cc_block(results: list[Any], pending: list[tuple[str, str]], enabled: bool = True,
             backing_off: bool = False, compact: bool = False, reference_ts: int | None = None,
             none_reason: str = "") -> list[str]:
    """The Cheburcheck section of a notification, with an explicit reliability status."""
    if not enabled:
        return []
    lines = ["<b>Cheburcheck</b>"]
    if not results and not pending:
        lines[0] += " — " + (none_reason or "данные получить не удалось")
        return lines
    for result in results:
        lines.extend(cc_target_lines(result, compact, reference_ts))
    for target, kind in pending:
        status = sm.RELIABILITY[sm.UNAVAILABLE if backing_off else sm.PENDING]
        lines.append(f"🔎 {_KIND_TITLES.get(kind, kind)} {code(target)} — {status}")
    if backing_off and pending:
        lines.append("<i>Недоступность Cheburcheck на оценку состояния сервера не влияет.</i>")
    return lines


# ── incidents ───────────────────────────────────────────────────────────────

def _server_lines(view: dict[str, Any]) -> list[str]:
    lines = [f"Сервер: <b>{h(view['name'])}</b>"]
    if view.get("aliases"):
        lines.append("Также в подписке: " + h(", ".join(view["aliases"][:3])))
    address, ips = view["address"], view.get("ips") or []
    if view.get("address_is_ip"):
        lines.append(f"IP: {code(address)}")
    else:
        lines.append(f"Домен: {code(address)}")
        lines.append("IP: " + (", ".join(code(ip) for ip in ips[:4]) if ips else "не определён"))
    lines.append(f"Порт: {view['port']} · {h(view['kind'])}")
    if view.get("sni") and view["sni"] != address:
        lines.append(f"SNI: {code(view['sni'])}")
    return lines


def down_text(view: dict[str, Any], cc_lines: list[str]) -> str:
    lines = ["🚨 <b>СЕРВЕР НЕДОСТУПЕН</b>", ""]
    lines += _server_lines(view)
    lines.append("Состояние: <b>DOWN</b>")
    lines.append(f"Обнаружено: {fmt_time(view['started_at'])} "
                 f"(подтверждено {checks_word(view['fails'])} к {fmt_time(view['confirmed_at'])})")
    lines.append(f"Причина: {h(view['reason'])}")
    if view.get("assessment"):
        lines += ["", f"Вероятная причина: {h(view['assessment'])}"]
    if cc_lines:
        lines += ["", *cc_lines]
    return clip("\n".join(lines))


def down_node_text(views: list[dict[str, Any]], cc_lines: list[str]) -> str:
    """Several configurations of one physical server went down together."""
    first = views[0]
    lines = ["🚨 <b>СЕРВЕР НЕДОСТУПЕН</b>", "", f"Сервер: <b>{h(first['name'])}</b>"]
    if first.get("address_is_ip"):
        lines.append(f"IP: {code(first['address'])}")
    else:
        lines.append(f"Домен: {code(first['address'])}")
        ips = first.get("ips") or []
        lines.append("IP: " + (", ".join(code(ip) for ip in ips[:4]) if ips else "не определён"))
    lines.append("Состояние: <b>DOWN</b>")
    lines.append(f"Обнаружено: {fmt_time(min(v['started_at'] for v in views))} "
                 f"(подтверждено {checks_word(first['fails'])})")
    lines += ["", "Недоступны конфигурации:"]
    for view in views:
        lines.append(f"• {view['port']} · {h(view['kind'])} — {h(view['reason'])}")
    if first.get("assessment"):
        lines += ["", f"Вероятная причина: {h(first['assessment'])}"]
    if cc_lines:
        lines += ["", *cc_lines]
    return clip("\n".join(lines))


def down_digest_text(views: list[dict[str, Any]], total_servers: int, cc_lines: list[str]) -> str:
    lines = [
        "🚨 <b>МАССОВАЯ НЕДОСТУПНОСТЬ</b>", "",
        f"Недоступны {servers_word(len(views))} из {total_servers}.",
        f"Обнаружено: {fmt_time(min(v['started_at'] for v in views))}, "
        f"подтверждено {checks_word(views[0]['fails'])}.",
        "Сеть самого мониторинга проверена и работает — это не сбой VPS.", "",
    ]
    reasons: dict[str, list[dict[str, Any]]] = {}
    for view in views:
        reasons.setdefault(view["reason_short"], []).append(view)
    for reason, group in reasons.items():
        lines.append(f"<b>{h(reason)}</b> ({len(group)}):")
        for view in group[:25]:
            lines.append(f"• {h(view['name'])} — {code(view['endpoint'])}")
        if len(group) > 25:
            lines.append(f"… и ещё {len(group) - 25}")
    assessments = list(dict.fromkeys(view["assessment"] for view in views if view.get("assessment")))
    if len(assessments) == 1:
        lines += ["", f"Вероятная причина: {h(assessments[0])}"]
    if cc_lines:
        lines += ["", *cc_lines]
    return clip("\n".join(lines))


def recovered_text(view: dict[str, Any]) -> str:
    lines = [
        "🟢 <b>СЕРВЕР ВОССТАНОВЛЕН</b>", "",
        f"Сервер: <b>{h(view['name'])}</b>",
        f"Адрес: {code(view['endpoint'])} · {h(view['kind'])}",
        f"Был недоступен: <b>{fmt_duration(view['resolved_at'] - view['started_at'])}</b> "
        f"({period(view['started_at'], view['resolved_at'])})",
        f"Подтверждено {view['oks']} успешными проверками подряд к {fmt_time(view['recovered_at'])}",
    ]
    return "\n".join(lines)


def recovered_node_text(views: list[dict[str, Any]]) -> str:
    """Several configurations of one physical server came back together."""
    first = views[0]
    started = min(view["started_at"] for view in views)
    resolved = max(view["resolved_at"] for view in views)
    lines = [
        "🟢 <b>СЕРВЕР ВОССТАНОВЛЕН</b>", "",
        f"Сервер: <b>{h(first['name'])}</b>",
        f"Адрес: {code(first['address'])}",
        f"Был недоступен: <b>{fmt_duration(resolved - started)}</b> ({period(started, resolved)})",
        "Восстановлены конфигурации:",
    ]
    lines += [f"• {view['port']} · {h(view['kind'])}" for view in views]
    lines.append(f"Подтверждено {first['oks']} успешными проверками подряд к "
                 f"{fmt_time(max(view['recovered_at'] for view in views))}")
    return "\n".join(lines)


def recovered_digest_text(views: list[dict[str, Any]]) -> str:
    lines = ["🟢 <b>СЕРВЕРЫ ВОССТАНОВЛЕНЫ</b>", "", f"Снова доступны {servers_word(len(views))}:"]
    for view in views[:30]:
        lines.append(f"• {h(view['name'])} — был недоступен {fmt_duration(view['resolved_at'] - view['started_at'])} "
                     f"({period(view['started_at'], view['resolved_at'])})")
    if len(views) > 30:
        lines.append(f"… и ещё {len(views) - 30}")
    lines += ["", f"Каждый подтверждён {views[0]['oks']} успешными проверками подряд."]
    return clip("\n".join(lines))


def cc_followup_text(names: list[str], status: str, assessment: str) -> str:
    title = names[0] if len(names) == 1 else f"{len(names)} серверов"
    if status == "unavailable":
        return (f"ℹ️ Cheburcheck: получить данные по инциденту «{h(title)}» не удалось — сервис был недоступен. "
                "На оценку состояния сервера это не влияло.")
    text = f"ℹ️ Cheburcheck: данные по инциденту «{h(title)}» получены, сообщение выше дополнено."
    if assessment:
        text += f"\nВероятная причина: {h(assessment)}"
    return text


def flapping_text(view: dict[str, Any], count: int, window: int) -> str:
    return "\n".join([
        "⚠️ <b>СЕРВЕР НЕСТАБИЛЕН</b>", "",
        f"Сервер: <b>{h(view['name'])}</b>",
        f"Адрес: {code(view['endpoint'])} · {h(view['kind'])}",
        f"Падений за {fmt_duration(window)}: <b>{count}</b>. Сейчас: <b>DOWN</b> с {fmt_time(view['started_at'])}.",
        f"Причина последнего: {h(view['reason'])}", "",
        "Уведомления о его падениях и восстановлениях приостановлены, пока сервер не проработает "
        f"без сбоев {fmt_duration(window)}. История продолжает записываться.",
    ])


def stable_text(name: str, endpoint: str, state: str, since: int | None, window: int) -> str:
    if state == "DOWN":
        tail = f"Сервер остаётся <b>недоступным</b> с {fmt_datetime(since)}."
    else:
        tail = "Сервер <b>доступен</b>."
    return "\n".join([
        "ℹ️ <b>Сервер стабилизировался</b>", "",
        f"Сервер: <b>{h(name)}</b> ({code(endpoint)})",
        f"Смен состояния не было {fmt_duration(window)}. {tail}",
        "Уведомления по нему снова включены.",
    ])


def partial_text(name: str, endpoint: str, note: str, count: int) -> str:
    return "\n".join([
        "⚠️ <b>Частичная недоступность</b>", "",
        f"Сервер: <b>{h(name)}</b> ({code(endpoint)})",
        f"Сервер работает, но часть его адресов недоступна: {h(note)}.",
        f"Подтверждено {checks_word(count)} подряд.",
    ])


def partial_cleared_text(name: str, endpoint: str) -> str:
    return f"🟢 Все адреса сервера <b>{h(name)}</b> ({code(endpoint)}) снова доступны."


# ── monitor's own events ────────────────────────────────────────────────────

def started_text(info: dict[str, Any]) -> str:
    lines = ["▶️ <b>Мониторинг запущен</b>", ""]
    if info.get("downtime") and info["downtime"] > 90:
        lines.append(f"Не работал: {fmt_duration(info['downtime'])} "
                     f"(с {fmt_short(info['last_alive'])} до {fmt_short(info['now'])} МСК) — "
                     "за это время проверки не выполнялись.")
    elif info.get("first_run"):
        lines.append("Первый запуск.")
    lines.append(f"Серверов под наблюдением: {info['servers']}"
                 + (f", недоступных на момент остановки: {info['down']}" if info.get("down") else ""))
    lines.append(f"Интервал проверки: {info['interval']}")
    lines.append("Сквозная проверка через Xray: " + (f"включена ({h(info['xray'])})" if info.get("e2e") else
                                                      f"<b>не работает</b> — {h(info.get('e2e_problem') or 'выключена')}"))
    if info.get("paused"):
        lines.append("⏸ Мониторинг на паузе.")
    if not info["servers"]:
        lines.append("\nДобавьте подписку — пришлите ссылку или нажмите «➕ Добавить подписку».")
    return "\n".join(lines)


def monitor_problem_text(problem: str, details: list[str], since: int) -> str:
    return "\n".join([
        "⚠️ <b>ПРОБЛЕМА МОНИТОРИНГА</b>", "",
        f"С {fmt_time(since)} {h(problem)}.",
        "Контроль: " + h("; ".join(details)), "",
        "Пока это не устранено, результаты проверок не учитываются: состояния серверов заморожены, "
        "уведомления о падениях и восстановлениях не отправляются.",
    ])


def monitor_restored_text(problem: str, since: int, until: int) -> str:
    return "\n".join([
        "✅ <b>Мониторинг восстановлен</b>", "",
        f"Проблема «{h(problem)}» устранена.",
        f"Проверки не учитывались {fmt_duration(until - since)} ({period(since, until)}).",
    ])


def dns_problem_text(detail: str, since: int) -> str:
    return "\n".join([
        "⚠️ <b>Проблема DNS на сервере мониторинга</b>", "",
        f"С {fmt_time(since)} системный DNS-резолвер не отвечает ({h(detail)}).",
        "Мониторинг продолжает работу через резервные резолверы и последние известные IP-адреса; "
        "серверы из-за этого недоступными не считаются.",
    ])


def dns_restored_text(since: int, until: int) -> str:
    return f"✅ Системный DNS-резолвер снова отвечает. Проблема длилась {fmt_duration(until - since)}."


def overrun_text(duration: float, interval: int) -> str:
    return "\n".join([
        "⚠️ <b>Цикл проверки не укладывается в интервал</b>", "",
        f"Последние циклы занимают около {fmt_duration(duration)} при интервале {fmt_duration(interval)}.",
        "Увеличьте интервал или число одновременных проверок в настройках.",
    ])


def e2e_broken_text(problem: str) -> str:
    return "\n".join([
        "⚠️ <b>Сквозная проверка не работает</b>", "",
        h(problem),
        "Серверы проверяются по уровням DNS → TCP/QUIC → TLS. Блокировку самого протокола при открытом "
        "порте так обнаружить нельзя. Установите Xray-core (см. README) или отключите сквозную проверку в настройках.",
    ])


def cc_back_text(downtime: int, waiting: int) -> str:
    text = f"✅ <b>Cheburcheck снова доступен</b> (не отвечал {fmt_duration(downtime)})."
    if waiting:
        text += f"\nДанные по отложенным инцидентам ({waiting}) запрашиваются; сообщения будут дополнены."
    return text


def cc_api_changed_text(detail: str) -> str:
    return "\n".join([
        "⚠️ <b>Cheburcheck отвечает в неожиданном формате</b>", "",
        f"Ошибка разбора: {h(detail)}.",
        "Вероятно, API сервиса изменился. Собственные проверки серверов работают как прежде; "
        "данные Cheburcheck временно не добавляются. Проверьте наличие обновления бота.",
    ])


# ── subscriptions ───────────────────────────────────────────────────────────

def subscription_error_text(hint: str, title: str, message: str, last_ok: int | None, servers: int) -> str:
    lines = ["⚠️ <b>Не удалось обновить подписку</b>", "", f"Подписка: {h(title or hint)} ({code(hint)})",
             f"Ошибка: {h(message)}"]
    if last_ok:
        lines.append(f"Последнее успешное обновление: {fmt_datetime(last_ok)}")
    lines += ["", f"Список серверов не изменён ({servers}), мониторинг продолжается по сохранённым данным."]
    return "\n".join(lines)


def subscription_ok_again_text(hint: str, title: str) -> str:
    return f"✅ Подписка {h(title or hint)} ({code(hint)}) снова обновляется."


def subscription_changed_text(hint: str, title: str, added: list[str], restored: list[str],
                              archived: list[str], total: int) -> str:
    lines = ["🔁 <b>Состав серверов подписки изменился</b>", "", f"Подписка: {h(title or hint)} ({code(hint)})"]
    for caption, names in (("Добавлены", added), ("Возвращены", restored), ("Удалены", archived)):
        if names:
            lines.append(f"{caption} ({len(names)}): " + h(", ".join(names[:12])) + (" …" if len(names) > 12 else ""))
    lines.append(f"Всего серверов в подписке: {total}")
    return "\n".join(lines)


def subscription_needs_confirm_text(hint: str, title: str, removing: int, total: int) -> str:
    return "\n".join([
        "❓ <b>Подписка сильно изменилась</b>", "",
        f"Подписка: {h(title or hint)} ({code(hint)})",
        f"Новый ответ не содержит {removing} из {total} отслеживаемых серверов.",
        "Чтобы не потерять наблюдение из-за временного сбоя панели, список оставлен без изменений.",
        "Если так и задумано — откройте «➕ Добавить подписку» и нажмите «Обновить» с подтверждением.",
    ])


def subscription_expiring_text(hint: str, title: str, expire_at: int) -> str:
    return "\n".join([
        "⏳ <b>Подписка скоро истекает</b>", "",
        f"Подписка: {h(title or hint)} ({code(hint)})",
        f"Срок действия: до {fmt_datetime(expire_at)}.",
        "После истечения панель перестанет отдавать список серверов, а сквозная проверка — проходить. "
        "Мониторинг продолжит проверять сохранённые серверы по уровням DNS → TCP → TLS.",
    ])


def credentials_suspended_text(hint: str, title: str, reason: str, count: int) -> str:
    return "\n".join([
        "⚠️ <b>Проблема с подпиской, а не с серверами</b>", "",
        f"Подписка: {h(title or hint)} ({code(hint)})",
        f"Сквозная проверка перестала проходить сразу на всех серверах подписки ({count}), "
        f"при этом сами серверы отвечают. Панель сообщает: {h(reason)}.",
        "Похоже, учётные данные подписки больше не действуют (истёк срок, исчерпан трафик, отключён доступ).", "",
        "Сквозная проверка для этой подписки приостановлена, серверы недоступными не считаются; "
        "они проверяются по уровням DNS → TCP → TLS. После продления подписки всё возобновится автоматически.",
    ])


def credentials_resumed_text(hint: str, title: str) -> str:
    return f"✅ Подписка {h(title or hint)} ({code(hint)}) снова активна — сквозная проверка возобновлена."
