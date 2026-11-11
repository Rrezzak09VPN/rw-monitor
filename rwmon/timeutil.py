"""Time helpers: UTC storage, Moscow-time presentation, Russian durations."""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

try:
    from zoneinfo import ZoneInfo

    MSK = ZoneInfo("Europe/Moscow")
except Exception:  # noqa: BLE001 - tzdata may be absent; Moscow is UTC+3 without DST
    MSK = timezone(timedelta(hours=3), "MSK")


def now_ts() -> int:
    """Current wall-clock time, unix seconds (UTC)."""
    return int(time.time())


def to_msk(ts: int | float) -> datetime:
    return datetime.fromtimestamp(ts, MSK)


def fmt_time(ts: int | float | None) -> str:
    """``12:34:56 МСК``"""
    return f"{to_msk(ts):%H:%M:%S} МСК" if ts else "—"


def fmt_datetime(ts: int | float | None) -> str:
    """``10.11.2026 12:34:56 МСК``"""
    return f"{to_msk(ts):%d.%m.%Y %H:%M:%S} МСК" if ts else "—"


def fmt_short(ts: int | float | None, now: int | float | None = None) -> str:
    """``12:34`` for today, ``10.11 12:34`` otherwise."""
    if not ts:
        return "—"
    moment = to_msk(ts)
    today = to_msk(now if now is not None else time.time()).date()
    return f"{moment:%H:%M}" if moment.date() == today else f"{moment:%d.%m %H:%M}"


def _plural(n: int, one: str, few: str, many: str) -> str:
    n = abs(n)
    if n % 10 == 1 and n % 100 != 11:
        return one
    if 2 <= n % 10 <= 4 and not 12 <= n % 100 <= 14:
        return few
    return many


def fmt_duration(seconds: int | float | None) -> str:
    """Human-readable Russian duration: ``45 секунд``, ``17 минут``, ``2 ч 05 мин``."""
    if seconds is None:
        return "—"
    seconds = max(0, int(round(seconds)))
    if seconds < 60:
        return f"{seconds} {_plural(seconds, 'секунда', 'секунды', 'секунд')}"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes} {_plural(minutes, 'минута', 'минуты', 'минут')}"
    hours, minutes = divmod(minutes, 60)
    if hours < 24:
        return f"{hours} ч {minutes:02d} мин" if minutes else f"{hours} ч"
    days, hours = divmod(hours, 24)
    return f"{days} д {hours} ч" if hours else f"{days} д"


def fmt_interval(seconds: int | float) -> str:
    """Compact setting value: ``30 с``, ``3 мин``, ``1 ч``."""
    seconds = int(seconds)
    if seconds < 60 or seconds % 60:
        return f"{seconds} с"
    if seconds < 3600 or seconds % 3600:
        return f"{seconds // 60} мин"
    return f"{seconds // 3600} ч"


def parse_duration(text: str) -> int | None:
    """Parse ``90``, ``90s``, ``15m``, ``2h``, ``1d``, ``15 мин``, ``2 ч`` into seconds."""
    text = (text or "").strip().lower().replace(",", ".")
    if not text:
        return None
    units = {
        "s": 1, "с": 1, "сек": 1, "sec": 1,
        "m": 60, "м": 60, "мин": 60, "min": 60,
        "h": 3600, "ч": 3600, "час": 3600,
        "d": 86400, "д": 86400, "дн": 86400, "day": 86400,
    }
    number, unit = text, ""
    for index, char in enumerate(text):
        if not (char.isdigit() or char == "."):
            number, unit = text[:index], text[index:].strip().rstrip(".")
            break
    try:
        value = float(number)
    except ValueError:
        return None
    factor = units.get(unit, 1 if not unit else None)
    if factor is None or value < 0:
        return None
    return int(value * factor)
