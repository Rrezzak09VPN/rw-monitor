"""Runtime settings: values the owner can change from Telegram.

Effective value = override stored in the DB, otherwise the default from .env.
Overrides survive restarts and can be reset to the .env value.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .config import Config, parse_intervals, validate_proxy_url
from .db.database import Database
from .security import SecretBox, mask_proxy
from .timeutil import fmt_interval, now_ts, parse_duration


@dataclass(frozen=True)
class Spec:
    key: str
    title: str
    kind: str  # duration | int | bool | choice | intervals | proxy
    group: str
    minimum: float | None = None
    maximum: float | None = None
    choices: tuple[str, ...] = ()
    presets: tuple[str, ...] = ()
    hint: str = ""


SPECS: tuple[Spec, ...] = (
    # monitoring
    Spec("check_interval", "Интервал проверки", "duration", "monitor", 20, 86400,
         presets=("1m", "3m", "5m", "10m")),
    Spec("fail_threshold", "Неудач подряд до DOWN", "int", "monitor", 2, 20, presets=("2", "3", "4", "5")),
    Spec("recovery_threshold", "Успехов подряд до восстановления", "int", "monitor", 1, 20,
         presets=("2", "3", "5")),
    Spec("recheck_intervals", "Интервалы перепроверок", "intervals", "monitor",
         presets=("20,40", "30,60", "60,120"),
         hint="Секунды через запятую, например 30,60. Последнее значение повторяется."),
    Spec("recovery_recheck_interval", "Интервал проверок при восстановлении", "duration", "monitor",
         5, 3600, presets=("15s", "30s", "1m")),
    Spec("recovered_hold", "Наблюдение после восстановления", "duration", "monitor", 0, 86400,
         presets=("5m", "10m", "30m")),
    Spec("check_concurrency", "Одновременных проверок", "int", "monitor", 1, 50,
         presets=("3", "5", "10")),
    # timeouts
    Spec("dns_timeout", "Таймаут DNS", "duration", "timeouts", 1, 30, presets=("3s", "4s", "6s")),
    Spec("tcp_timeout", "Таймаут TCP-соединения", "duration", "timeouts", 1, 60,
         presets=("3s", "5s", "8s", "10s")),
    Spec("tls_timeout", "Таймаут TLS-рукопожатия", "duration", "timeouts", 1, 60,
         presets=("5s", "7s", "10s")),
    Spec("quic_timeout", "Таймаут UDP/QUIC", "duration", "timeouts", 1, 30, presets=("2s", "3s", "5s")),
    Spec("e2e_timeout", "Таймаут сквозной проверки", "duration", "timeouts", 3, 120,
         presets=("8s", "12s", "20s")),
    # end-to-end
    Spec("e2e_mode", "Сквозная проверка через Xray", "choice", "e2e", choices=("on", "off")),
    Spec("e2e_data_probe_every", "Проверка передачи данных (0 — выкл.)", "duration", "e2e", 0, 86400,
         presets=("0", "5m", "15m", "1h"),
         hint="Как часто загружать тестовый объём через туннель, чтобы поймать обрыв после 16–20 КБ."),
    # cheburcheck
    Spec("cheburcheck_enabled", "Запросы к Cheburcheck", "bool", "cheburcheck"),
    Spec("cheburcheck_probe", "Региональные замеры", "bool", "cheburcheck"),
    Spec("cheburcheck_wait", "Ждать ответ перед уведомлением", "duration", "cheburcheck", 0, 180,
         presets=("0", "20s", "40s", "90s")),
    Spec("cheburcheck_cache_ttl", "Срок годности результата", "duration", "cheburcheck", 0, 86400,
         presets=("30m", "1h", "3h")),
    Spec("cheburcheck_daily_limit", "Запросов в сутки, не более", "int", "cheburcheck", 1, 10000,
         presets=("100", "300", "1000")),
    # subscriptions
    Spec("subscription_refresh_interval", "Автообновление подписок (0 — выкл.)", "duration",
         "subscriptions", 0, 7 * 86400, presets=("0", "30m", "1h", "6h")),
    # telegram
    Spec("telegram_proxy_url", "Прокси для Telegram", "proxy", "telegram",
         hint="Например socks5://user:pass@host:1080 или http://host:3128. «-» — без прокси."),
)

SPEC_BY_KEY: dict[str, Spec] = {spec.key: spec for spec in SPECS}

GROUP_TITLES = {
    "monitor": "⏱ Проверки и пороги",
    "timeouts": "⌛ Таймауты",
    "e2e": "🔗 Сквозная проверка",
    "cheburcheck": "🛰 Cheburcheck",
    "subscriptions": "📥 Подписки",
    "telegram": "🌐 Прокси Telegram",
}

_TRUE = {"1", "true", "on", "yes", "да", "вкл", "включить", "включено"}
_FALSE = {"0", "false", "off", "no", "нет", "выкл", "выключить", "выключено"}


_ENC = "enc:"


class SettingError(ValueError):
    pass


def _parse(spec: Spec, raw: Any) -> Any:
    text = str(raw).strip()
    if spec.kind == "duration":
        value = parse_duration(text)
        if value is None:
            raise SettingError("не удалось разобрать значение. Примеры: 90, 30s, 5m, 1h")
        _check_range(spec, value)
        return value
    if spec.kind == "int":
        if not text.lstrip("-").isdigit():
            raise SettingError("нужно целое число")
        value = int(text)
        _check_range(spec, value)
        return value
    if spec.kind == "bool":
        lowered = text.lower()
        if lowered in _TRUE:
            return True
        if lowered in _FALSE:
            return False
        raise SettingError("допустимо: вкл / выкл")
    if spec.kind == "choice":
        lowered = text.lower()
        if lowered not in spec.choices:
            raise SettingError(f"допустимые значения: {', '.join(spec.choices)}")
        return lowered
    if spec.kind == "intervals":
        try:
            return ",".join(str(item) for item in parse_intervals(text))
        except ValueError as exc:
            raise SettingError(str(exc)) from exc
    if spec.kind == "proxy":
        if text in ("-", "нет", "none", "off"):
            return ""
        try:
            return validate_proxy_url(text)
        except ValueError as exc:
            raise SettingError(str(exc)) from exc
    raise SettingError("неизвестный тип настройки")


def _check_range(spec: Spec, value: float) -> None:
    if spec.minimum is not None and value < spec.minimum:
        raise SettingError(f"минимум — {_plain(spec, spec.minimum)}")
    if spec.maximum is not None and value > spec.maximum:
        raise SettingError(f"максимум — {_plain(spec, spec.maximum)}")


def _plain(spec: Spec, value: Any) -> str:
    if spec.kind == "duration":
        return fmt_interval(value) if value else "выключено" if spec.minimum == 0 else "0 с"
    if spec.kind == "bool":
        return "включено" if value else "выключено"
    if spec.kind == "choice":
        return {"on": "включена", "off": "выключена"}.get(str(value), str(value))
    if spec.kind == "intervals":
        return ", ".join(fmt_interval(int(item)) for item in str(value).split(","))
    if spec.kind == "proxy":
        return mask_proxy(str(value))
    return str(value)


class Settings:
    """Cached view over the ``settings`` table merged with .env defaults."""

    def __init__(self, config: Config, db: Database) -> None:
        self.config = config
        self.db = db
        self._raw: dict[str, str] = {}
        self._box = SecretBox(config.secret_key.get_secret_value())

    def _reveal(self, spec: Spec, stored: str) -> str:
        """Proxy addresses may carry credentials, so they are encrypted at rest."""
        if spec.kind == "proxy" and stored.startswith(_ENC):
            return self._box.decrypt(stored[len(_ENC):].encode())
        return stored

    async def load(self) -> None:
        rows = await self.db.fetchall("SELECT key, value FROM settings")
        self._raw = {row["key"]: row["value"] for row in rows}

    # ── owner-facing settings ───────────────────────────────────────────────
    def get(self, key: str) -> Any:
        spec = SPEC_BY_KEY[key]
        default = getattr(self.config, key)
        if key in self._raw:
            try:
                return _parse(spec, self._reveal(spec, self._raw[key]))
            except (SettingError, ValueError):
                return default
        if spec.kind == "duration":
            return int(default)
        return default

    def is_overridden(self, key: str) -> bool:
        return key in self._raw

    def display(self, key: str) -> str:
        return _plain(SPEC_BY_KEY[key], self.get(key))

    def preset_label(self, key: str, preset: str) -> str:
        spec = SPEC_BY_KEY[key]
        return _plain(spec, _parse(spec, preset))

    async def set(self, key: str, raw: Any) -> Any:
        spec = SPEC_BY_KEY.get(key)
        if spec is None:
            raise SettingError("неизвестная настройка")
        value = _parse(spec, raw)
        stored = ("1" if value else "0") if spec.kind == "bool" else str(value)
        if spec.kind == "proxy" and stored:
            stored = _ENC + self._box.encrypt(stored).decode()
        await self._store(key, stored)
        return value

    async def reset(self, key: str) -> None:
        self._raw.pop(key, None)
        await self.db.execute("DELETE FROM settings WHERE key=?", (key,))

    async def reset_all(self) -> int:
        keys = [key for key in self._raw if key in SPEC_BY_KEY]
        for key in keys:
            await self.reset(key)
        return len(keys)

    # ── internal key/value storage (not shown as settings) ──────────────────
    def raw(self, key: str, default: str = "") -> str:
        return self._raw.get(key, default)

    def raw_int(self, key: str, default: int = 0) -> int:
        try:
            return int(self._raw.get(key, default))
        except (TypeError, ValueError):
            return default

    async def set_raw(self, key: str, value: Any) -> None:
        await self._store(key, str(value))

    async def del_raw(self, key: str) -> None:
        self._raw.pop(key, None)
        await self.db.execute("DELETE FROM settings WHERE key=?", (key,))

    async def _store(self, key: str, value: str) -> None:
        self._raw[key] = value
        await self.db.execute(
            "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
            (key, value, now_ts()),
        )

    # ── convenience accessors ───────────────────────────────────────────────
    @property
    def recheck_intervals(self) -> list[int]:
        return parse_intervals(self.get("recheck_intervals"))

    def recheck_delay(self, fail_streak: int) -> int:
        """Delay before the next recheck after ``fail_streak`` consecutive failures."""
        intervals = self.recheck_intervals
        return intervals[min(max(fail_streak, 1), len(intervals)) - 1]

    @property
    def e2e_enabled(self) -> bool:
        return self.get("e2e_mode") == "on"

    # global pause -----------------------------------------------------------
    def pause_state(self, now: int | None = None) -> tuple[bool, int]:
        """Returns (paused, until_ts). ``until_ts == 0`` means "until resumed"."""
        if self.raw("monitor.paused") != "1":
            return False, 0
        until = self.raw_int("monitor.paused_until")
        if until and until <= (now if now is not None else now_ts()):
            return False, 0
        return True, until

    async def set_pause(self, paused: bool, until: int = 0) -> None:
        await self.set_raw("monitor.paused", "1" if paused else "0")
        await self.set_raw("monitor.paused_until", int(until) if paused else 0)
