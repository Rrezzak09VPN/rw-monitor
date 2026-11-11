"""Static configuration loaded from a single .env file (or process environment).

Values that the owner may change from Telegram are *defaults* here; the
effective value is resolved by :mod:`rwmon.settings` (DB override > .env).
"""

from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

PROXY_SCHEMES = ("socks5", "socks5h", "socks4", "http", "https")
PROXY_ENV_VARS = (
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "FTP_PROXY", "NO_PROXY",
    "http_proxy", "https_proxy", "all_proxy", "ftp_proxy", "no_proxy",
)


def validate_proxy_url(value: str) -> str:
    """Return a normalised proxy URL or raise ValueError. Empty string = no proxy."""
    value = (value or "").strip()
    if not value:
        return ""
    parts = urlsplit(value)
    if parts.scheme.lower() not in PROXY_SCHEMES:
        raise ValueError(f"схема прокси должна быть одной из: {', '.join(PROXY_SCHEMES)}")
    if not parts.hostname:
        raise ValueError("в адресе прокси не указан хост")
    try:
        port = parts.port
    except ValueError as exc:
        raise ValueError("некорректный порт прокси") from exc
    if not port:
        raise ValueError("в адресе прокси не указан порт")
    # python-socks does not know "socks5h"; remote DNS is the default there.
    if parts.scheme.lower() == "socks5h":
        value = "socks5" + value[len(parts.scheme):]
    return value


def split_csv(value: str) -> list[str]:
    return [item.strip() for item in (value or "").replace(";", ",").split(",") if item.strip()]


class Config(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore", case_sensitive=False)

    # ── Telegram ────────────────────────────────────────────────────────────
    telegram_bot_token: SecretStr
    telegram_owner_id: int = Field(gt=0)
    telegram_proxy_url: str = ""
    telegram_api_base_url: str = "https://api.telegram.org"

    # ── Storage ─────────────────────────────────────────────────────────────
    data_dir: Path = Path("/var/lib/rw-monitor")
    db_path: Path | None = None
    secret_key: SecretStr
    backup_keep: int = Field(7, ge=1, le=365)
    backup_hour_msk: int = Field(4, ge=0, le=23)

    # ── Monitoring (defaults; changeable from Telegram) ─────────────────────
    check_interval: int = Field(180, ge=20, le=86400)
    fail_threshold: int = Field(3, ge=2, le=20)
    recovery_threshold: int = Field(3, ge=1, le=20)
    recheck_intervals: str = "30,60"
    recovery_recheck_interval: int = Field(30, ge=5, le=3600)
    recovered_hold: int = Field(600, ge=0, le=86400)
    check_concurrency: int = Field(5, ge=1, le=50)

    dns_timeout: float = Field(4.0, ge=1, le=30)
    tcp_timeout: float = Field(5.0, ge=1, le=60)
    tls_timeout: float = Field(7.0, ge=1, le=60)
    quic_timeout: float = Field(3.0, ge=1, le=30)
    e2e_timeout: float = Field(12.0, ge=3, le=120)
    tcp_attempts: int = Field(2, ge=1, le=5)

    dns_resolvers: str = "77.88.8.8,8.8.8.8"
    ip_family: str = "auto"  # auto | ipv4 | ipv6 | both
    max_ips_per_server: int = Field(4, ge=1, le=16)

    # ── Self-health ─────────────────────────────────────────────────────────
    canary_ru: str = "ya.ru:443,vk.com:443,77.88.8.8:53"
    canary_foreign: str = "www.google.com:443,github.com:443,www.microsoft.com:443,8.8.8.8:53"
    canary_dns_name: str = "ya.ru"
    mass_fail_percent: int = Field(50, ge=10, le=100)
    mass_fail_min: int = Field(3, ge=2, le=1000)
    flap_max_incidents: int = Field(3, ge=2, le=50)
    flap_window: int = Field(3600, ge=300, le=86400)
    state_stale_after: int = Field(600, ge=60, le=86400)

    # ── End-to-end check through Xray ───────────────────────────────────────
    e2e_mode: str = "on"  # on | off
    xray_bin: str = "/usr/local/bin/xray"
    e2e_test_urls: str = "https://www.gstatic.com/generate_204,https://cp.cloudflare.com/generate_204"
    e2e_data_probe_every: int = Field(900, ge=0, le=86400)  # 0 = disabled
    e2e_data_probe_url: str = "https://speed.cloudflare.com/__down?bytes=131072"
    e2e_data_probe_bytes: int = Field(131072, ge=1024, le=10_000_000)
    e2e_concurrency: int = Field(3, ge=1, le=20)

    # ── Subscriptions ───────────────────────────────────────────────────────
    subscription_user_agent: str = "rw-monitor/1.0"
    subscription_fallback_user_agents: str = (
        "Happ/3.13.0,v2rayNG/1.10.31,v2RayTun/5.16.0,INCY/1.4.0,Streisand,clash-verge/v2.4.2"
    )
    subscription_extra_profiles: str = "json,mihomo"
    subscription_refresh_interval: int = Field(3600, ge=0, le=7 * 86400)  # 0 = disabled
    subscription_proxy_url: str = ""
    subscription_timeout: float = Field(20.0, ge=3, le=120)
    subscription_hwid: str = ""  # empty = generated once and stored in the DB

    # ── Cheburcheck ─────────────────────────────────────────────────────────
    cheburcheck_enabled: bool = True
    cheburcheck_base_url: str = "https://cheburcheck.ru"
    cheburcheck_proxy_url: str = ""
    cheburcheck_probe: bool = True  # request dynamic regional probes
    cheburcheck_wait: int = Field(40, ge=0, le=180)
    cheburcheck_cache_ttl: int = Field(3600, ge=0, le=86400)
    cheburcheck_daily_limit: int = Field(300, ge=1, le=10000)
    cheburcheck_check_interval: float = Field(3.0, ge=2, le=60)
    cheburcheck_probe_interval: float = Field(15.0, ge=12, le=300)
    cheburcheck_targets: str = "ip,domain,sni"

    # ── Retention ───────────────────────────────────────────────────────────
    retention_checks_days: int = Field(14, ge=1, le=3650)
    retention_events_days: int = Field(180, ge=1, le=3650)
    retention_cheburcheck_days: int = Field(90, ge=1, le=3650)

    # ── Misc ────────────────────────────────────────────────────────────────
    log_level: str = "INFO"
    heartbeat_url: str = ""
    heartbeat_interval: int = Field(300, ge=30, le=86400)

    @field_validator("telegram_proxy_url", "subscription_proxy_url", "cheburcheck_proxy_url")
    @classmethod
    def _check_proxy(cls, value: str) -> str:
        return validate_proxy_url(value)

    @field_validator("telegram_bot_token")
    @classmethod
    def _check_token(cls, value: SecretStr) -> SecretStr:
        token = value.get_secret_value().strip()
        head, sep, tail = token.partition(":")
        if not sep or not head.isdigit() or len(tail) < 20:
            raise ValueError("ожидается токен вида 123456:ABC… (выдаёт @BotFather)")
        return SecretStr(token)

    @field_validator("recheck_intervals")
    @classmethod
    def _check_recheck(cls, value: str) -> str:
        parse_intervals(value)
        return value

    @field_validator("e2e_mode")
    @classmethod
    def _check_e2e(cls, value: str) -> str:
        value = value.strip().lower()
        if value not in ("on", "off"):
            raise ValueError("допустимые значения: on, off")
        return value

    @field_validator("ip_family")
    @classmethod
    def _check_family(cls, value: str) -> str:
        value = value.strip().lower()
        if value not in ("auto", "ipv4", "ipv6", "both"):
            raise ValueError("допустимые значения: auto, ipv4, ipv6, both")
        return value

    @field_validator("log_level")
    @classmethod
    def _check_level(cls, value: str) -> str:
        value = value.strip().upper()
        if value not in ("DEBUG", "INFO", "WARNING", "ERROR"):
            raise ValueError("допустимые значения: DEBUG, INFO, WARNING, ERROR")
        return value

    @model_validator(mode="after")
    def _derive(self) -> "Config":
        if self.db_path is None:
            self.db_path = self.data_dir / "rwmon.sqlite3"
        return self

    @property
    def backup_dir(self) -> Path:
        return self.data_dir / "backups"

    @property
    def run_dir(self) -> Path:
        return self.data_dir / "run"


def parse_intervals(value: str) -> list[int]:
    """Parse "30,60" into [30, 60]; every item must be 5..3600 seconds."""
    items = split_csv(value)
    if not items:
        raise ValueError("нужен хотя бы один интервал")
    result = []
    for item in items:
        if not item.isdigit() or not 5 <= int(item) <= 3600:
            raise ValueError("интервалы задаются в секундах, от 5 до 3600, через запятую")
        result.append(int(item))
    return result


def load_config(env_file: str | os.PathLike | None = None) -> Config:
    """Load configuration. ``env_file`` falls back to $RWMON_ENV_FILE, then ./.env."""
    path = env_file or os.environ.get("RWMON_ENV_FILE") or ".env"
    path = Path(path)
    return Config(_env_file=path if path.is_file() else None)  # type: ignore[call-arg]


def scrub_proxy_env() -> list[str]:
    """Remove proxy variables from the process environment.

    Server checks must leave the host directly; nothing in this process is
    allowed to pick a proxy up implicitly.
    """
    removed = [name for name in PROXY_ENV_VARS if os.environ.pop(name, None) is not None]
    return removed
