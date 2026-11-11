"""Downloading subscriptions and diagnosing what the panel answered."""

from __future__ import annotations

import asyncio
import base64
import logging
import platform
from collections import Counter
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urlsplit, urlunsplit

import aiohttp

from ..config import Config, split_csv
from ..neterrors import PROXY_ERRORS
from ..security import mask_url
from ..timeutil import fmt_datetime, now_ts
from .model import ServerConfig, merge_servers
from .parsers import ParseResult, parse_subscription

log = logging.getLogger(__name__)

MAX_BODY = 5 * 1024 * 1024
EXTRA_SUFFIXES = {"json": "json", "mihomo": "mihomo", "singbox": "singbox", "clash": "clash", "stash": "stash"}

# Statuses of LoadResult
OK = "ok"
NEEDS_HWID = "needs_hwid"
HWID_LIMIT = "hwid_limit"
NO_SERVERS = "no_servers"
BLOCKED = "blocked"
NOT_FOUND = "not_found"
HTML = "html"
ENCRYPTED = "encrypted"
UNSUPPORTED = "unsupported"
NETWORK = "network"
UNKNOWN = "unknown"

# Statuses where another User-Agent may help.
_UA_RELATED = (BLOCKED, HTML, UNKNOWN, NO_SERVERS)


@dataclass
class FetchResponse:
    status: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    error: str = ""       # '' | timeout | connect | tls | dropped | too_large | error
    error_text: str = ""


@dataclass
class LoadResult:
    status: str
    message: str = ""
    servers: list[ServerConfig] = field(default_factory=list)
    formats: list[str] = field(default_factory=list)
    placeholders: list[str] = field(default_factory=list)
    skipped: Counter = field(default_factory=Counter)
    user_agent: str = ""
    title: str = ""
    userinfo: dict[str, int] = field(default_factory=dict)
    http_status: int | None = None
    hwid_active: bool = False

    @property
    def ok(self) -> bool:
        return self.status == OK

    @property
    def expire_at(self) -> int:
        return int(self.userinfo.get("expire", 0) or 0)


def validate_subscription_url(text: str) -> str:
    """Return a cleaned URL or raise ValueError with a message for the owner."""
    url = (text or "").strip()
    parts = urlsplit(url)
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
        raise ValueError("нужна ссылка вида https://…")
    if len(url) > 2048 or any(ch.isspace() for ch in url):
        raise ValueError("ссылка содержит недопустимые символы")
    return urlunsplit((parts.scheme.lower(), parts.netloc, parts.path, parts.query, ""))


def with_suffix(url: str, suffix: str) -> str:
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path.rstrip("/") + "/" + suffix, parts.query, ""))


def decode_header_text(value: str) -> str:
    """Remnawave encodes some headers as ``base64:<data>``."""
    value = (value or "").strip()
    if value.startswith("base64:"):
        try:
            return base64.b64decode(value[7:] + "=" * (-len(value[7:]) % 4)).decode("utf-8", "replace").strip()
        except Exception:  # noqa: BLE001
            return ""
    return value


def parse_userinfo(value: str) -> dict[str, int]:
    result: dict[str, int] = {}
    for part in (value or "").split(";"):
        key, sep, number = part.strip().partition("=")
        if sep and number.strip().lstrip("-").isdigit():
            result[key.strip().lower()] = int(number)
    return result


class SubscriptionFetcher:
    """HTTP client for subscriptions. Never follows process-wide proxy settings."""

    def __init__(self, config: Config, hwid_provider: Callable[[], str]) -> None:
        self.config = config
        self._hwid_provider = hwid_provider
        self._session: aiohttp.ClientSession | None = None

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            connector = None
            if self.config.subscription_proxy_url:
                from aiohttp_socks import ProxyConnector

                connector = ProxyConnector.from_url(self.config.subscription_proxy_url)
            self._session = aiohttp.ClientSession(
                connector=connector, trust_env=False,
                timeout=aiohttp.ClientTimeout(total=self.config.subscription_timeout),
                cookie_jar=aiohttp.DummyCookieJar(),
            )
        return self._session

    async def close(self) -> None:
        if self._session is not None and not self._session.closed:
            await self._session.close()

    def _headers(self, user_agent: str, use_hwid: bool) -> dict[str, str]:
        headers = {"User-Agent": user_agent, "Accept": "*/*"}
        if use_hwid:
            headers.update({
                "x-hwid": self._hwid_provider(),
                "x-device-os": "Linux",
                "x-ver-os": platform.release()[:40] or "unknown",
                "x-device-model": "rw-monitor",
            })
        return headers

    async def request(self, url: str, user_agent: str, use_hwid: bool) -> FetchResponse:
        session = await self._get_session()
        try:
            async with session.get(
                url, headers=self._headers(user_agent, use_hwid), allow_redirects=True, max_redirects=5,
            ) as response:
                body = await response.content.read(MAX_BODY + 1)
                headers = {key.lower(): value for key, value in response.headers.items()}
                if len(body) > MAX_BODY:
                    return FetchResponse(response.status, headers, b"", "too_large", "ответ больше 5 МБ")
                return FetchResponse(response.status, headers, body)
        except asyncio.TimeoutError:
            return FetchResponse(error="timeout", error_text="таймаут ожидания ответа")
        except aiohttp.ClientSSLError as exc:
            return FetchResponse(error="tls", error_text=f"ошибка TLS: {exc.__class__.__name__}")
        except (aiohttp.ServerDisconnectedError, aiohttp.ClientPayloadError):
            return FetchResponse(error="dropped", error_text="сервер разорвал соединение")
        except aiohttp.ClientConnectorError as exc:
            return FetchResponse(error="connect", error_text=f"не удалось подключиться: {exc.os_error or exc}")
        except aiohttp.ClientOSError as exc:
            kind = "dropped" if exc.errno in (104, 32) else "error"
            return FetchResponse(error=kind, error_text=f"сетевая ошибка: {exc.strerror or exc}")
        except aiohttp.ClientError as exc:
            return FetchResponse(error="error", error_text=f"ошибка HTTP-клиента: {exc.__class__.__name__}")
        except PROXY_ERRORS as exc:
            return FetchResponse(error="proxy", error_text=f"прокси для подписок не отвечает ({exc.__class__.__name__})")
        except OSError as exc:
            return FetchResponse(error="error", error_text=f"сетевая ошибка: {exc.strerror or exc.__class__.__name__}")

    # ── high-level loading ──────────────────────────────────────────────────
    async def load(self, url: str, user_agent: str = "", use_hwid: bool = False,
                   allow_fallback: bool = False) -> LoadResult:
        """Fetch a subscription, pick a working request profile and merge formats."""
        primary_ua = user_agent or self.config.subscription_user_agent
        result, parsed = await self._attempt(url, primary_ua, use_hwid)
        if not result.ok and result.status in _UA_RELATED and allow_fallback:
            for candidate in split_csv(self.config.subscription_fallback_user_agents):
                if candidate == primary_ua:
                    continue
                await asyncio.sleep(0.5)
                other, other_parsed = await self._attempt(url, candidate, use_hwid)
                if other.ok or other.status in (NEEDS_HWID, HWID_LIMIT):
                    result, parsed = other, other_parsed
                    break
        if not result.ok:
            log.info("subscription %s: %s (%s)", mask_url(url), result.status, result.message)
            return result
        groups = [parsed.servers]
        for profile in split_csv(self.config.subscription_extra_profiles):
            suffix = EXTRA_SUFFIXES.get(profile)
            if not suffix:
                continue
            await asyncio.sleep(0.3)
            extra = await self.request(with_suffix(url, suffix), result.user_agent, use_hwid)
            if extra.error or extra.status != 200:
                continue  # access by path may be disabled on the panel: not an error
            extra_parsed = parse_subscription(extra.body)
            if extra_parsed.has_servers and extra_parsed.format != parsed.format:
                groups.append(extra_parsed.servers)
                result.formats.append(extra_parsed.format_label)
                result.skipped.update(extra_parsed.skipped)
        result.servers = merge_servers(groups)
        log.info("subscription %s: %d servers, formats: %s", mask_url(url), len(result.servers),
                 ", ".join(result.formats))
        return result

    async def _attempt(self, url: str, user_agent: str, use_hwid: bool) -> tuple[LoadResult, ParseResult]:
        response = await self.request(url, user_agent, use_hwid)
        parsed = parse_subscription(response.body) if not response.error else ParseResult("empty")
        return classify(response, parsed, user_agent, use_hwid), parsed


def classify(response: FetchResponse, parsed: ParseResult, user_agent: str, use_hwid: bool) -> LoadResult:
    """Turn a raw response into a diagnosis the owner can act upon."""
    headers = response.headers
    result = LoadResult(
        status=UNKNOWN, user_agent=user_agent, http_status=response.status,
        title=decode_header_text(headers.get("profile-title", "")),
        userinfo=parse_userinfo(headers.get("subscription-userinfo", "")),
        hwid_active=headers.get("x-hwid-active") == "true",
        placeholders=list(parsed.placeholders), skipped=Counter(parsed.skipped),
    )
    if response.error:
        if response.error == "dropped":
            result.status = BLOCKED
            result.message = ("сервер разорвал соединение: запрос отклонён правилом панели "
                              "либо такой клиент не обслуживается")
        else:
            result.status, result.message = NETWORK, response.error_text
        return result
    if response.status != 200:
        if response.status in (403, 451):
            result.status = BLOCKED
            result.message = f"панель отклонила запрос (HTTP {response.status})"
        elif response.status == 404:
            result.status = NOT_FOUND
            result.message = "подписка не найдена или запрос отклонён (HTTP 404)"
        else:
            result.status, result.message = NETWORK, f"неожиданный ответ сервера: HTTP {response.status}"
        return result
    if parsed.has_servers:
        result.status = OK
        result.formats = [parsed.format_label]
        return result
    notes = "; ".join(dict.fromkeys(parsed.placeholders))[:300]
    quoted = f" Сообщение панели: «{notes}»" if notes else ""
    if headers.get("x-hwid-max-devices-reached") == "true":
        result.status = HWID_LIMIT
        result.message = "на подписке исчерпан лимит устройств (HWID)." + quoted
    elif not use_hwid and (headers.get("x-hwid-not-supported") == "true" or headers.get("x-hwid-limit") == "true"):
        result.status = NEEDS_HWID
        result.message = "панель ограничивает число устройств и требует идентификатор устройства (HWID)." + quoted
    elif parsed.format == "html":
        result.status, result.message = HTML, "вместо подписки получена веб-страница"
    elif parsed.format == "encrypted":
        result.status = ENCRYPTED
        result.message = "ответ зашифрован для клиентского приложения, расшифровать его невозможно"
    elif parsed.format == "unsupported":
        result.status, result.message = UNSUPPORTED, "формат подписки не поддерживается"
    elif parsed.placeholders or parsed.format == "empty" or parsed.format in ("links", "xray_json", "mihomo", "singbox"):
        result.status = NO_SERVERS
        expire = result.expire_at
        if expire and expire < now_ts():
            result.message = f"срок действия подписки истёк {fmt_datetime(expire)}." + quoted
        elif notes:
            result.message = "панель не выдала ни одного сервера." + quoted
        else:
            result.message = "в ответе нет ни одного сервера"
    else:
        result.status, result.message = UNKNOWN, "формат ответа не распознан"
    return result
