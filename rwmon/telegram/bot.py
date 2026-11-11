"""Bot construction, the Telegram proxy and the owner-only gate."""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Awaitable, Callable

from aiogram import BaseMiddleware, Bot
from aiogram.client.default import DefaultBotProperties
from aiogram.client.session.aiohttp import AiohttpSession
from aiogram.client.telegram import TelegramAPIServer
from aiogram.enums import ChatType, ParseMode
from aiogram.types import TelegramObject, Update

from ..config import Config
from ..security import MASKER, mask_proxy
from ..settings import Settings

log = logging.getLogger(__name__)

PROBE_TIMEOUT = 20


class OwnerOnlyMiddleware(BaseMiddleware):
    """Drops every update that is not from the owner in a private chat.

    Registered as the outermost middleware, so nothing else in the bot ever
    sees foreign updates. There is no reply and no logging of their content.
    """

    def __init__(self, owner_id: int) -> None:
        self.owner_id = owner_id
        self.dropped = 0
        self._last_report = 0.0
        self._since_report = 0

    @staticmethod
    def _origin(update: Update) -> tuple[int | None, str | None]:
        if update.message is not None:
            user = update.message.from_user
            return (user.id if user else None), update.message.chat.type
        if update.callback_query is not None:
            message = update.callback_query.message
            return update.callback_query.from_user.id, (message.chat.type if message is not None else None)
        return None, None

    def allowed(self, update: Update) -> bool:
        user_id, chat_type = self._origin(update)
        return user_id == self.owner_id and chat_type == ChatType.PRIVATE

    async def __call__(self, handler: Callable[[TelegramObject, dict[str, Any]], Awaitable[Any]],
                       event: TelegramObject, data: dict[str, Any]) -> Any:
        if isinstance(event, Update) and self.allowed(event):
            return await handler(event, data)
        self.dropped += 1
        self._since_report += 1
        now = time.monotonic()
        if now - self._last_report >= 60:
            log.info("ignored %d update(s) from non-owner sources", self._since_report)
            self._last_report, self._since_report = now, 0
        return None


def _session(proxy_url: str, api_base: str = "") -> AiohttpSession:
    kwargs: dict[str, Any] = {}
    if api_base and api_base.rstrip("/") != "https://api.telegram.org":
        kwargs["api"] = TelegramAPIServer.from_base(api_base.rstrip("/"), is_local=False)
    session = AiohttpSession(proxy=proxy_url or None, **kwargs)
    session.timeout = 60
    return session


class BotManager:
    """Owns the Bot and lets the Telegram proxy be replaced safely at run time."""

    def __init__(self, config: Config, settings: Settings) -> None:
        self.config = config
        self.settings = settings
        token = config.telegram_bot_token.get_secret_value()
        MASKER.register(token)
        self.proxy_url = self.effective_proxy()
        self._register(self.proxy_url)
        self.bot = Bot(token, session=_session(self.proxy_url, config.telegram_api_base_url),
                       default=DefaultBotProperties(parse_mode=ParseMode.HTML, link_preview_is_disabled=True))
        self.last_ok_at = 0.0
        self.last_error = ""
        self.reverted = ""        # set when a broken override was replaced by the .env value
        self.on_reachable: Callable[[], None] | None = None   # called when the route is seen working again
        self._lock = asyncio.Lock()

    def _reachable(self) -> None:
        self.last_ok_at, self.last_error = time.time(), ""
        if self.on_reachable is not None:
            self.on_reachable()

    @staticmethod
    def _register(proxy_url: str) -> None:
        if "@" in proxy_url:
            MASKER.register(proxy_url, mask_proxy(proxy_url))

    def effective_proxy(self) -> str:
        return str(self.settings.get("telegram_proxy_url") or "")

    @property
    def proxy_label(self) -> str:
        return mask_proxy(self.proxy_url)

    @property
    def route(self) -> str:
        """The Telegram route for log lines."""
        return mask_proxy(self.proxy_url) if self.proxy_url else "a direct connection"

    async def probe(self, proxy_url: str, timeout: float = PROBE_TIMEOUT) -> tuple[bool, str]:
        """Can the Bot API be reached through this proxy? Uses a throw-away session."""
        self._register(proxy_url)
        session = _session(proxy_url, self.config.telegram_api_base_url)
        probe_bot = Bot(self.config.telegram_bot_token.get_secret_value(), session=session)
        try:
            me = await asyncio.wait_for(probe_bot.get_me(), timeout)
            return True, f"@{me.username}"
        except asyncio.TimeoutError:
            return False, f"нет ответа за {int(timeout)} с"
        except Exception as exc:  # noqa: BLE001 - any failure means "this proxy does not work"
            return False, MASKER.mask(f"{exc.__class__.__name__}: {exc}")[:160]
        finally:
            await session.close()

    async def _swap(self, proxy_url: str) -> None:
        old = self.bot.session
        self.bot.session = _session(proxy_url, self.config.telegram_api_base_url)
        self.proxy_url = proxy_url
        try:
            await old.close()
        except Exception:  # noqa: BLE001
            pass

    async def change_proxy(self, raw: str) -> tuple[bool, str]:
        """Validate, test and only then apply and persist a new proxy. → (applied, message)."""
        async with self._lock:
            from ..settings import (  # validation shared with the settings layer
                SPEC_BY_KEY,
                _parse,
            )
            candidate = _parse(SPEC_BY_KEY["telegram_proxy_url"], raw)
            ok, detail = await self.probe(candidate)
            if not ok:
                return False, f"прокси не работает ({detail}). Настройка не изменена."
            previous = self.proxy_url
            await self._swap(candidate)
            ok, detail = await self.probe(candidate)
            if not ok:       # worked a moment ago, fails now: do not risk losing control
                await self._swap(previous)
                return False, f"прокси нестабилен ({detail}). Настройка не изменена."
            await self.settings.set("telegram_proxy_url", raw)
            self._reachable()
            return True, f"прокси применён: {mask_proxy(candidate)} (бот {detail})"

    async def reset_proxy(self) -> tuple[bool, str]:
        """Return to the value from the configuration file."""
        async with self._lock:
            await self.settings.reset("telegram_proxy_url")
            target = self.config.telegram_proxy_url
            await self._swap(target)
            ok, detail = await self.probe(target)
            if ok:
                self._reachable()
            return ok, (f"используется значение из файла конфигурации: {mask_proxy(target)}"
                        + ("" if ok else f" — сейчас не отвечает ({detail})"))

    async def ensure_reachable(self) -> bool:
        """Start-up check. A broken override from the database falls back to the .env value."""
        ok, detail = await self.probe(self.proxy_url)
        if ok:
            self._reachable()
            return True
        self.last_error = detail
        fallback = self.config.telegram_proxy_url
        if self.settings.is_overridden("telegram_proxy_url") and fallback != self.proxy_url:
            ok_fallback, _ = await self.probe(fallback)
            if ok_fallback:
                broken = mask_proxy(self.proxy_url)
                await self.settings.reset("telegram_proxy_url")
                await self._swap(fallback)
                self.reverted = broken
                self._reachable()
                log.warning("telegram proxy from settings (%s) does not work; reverted to the .env value", broken)
                return True
        log.warning("Bot API is not reachable via %s: %s", self.route, detail)
        return False

    async def watchdog(self, on_revert: Callable[[str], Awaitable[None]], interval: float = 120.0) -> None:
        """If an owner-set proxy dies later, go back to the .env value instead of going deaf."""
        failures = 0
        while True:
            await asyncio.sleep(interval)
            ok, detail = await self.probe(self.proxy_url)
            if ok:
                if failures:
                    self._reachable()
                failures, self.last_ok_at, self.last_error = 0, time.time(), ""
                continue
            failures += 1
            self.last_error = detail
            fallback = self.config.telegram_proxy_url
            if failures >= 3 and self.settings.is_overridden("telegram_proxy_url") and fallback != self.proxy_url:
                ok_fallback, _ = await self.probe(fallback)
                if ok_fallback:
                    async with self._lock:
                        broken = mask_proxy(self.proxy_url)
                        await self.settings.reset("telegram_proxy_url")
                        await self._swap(fallback)
                    failures = 0
                    self._reachable()
                    log.warning("telegram proxy %s stopped working; reverted to the .env value", broken)
                    await on_revert(broken)

    async def close(self) -> None:
        await self.bot.session.close()
