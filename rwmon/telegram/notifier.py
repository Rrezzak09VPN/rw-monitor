"""Delivers queued messages to the owner. Survives proxy outages and restarts."""

from __future__ import annotations

import asyncio
import logging
import re
import time
from typing import Any

from aiogram import Bot
from aiogram.exceptions import (
    ClientDecodeError,
    TelegramAPIError,
    TelegramBadRequest,
    TelegramForbiddenError,
    TelegramNetworkError,
    TelegramRetryAfter,
    TelegramServerError,
    TelegramUnauthorizedError,
)
from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup, ReplyParameters

from ..db.database import Database, Row, jload
from ..neterrors import PROXY_ERRORS
from ..outbox import Outbox
from ..timeutil import fmt_duration

log = logging.getLogger(__name__)

LATE_AFTER = 180          # a message delivered later than this says so
RETRY_PAUSES = (5, 15, 30, 60)   # between attempts while Telegram is unreachable; the last value repeats
MAX_API_ERRORS = 20              # attempts for a message Telegram keeps rejecting for an unknown reason


def build_markup(raw: str) -> InlineKeyboardMarkup | None:
    rows = jload(raw, None) if raw else None
    if not rows:
        return None
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text=item["text"], callback_data=item["callback_data"]) for item in row]
        for row in rows])


class Notifier:
    def __init__(self, bot: Bot, db: Database, outbox: Outbox, owner_id: int) -> None:
        self.bot = bot
        self.db = db
        self.outbox = outbox
        self.owner_id = owner_id
        self.last_error = ""
        self.sent = 0
        self._task: asyncio.Task | None = None
        self._failures = 0

    async def start(self) -> None:
        self._task = asyncio.create_task(self._run(), name="notifier")

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
            self._task = None

    def kick(self) -> None:
        """Telegram is known to be reachable again: retry the queue now instead of waiting out the pause."""
        self._failures = 0
        self.outbox.wake.set()

    async def _run(self) -> None:
        while True:
            try:
                delay = await self._drain()
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                log.exception("notifier failed")
                delay = 30.0
            try:
                await asyncio.wait_for(self.outbox.wake.wait(), delay)
            except asyncio.TimeoutError:
                pass
            self.outbox.wake.clear()

    async def _drain(self) -> float:
        """Send pending messages in order. Returns how long to sleep before the next attempt."""
        while True:
            row = await self.db.fetchone("SELECT * FROM notifications WHERE status='pending' ORDER BY id LIMIT 1")
            if row is None:
                return 60.0
            outcome = await self._deliver(row)
            if outcome == "retry":
                self._failures += 1
                return float(RETRY_PAUSES[min(self._failures - 1, len(RETRY_PAUSES) - 1)])
            if isinstance(outcome, float):
                return outcome
            self._failures = 0
            await asyncio.sleep(0.35)      # stay well below Telegram's per-chat rate limit

    async def _mark(self, row: Row, status: str, message_id: int | None = None, error: str = "") -> None:
        await self.db.update(
            "notifications", {"id": row["id"]}, status=status, attempts=row["attempts"] + 1,
            sent_at=int(time.time()) if status == "sent" else None, tg_message_id=message_id, last_error=error[:300])

    async def _message_id(self, notification_id: int | None) -> int | None:
        if not notification_id:
            return None
        return await self.db.scalar(
            "SELECT tg_message_id FROM notifications WHERE id=? AND status='sent'", (notification_id,))

    async def _deliver(self, row: Row) -> Any:
        text = row["text"]
        markup = build_markup(row["markup_json"])
        try:
            if row["edit_of"]:
                original = await self.db.fetchone("SELECT * FROM notifications WHERE id=?", (row["edit_of"],))
                if original is None or original["status"] == "failed":
                    await self._mark(row, "skipped")
                    return "done"
                if original["status"] == "pending":       # not sent yet: just replace its text
                    await self.db.update("notifications", {"id": original["id"]}, text=text)
                    await self._mark(row, "merged")
                    return "done"
                await self.bot.edit_message_text(
                    text, chat_id=self.owner_id, message_id=original["tg_message_id"],
                    reply_markup=build_markup(original["markup_json"]), request_timeout=30)
                await self._mark(row, "sent", original["tg_message_id"])
                return "done"
            delay = int(time.time()) - row["created_at"]
            if delay > LATE_AFTER:
                text += f"\n\n⏱ <i>Доставлено с задержкой {fmt_duration(delay)}: не было связи с Telegram.</i>"
            reply_id = await self._message_id(row["reply_to"])
            message = await self.bot.send_message(
                self.owner_id, text, reply_markup=markup, disable_notification=bool(row["silent"]),
                reply_parameters=ReplyParameters(message_id=reply_id, allow_sending_without_reply=True) if reply_id else None,
                request_timeout=30)
            await self._mark(row, "sent", message.message_id)
            self.sent += 1
            self.last_error = ""
            return "done"
        except TelegramRetryAfter as exc:
            self.last_error = f"лимит Telegram, пауза {exc.retry_after} с"
            return float(exc.retry_after) + 1.0
        except TelegramBadRequest as exc:
            reason = str(exc)
            if row["edit_of"]:
                # "message is not modified", "message to edit not found", too old to edit: nothing to do
                await self._mark(row, "skipped", error=reason)
                return "done"
            if "parse" in reason.lower() and not row["last_error"].startswith("plain:"):
                # Broken markup must not lose the notification: resend as plain text.
                plain = re.sub(r"<[^>]+>", "", text)
                await self.db.update("notifications", {"id": row["id"]}, text=plain, last_error="plain:" + reason[:200])
                log.warning("notification %s had invalid markup; resending as plain text", row["id"])
                return "done"
            log.error("notification %s rejected by Telegram: %s", row["id"], reason)
            await self._mark(row, "failed", error=reason)
            return "done"
        except TelegramForbiddenError as exc:
            # The owner has not opened the chat with the bot (or blocked it). Keep the message.
            self.last_error = "бот не может писать владельцу: откройте чат с ботом и нажмите /start"
            log.warning("cannot message the owner: %s", exc)
            await self.db.update("notifications", {"id": row["id"]}, attempts=row["attempts"] + 1,
                                 last_error=str(exc)[:300])
            return 60.0
        except TelegramUnauthorizedError as exc:
            self.last_error = "Telegram отклонил токен бота (TELEGRAM_BOT_TOKEN)"
            log.error("bot token rejected: %s", exc)
            return 300.0
        except (TelegramNetworkError, TelegramServerError, ClientDecodeError, asyncio.TimeoutError, OSError,
                *PROXY_ERRORS) as exc:
            # ClientDecodeError: something on the way (a proxy, a gateway) answered instead of Telegram.
            self.last_error = f"нет связи с Telegram ({exc.__class__.__name__})"
            await self.db.update("notifications", {"id": row["id"]}, attempts=row["attempts"] + 1,
                                 last_error=self.last_error)
            return "retry"
        except TelegramAPIError as exc:
            # An answer we do not know how to treat. Keep trying for a while, but never let one
            # message block the queue forever.
            self.last_error = f"Telegram отклонил запрос ({exc.__class__.__name__})"
            log.error("notification %s: unexpected Telegram API error: %s", row["id"], exc)
            if row["attempts"] + 1 >= MAX_API_ERRORS:
                await self._mark(row, "failed", error=str(exc))
                return "done"
            await self.db.update("notifications", {"id": row["id"]}, attempts=row["attempts"] + 1,
                                 last_error=str(exc)[:300])
            return 120.0
