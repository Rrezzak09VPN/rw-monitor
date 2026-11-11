"""A fake Telegram Bot API: enough of it to run the real bot against."""

from __future__ import annotations

import asyncio
import json
import socket
import time
from typing import Any

from aiohttp import web

BOT_ID = 123456789


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class FakeTelegram:
    def __init__(self, token: str) -> None:
        self.token = token
        self.port = free_port()
        self.sent: list[dict[str, Any]] = []        # sendMessage calls
        self.edits: list[dict[str, Any]] = []       # editMessageText calls
        self.deleted: list[int] = []
        self.answers: list[dict[str, Any]] = []     # answerCallbackQuery calls
        self.calls: list[str] = []
        self.messages: dict[int, dict[str, Any]] = {}
        self.fail = ""                              # "" | "502" | "drop" | "429"
        self.forbidden = False
        self._updates: list[dict[str, Any]] = []
        self._update_id = 1000
        self._message_id = 100
        self._wake = asyncio.Event()
        self._runner: web.AppRunner | None = None

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    async def start(self) -> "FakeTelegram":
        app = web.Application()
        app.router.add_post("/bot{token}/{method}", self._handle)
        app.router.add_get("/bot{token}/{method}", self._handle)
        self._runner = web.AppRunner(app)
        await self._runner.setup()
        await web.TCPSite(self._runner, "127.0.0.1", self.port).start()
        return self

    async def stop(self) -> None:
        if self._runner:
            await self._runner.cleanup()
            self._runner = None

    # ── driving the bot ─────────────────────────────────────────────────────

    def _next_message_id(self) -> int:
        self._message_id += 1
        return self._message_id

    @staticmethod
    def _user(user_id: int) -> dict[str, Any]:
        return {"id": user_id, "is_bot": False, "first_name": f"user{user_id}"}

    def push_message(self, user_id: int, text: str, chat_type: str = "private", chat_id: int | None = None) -> int:
        self._update_id += 1
        message_id = self._next_message_id()
        chat = {"id": chat_id if chat_id is not None else user_id, "type": chat_type}
        if chat_type != "private":
            chat["title"] = "group"
        self._updates.append({"update_id": self._update_id, "message": {
            "message_id": message_id, "date": int(time.time()), "chat": chat, "from": self._user(user_id), "text": text}})
        self._wake.set()
        return message_id

    def push_callback(self, user_id: int, data: str, message_id: int | None = None, chat_type: str = "private") -> None:
        self._update_id += 1
        if message_id is None:
            message_id = self.sent[-1]["message_id"] if self.sent else self._next_message_id()
        stored = self.messages.get(message_id, {"text": "…"})
        self._updates.append({"update_id": self._update_id, "callback_query": {
            "id": f"cb{self._update_id}", "from": self._user(user_id), "chat_instance": "ci", "data": data,
            "message": {"message_id": message_id, "date": int(time.time()),
                        "chat": {"id": user_id, "type": chat_type},
                        "from": {"id": BOT_ID, "is_bot": True, "first_name": "bot"}, "text": stored.get("text", "…")}}})
        self._wake.set()

    async def wait_idle(self, timeout: float = 5.0) -> None:
        """Wait until the bot has fetched every queued update and had time to handle it."""
        deadline = time.monotonic() + timeout
        while self._updates and time.monotonic() < deadline:
            await asyncio.sleep(0.02)
        await asyncio.sleep(0.15)

    async def wait_sent(self, count: int, timeout: float = 5.0) -> None:
        deadline = time.monotonic() + timeout
        while len(self.sent) < count and time.monotonic() < deadline:
            await asyncio.sleep(0.02)

    def last_text(self) -> str:
        """Text of the most recent outgoing message or edit."""
        latest = max(self.sent[-1:] + self.edits[-1:], key=lambda item: item["seq"], default=None)
        return latest["text"] if latest else ""

    def last_buttons(self) -> list[str]:
        latest = max(self.sent[-1:] + self.edits[-1:], key=lambda item: item["seq"], default=None)
        return [button["callback_data"] for row in (latest or {}).get("buttons", []) for button in row]

    # ── HTTP ────────────────────────────────────────────────────────────────

    @staticmethod
    def _ok(result: Any) -> web.Response:
        return web.json_response({"ok": True, "result": result})

    @staticmethod
    def _error(status: int, description: str, **parameters: Any) -> web.Response:
        body: dict[str, Any] = {"ok": False, "error_code": status, "description": description}
        if parameters:
            body["parameters"] = parameters
        return web.json_response(body, status=status)

    async def _handle(self, request: web.Request) -> web.StreamResponse:
        method = request.match_info["method"]
        if request.match_info["token"] != self.token:
            return self._error(401, "Unauthorized")
        data = dict(await request.post()) if request.method == "POST" else dict(request.query)
        self.calls.append(method)
        if self.fail == "drop":
            request.transport.close()
            return web.Response(status=500)
        if self.fail == "502":
            return web.Response(status=502, text="Bad Gateway")
        if method == "getMe":
            return self._ok({"id": BOT_ID, "is_bot": True, "first_name": "rw-monitor", "username": "rwmon_test_bot",
                             "can_join_groups": False, "can_read_all_group_messages": False,
                             "supports_inline_queries": False})
        if method == "getUpdates":
            offset = int(data.get("offset") or 0)
            self._updates = [item for item in self._updates if item["update_id"] >= offset]
            if not self._updates:
                self._wake.clear()
                try:
                    await asyncio.wait_for(self._wake.wait(), min(float(data.get("timeout") or 0), 1.0))
                except asyncio.TimeoutError:
                    pass
            return self._ok(list(self._updates))
        if method in ("setMyCommands", "deleteWebhook"):
            return self._ok(True)
        if method == "answerCallbackQuery":
            self.answers.append(data)
            return self._ok(True)
        if method == "deleteMessage":
            self.deleted.append(int(data["message_id"]))
            return self._ok(True)
        if method in ("sendMessage", "editMessageText"):
            if self.fail == "429":
                self.fail = ""
                return self._error(429, "Too Many Requests: retry after 1", retry_after=1)
            if self.forbidden:
                return self._error(403, "Forbidden: bot can't initiate conversation with a user")
            text = str(data.get("text", ""))
            if "<bad>" in text:
                return self._error(400, "Bad Request: can't parse entities: Unsupported start tag \"bad\"")
            markup = json.loads(data["reply_markup"]) if data.get("reply_markup") else {}
            seq = len(self.sent) + len(self.edits) + 1
            if method == "sendMessage":
                message_id = self._next_message_id()
                reply = json.loads(data["reply_parameters"]) if data.get("reply_parameters") else {}
                record = {"message_id": message_id, "chat_id": int(data["chat_id"]), "text": text, "seq": seq,
                          "buttons": markup.get("inline_keyboard", []), "reply_to": reply.get("message_id"),
                          "silent": str(data.get("disable_notification", "")).lower() == "true",
                          "parse_mode": data.get("parse_mode")}
                self.sent.append(record)
            else:
                message_id = int(data["message_id"])
                if message_id not in self.messages:
                    return self._error(400, "Bad Request: message to edit not found")
                if self.messages[message_id]["text"] == text and self.messages[message_id]["buttons"] == markup.get("inline_keyboard", []):
                    return self._error(400, "Bad Request: message is not modified")
                record = {"message_id": message_id, "chat_id": int(data["chat_id"]), "text": text, "seq": seq,
                          "buttons": markup.get("inline_keyboard", [])}
                self.edits.append(record)
            self.messages[message_id] = record
            return self._ok({"message_id": message_id, "date": int(time.time()),
                             "chat": {"id": int(data["chat_id"]), "type": "private"},
                             "from": {"id": BOT_ID, "is_bot": True, "first_name": "bot"}, "text": text})
        return self._error(404, f"Not Found: method {method}")
