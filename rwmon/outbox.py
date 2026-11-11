"""Persistent queue of outgoing Telegram messages.

Producers (monitoring, subscriptions, Cheburcheck) only write rows here. The
Telegram sender drains the queue, so a broken proxy or a restart never loses a
notification, and a unique ``dedup_key`` guarantees one message per event.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

from .db.database import Database, jdump


class Outbox:
    def __init__(self, db: Database) -> None:
        self.db = db
        self.wake = asyncio.Event()

    async def add(self, kind: str, text: str, *, dedup_key: str | None = None, server_id: int | None = None,
                  incident_id: int | None = None, markup: Any = None, silent: bool = False,
                  reply_to: int | None = None, edit_of: int | None = None) -> int | None:
        """Queue a message. Returns its id, or None when ``dedup_key`` was already used."""
        fields = dict(
            created_at=int(time.time()), kind=kind, dedup_key=dedup_key, server_id=server_id,
            incident_id=incident_id, text=text, markup_json=jdump(markup) if markup else "",
            silent=int(silent), reply_to=reply_to, edit_of=edit_of,
        )
        if dedup_key is not None:
            if not await self.db.insert_ignore("notifications", **fields):
                return None
            row_id = await self.db.scalar("SELECT id FROM notifications WHERE dedup_key=?", (dedup_key,))
        else:
            row_id = await self.db.insert("notifications", **fields)
        self.wake.set()
        return row_id

    async def pending_count(self) -> int:
        return int(await self.db.scalar("SELECT COUNT(*) FROM notifications WHERE status='pending'") or 0)
