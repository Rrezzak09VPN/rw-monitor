"""Thin async wrapper around a single SQLite connection (WAL mode).

All access is serialised by one asyncio lock, which makes ``tx()`` blocks
atomic with respect to every other coroutine of the process.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import sqlite3
from contextvars import ContextVar
from pathlib import Path
from typing import Any, AsyncIterator, Iterable

import aiosqlite

from .schema import MIGRATIONS

log = logging.getLogger(__name__)

_IN_TX: ContextVar[bool] = ContextVar("rwmon_in_tx", default=False)

Row = dict[str, Any]


def jdump(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def jload(text: str | None, default: Any = None) -> Any:
    if not text:
        return default
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return default


class Database:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._conn: aiosqlite.Connection | None = None
        self._lock = asyncio.Lock()

    # ── lifecycle ───────────────────────────────────────────────────────────
    async def open(self) -> None:
        if str(self.path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = await aiosqlite.connect(self.path, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        await self._conn.execute("PRAGMA journal_mode=WAL")
        await self._conn.execute("PRAGMA synchronous=NORMAL")
        await self._conn.execute("PRAGMA foreign_keys=ON")
        await self._conn.execute("PRAGMA busy_timeout=5000")
        await self._migrate()
        if str(self.path) != ":memory:":
            with contextlib.suppress(OSError):
                self.path.chmod(0o600)

    async def close(self) -> None:
        if self._conn is not None:
            with contextlib.suppress(Exception):
                await self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            await self._conn.close()
            self._conn = None

    async def _migrate(self) -> None:
        assert self._conn is not None
        cursor = await self._conn.execute("PRAGMA user_version")
        version = (await cursor.fetchone())[0]
        if version > len(MIGRATIONS):
            raise RuntimeError(
                f"база данных версии {version} новее, чем поддерживает программа ({len(MIGRATIONS)})"
            )
        for index in range(version, len(MIGRATIONS)):
            log.info("applying database migration %d", index + 1)
            script = f"BEGIN;\n{MIGRATIONS[index]}\nPRAGMA user_version={index + 1};\nCOMMIT;"
            await self._conn.executescript(script)

    # ── primitives ──────────────────────────────────────────────────────────
    @property
    def conn(self) -> aiosqlite.Connection:
        if self._conn is None:
            raise RuntimeError("database is not open")
        return self._conn

    @contextlib.asynccontextmanager
    async def _guard(self) -> AsyncIterator[None]:
        if _IN_TX.get():
            yield
        else:
            async with self._lock:
                yield

    @contextlib.asynccontextmanager
    async def tx(self) -> AsyncIterator["Database"]:
        """Atomic block. Nested use joins the outer transaction."""
        if _IN_TX.get():
            yield self
            return
        async with self._lock:
            token = _IN_TX.set(True)
            await self.conn.execute("BEGIN IMMEDIATE")
            try:
                yield self
            except BaseException:
                await self.conn.execute("ROLLBACK")
                raise
            else:
                await self.conn.execute("COMMIT")
            finally:
                _IN_TX.reset(token)

    async def execute(self, sql: str, params: Iterable[Any] = ()) -> int:
        """Run a statement; returns lastrowid for INSERT, rowcount otherwise."""
        async with self._guard():
            cursor = await self.conn.execute(sql, tuple(params))
            result = cursor.lastrowid if sql.lstrip()[:6].upper() == "INSERT" else cursor.rowcount
            await cursor.close()
            return result or 0

    async def executemany(self, sql: str, rows: Iterable[Iterable[Any]]) -> None:
        async with self._guard():
            await self.conn.executemany(sql, [tuple(row) for row in rows])

    async def fetchall(self, sql: str, params: Iterable[Any] = ()) -> list[Row]:
        async with self._guard():
            cursor = await self.conn.execute(sql, tuple(params))
            rows = await cursor.fetchall()
            await cursor.close()
            return [dict(row) for row in rows]

    async def fetchone(self, sql: str, params: Iterable[Any] = ()) -> Row | None:
        async with self._guard():
            cursor = await self.conn.execute(sql, tuple(params))
            row = await cursor.fetchone()
            await cursor.close()
            return dict(row) if row is not None else None

    async def scalar(self, sql: str, params: Iterable[Any] = (), default: Any = None) -> Any:
        async with self._guard():
            cursor = await self.conn.execute(sql, tuple(params))
            row = await cursor.fetchone()
            await cursor.close()
            return row[0] if row is not None and row[0] is not None else default

    # ── generic helpers ─────────────────────────────────────────────────────
    async def insert(self, table: str, **fields: Any) -> int:
        columns = ", ".join(fields)
        marks = ", ".join("?" for _ in fields)
        return await self.execute(f"INSERT INTO {table} ({columns}) VALUES ({marks})", fields.values())

    async def insert_ignore(self, table: str, **fields: Any) -> int:
        """INSERT OR IGNORE; returns the new rowid or 0 when the row already existed."""
        columns = ", ".join(fields)
        marks = ", ".join("?" for _ in fields)
        async with self._guard():
            cursor = await self.conn.execute(
                f"INSERT OR IGNORE INTO {table} ({columns}) VALUES ({marks})", tuple(fields.values())
            )
            rowid = cursor.lastrowid if cursor.rowcount else 0
            await cursor.close()
            return rowid or 0

    async def update(self, table: str, where: dict[str, Any], **fields: Any) -> int:
        if not fields:
            return 0
        assignments = ", ".join(f"{name}=?" for name in fields)
        condition = " AND ".join(f"{name}=?" for name in where)
        return await self.execute(
            f"UPDATE {table} SET {assignments} WHERE {condition}",
            [*fields.values(), *where.values()],
        )

    # ── backup ──────────────────────────────────────────────────────────────
    async def backup_to(self, target: str | Path) -> None:
        """Consistent online copy using the SQLite backup API."""
        target = Path(target)
        target.parent.mkdir(parents=True, exist_ok=True)
        async with self._lock:
            destination = await aiosqlite.connect(target)
            try:
                await self.conn.backup(destination)
            finally:
                await destination.close()
        with contextlib.suppress(OSError):
            target.chmod(0o600)
