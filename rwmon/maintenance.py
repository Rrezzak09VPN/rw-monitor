"""Housekeeping: history retention and database backups."""

from __future__ import annotations

import asyncio
import logging
import os
import time
from pathlib import Path

from .config import Config
from .db.database import Database
from .settings import Settings
from .timeutil import to_msk

log = logging.getLogger(__name__)

DAY = 86400
LAST_BACKUP_KEY = "runtime.last_backup_day"


class Maintenance:
    def __init__(self, config: Config, db: Database, settings: Settings) -> None:
        self.config = config
        self.db = db
        self.settings = settings
        self._task: asyncio.Task | None = None

    async def start(self) -> None:
        self._task = asyncio.create_task(self._run(), name="maintenance")

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
            self._task = None

    async def _run(self) -> None:
        await asyncio.sleep(120)
        while True:
            try:
                await self.cleanup()
                now = to_msk(time.time())
                day = f"{now:%Y%m%d}"
                if now.hour >= self.config.backup_hour_msk and self.settings.raw(LAST_BACKUP_KEY) != day:
                    await self.backup()
                    await self.settings.set_raw(LAST_BACKUP_KEY, day)
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                log.exception("maintenance failed")
            await asyncio.sleep(3600)

    async def cleanup(self) -> dict[str, int]:
        """Delete history older than the configured retention. Returns deleted row counts."""
        now = int(time.time())
        checks_before = now - self.config.retention_checks_days * DAY
        events_before = now - self.config.retention_events_days * DAY
        cc_before = now - self.config.retention_cheburcheck_days * DAY
        deleted = {
            "checks": await self.db.execute("DELETE FROM checks WHERE ts<?", (checks_before,)),
            "state_events": await self.db.execute("DELETE FROM state_events WHERE ts<?", (events_before,)),
            "monitor_events": await self.db.execute("DELETE FROM monitor_events WHERE ts<?", (events_before,)),
            "notifications": await self.db.execute(
                "DELETE FROM notifications WHERE status<>'pending' AND created_at<?", (events_before,)),
            "incidents": await self.db.execute(
                "DELETE FROM incidents WHERE (recovered_at IS NOT NULL OR close_reason<>'') AND started_at<?",
                (events_before,)),
            "cheburcheck_results": await self.db.execute(
                "DELETE FROM cheburcheck_results WHERE requested_at<?", (cc_before,)),
            "cheburcheck_queue": await self.db.execute(
                "DELETE FROM cheburcheck_queue WHERE status<>'pending' AND created_at<?", (now - 7 * DAY,)),
            "archived_servers": await self.db.execute(
                "DELETE FROM servers WHERE archived=1 AND archived_at<?", (events_before,)),
            "addresses": await self.db.execute(
                "DELETE FROM server_addresses WHERE last_seen<?", (now - 30 * DAY,)),
        }
        week_ago = time.strftime("%Y%m%d", time.gmtime(now - 7 * DAY))
        for row in await self.db.fetchall("SELECT key FROM settings WHERE key LIKE 'cc.used.%'"):
            if row["key"].rsplit(".", 1)[-1] < week_ago:
                await self.settings.del_raw(row["key"])
        if any(deleted.values()):
            log.info("retention cleanup: %s", ", ".join(f"{name}={count}" for name, count in deleted.items() if count))
        await self.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        return deleted

    async def backup(self) -> Path:
        """Consistent online copy of the database; old copies beyond BACKUP_KEEP are removed."""
        directory = self.config.backup_dir
        directory.mkdir(parents=True, exist_ok=True)
        os.chmod(directory, 0o700)
        target = directory / f"rwmon-{to_msk(time.time()):%Y%m%d-%H%M%S}.sqlite3"
        await self.db.backup_to(target)
        os.chmod(target, 0o600)
        for old in self.list_backups()[self.config.backup_keep:]:
            old.unlink(missing_ok=True)
        log.info("database backup written: %s (%d KB)", target.name, target.stat().st_size // 1024)
        return target

    def list_backups(self) -> list[Path]:
        directory = self.config.backup_dir
        if not directory.is_dir():
            return []
        return sorted(directory.glob("rwmon-*.sqlite3"), reverse=True)
