from __future__ import annotations

import time
from dataclasses import dataclass

import pytest
import pytest_asyncio

import rwmon.subscription.model as model
from rwmon.cheburcheck.service import CheburcheckService
from rwmon.config import Config
from rwmon.db.database import Database
from rwmon.monitor.alerts import Alerts
from rwmon.monitor.service import Monitor
from rwmon.outbox import Outbox
from rwmon.security import SecretBox
from rwmon.settings import Settings
from rwmon.subscription.service import SubscriptionService

from .fakes.checks import FakeChecker, FakeE2E, FakeHealth
from .fakes.panel import FakePanel, vless_link

TOKEN = "123456789:" + "A" * 35
OWNER = 777000111


class Clock:
    """Moves wall-clock time forward without waiting."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.offset = 0.0
        real = time.time
        monkeypatch.setattr(time, "time", lambda: real() + self.offset)

    def advance(self, seconds: float) -> None:
        self.offset += seconds


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> Clock:
    return Clock(monkeypatch)


@pytest.fixture(autouse=True)
def allow_loopback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(model, "LOOPBACK_IS_PLACEHOLDER", False)


def make_config(tmp_path, **overrides) -> Config:
    values = dict(
        telegram_bot_token=TOKEN, telegram_owner_id=OWNER, secret_key=SecretBox.generate_key(),
        data_dir=str(tmp_path), subscription_extra_profiles="", cheburcheck_enabled=False,
        subscription_refresh_interval=0, _env_file=None,
    )
    values.update(overrides)
    return Config(**values)


@dataclass
class Env:
    config: Config
    db: Database
    settings: Settings
    subs: SubscriptionService
    outbox: Outbox
    cc: CheburcheckService
    alerts: Alerts
    monitor: Monitor
    checker: FakeChecker
    health: FakeHealth
    panel: FakePanel

    async def add_servers(self, *hosts: str) -> list[dict]:
        self.panel.links = [vless_link(f"Srv-{index + 1}", host) for index, host in enumerate(hosts)]
        result = await self.subs.add(self.panel.url)
        assert result.ok, result.message
        return await self.monitor.active_servers()

    async def cycle(self, kind: str = "scheduled"):
        summary = await self.monitor._round(await self.monitor.active_servers(), kind)
        await self.alerts.drain()
        return summary

    async def rechecks(self):
        """Run the accelerated rechecks that are due right now, like the scheduler would."""
        from rwmon.monitor.service import SERVER_SQL
        due = await self.db.fetchall(
            SERVER_SQL + "WHERE s.archived=0 AND s.monitor_enabled=1 AND s.paused_until IS NULL "
            "AND st.next_check_at IS NOT NULL AND st.next_check_at<=?", (int(time.time()),))
        summary = await self.monitor._round(due, "recheck") if due else None
        await self.alerts.drain()
        return summary

    async def states(self) -> dict[str, str]:
        rows = await self.db.fetchall(
            "SELECT s.address, st.state FROM servers s JOIN server_state st ON st.server_id=s.id WHERE s.archived=0")
        return {row["address"]: row["state"] for row in rows}

    async def messages(self, kind: str | None = None) -> list[dict]:
        if kind:
            return await self.db.fetchall("SELECT * FROM notifications WHERE kind=? ORDER BY id", (kind,))
        return await self.db.fetchall("SELECT * FROM notifications ORDER BY id")


@pytest_asyncio.fixture
async def env(tmp_path):
    config = make_config(tmp_path)
    db = Database(config.db_path)
    await db.open()
    settings = Settings(config, db)
    await settings.load()
    subs = SubscriptionService(config, db, settings, SecretBox(config.secret_key.get_secret_value()))
    await subs.start()
    outbox = Outbox(db)
    cc = CheburcheckService(config, db, settings)
    alerts = Alerts(config, db, settings, outbox, cc)
    await alerts.start()
    checker, health = FakeChecker(), FakeHealth()
    monitor = Monitor(config, db, settings, subs, checker, health, FakeE2E(), alerts)
    panel = await FakePanel().start()
    environment = Env(config, db, settings, subs, outbox, cc, alerts, monitor, checker, health, panel)
    try:
        yield environment
    finally:
        await environment.alerts.stop()      # tests may swap these two for differently configured ones
        await environment.cc.stop()
        await panel.stop()
        await subs.close()
        await db.close()
