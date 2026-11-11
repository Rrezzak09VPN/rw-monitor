from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass

import pytest_asyncio
from aiogram import Dispatcher
from aiogram.fsm.storage.memory import MemoryStorage

from rwmon.app import ALLOWED_UPDATES
from rwmon.cheburcheck.service import CheburcheckService
from rwmon.db.database import Database
from rwmon.maintenance import Maintenance
from rwmon.monitor.alerts import Alerts
from rwmon.monitor.service import Monitor
from rwmon.outbox import Outbox
from rwmon.security import SecretBox
from rwmon.settings import Settings
from rwmon.subscription.service import SubscriptionService
from rwmon.telegram.bot import BotManager, OwnerOnlyMiddleware
from rwmon.telegram.context import Ctx
from rwmon.telegram.handlers import build_router
from rwmon.telegram.notifier import Notifier

from ..conftest import OWNER, TOKEN, Env, make_config
from ..fakes.checks import FakeChecker, FakeE2E, FakeHealth
from ..fakes.panel import FakePanel
from ..fakes.telegram import FakeTelegram


@dataclass
class TgEnv(Env):
    api: FakeTelegram = None
    botman: BotManager = None
    notifier: Notifier = None
    gate: OwnerOnlyMiddleware = None
    ctx: Ctx = None

    async def say(self, text: str, user: int = OWNER, **kwargs) -> None:
        self.api.push_message(user, text, **kwargs)
        await self.api.wait_idle()

    async def press(self, data: str, user: int = OWNER, **kwargs) -> None:
        self.api.push_callback(user, data, **kwargs)
        await self.api.wait_idle()

    async def wait_text(self, needle: str, timeout: float = 30.0) -> str:
        """Wait until the latest outgoing text contains ``needle`` (for slow, multi-step handlers)."""
        deadline = asyncio.get_running_loop().time() + timeout
        while asyncio.get_running_loop().time() < deadline:
            if needle in self.api.last_text():
                break
            await asyncio.sleep(0.05)
        return self.api.last_text()

    async def flush(self) -> None:
        """Let queued notifications reach the fake Telegram."""
        await self.alerts.drain()
        self.outbox.wake.set()
        for _ in range(200):
            if await self.outbox.pending_count() == 0:
                break
            await asyncio.sleep(0.02)
        await asyncio.sleep(0.05)


async def build_tg(tmp_path, proxy_url: str = "", **overrides):
    api = await FakeTelegram(TOKEN).start()
    config = make_config(tmp_path, telegram_api_base_url=api.base_url, telegram_proxy_url=proxy_url, **overrides)
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
    maintenance = Maintenance(config, db, settings)
    botman = BotManager(config, settings)
    notifier = Notifier(botman.bot, db, outbox, config.telegram_owner_id)
    ctx = Ctx(config, db, settings, subs, monitor, cc, alerts, outbox, botman, notifier, maintenance)
    dispatcher = Dispatcher(storage=MemoryStorage())
    gate = OwnerOnlyMiddleware(config.telegram_owner_id)
    dispatcher.update.outer_middleware(gate)
    dispatcher.include_router(build_router())
    dispatcher["ctx"] = ctx
    panel = await FakePanel().start()
    await notifier.start()
    polling = asyncio.create_task(dispatcher.start_polling(
        botman.bot, allowed_updates=ALLOWED_UPDATES, handle_signals=False, close_bot_session=False, polling_timeout=1))
    env = TgEnv(config, db, settings, subs, outbox, cc, alerts, monitor, checker, health, panel,
                api=api, botman=botman, notifier=notifier, gate=gate, ctx=ctx)

    async def close() -> None:
        with contextlib.suppress(Exception):
            await dispatcher.stop_polling()
        polling.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await polling
        await notifier.stop()
        await alerts.stop()
        await cc.stop()
        await panel.stop()
        await subs.close()
        await botman.close()
        await db.close()
        await api.stop()

    return env, close


@pytest_asyncio.fixture
async def tg(tmp_path):
    env, close = await build_tg(tmp_path)
    try:
        yield env
    finally:
        await close()
