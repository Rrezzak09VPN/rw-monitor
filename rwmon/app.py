"""Application wiring and lifecycle."""

from __future__ import annotations

import asyncio
import contextlib
import fcntl
import logging
import os
import signal
import socket
import time
from pathlib import Path

from aiogram import Dispatcher
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.types import BotCommand

from . import __version__
from .cheburcheck.service import CheburcheckService
from .checks.dns import DnsResolver, detect_ipv6
from .checks.e2e import E2EChecker
from .checks.pipeline import Checker
from .checks.selfhealth import SelfHealth
from .config import Config, scrub_proxy_env, split_csv
from .db.database import Database
from .maintenance import Maintenance
from .monitor.alerts import Alerts
from .monitor.service import Monitor
from .outbox import Outbox
from .security import MASKER, SecretBox, mask_proxy
from .settings import Settings
from .subscription.service import SubscriptionService
from .telegram.bot import BotManager, OwnerOnlyMiddleware
from .telegram.context import Ctx
from .telegram.handlers import build_router
from .telegram.notifier import Notifier

log = logging.getLogger(__name__)

ALLOWED_UPDATES = ["message", "callback_query"]


def sd_notify(message: str) -> None:
    """Minimal systemd notification (READY=1, WATCHDOG=1, STOPPING=1). No-op outside systemd."""
    address = os.environ.get("NOTIFY_SOCKET")
    if not address:
        return
    if address.startswith("@"):
        address = "\0" + address[1:]
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            sock.connect(address)
            sock.sendall(message.encode())
    except OSError:
        pass


class InstanceLock:
    """Advisory lock: one running instance per data directory."""

    def __init__(self, directory: Path) -> None:
        self.path = directory / "rwmon.lock"
        self._handle = None

    def acquire(self) -> bool:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._handle = open(self.path, "w")
        try:
            fcntl.flock(self._handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self._handle.close()
            self._handle = None
            return False
        self._handle.write(str(os.getpid()))
        self._handle.flush()
        return True

    def release(self) -> None:
        if self._handle is not None:
            with contextlib.suppress(OSError):
                fcntl.flock(self._handle, fcntl.LOCK_UN)
            self._handle.close()
            self._handle = None


def build_checks(config: Config) -> tuple[DnsResolver, E2EChecker, Checker, SelfHealth]:
    family = config.ip_family
    want_v6 = family in ("ipv6", "both") or (family == "auto" and detect_ipv6())
    want_v4 = family != "ipv6"
    resolver = DnsResolver(split_csv(config.dns_resolvers), want_v4=want_v4, want_v6=want_v6)
    e2e = E2EChecker(config.xray_bin, split_csv(config.e2e_test_urls), config.e2e_data_probe_url,
                     config.e2e_data_probe_bytes, config.e2e_concurrency)
    checker = Checker(resolver, e2e, ipv6=want_v6, max_ips=config.max_ips_per_server,
                      tcp_attempts=config.tcp_attempts)
    health = SelfHealth(resolver, split_csv(config.canary_ru), split_csv(config.canary_foreign), config.canary_dns_name)
    return resolver, e2e, checker, health


class App:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.stop_event = asyncio.Event()
        self.ctx: Ctx | None = None
        self.dispatcher: Dispatcher | None = None
        self._lock = InstanceLock(config.run_dir)
        self._tasks: list[asyncio.Task] = []

    async def run(self) -> int:
        config = self.config
        config.data_dir.mkdir(parents=True, exist_ok=True)
        with contextlib.suppress(OSError):
            os.chmod(config.data_dir, 0o700)
        if not self._lock.acquire():
            log.error("another instance is already running with data directory %s", config.data_dir)
            return 1
        removed = scrub_proxy_env()
        if removed:
            log.warning("proxy variables removed from the environment (server checks must go direct): %s",
                        ", ".join(removed))
        MASKER.register(config.telegram_bot_token.get_secret_value())
        MASKER.register(config.secret_key.get_secret_value())
        for proxy in (config.telegram_proxy_url, config.cheburcheck_proxy_url, config.subscription_proxy_url):
            if "@" in proxy:
                MASKER.register(proxy, mask_proxy(proxy))

        db = Database(config.db_path)
        await db.open()
        try:
            return await self._run(db)
        finally:
            await db.close()
            self._lock.release()

    async def _run(self, db: Database) -> int:
        config = self.config
        settings = Settings(config, db)
        await settings.load()
        subs = SubscriptionService(config, db, settings, SecretBox(config.secret_key.get_secret_value()))
        await subs.start()
        _, e2e, checker, health = build_checks(config)
        outbox = Outbox(db)
        cc = CheburcheckService(config, db, settings)
        alerts = Alerts(config, db, settings, outbox, cc)
        monitor = Monitor(config, db, settings, subs, checker, health, e2e, alerts)
        maintenance = Maintenance(config, db, settings)
        botman = BotManager(config, settings)
        notifier = Notifier(botman.bot, db, outbox, config.telegram_owner_id)
        botman.on_reachable = notifier.kick
        ctx = self.ctx = Ctx(config, db, settings, subs, monitor, cc, alerts, outbox, botman, notifier, maintenance)

        dispatcher = self.dispatcher = Dispatcher(storage=MemoryStorage())
        dispatcher.update.outer_middleware(OwnerOnlyMiddleware(config.telegram_owner_id))
        dispatcher.include_router(build_router())
        dispatcher["ctx"] = ctx

        log.info("rw-monitor %s starting; owner id %s; telegram route: %s; server checks: direct",
                 __version__, config.telegram_owner_id, mask_proxy(botman.proxy_url) if botman.proxy_url else "direct")
        await cc.start()
        await alerts.start()
        await monitor.start()          # monitoring does not depend on Telegram being reachable
        await maintenance.start()
        await notifier.start()

        self._tasks = [
            asyncio.create_task(self._telegram(botman, dispatcher, outbox), name="telegram"),
            asyncio.create_task(self._watchdog(monitor), name="systemd-watchdog"),
        ]
        if config.heartbeat_url:
            self._tasks.append(asyncio.create_task(self._heartbeat(monitor), name="external-heartbeat"))
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            with contextlib.suppress(NotImplementedError):
                loop.add_signal_handler(sig, self.stop_event.set)
        sd_notify("READY=1")
        await self.stop_event.wait()

        log.info("stopping")
        sd_notify("STOPPING=1")
        # The long-poll request is interrupted on purpose; aiogram would report it as an error.
        logging.getLogger("aiogram.dispatcher").setLevel(logging.CRITICAL)
        for task in self._tasks:
            task.cancel()
        with contextlib.suppress(Exception):
            await dispatcher.stop_polling()
        for task in self._tasks:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
        await monitor.stop()
        await notifier.stop()
        await maintenance.stop()
        await alerts.stop()
        await cc.stop()
        await subs.close()
        await botman.close()
        log.info("stopped")
        return 0

    async def _telegram(self, botman: BotManager, dispatcher: Dispatcher, outbox: Outbox) -> None:
        """Bring the bot up and keep polling. Telegram being unreachable never stops monitoring."""
        delay = 5.0
        while not await botman.ensure_reachable():
            await asyncio.sleep(delay)
            delay = min(delay * 2, 120.0)
        if botman.reverted:
            await outbox.add("proxy_reverted", (
                "⚠️ <b>Прокси Telegram возвращён к значению из файла конфигурации</b>\n\n"
                f"Заданный в настройках прокси {botman.reverted} не отвечал при запуске."))
        with contextlib.suppress(Exception):
            await botman.bot.set_my_commands([
                BotCommand(command="menu", description="Главное меню"),
                BotCommand(command="status", description="Статус мониторинга"),
                BotCommand(command="cancel", description="Отменить ввод"),
                BotCommand(command="help", description="Справка"),
            ])
        watchdog = asyncio.create_task(botman.watchdog(self._proxy_reverted), name="telegram-proxy-watchdog")
        try:
            await dispatcher.start_polling(
                botman.bot, allowed_updates=ALLOWED_UPDATES, handle_signals=False, close_bot_session=False)
        finally:
            watchdog.cancel()

    async def _proxy_reverted(self, broken: str) -> None:
        if self.ctx is not None:
            await self.ctx.outbox.add("proxy_reverted", (
                "⚠️ <b>Прокси Telegram возвращён к значению из файла конфигурации</b>\n\n"
                f"Заданный в настройках прокси {broken} перестал отвечать."))
            await self.ctx.monitor.note("settings", "прокси Telegram перестал отвечать — возвращено значение из конфигурации")

    async def _watchdog(self, monitor: Monitor) -> None:
        """Tell systemd we are alive only while the monitoring loop really makes progress."""
        usec = int(os.environ.get("WATCHDOG_USEC", "0") or 0)
        interval = max(5.0, usec / 2_000_000) if usec else 30.0
        while True:
            await asyncio.sleep(interval)
            if time.monotonic() - monitor.alive_at < max(300.0, 4 * interval):
                sd_notify("WATCHDOG=1")
            else:
                log.error("monitoring loop has made no progress for %.0f s", time.monotonic() - monitor.alive_at)


    async def _heartbeat(self, monitor: Monitor) -> None:
        """Ping an external dead-man's-switch so that someone notices if this whole host dies.

        Sent directly (never through a proxy) and only while monitoring makes progress.
        """
        import aiohttp
        url = self.config.heartbeat_url
        MASKER.register(url, "<heartbeat-url>")
        failures = 0
        async with aiohttp.ClientSession(trust_env=False, timeout=aiohttp.ClientTimeout(total=15)) as session:
            while True:
                if time.monotonic() - monitor.alive_at < 300:
                    try:
                        async with session.get(url) as response:
                            await response.read()
                        failures = 0
                    except (aiohttp.ClientError, asyncio.TimeoutError, OSError) as exc:
                        failures += 1
                        if failures in (1, 10):
                            log.warning("external heartbeat failed: %s", exc.__class__.__name__)
                await asyncio.sleep(self.config.heartbeat_interval)


async def run_app(config: Config) -> int:
    return await App(config).run()
