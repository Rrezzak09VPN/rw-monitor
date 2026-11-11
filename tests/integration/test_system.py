"""The whole service as a real process: `python -m rwmon run` against local stand-ins.

Real Xray servers on loopback are the monitored "VPN servers", a fake panel serves the
subscription, a fake Bot API plays Telegram. Covers the full path — import, checks, DOWN,
RECOVERED, restart with state kept — plus systemd notifications and clean shutdown.
"""

import asyncio
import os
import signal
import socket
import sqlite3
import sys
import time
from pathlib import Path

import pytest

from rwmon.security import SecretBox

from ..conftest import OWNER, TOKEN
from ..fakes.cheburcheck import FakeCheburcheck
from ..fakes.panel import FakePanel
from ..fakes.telegram import FakeTelegram
from ..fakes.xray_bench import Bench, find_xray

pytestmark = pytest.mark.skipif(find_xray() is None, reason="xray binary not found")
ROOT = Path(__file__).resolve().parents[2]


class Service:
    def __init__(self, env_file: Path, notify_path: Path) -> None:
        self.env_file, self.notify_path = env_file, notify_path
        self.process: asyncio.subprocess.Process | None = None
        self.log = b""
        self.notifications: list[str] = []
        self._socket: socket.socket | None = None
        self._reader: asyncio.Task | None = None

    async def start(self) -> None:
        self.notify_path.unlink(missing_ok=True)
        self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self._socket.bind(str(self.notify_path))
        self._socket.setblocking(False)
        env = {
            "PATH": os.environ["PATH"], "RWMON_ENV_FILE": str(self.env_file), "RWMON_ALLOW_LOOPBACK": "1",
            "NOTIFY_SOCKET": str(self.notify_path), "WATCHDOG_USEC": "4000000",
            "HTTPS_PROXY": "http://127.0.0.1:9", "ALL_PROXY": "socks5://127.0.0.1:9",   # must be ignored by the service
        }
        self.process = await asyncio.create_subprocess_exec(
            sys.executable, "-m", "rwmon", "run", cwd=ROOT, env=env,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        self._reader = asyncio.create_task(self._read())

    async def _read(self) -> None:
        assert self.process and self.process.stdout
        while chunk := await self.process.stdout.read(65536):
            self.log += chunk

    def drain_notify(self) -> list[str]:
        while True:
            try:
                self.notifications.append(self._socket.recv(4096).decode())
            except (BlockingIOError, OSError):
                return self.notifications

    async def stop(self, sig: int = signal.SIGTERM) -> int:
        assert self.process
        if self.process.returncode is None:
            self.process.send_signal(sig)
        code = await asyncio.wait_for(self.process.wait(), 30)
        if self._reader:
            await self._reader
        self.drain_notify()
        self._socket.close()
        return code


async def until(predicate, timeout: float, what: str):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if asyncio.iscoroutine(value):
            value = await value
        if value:
            return value
        await asyncio.sleep(0.25)
    raise AssertionError(f"timed out waiting for: {what}")


def texts(api: FakeTelegram) -> list[str]:
    return [item["text"] for item in api.sent]


async def test_full_lifecycle_as_a_real_process(tmp_path):
    bench = await Bench.start()
    api = await FakeTelegram(TOKEN).start()
    panel = await FakePanel().start()
    cc = await FakeCheburcheck().start()
    links = bench.links()
    panel.links = [links["reality"], links["trojan"], links["ss"]]
    canary = f"127.0.0.1:{bench.ports['web']}"
    env_file = tmp_path / "rwmon.env"
    env_file.write_text("\n".join([
        f"TELEGRAM_BOT_TOKEN={TOKEN}", f"TELEGRAM_OWNER_ID={OWNER}", f"SECRET_KEY={SecretBox.generate_key()}",
        f"TELEGRAM_API_BASE_URL={api.base_url}", f"DATA_DIR={tmp_path / 'data'}",
        "CHECK_INTERVAL=20", "RECHECK_INTERVALS=5,5", "RECOVERY_RECHECK_INTERVAL=5", "FAIL_THRESHOLD=3",
        "RECOVERY_THRESHOLD=3", "TCP_TIMEOUT=2", "TLS_TIMEOUT=3", "E2E_TIMEOUT=5",
        f"XRAY_BIN={bench.xray}", f"E2E_TEST_URLS={bench.test_url}", f"E2E_DATA_PROBE_URL={bench.data_url()}",
        f"CANARY_RU={canary}", f"CANARY_FOREIGN={canary}", "CANARY_DNS_NAME=", "SUBSCRIPTION_EXTRA_PROFILES=",
        f"CHEBURCHECK_BASE_URL={cc.base_url}", "CHEBURCHECK_CHECK_INTERVAL=2", "CHEBURCHECK_PROBE_INTERVAL=12",
        "CHEBURCHECK_WAIT=5", "LOG_LEVEL=INFO",
    ]))
    env_file.chmod(0o600)
    service = Service(env_file, tmp_path / "notify.sock")
    db_path = tmp_path / "data" / "rwmon.sqlite3"

    def db(sql: str, *args):
        connection = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        try:
            return connection.execute(sql, args).fetchall()
        finally:
            connection.close()

    try:
        # ── first start ───────────────────────────────────────────────────
        await service.start()
        await until(lambda: any("Мониторинг запущен" in text for text in texts(api)), 30, "start notification")
        assert "Первый запуск" in texts(api)[0] and "Сквозная проверка через Xray: включена" in texts(api)[0]
        await until(lambda: "READY=1" in service.drain_notify(), 10, "systemd READY")

        # ── the owner sends the subscription link ─────────────────────────
        api.push_message(OWNER, panel.url)
        await until(lambda: any("Подписка добавлена" in item["text"] for item in api.edits), 30, "import report")
        await until(lambda: len(db("SELECT 1 FROM server_state WHERE state='OK'")) == 3, 40, "all servers OK")
        assert db("SELECT COUNT(*) FROM checks WHERE ok=0")[0][0] == 0
        assert bench.hits >= 3                                           # real requests through real tunnels

        # ── the server dies ───────────────────────────────────────────────
        bench.stop_xray()
        stopped_at = time.time()
        await until(lambda: any("НЕДОСТУПН" in text for text in texts(api)), 90, "DOWN notification")
        elapsed = time.time() - stopped_at
        down = next(text for text in texts(api) if "НЕДОСТУПН" in text)
        assert "МАССОВАЯ НЕДОСТУПНОСТЬ" in down and "3 сервера из 3" in down and "подтверждено 3 проверками" in down
        assert "Сеть самого мониторинга проверена" in down
        assert elapsed >= 9                                              # never on the first failure: 2 rechecks came first
        checks = db("SELECT server_id, COUNT(*) FROM checks WHERE ok=0 GROUP BY server_id")
        assert len(checks) == 3 and all(count >= 3 for _, count in checks)
        assert len([text for text in texts(api) if "НЕДОСТУПН" in text]) == 1

        # ── restart while servers are down: state is kept, nothing is repeated ──
        assert await service.stop() == 0
        assert "STOPPING=1" in service.notifications and any(item == "WATCHDOG=1" for item in service.notifications)
        first_log = service.log.decode()
        assert TOKEN not in first_log and panel.token not in first_log and bench.uuid not in first_log
        assert "proxy variables removed from the environment" in first_log
        sent_before = len(api.sent)
        service = Service(env_file, tmp_path / "notify.sock")
        await service.start()
        await until(lambda: len(api.sent) > sent_before and "Мониторинг запущен" in texts(api)[-1], 30, "second start")
        assert "недоступных на момент остановки: 3" in texts(api)[-1]
        await asyncio.sleep(25)                                          # a full cycle passes with the servers still dead
        assert {row[0] for row in db("SELECT state FROM server_state")} == {"DOWN"}
        assert len([text for text in texts(api) if "НЕДОСТУПН" in text]) == 1
        assert db("SELECT COUNT(*) FROM incidents")[0][0] == 3

        # ── the server comes back ─────────────────────────────────────────
        await bench.restart_xray()
        await until(lambda: any("ВОССТАНОВЛЕН" in text for text in texts(api)), 90, "RECOVERED notification")
        up = next(text for text in texts(api) if "ВОССТАНОВЛЕН" in text)
        assert "СЕРВЕРЫ ВОССТАНОВЛЕНЫ" in up and "3 успешными проверками подряд" in up and "был недоступен" in up
        assert {row[0] for row in db("SELECT state FROM server_state")} == {"RECOVERED"}
        assert db("SELECT COUNT(*) FROM incidents WHERE recovered_at IS NULL")[0][0] == 0

        # ── third-party lookups ───────────────────────────────────────────
        assert cc.check_calls == []          # loopback/private addresses are never sent to a third-party service

        # ── a second instance on the same data refuses to start ───────────
        clone = await asyncio.create_subprocess_exec(
            sys.executable, "-m", "rwmon", "run", cwd=ROOT,
            env={"PATH": os.environ["PATH"], "RWMON_ENV_FILE": str(env_file)},
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        output, _ = await asyncio.wait_for(clone.communicate(), 30)
        assert clone.returncode == 1 and b"another instance is already running" in output

        # ── hard kill (power loss): the next start is clean, the database is intact ──
        service.process.kill()
        await service.process.wait()
        hard_log = service.log.decode()
        connection = sqlite3.connect(db_path)
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        connection.close()
        sent_before = len(api.sent)
        service = Service(env_file, tmp_path / "notify.sock")
        await service.start()
        await until(lambda: len(api.sent) > sent_before and "Мониторинг запущен" in texts(api)[-1], 30, "start after kill")
        await until(lambda: "READY=1" in service.drain_notify(), 10, "systemd READY after kill")
        assert {row[0] for row in db("SELECT state FROM server_state")} <= {"RECOVERED", "OK"}
        assert len([text for text in texts(api) if "НЕДОСТУПН" in text]) == 1
        assert len([text for text in texts(api) if "ВОССТАНОВЛЕН" in text]) == 1
        assert "Traceback" not in hard_log

        assert await service.stop(signal.SIGINT) == 0
        log = service.log.decode()
        if os.environ.get("RWMON_KEEP_LOG"):
            Path(os.environ["RWMON_KEEP_LOG"]).write_text(first_log + "\n===== restart =====\n" + log)
        assert "Traceback" not in first_log and "Traceback" not in log
        assert oct(db_path.stat().st_mode & 0o777) == "0o600"
    finally:
        if service.process and service.process.returncode is None:
            service.process.kill()
        await bench.stop()
        await api.stop()
        await panel.stop()
        await cc.stop()
