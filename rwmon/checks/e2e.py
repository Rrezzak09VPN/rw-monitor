"""End-to-end check: a real request through the server via a one-shot Xray client.

This is the only check that proves the VPN protocol itself works. Xray is
started for a single check with the configuration passed on stdin (no keys on
disk), listens on a loopback SOCKS port and is terminated right after.
"""

from __future__ import annotations

import asyncio
import collections
import json
import logging
import os
import re
import shutil
import socket
import time
from typing import Any

import aiohttp
from aiohttp_socks import (
    ProxyConnectionError,
    ProxyConnector,
    ProxyError,
    ProxyTimeoutError,
    ProxyType,
)

from ..security import MASKER
from .results import Stage
from .xraycfg import build_config

log = logging.getLogger(__name__)

_LOG_PREFIX_RE = re.compile(r"^\d{4}/\d{2}/\d{2} [\d:.]+ (\[\w+\] )?(\[\d+\] )?")
_IMPORTANT = ("failed", "error", "timeout", "refused", "reset", "invalid", "rejected", "closed", "unreachable")
_NOISE = ("deprecated", "reading config", "xray, penetrates", "accepted tcp", "accepted udp", "listening", "logger started", "health check")


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class E2EChecker:
    def __init__(self, xray_bin: str, urls: list[str], data_url: str, data_bytes: int,
                 concurrency: int = 2, start_timeout: float = 5.0) -> None:
        self.xray_bin = xray_bin
        self.urls = urls
        self.data_url = data_url
        self.data_bytes = data_bytes
        self.start_timeout = start_timeout
        self.available = False
        self.version = ""
        self.problem = "проверка ещё не выполнялась"
        self._semaphore = asyncio.Semaphore(max(1, concurrency))

    async def probe_binary(self) -> bool:
        """Find out whether Xray can be run at all. Never raises."""
        path = self.xray_bin if os.path.sep in self.xray_bin else shutil.which(self.xray_bin)
        if not path or not os.path.isfile(path) or not os.access(path, os.X_OK):
            self.available, self.problem = False, f"исполняемый файл Xray не найден ({self.xray_bin})"
            return False
        try:
            proc = await asyncio.create_subprocess_exec(
                path, "version", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
            out, _ = await asyncio.wait_for(proc.communicate(), 10)
        except (OSError, asyncio.TimeoutError) as exc:
            self.available, self.problem = False, f"Xray не запускается: {exc.__class__.__name__}"
            return False
        first = out.decode("utf-8", "replace").strip().splitlines()[0] if out.strip() else ""
        if proc.returncode != 0 or not first.startswith("Xray"):
            self.available, self.problem = False, f"Xray не запускается: {first[:80] or proc.returncode}"
            return False
        self.xray_bin, self.available, self.problem = path, True, ""
        self.version = first.split("(")[0].strip()
        return True

    async def check(self, outbound: dict[str, Any], timeout: float, data_probe: bool = False,
                    target: str = "", quick: bool = False) -> Stage:
        """Run the end-to-end check. ``ok=None`` means the check itself could not run.

        ``quick`` asks for a single attempt: used as a second opinion when the lower
        layers have already failed, so a dead server does not cost two full timeouts.
        """
        if not self.available:
            return Stage("e2e", None, "e2e_unavailable", self.problem, None, target)
        async with self._semaphore:
            return await self._check(outbound, timeout, data_probe, target, quick)

    async def _check(self, outbound: dict[str, Any], timeout: float, data_probe: bool, target: str,
                     quick: bool = False) -> Stage:
        port = _free_port()
        config = json.dumps(build_config(outbound, port)).encode()
        started = time.monotonic()
        try:
            proc = await asyncio.create_subprocess_exec(
                self.xray_bin, "run", "-c", "stdin:",
                stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT, start_new_session=True,
                env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "XRAY_LOCATION_ASSET": os.path.dirname(self.xray_bin)},
            )
        except OSError as exc:
            return Stage("e2e", None, "e2e_unavailable", f"Xray не запускается: {exc.__class__.__name__}", None, target)
        lines: collections.deque[str] = collections.deque(maxlen=40)
        reader = asyncio.create_task(self._drain(proc, lines))
        try:
            assert proc.stdin is not None
            try:
                proc.stdin.write(config)
                await proc.stdin.drain()
                proc.stdin.close()
            except (BrokenPipeError, ConnectionResetError):
                pass
            if not await self._wait_listening(proc, port):
                await asyncio.sleep(0.1)
                return Stage("e2e", None, "e2e_unavailable",
                             "Xray не принял конфигурацию: " + (self._last_line(lines) or "нет вывода"), None, target)
            stage = await self._requests(port, timeout, data_probe, lines, target, quick)
            if stage.ms is None:
                stage.ms = int((time.monotonic() - started) * 1000)
            return stage
        finally:
            await self._stop(proc)
            reader.cancel()

    @staticmethod
    async def _drain(proc: asyncio.subprocess.Process, lines: collections.deque[str]) -> None:
        assert proc.stdout is not None
        try:
            while True:
                raw = await proc.stdout.readline()
                if not raw:
                    return
                lines.append(_LOG_PREFIX_RE.sub("", raw.decode("utf-8", "replace").strip()))
        except (asyncio.CancelledError, ValueError):
            return

    @staticmethod
    def _last_line(lines: collections.deque[str]) -> str:
        """Most telling line of the Xray log, with secrets masked and noise removed."""
        for line in reversed(lines):
            lower = line.lower()
            if not line or any(word in lower for word in _NOISE):
                continue
            if any(word in lower for word in _IMPORTANT):
                line = re.sub(r"tcp:127\.0\.0\.1:\d+|app/proxyman/outbound: ", "", line)
                return MASKER.mask(" ".join(line.split()))[:200]
        return ""

    async def _wait_listening(self, proc: asyncio.subprocess.Process, port: int) -> bool:
        deadline = time.monotonic() + self.start_timeout
        while time.monotonic() < deadline:
            if proc.returncode is not None:
                return False
            try:
                _, writer = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", port), 0.5)
                writer.close()
                return True
            except (OSError, asyncio.TimeoutError):
                await asyncio.sleep(0.05)
        return False

    @staticmethod
    async def _stop(proc: asyncio.subprocess.Process) -> None:
        if proc.returncode is not None:
            return
        try:
            proc.terminate()
            await asyncio.wait_for(proc.wait(), 2)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
        except ProcessLookupError:
            pass

    async def _requests(self, port: int, timeout: float, data_probe: bool,
                        lines: collections.deque[str], target: str, quick: bool = False) -> Stage:
        failure: tuple[str, str] | None = None
        latency: int | None = None
        # trust_env=False: environment proxies must never leak into checks.
        for url in self.urls[:1] if quick else self.urls:
            code, detail, latency = await self._get(port, url, timeout, None)
            if code == "ok":
                failure = None
                break
            failure = (code, detail)
        if failure is not None:
            code, detail = failure
            xray = self._last_line(lines)
            return Stage("e2e", False, code, f"{detail}; xray: {xray}" if xray else detail, None, target)
        if data_probe and self.data_url:
            code, detail, _ = await self._get(port, self.data_url, timeout, self.data_bytes)
            if code != "ok":
                xray = self._last_line(lines)
                return Stage("e2e", False, code, f"{detail}; xray: {xray}" if xray else detail, latency, target)
            return Stage("e2e", True, "ok", f"туннель работает, передано {self.data_bytes // 1024} КБ", latency, target)
        return Stage("e2e", True, "ok", "туннель работает", latency, target)

    async def _get(self, port: int, url: str, timeout: float, want_bytes: int | None) -> tuple[str, str, int | None]:
        connector = ProxyConnector(proxy_type=ProxyType.SOCKS5, host="127.0.0.1", port=port, rdns=True)
        started = time.monotonic()
        received = 0
        try:
            async with aiohttp.ClientSession(connector=connector, trust_env=False,
                                             timeout=aiohttp.ClientTimeout(total=timeout)) as session:
                async with session.get(url, allow_redirects=False,
                                       headers={"User-Agent": "Mozilla/5.0", "Accept-Encoding": "identity"}) as response:
                    latency = int((time.monotonic() - started) * 1000)
                    if want_bytes is None:
                        return "ok", f"HTTP {response.status}", latency
                    if response.status >= 400:
                        # The test resource itself is broken; the tunnel answered, so it works.
                        return "ok", f"HTTP {response.status}", latency
                    async for chunk in response.content.iter_chunked(16384):
                        received += len(chunk)
                        if received >= want_bytes:
                            break
                    if received < want_bytes:
                        return "e2e_stall", f"получено {received} из {want_bytes} байт, поток закрыт", latency
                    return "ok", "", latency
        except (asyncio.TimeoutError, ProxyTimeoutError):
            if want_bytes is not None and received:
                return "e2e_stall", f"получено {received} из {want_bytes} байт, далее таймаут", None
            return "e2e_timeout", f"нет ответа за {timeout:g} с", None
        except ProxyError as exc:
            return "e2e_failed", f"туннель не установлен ({str(exc)[:60]})", None
        except (ProxyConnectionError, aiohttp.ClientError, OSError) as exc:
            if want_bytes is not None and received:
                return "e2e_stall", f"получено {received} из {want_bytes} байт, соединение оборвано", None
            return "e2e_failed", f"соединение через туннель оборвано ({exc.__class__.__name__})", None
