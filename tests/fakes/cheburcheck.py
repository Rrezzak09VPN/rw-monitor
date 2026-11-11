"""A fake Cheburcheck API built from real recorded responses."""

from __future__ import annotations

import asyncio
import json
import socket
from pathlib import Path

from aiohttp import web

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "cheburcheck"


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def load_probe_events(name: str) -> list[tuple[str, dict]]:
    events, event, data = [], "", ""
    for line in (FIXTURES / f"probe_{name}.sse").read_text(encoding="utf-8").splitlines():
        if line.startswith("event:"):
            event = line[6:].strip()
        elif line.startswith("data:"):
            data += line[5:].strip()
        elif not line and data:
            events.append((event, json.loads(data)))
            event, data = "", ""
    if data:
        events.append((event, json.loads(data)))
    return events


class FakeCheburcheck:
    def __init__(self) -> None:
        self.port = free_port()
        self.mode = "ok"            # ok | down | rate_limit | garbage | probe_down | reject | cut_stream
        self.verdict = "tspu_block"  # verdict returned by most probes for IP targets
        self.blocked_share = 0.9
        self.check_calls: list[str] = []
        self.probe_calls = 0
        self._runner: web.AppRunner | None = None
        self._ip_events = load_probe_events("1.1.1.1")
        self._domain_events = load_probe_events("rutracker.org")
        self._static_ip = json.loads((FIXTURES / "check_1.1.1.1.json").read_text(encoding="utf-8"))
        self._static_domain = json.loads((FIXTURES / "check_rutracker.org.json").read_text(encoding="utf-8"))

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    async def start(self) -> "FakeCheburcheck":
        app = web.Application()
        app.router.add_get("/api/v1/check", self._check)
        app.router.add_get("/api/v1/probe/{probe_id}", self._probe)
        self._runner = web.AppRunner(app)
        await self._runner.setup()
        await web.TCPSite(self._runner, "127.0.0.1", self.port).start()
        return self

    async def stop(self) -> None:
        if self._runner:
            await self._runner.cleanup()
            self._runner = None

    async def _check(self, request: web.Request) -> web.StreamResponse:
        target = request.query.get("target", "")
        self.check_calls.append(target)
        if self.mode == "down":
            return web.Response(status=502, text="Bad Gateway")
        if self.mode == "rate_limit":
            return web.Response(status=429, headers={"Retry-After": "1"}, text="Too Many Requests")
        if self.mode == "garbage":
            return web.json_response({"unexpected": "shape"})
        if self.mode == "reject":
            return web.Response(status=403, text="Forbidden")
        is_ip = target.replace(".", "").isdigit()
        body = dict(self._static_ip if is_ip else self._static_domain)
        body.update(target=target, id=("ip:" if is_ip else "dom:") + target,
                    ips=[target] if is_ip else ["93.184.216.34"])
        if not is_ip:
            body["rkn_domain"] = None
            body["blocked"] = False
        return web.json_response(body)

    async def _probe(self, request: web.Request) -> web.StreamResponse:
        self.probe_calls += 1
        if self.mode in ("down", "probe_down"):
            return web.Response(status=503, text="Service Unavailable")
        probe_id = request.match_info["probe_id"]
        events = self._ip_events if probe_id.startswith("ip:") else self._domain_events
        response = web.StreamResponse(headers={"Content-Type": "text/event-stream"})
        await response.prepare(request)
        results = [item for item in events if item[0] == "result"]
        cut = int(len(results) * self.blocked_share)
        index = 0
        for event, data in events:
            data = dict(data)
            if event == "result" and probe_id.startswith("ip:"):
                data["verdicts"] = [self.verdict] if index < cut else ["ok"]
                index += 1
            if self.mode == "cut_stream" and index >= 5:
                request.transport.close()          # the stream dies after a few probe answers
                return response
            await response.write(f"event: {event}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n".encode())
            await asyncio.sleep(0)
        await response.write_eof()
        return response
