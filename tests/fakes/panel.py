"""A fake Remnawave subscription endpoint (only what a client can see)."""

from __future__ import annotations

import base64
import socket

from aiohttp import web

EXPIRED_LINK = ("vless://00000000-0000-0000-0000-000000000000@0.0.0.0:1?type=tcp&security=none"
                "#%E2%8C%9B%20Subscription%20expired")
HWID_LINK = ("vless://00000000-0000-0000-0000-000000000000@0.0.0.0:1?type=tcp&security=none"
             "#%F0%9F%9B%91%20App%20not%20supported")


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class FakePanel:
    """Serves ``/sub/<token>`` and ``/sub/<token>/<suffix>``; behaviour is switched by attributes."""

    def __init__(self) -> None:
        self.port = free_port()
        self.token = "TESTtoken123456"
        self.links: list[str] = []
        self.mode = "ok"            # ok | expired | hwid | hwid_limit | error500 | html | notfound | drop
        self.title = "Test panel"
        self.expire = 0
        self.json_body: bytes | None = None
        self.mihomo_body: bytes | None = None
        self.requests: list[dict] = []
        self._runner: web.AppRunner | None = None

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/sub/{self.token}"

    async def start(self) -> "FakePanel":
        app = web.Application()
        app.router.add_get("/sub/{token}", self._handle)
        app.router.add_get("/sub/{token}/{suffix}", self._handle)
        self._runner = web.AppRunner(app)
        await self._runner.setup()
        await web.TCPSite(self._runner, "127.0.0.1", self.port).start()
        return self

    async def stop(self) -> None:
        if self._runner:
            await self._runner.cleanup()
            self._runner = None

    def _headers(self) -> dict[str, str]:
        headers = {
            "profile-title": "base64:" + base64.b64encode(self.title.encode()).decode(),
            "profile-update-interval": "1",
            "subscription-userinfo": f"upload=0; download=1024; total=0; expire={self.expire}",
        }
        return headers

    async def _handle(self, request: web.Request) -> web.StreamResponse:
        suffix = request.match_info.get("suffix", "")
        self.requests.append({
            "suffix": suffix, "ua": request.headers.get("User-Agent", ""), "hwid": request.headers.get("x-hwid", ""),
        })
        if request.match_info["token"] != self.token or self.mode == "notfound":
            return web.Response(status=404, text="Not Found")
        if self.mode == "drop":
            request.transport.close()
            return web.Response(status=500)
        if self.mode == "error500":
            return web.Response(status=500, text="Internal Server Error")
        if self.mode == "html":
            return web.Response(text="<!DOCTYPE html><html><body>Subscription page</body></html>",
                                content_type="text/html")
        headers = self._headers()
        if self.mode in ("hwid", "hwid_limit") and (self.mode == "hwid_limit" or not request.headers.get("x-hwid")):
            headers["x-hwid-not-supported" if self.mode == "hwid" else "x-hwid-max-devices-reached"] = "true"
            return web.Response(body=base64.b64encode(HWID_LINK.encode()), headers=headers, content_type="text/plain")
        if self.mode == "hwid":
            headers["x-hwid-active"] = "true"
        if self.mode == "expired":
            return web.Response(body=base64.b64encode(EXPIRED_LINK.encode()), headers=headers, content_type="text/plain")
        if suffix == "json":
            if self.json_body is None:
                return web.Response(status=404)
            return web.Response(body=self.json_body, headers=headers, content_type="application/json")
        if suffix == "mihomo":
            if self.mihomo_body is None:
                return web.Response(status=404)
            return web.Response(body=self.mihomo_body, headers=headers, content_type="text/yaml")
        if suffix:
            return web.Response(status=404)
        return web.Response(body=base64.b64encode("\n".join(self.links).encode()), headers=headers,
                            content_type="text/plain")


def vless_link(name: str, host: str, port: int = 443, uuid: str = "11111111-2222-4333-8444-555555555555",
               sni: str = "") -> str:
    return (f"vless://{uuid}@{host}:{port}?type=tcp&security=reality&sni={sni or host}&fp=chrome"
            f"&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=abcd&flow=xtls-rprx-vision#{name}")
