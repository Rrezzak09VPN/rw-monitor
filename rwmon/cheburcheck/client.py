"""HTTP client for the Cheburcheck API (https://cheburcheck.ru).

Only the two endpoints that exist and are open are used:

* ``GET /api/v1/check?target=`` – static data (registries, subnets, CDN, ASN, geo);
* ``GET /api/v1/probe/<id>`` – live regional measurements, a Server-Sent Events stream.

The API is undocumented and may change, so every field is read defensively.
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from typing import Any

import aiohttp
from aiohttp_socks import ProxyConnector, ProxyTimeoutError

from ..neterrors import PROXY_ERRORS

log = logging.getLogger(__name__)

UNAVAILABLE = "unavailable"     # network error, timeout, 5xx
RATE_LIMITED = "rate_limited"   # 429
REJECTED = "rejected"           # 400 / 403 / 404: the service refuses this target
EXPIRED = "expired"             # 401: the probe context token is no longer valid
PROTOCOL = "protocol"           # unexpected response: the API has probably changed


class CheburcheckError(Exception):
    def __init__(self, kind: str, message: str, status: int | None = None,
                 retry_after: float | None = None) -> None:
        super().__init__(message)
        self.kind = kind
        self.status = status
        self.retry_after = retry_after

    @property
    def service_down(self) -> bool:
        """The failure says something about the service, not about the target."""
        return self.kind in (UNAVAILABLE, PROTOCOL)


@dataclass
class ProbeData:
    results: list[dict[str, Any]] = field(default_factory=list)
    online: int = 0
    responses: int = 0
    done: bool = False


def _retry_after(response: aiohttp.ClientResponse) -> float | None:
    try:
        return max(1.0, float(response.headers.get("Retry-After", "")))
    except ValueError:
        return None


class CheburcheckClient:
    def __init__(self, base_url: str, proxy_url: str = "", timeout: float = 15.0,
                 probe_timeout: float = 45.0, user_agent: str = "rw-monitor/1.0") -> None:
        self.base_url = base_url.rstrip("/")
        self.proxy_url = proxy_url
        self.timeout = timeout
        self.probe_timeout = probe_timeout
        self.user_agent = user_agent
        self._session: aiohttp.ClientSession | None = None

    def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            connector = (ProxyConnector.from_url(self.proxy_url) if self.proxy_url
                         else aiohttp.TCPConnector(limit=4, ttl_dns_cache=300))
            # trust_env=False: proxies from the environment are never picked up implicitly.
            self._session = aiohttp.ClientSession(
                connector=connector, trust_env=False,
                headers={"User-Agent": self.user_agent, "Accept": "application/json, text/event-stream"})
        return self._session

    async def close(self) -> None:
        if self._session is not None and not self._session.closed:
            await self._session.close()
        self._session = None

    @staticmethod
    def _raise_for_status(response: aiohttp.ClientResponse) -> None:
        status = response.status
        if status == 200:
            return
        if status == 429:
            raise CheburcheckError(RATE_LIMITED, "превышен лимит запросов", status, _retry_after(response))
        if status == 401:
            raise CheburcheckError(EXPIRED, "идентификатор проверки устарел", status)
        if status in (400, 403, 404, 422):
            raise CheburcheckError(REJECTED, f"сервис отклонил цель (HTTP {status})", status)
        raise CheburcheckError(UNAVAILABLE, f"HTTP {status}", status, _retry_after(response))

    async def check(self, target: str) -> dict[str, Any]:
        """Static lookup. Returns the decoded JSON object."""
        try:
            async with self._get_session().get(
                f"{self.base_url}/api/v1/check", params={"target": target},
                timeout=aiohttp.ClientTimeout(total=self.timeout),
            ) as response:
                self._raise_for_status(response)
                try:
                    data = json.loads(await response.text())
                except ValueError as exc:
                    raise CheburcheckError(PROTOCOL, "ответ не является JSON", response.status) from exc
        except CheburcheckError:
            raise
        except (asyncio.TimeoutError, ProxyTimeoutError) as exc:
            raise CheburcheckError(UNAVAILABLE, "таймаут") from exc
        except (aiohttp.ClientError, OSError, *PROXY_ERRORS) as exc:
            raise CheburcheckError(UNAVAILABLE, f"ошибка соединения ({exc.__class__.__name__})") from exc
        if not isinstance(data, dict) or "blocked" not in data:
            raise CheburcheckError(PROTOCOL, "неожиданный формат ответа")
        return data

    async def probe(self, probe_id: str) -> ProbeData:
        """Live regional measurements. Collects the SSE stream until ``done`` or the deadline.

        A stream that breaks after some results is returned as partial data
        (``done=False``); only a failure before any result raises.
        """
        data = ProbeData()
        try:
            async with self._get_session().get(
                f"{self.base_url}/api/v1/probe/{probe_id}",
                timeout=aiohttp.ClientTimeout(total=self.probe_timeout, sock_connect=self.timeout),
            ) as response:
                self._raise_for_status(response)
                event, payload = "", []
                async for raw in response.content:
                    line = raw.decode("utf-8", "replace").rstrip("\r\n")
                    if line.startswith(":"):
                        continue
                    if line.startswith("event:"):
                        event = line[6:].strip()
                    elif line.startswith("data:"):
                        payload.append(line[5:].lstrip())
                    elif not line:
                        if payload:
                            self._dispatch(event or "message", "\n".join(payload), data)
                        event, payload = "", []
                        if data.done:
                            break
        except CheburcheckError:
            raise
        except (asyncio.TimeoutError, aiohttp.ClientError, OSError, *PROXY_ERRORS) as exc:
            if not data.results:
                timed_out = isinstance(exc, (asyncio.TimeoutError, ProxyTimeoutError))
                kind = "таймаут" if timed_out else f"ошибка соединения ({exc.__class__.__name__})"
                raise CheburcheckError(UNAVAILABLE, kind) from exc
            log.info("cheburcheck probe stream ended early with %d results", len(data.results))
        return data

    @staticmethod
    def _dispatch(event: str, payload: str, data: ProbeData) -> None:
        try:
            item = json.loads(payload)
        except ValueError:
            return
        if not isinstance(item, dict):
            return
        if event == "started":
            data.online = int(item.get("online_probes") or 0)
        elif event == "result":
            data.results.append(item)
        elif event == "done":
            data.done = True
            data.online = int(item.get("online_probes") or data.online)
            data.responses = int(item.get("response_count") or len(data.results))
