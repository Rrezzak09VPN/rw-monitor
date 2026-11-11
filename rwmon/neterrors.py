"""Network error groups shared by the HTTP clients.

aiohttp-socks raises its own exception types for proxy failures; they derive
neither from ``OSError`` nor from ``aiohttp.ClientError``, so they have to be
named explicitly wherever a request may go through a proxy.
"""

from __future__ import annotations

from aiohttp_socks import ProxyConnectionError, ProxyError, ProxyTimeoutError

PROXY_ERRORS: tuple[type[Exception], ...] = (ProxyConnectionError, ProxyError, ProxyTimeoutError)
