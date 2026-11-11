"""A minimal SOCKS5 proxy (CONNECT only) that records what goes through it."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import struct


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Socks5Proxy:
    def __init__(self, username: str = "", password: str = "") -> None:
        self.port = free_port()
        self.username, self.password = username, password
        self.targets: list[tuple[str, int]] = []
        self.auth_failures = 0
        self.enabled = True
        self._server: asyncio.AbstractServer | None = None
        self._tasks: set[asyncio.Task] = set()

    @property
    def url(self) -> str:
        auth = f"{self.username}:{self.password}@" if self.username else ""
        return f"socks5://{auth}127.0.0.1:{self.port}"

    async def start(self) -> "Socks5Proxy":
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", self.port)
        return self

    async def go_down(self) -> None:
        """Refuse new clients and cut the tunnels that are already open."""
        self.enabled = False
        for task in list(self._tasks):
            task.cancel()
        await asyncio.sleep(0.05)

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
        for task in list(self._tasks):
            task.cancel()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._tasks.add(asyncio.current_task())
        try:
            if not self.enabled:
                return
            version, count = await reader.readexactly(2)
            methods = await reader.readexactly(count)
            if self.username:
                if 2 not in methods:
                    writer.write(b"\x05\xff")
                    return
                writer.write(b"\x05\x02")
                await reader.readexactly(1)
                user = await reader.readexactly((await reader.readexactly(1))[0])
                secret = await reader.readexactly((await reader.readexactly(1))[0])
                if user.decode() != self.username or secret.decode() != self.password:
                    self.auth_failures += 1
                    writer.write(b"\x01\x01")
                    return
                writer.write(b"\x01\x00")
            else:
                writer.write(b"\x05\x00")
            _, command, _, kind = await reader.readexactly(4)
            if kind == 1:
                host = str(ipaddress.IPv4Address(await reader.readexactly(4)))
            elif kind == 3:
                host = (await reader.readexactly((await reader.readexactly(1))[0])).decode()
            else:
                host = str(ipaddress.IPv6Address(await reader.readexactly(16)))
            port = struct.unpack("!H", await reader.readexactly(2))[0]
            self.targets.append((host, port))
            try:
                up_reader, up_writer = await asyncio.open_connection(host, port)
            except OSError:
                writer.write(b"\x05\x05\x00\x01" + bytes(6))
                return
            writer.write(b"\x05\x00\x00\x01" + bytes(6))
            await writer.drain()

            async def pump(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
                try:
                    while data := await src.read(65536):
                        dst.write(data)
                        await dst.drain()
                except (OSError, asyncio.CancelledError):
                    pass
                finally:
                    try:
                        dst.close()
                    except OSError:
                        pass

            await asyncio.gather(pump(reader, up_writer), pump(up_reader, writer))
        except (asyncio.IncompleteReadError, OSError, asyncio.CancelledError):
            pass
        finally:
            self._tasks.discard(asyncio.current_task())
            try:
                writer.close()
            except OSError:
                pass
