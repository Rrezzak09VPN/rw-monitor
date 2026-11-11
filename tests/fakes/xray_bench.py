"""A hermetic local stand with real Xray servers for integration tests.

Everything listens on loopback: an Xray server with several inbounds
(VLESS+REALITY, Trojan+WS+TLS, Hysteria2, Shadowsocks), a TLS "cover" site for
REALITY, an HTTP target that the tunnel fetches, and a throttling TCP relay
that emulates DPI behaviour (freeze after N bytes, drop, reset).
"""

from __future__ import annotations

import asyncio
import datetime
import hashlib
import json
import os
import shutil
import socket
import ssl
import subprocess
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from aiohttp import web
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

SNI = "bench.test"


def find_xray() -> str | None:
    for candidate in (os.environ.get("XRAY_BIN"), "/usr/local/bin/xray", "/tmp/xray/xray", shutil.which("xray")):
        if candidate and os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def free_port(udp: bool = False) -> int:
    kind = socket.SOCK_DGRAM if udp else socket.SOCK_STREAM
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def make_cert(directory: Path, name: str = SNI) -> tuple[Path, Path, str]:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = directory / "cert.pem", directory / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    digest = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
    return cert_path, key_path, digest


class Relay:
    """TCP relay with fault injection, standing in for a DPI box on the path."""

    def __init__(self, target_port: int) -> None:
        self.target_port = target_port
        self.port = free_port()
        self.mode = "pass"          # pass | drop | reset | freeze_after | close
        self.limit = 16 * 1024      # bytes server→client allowed in freeze_after mode
        self._server: asyncio.AbstractServer | None = None
        self._tasks: set[asyncio.Task] = set()

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", self.port)

    async def stop(self) -> None:
        if self._server:
            self._server.close()
        for task in list(self._tasks):
            task.cancel()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        self._tasks.add(task)
        try:
            if self.mode == "close":
                writer.close()
                return
            if self.mode == "reset":
                await reader.read(1)   # wait for the ClientHello, then RST
                sock = writer.get_extra_info("socket")
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b"\x01\x00\x00\x00\x00\x00\x00\x00")
                writer.close()
                return
            if self.mode == "drop":
                await asyncio.sleep(3600)
                return
            up_reader, up_writer = await asyncio.open_connection("127.0.0.1", self.target_port)
            budget = [self.limit]

            async def pump(src, dst, limited: bool) -> None:
                try:
                    while True:
                        data = await src.read(16384)
                        if not data:
                            break
                        if limited and self.mode == "freeze_after":
                            if budget[0] <= 0:
                                await asyncio.sleep(3600)
                            data = data[: budget[0]]
                            budget[0] -= len(data)
                        dst.write(data)
                        await dst.drain()
                except (OSError, asyncio.CancelledError):
                    pass
                finally:
                    try:
                        dst.close()
                    except OSError:
                        pass

            await asyncio.gather(pump(reader, up_writer, False), pump(up_reader, writer, True))
        except (OSError, asyncio.CancelledError):
            pass
        finally:
            self._tasks.discard(task)
            try:
                writer.close()
            except OSError:
                pass


@dataclass
class Bench:
    xray: str
    workdir: Path
    uuid: str = ""
    private_key: str = ""
    public_key: str = ""
    short_id: str = "0123abcd"
    password: str = "bench-password"
    ss_password: str = "bench-ss-password"
    cert_sha256: str = ""
    ports: dict[str, int] = field(default_factory=dict)
    relay: Relay | None = None
    _proc: subprocess.Popen | None = None
    _runners: list = field(default_factory=list)
    hits: int = 0

    # ── lifecycle ───────────────────────────────────────────────────────────

    @classmethod
    async def start(cls) -> "Bench":
        xray = find_xray()
        if not xray:
            raise RuntimeError("xray binary not found")
        bench = cls(xray=xray, workdir=Path(tempfile.mkdtemp(prefix="rwmon-bench-")))
        bench.uuid = str(uuid.uuid4())
        out = subprocess.run([xray, "x25519"], capture_output=True, text=True, check=True).stdout
        for line in out.splitlines():
            key, _, value = line.partition(":")
            if key.strip().startswith("PrivateKey") or key.strip().startswith("Private key"):
                bench.private_key = value.strip()
            elif "PublicKey" in key or "Public key" in key:
                bench.public_key = value.strip()
        cert, key, bench.cert_sha256 = make_cert(bench.workdir)
        for name in ("reality", "trojan", "ss", "ws", "cover", "web"):
            bench.ports[name] = free_port()
        bench.ports["hy2"] = free_port(udp=True)
        await bench._start_web(cert, key)
        bench._start_xray(cert, key)
        await bench._wait_port(bench.ports["reality"])
        bench.relay = Relay(bench.ports["reality"])
        await bench.relay.start()
        bench.ports["relay"] = bench.relay.port
        return bench

    async def stop(self) -> None:
        if self.relay:
            await self.relay.stop()
        self.stop_xray()
        for runner in self._runners:
            await runner.cleanup()
        shutil.rmtree(self.workdir, ignore_errors=True)

    def stop_xray(self) -> None:
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        self._proc = None

    async def restart_xray(self) -> None:
        self._start_xray(self.workdir / "cert.pem", self.workdir / "key.pem")
        await self._wait_port(self.ports["reality"])

    @staticmethod
    async def _wait_port(port: int, timeout: float = 8.0) -> None:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while loop.time() < deadline:
            try:
                _, writer = await asyncio.open_connection("127.0.0.1", port)
                writer.close()
                return
            except OSError:
                await asyncio.sleep(0.05)
        raise RuntimeError(f"port {port} did not open")

    async def _start_web(self, cert: Path, key: Path) -> None:
        async def no_content(request: web.Request) -> web.Response:
            self.hits += 1
            return web.Response(status=204)

        async def blob(request: web.Request) -> web.Response:
            size = int(request.query.get("bytes", "131072"))
            return web.Response(body=os.urandom(size), content_type="application/octet-stream")

        app = web.Application()
        app.router.add_get("/generate_204", no_content)
        app.router.add_get("/blob", blob)
        runner = web.AppRunner(app)
        await runner.setup()
        await web.TCPSite(runner, "127.0.0.1", self.ports["web"]).start()
        self._runners.append(runner)

        cover = web.Application()
        cover.router.add_get("/", lambda request: web.Response(text="cover"))
        cover_runner = web.AppRunner(cover)
        await cover_runner.setup()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        # REALITY copies the cover site's handshake record sizes and needs room in
        # EncryptedExtensions, which a bare TLS server (no ALPN) does not leave.
        context.set_alpn_protocols(["h2", "http/1.1"])
        await web.TCPSite(cover_runner, "127.0.0.1", self.ports["cover"], ssl_context=context).start()
        self._runners.append(cover_runner)

    def _start_xray(self, cert: Path, key: Path) -> None:
        certificates = [{"certificateFile": str(cert), "keyFile": str(key)}]
        config = {
            "log": {"loglevel": "warning"},
            "inbounds": [
                {"tag": "reality", "listen": "127.0.0.1", "port": self.ports["reality"], "protocol": "vless",
                 "settings": {"clients": [{"id": self.uuid, "flow": "xtls-rprx-vision"}], "decryption": "none"},
                 "streamSettings": {"network": "raw", "security": "reality", "realitySettings": {
                     "target": f"127.0.0.1:{self.ports['cover']}", "serverNames": [SNI],
                     "privateKey": self.private_key, "shortIds": [self.short_id]}}},
                {"tag": "trojan", "listen": "127.0.0.1", "port": self.ports["trojan"], "protocol": "trojan",
                 "settings": {"clients": [{"password": self.password}]},
                 "streamSettings": {"network": "ws", "security": "tls", "wsSettings": {"path": "/ws"},
                                    "tlsSettings": {"certificates": certificates}}},
                {"tag": "ws", "listen": "127.0.0.1", "port": self.ports["ws"], "protocol": "vless",
                 "settings": {"clients": [{"id": self.uuid}], "decryption": "none"},
                 "streamSettings": {"network": "ws", "security": "none", "wsSettings": {"path": "/plain"}}},
                {"tag": "ss", "listen": "127.0.0.1", "port": self.ports["ss"], "protocol": "shadowsocks",
                 "settings": {"method": "chacha20-ietf-poly1305", "password": self.ss_password, "network": "tcp"}},
                {"tag": "hy2", "listen": "127.0.0.1", "port": self.ports["hy2"], "protocol": "hysteria",
                 "settings": {"version": 2, "clients": [{"auth": self.password}]},
                 "streamSettings": {"network": "hysteria", "security": "tls",
                                    "hysteriaSettings": {"version": 2},
                                    "tlsSettings": {"certificates": certificates, "alpn": ["h3"]}}},
            ],
            # Xray blocks private targets for proxied traffic by default; the stand's target is local.
            "outbounds": [{"protocol": "freedom", "settings": {
                "finalRules": [{"action": "allow", "ip": ["127.0.0.0/8"]}]}}],
        }
        path = self.workdir / "server.json"
        path.write_text(json.dumps(config))
        log = open(self.workdir / "server.log", "ab")
        self._proc = subprocess.Popen([self.xray, "run", "-c", str(path)], stdout=log, stderr=subprocess.STDOUT)

    # ── client-side material ────────────────────────────────────────────────

    @property
    def test_url(self) -> str:
        return f"http://127.0.0.1:{self.ports['web']}/generate_204"

    def data_url(self, size: int = 131072) -> str:
        return f"http://127.0.0.1:{self.ports['web']}/blob?bytes={size}"

    def links(self, via_relay: bool = False) -> dict[str, str]:
        """Share links for every inbound, as a Remnawave subscription would list them."""
        reality_port = self.ports["relay"] if via_relay else self.ports["reality"]
        return {
            "reality": (f"vless://{self.uuid}@127.0.0.1:{reality_port}?type=tcp&security=reality&sni={SNI}"
                        f"&fp=chrome&pbk={self.public_key}&sid={self.short_id}&flow=xtls-rprx-vision#Bench%20REALITY"),
            "trojan": (f"trojan://{self.password}@127.0.0.1:{self.ports['trojan']}?type=ws&security=tls&sni={SNI}"
                       f"&path=%2Fws&allowInsecure=1#Bench%20Trojan"),
            "ws": f"vless://{self.uuid}@127.0.0.1:{self.ports['ws']}?type=ws&security=none&path=%2Fplain#Bench%20WS",
            "ss": ("ss://" + _b64(f"chacha20-ietf-poly1305:{self.ss_password}")
                   + f"@127.0.0.1:{self.ports['ss']}#Bench%20SS"),
            "hy2": (f"hysteria2://{self.password}@127.0.0.1:{self.ports['hy2']}?sni={SNI}&insecure=1"
                    f"&pinSHA256={self.cert_sha256}#Bench%20HY2"),
        }

    def subscription_body(self, names: list[str] | None = None, via_relay: bool = False) -> bytes:
        import base64
        links = self.links(via_relay)
        chosen = [links[name] for name in (names or list(links))]
        return base64.b64encode("\n".join(chosen).encode())


def _b64(text: str) -> str:
    import base64
    return base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")
