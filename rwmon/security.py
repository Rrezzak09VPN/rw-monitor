"""Field encryption and masking helpers for secrets."""

from __future__ import annotations

import hashlib
import re
from urllib.parse import urlsplit

from cryptography.fernet import Fernet, InvalidToken


class SecretBox:
    """Symmetric encryption for sensitive DB fields (subscription URLs, credentials)."""

    def __init__(self, key: str) -> None:
        try:
            self._fernet = Fernet(key.strip().encode())
        except Exception as exc:  # noqa: BLE001 - any failure means a bad key
            raise ValueError(
                "SECRET_KEY некорректен. Сгенерируйте ключ командой: python -m rwmon genkey"
            ) from exc

    @staticmethod
    def generate_key() -> str:
        return Fernet.generate_key().decode()

    def encrypt(self, text: str) -> bytes:
        return self._fernet.encrypt(text.encode("utf-8"))

    def decrypt(self, blob: bytes) -> str:
        try:
            return self._fernet.decrypt(bytes(blob)).decode("utf-8")
        except InvalidToken as exc:
            raise ValueError(
                "не удалось расшифровать данные: SECRET_KEY не соответствует базе"
            ) from exc


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def mask_url(url: str) -> str:
    """``https://host/path/abcdEFGH`` → ``host/…EFGH`` (safe to show and log)."""
    try:
        parts = urlsplit(url)
        host = parts.hostname or "?"
        tail = parts.path.rstrip("/").rsplit("/", 1)[-1]
        return f"{host}/…{tail[-4:]}" if tail else host
    except ValueError:
        return "…"


def mask_proxy(url: str) -> str:
    """Hide proxy credentials: ``socks5://user:pass@h:1080`` → ``socks5://***@h:1080``."""
    if not url:
        return "без прокси"
    try:
        parts = urlsplit(url)
        auth = "***@" if (parts.username or parts.password) else ""
        return f"{parts.scheme}://{auth}{parts.hostname}:{parts.port}"
    except ValueError:
        return "…"


_TOKEN_RE = re.compile(r"\b(?:bot)?\d{6,12}:[A-Za-z0-9_-]{30,}\b")
_URL_AUTH_RE = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@")
_SHARE_LINK_RE = re.compile(r"(?i)\b(vless|trojan|ss|vmess|hysteria2|hy2)://[^\s@#]+(@?)")
_UUID_RE = re.compile(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")


class SecretMasker:
    """Redacts secrets from arbitrary text (log lines, error messages)."""

    def __init__(self) -> None:
        self._literals: dict[str, str] = {}

    def register(self, secret: str, replacement: str = "***") -> None:
        """Register an exact secret string (token, subscription URL, key)."""
        if secret and len(secret) >= 6:
            self._literals[secret] = replacement

    def mask(self, text: str) -> str:
        if not text:
            return text
        for secret, replacement in self._literals.items():
            if secret in text:
                text = text.replace(secret, replacement)
        text = _TOKEN_RE.sub("***TOKEN***", text)
        text = _SHARE_LINK_RE.sub(lambda m: f"{m.group(1)}://***{m.group(2)}", text)
        text = _URL_AUTH_RE.sub(r"\1***@", text)
        text = _UUID_RE.sub("***UUID***", text)
        return text


MASKER = SecretMasker()
