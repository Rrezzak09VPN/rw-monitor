"""Subscriptions: adding, refreshing and reconciling the monitored server list."""

from __future__ import annotations

import asyncio
import logging
import secrets as pysecrets
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from ..config import Config
from ..db.database import Database, Row, jdump, jload
from ..security import MASKER, SecretBox, mask_url, sha256_hex
from ..settings import Settings
from ..timeutil import now_ts
from . import fetcher as F
from .fetcher import LoadResult, SubscriptionFetcher, validate_subscription_url
from .model import ServerConfig

log = logging.getLogger(__name__)

NEEDS_CONFIRM = "needs_confirm"
ADDRESS_TTL = 48 * 3600
HWID_KEY = "subscription.hwid"


@dataclass
class SyncResult:
    status: str
    message: str = ""
    sub_id: int | None = None
    title: str = ""
    hint: str = ""
    is_new: bool = False
    formats: list[str] = field(default_factory=list)
    added: list[str] = field(default_factory=list)
    restored: list[str] = field(default_factory=list)
    archived: list[str] = field(default_factory=list)
    pending_removal: list[str] = field(default_factory=list)
    unchanged: int = 0
    total: int = 0
    placeholders: list[str] = field(default_factory=list)
    skipped: Counter = field(default_factory=Counter)
    expire_at: int = 0
    first_failure: bool = False
    recovered: bool = False

    @property
    def ok(self) -> bool:
        return self.status == F.OK

    @property
    def changed(self) -> bool:
        return bool(self.added or self.restored or self.archived)


class SubscriptionService:
    def __init__(self, config: Config, db: Database, settings: Settings, box: SecretBox) -> None:
        self.config = config
        self.db = db
        self.settings = settings
        self.box = box
        self.fetcher = SubscriptionFetcher(config, lambda: self.hwid)
        self._locks: dict[str, asyncio.Lock] = defaultdict(asyncio.Lock)

    # ── lifecycle ───────────────────────────────────────────────────────────
    async def start(self) -> None:
        if not self.config.subscription_hwid and not self.settings.raw(HWID_KEY):
            await self.settings.set_raw(HWID_KEY, pysecrets.token_hex(16))
        for row in await self.db.fetchall("SELECT url_enc FROM subscriptions"):
            try:
                self._register_secret(self.box.decrypt(row["url_enc"]))
            except ValueError:
                log.error("cannot decrypt a stored subscription URL: SECRET_KEY mismatch")

    async def close(self) -> None:
        await self.fetcher.close()

    @property
    def hwid(self) -> str:
        """Stable device identifier presented to panels with a device limit."""
        return self.config.subscription_hwid or self.settings.raw(HWID_KEY)

    @staticmethod
    def _register_secret(url: str) -> None:
        MASKER.register(url, mask_url(url))
        tail = urlsplit(url).path.rstrip("/").rsplit("/", 1)[-1]
        if len(tail) >= 8:
            MASKER.register(tail, f"…{tail[-4:]}")

    # ── queries ─────────────────────────────────────────────────────────────
    async def list(self) -> list[Row]:
        return await self.db.fetchall(
            "SELECT s.*, (SELECT COUNT(*) FROM server_subscriptions ss JOIN servers v ON v.id=ss.server_id "
            "WHERE ss.subscription_id=s.id AND v.archived=0) AS server_count "
            "FROM subscriptions s ORDER BY s.id"
        )

    async def get(self, sub_id: int) -> Row | None:
        rows = [row for row in await self.list() if row["id"] == sub_id]
        return rows[0] if rows else None

    async def find_by_url(self, url: str) -> Row | None:
        return await self.db.fetchone("SELECT * FROM subscriptions WHERE url_hash=?", (sha256_hex(url),))

    # ── add / refresh / delete ──────────────────────────────────────────────
    async def add(self, raw_url: str, allow_hwid: bool = False) -> SyncResult:
        """Add a subscription; sending a known URL again refreshes it."""
        url = validate_subscription_url(raw_url)
        self._register_secret(url)
        async with self._locks[sha256_hex(url)]:
            existing = await self.find_by_url(url)
            if existing is not None:
                if allow_hwid and not existing["use_hwid"]:
                    await self.db.update("subscriptions", {"id": existing["id"]}, use_hwid=1)
                return await self._refresh_locked(existing["id"], force=False, interactive=True)
            loaded = await self.fetcher.load(url, use_hwid=allow_hwid, allow_fallback=True)
            hint = mask_url(url)
            if not loaded.ok:
                return self._failure(loaded, hint=hint, is_new=True)
            now = now_ts()
            async with self.db.tx():
                sub_id = await self.db.insert(
                    "subscriptions", url_enc=self.box.encrypt(url), url_hash=sha256_hex(url), url_hint=hint,
                    title=loaded.title or (urlsplit(url).hostname or ""), user_agent=loaded.user_agent,
                    use_hwid=int(allow_hwid), created_at=now, updated_at=now,
                )
                result = await self._apply(sub_id, loaded, force=True)
            result.is_new, result.hint = True, hint
            return result

    async def refresh(self, sub_id: int, force: bool = False, interactive: bool = False) -> SyncResult:
        row = await self.db.fetchone("SELECT url_hash FROM subscriptions WHERE id=?", (sub_id,))
        if row is None:
            return SyncResult("not_found", "подписка не найдена")
        async with self._locks[row["url_hash"]]:
            return await self._refresh_locked(sub_id, force, interactive)

    async def _refresh_locked(self, sub_id: int, force: bool, interactive: bool) -> SyncResult:
        sub = await self.db.fetchone("SELECT * FROM subscriptions WHERE id=?", (sub_id,))
        if sub is None:
            return SyncResult("not_found", "подписка не найдена")
        url = self.box.decrypt(sub["url_enc"])
        loaded = await self.fetcher.load(
            url, user_agent=sub["user_agent"], use_hwid=bool(sub["use_hwid"]), allow_fallback=interactive,
        )
        now = now_ts()
        if not loaded.ok:
            result = self._failure(loaded, sub_id=sub_id, hint=sub["url_hint"], title=sub["title"])
            result.first_failure = not sub["error_notified"]
            await self.db.update(
                "subscriptions", {"id": sub_id}, last_fetch_at=now, last_status=loaded.status,
                last_error=loaded.message[:500], updated_at=now,
                **({"expire_at": loaded.expire_at} if loaded.expire_at else {}),
            )
            return result
        async with self.db.tx():
            result = await self._apply(sub_id, loaded, force=force)
        result.hint, result.title = sub["url_hint"], sub["title"] or loaded.title
        result.recovered = bool(sub["error_notified"]) and result.ok
        return result

    async def mark_error_notified(self, sub_id: int) -> None:
        await self.db.update("subscriptions", {"id": sub_id}, error_notified=1)

    async def set_auto_refresh(self, sub_id: int, enabled: bool) -> None:
        await self.db.update("subscriptions", {"id": sub_id}, auto_refresh=int(enabled))

    async def delete(self, sub_id: int) -> list[str]:
        """Remove a subscription. Servers not present in other subscriptions are archived."""
        now = now_ts()
        async with self.db.tx():
            linked = await self.db.fetchall(
                "SELECT v.id, v.name FROM server_subscriptions ss JOIN servers v ON v.id=ss.server_id "
                "WHERE ss.subscription_id=?", (sub_id,),
            )
            await self.db.execute("DELETE FROM subscriptions WHERE id=?", (sub_id,))
            archived = []
            for server in linked:
                if await self._archive_if_orphan(server["id"], now):
                    archived.append(server["name"])
        return archived

    # ── internals ───────────────────────────────────────────────────────────
    @staticmethod
    def _failure(loaded: LoadResult, **extra: Any) -> SyncResult:
        return SyncResult(
            status=loaded.status, message=loaded.message, placeholders=loaded.placeholders,
            skipped=loaded.skipped, expire_at=loaded.expire_at, **extra,
        )

    def _server_fields(self, cfg: ServerConfig, now: int) -> dict[str, Any]:
        return dict(
            fingerprint=cfg.fingerprint, name=cfg.name, aliases_json=jdump(cfg.aliases),
            address=cfg.address, port=cfg.port, l4=cfg.l4, protocol=cfg.protocol,
            transport=cfg.transport, security=cfg.security, sni=cfg.sni, host=cfg.host, path=cfg.path,
            params_json=jdump(cfg.public_params()),
            secret_enc=self.box.encrypt(jdump({"secrets": cfg.secrets, "outbound": cfg.outbound})),
            node_key=cfg.node_key, updated_at=now,
        )

    async def _archive_if_orphan(self, server_id: int, now: int) -> bool:
        links = await self.db.scalar(
            "SELECT COUNT(*) FROM server_subscriptions WHERE server_id=?", (server_id,), 0)
        if links:
            return False
        await self.db.update("servers", {"id": server_id}, archived=1, archived_at=now, updated_at=now)
        await self.db.execute(
            "UPDATE incidents SET recovered_at=?, close_reason='removed' "
            "WHERE server_id=? AND recovered_at IS NULL AND close_reason=''", (now, server_id))
        await self.db.execute(
            "UPDATE server_state SET incident_id=NULL, next_check_at=NULL, fail_streak=0, ok_streak=0, "
            "flapping=0 WHERE server_id=?", (server_id,))
        return True

    async def _apply(self, sub_id: int, loaded: LoadResult, force: bool) -> SyncResult:
        """Reconcile the DB with a freshly loaded server list (inside a transaction)."""
        now = now_ts()
        result = SyncResult(F.OK, sub_id=sub_id, formats=loaded.formats, placeholders=loaded.placeholders,
                            skipped=loaded.skipped, expire_at=loaded.expire_at, title=loaded.title)
        linked = await self.db.fetchall(
            "SELECT v.* FROM server_subscriptions ss JOIN servers v ON v.id=ss.server_id "
            "WHERE ss.subscription_id=?", (sub_id,))
        all_by_fp = {row["fingerprint"]: row for row in await self.db.fetchall("SELECT * FROM servers")}
        matches: list[tuple[Row, ServerConfig]] = []
        matched_ids: set[int] = set()
        fresh: list[ServerConfig] = []
        for cfg in loaded.servers:
            row = all_by_fp.get(cfg.fingerprint)
            if row is not None and row["id"] not in matched_ids:
                matches.append((row, cfg))
                matched_ids.add(row["id"])
            elif row is None:
                fresh.append(cfg)
        # Same host whose SNI/path (pass 1) or address (pass 2) changed between requests.
        for row_key, cfg_key in (
            (lambda r: (r["address"], r["port"], r["protocol"], r["transport"], r["security"], r["name"]),
             lambda c: (c.address, c.port, c.protocol, c.transport, c.security, c.name)),
            (lambda r: (r["port"], r["protocol"], r["transport"], r["security"], r["name"]),
             lambda c: c.soft_key),
        ):
            leftovers: dict[tuple, list[Row]] = defaultdict(list)
            for row in linked:
                if row["id"] not in matched_ids:
                    leftovers[row_key(row)].append(row)
            candidates: dict[tuple, list[ServerConfig]] = defaultdict(list)
            for cfg in fresh:
                candidates[cfg_key(cfg)].append(cfg)
            for key, cfgs in candidates.items():
                rows = leftovers.get(key, [])
                if len(cfgs) == 1 and len(rows) == 1:
                    matches.append((rows[0], cfgs[0]))
                    matched_ids.add(rows[0]["id"])
                    fresh.remove(cfgs[0])

        to_remove = [row for row in linked if row["id"] not in matched_ids]
        if not force and len(linked) >= 2 and len(to_remove) * 2 > len(linked):
            result.status = NEEDS_CONFIRM
            result.pending_removal = [row["name"] for row in to_remove]
            result.total = len(linked)
            result.message = (f"из подписки исчезло {len(to_remove)} из {len(linked)} серверов. "
                              "Изменение не применено и ждёт подтверждения.")
            return result

        for row, cfg in matches:
            fields = self._server_fields(cfg, now)
            if row["address"] != cfg.address:
                for address, seen in ((row["address"], now - 1), (cfg.address, now)):
                    await self.db.execute(
                        "INSERT INTO server_addresses (server_id, address, first_seen, last_seen) "
                        "VALUES (?, ?, ?, ?) ON CONFLICT(server_id, address) DO UPDATE SET "
                        "last_seen=MAX(last_seen, excluded.last_seen)", (row["id"], address, seen, seen))
            else:
                await self.db.execute(
                    "UPDATE server_addresses SET last_seen=? WHERE server_id=? AND address=?",
                    (now, row["id"], cfg.address))
            if row["archived"]:
                fields.update(archived=0, archived_at=None)
                await self.db.execute(
                    "UPDATE server_state SET state='UNKNOWN', state_since=?, fail_streak=0, ok_streak=0, "
                    "incident_id=NULL, next_check_at=NULL WHERE server_id=?", (now, row["id"]))
                result.restored.append(cfg.name)
            else:
                result.unchanged += 1
            await self.db.update("servers", {"id": row["id"]}, **fields)
            await self._link(row["id"], sub_id, cfg.name, now)
        for cfg in fresh:
            server_id = await self.db.insert("servers", created_at=now, **self._server_fields(cfg, now))
            await self.db.insert("server_state", server_id=server_id, state="UNKNOWN", state_since=now)
            await self._link(server_id, sub_id, cfg.name, now)
            result.added.append(cfg.name)
        for row in to_remove:
            await self.db.execute(
                "DELETE FROM server_subscriptions WHERE server_id=? AND subscription_id=?", (row["id"], sub_id))
            if await self._archive_if_orphan(row["id"], now):
                result.archived.append(row["name"])
        await self.db.execute("DELETE FROM server_addresses WHERE last_seen < ?", (now - ADDRESS_TTL,))
        await self.db.update(
            "subscriptions", {"id": sub_id}, last_fetch_at=now, last_ok_at=now, last_status=F.OK,
            last_error="", last_formats=", ".join(loaded.formats), expire_at=loaded.expire_at or None,
            userinfo_json=jdump(loaded.userinfo), user_agent=loaded.user_agent, error_notified=0,
            updated_at=now, **({"title": loaded.title} if loaded.title else {}),
        )
        result.total = len(matches) + len(fresh)
        return result

    async def _link(self, server_id: int, sub_id: int, remark: str, now: int) -> None:
        await self.db.execute(
            "INSERT INTO server_subscriptions (server_id, subscription_id, remark, first_seen, last_seen) "
            "VALUES (?, ?, ?, ?, ?) ON CONFLICT(server_id, subscription_id) DO UPDATE SET "
            "remark=excluded.remark, last_seen=excluded.last_seen", (server_id, sub_id, remark, now, now))

    # ── helpers for other components ────────────────────────────────────────
    def decrypt_server_secret(self, row: Row) -> dict[str, Any]:
        """Credentials and raw outbound of a server (needed only for the E2E check)."""
        if not row.get("secret_enc"):
            return {"secrets": {}, "outbound": None}
        try:
            return jload(self.box.decrypt(row["secret_enc"]), {"secrets": {}, "outbound": None})
        except ValueError:
            return {"secrets": {}, "outbound": None}
