"""Cheburcheck integration: pacing, cache, circuit breaker and a persistent retry queue.

Rules that follow from the requirements:

* lookups happen only for confirmed incidents or on the owner's explicit request;
* an unavailable service never changes a server's state and is never hammered:
  a queue item is retried a few times with growing pauses, and after several
  consecutive failures the whole service is left alone for a while;
* results that could not be obtained are delivered later, when the service is back.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

from ..config import Config
from ..db.database import Database, Row, jdump, jload
from ..settings import Settings
from . import summary as sm
from .client import (
    PROTOCOL,
    RATE_LIMITED,
    REJECTED,
    CheburcheckClient,
    CheburcheckError,
)

log = logging.getLogger(__name__)

RETRY_PAUSES = (60, 180, 600, 1800, 3600)      # between attempts of one queued lookup
MAX_ATTEMPTS = 6
MAX_AGE = 24 * 3600
BREAKER_THRESHOLD = 3                          # consecutive service failures before backing off
BREAKER_PAUSES = (600, 1200, 2400, 3600)
MIN_PROBE_RESPONSES = 3


@dataclass
class CcResult:
    target: str
    kind: str
    requested_at: int
    static_status: str = "unavailable"   # ok | unavailable | rejected | disabled | skipped
    probe_status: str = "skipped"        # ok | partial | none | unavailable | skipped | rejected
    summary: dict[str, Any] = field(default_factory=dict)
    error: str = ""
    id: int | None = None
    from_cache: bool = False

    @property
    def reliability(self) -> str:
        if self.static_status == "skipped":
            return sm.UNAVAILABLE
        return sm.reliability(self.static_status, self.probe_status, self.summary)

    @property
    def static(self) -> dict[str, Any]:
        return self.summary.get("static") or {}

    @property
    def probes(self) -> dict[str, Any]:
        return self.summary.get("probes") or {}

    @classmethod
    def from_row(cls, row: Row, from_cache: bool = False) -> "CcResult":
        return cls(
            target=row["target"], kind=row["target_kind"], requested_at=row["requested_at"],
            static_status=row["static_status"], probe_status=row["probe_status"],
            summary=jload(row["summary_json"], {}), error=row["error"], id=row["id"], from_cache=from_cache,
        )


class _ServiceDown(Exception):
    def __init__(self, error: CheburcheckError) -> None:
        super().__init__(str(error))
        self.error = error


class _RateLimited(Exception):
    def __init__(self, delay: float) -> None:
        super().__init__("rate limited")
        self.delay = delay


class CheburcheckService:
    def __init__(self, config: Config, db: Database, settings: Settings,
                 client: CheburcheckClient | None = None) -> None:
        self.config = config
        self.db = db
        self.settings = settings
        self.client = client or CheburcheckClient(config.cheburcheck_base_url, config.cheburcheck_proxy_url)
        self.on_incident_update: Callable[[int], Awaitable[None]] | None = None
        self.on_back_online: Callable[[int, int], Awaitable[None]] | None = None
        self.on_api_changed: Callable[[str], Awaitable[None]] | None = None
        self._io_lock = asyncio.Lock()
        self._wake = asyncio.Event()
        self._changed = asyncio.Condition()
        self._task: asyncio.Task | None = None
        self._next_check = 0.0
        self._next_probe = 0.0
        self._breaker: dict[str, Any] = {
            "streak": 0, "open_until": 0, "step": 0, "down_since": 0, "last_ok_at": 0,
            "last_error": "", "protocol_streak": 0, "api_warned": 0,
        }

    # ── lifecycle ───────────────────────────────────────────────────────────

    async def start(self) -> None:
        saved = jload(self.settings.raw("cc.breaker"), {})
        if isinstance(saved, dict):
            self._breaker.update({key: saved[key] for key in self._breaker if key in saved})
        self._task = asyncio.create_task(self._worker(), name="cheburcheck-queue")

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
            self._task = None
        await self.client.close()

    # ── public state ────────────────────────────────────────────────────────

    @property
    def enabled(self) -> bool:
        return bool(self.settings.get("cheburcheck_enabled"))

    def _day_key(self, now: float | None = None) -> str:
        return "cc.used." + time.strftime("%Y%m%d", time.gmtime((now or time.time()) + 3 * 3600))

    def used_today(self) -> int:
        return self.settings.raw_int(self._day_key())

    async def status(self) -> dict[str, Any]:
        now = int(time.time())
        queue = await self.db.scalar("SELECT COUNT(*) FROM cheburcheck_queue WHERE status='pending'") or 0
        open_until = int(self._breaker["open_until"])
        return {
            "enabled": self.enabled, "available": now >= open_until and self._breaker["streak"] == 0,
            "open_until": open_until if open_until > now else 0, "down_since": int(self._breaker["down_since"]),
            "last_ok_at": int(self._breaker["last_ok_at"]), "last_error": self._breaker["last_error"],
            "used_today": self.used_today(), "limit": int(self.settings.get("cheburcheck_daily_limit")),
            "queue": int(queue),
        }

    @property
    def backing_off(self) -> bool:
        return time.time() < self._breaker["open_until"]

    # ── cache ───────────────────────────────────────────────────────────────

    async def cached(self, target: str) -> CcResult | None:
        """A stored result that is still fresh and complete enough to reuse."""
        ttl = int(self.settings.get("cheburcheck_cache_ttl"))
        if ttl <= 0:
            return None
        row = await self.db.fetchone(
            "SELECT * FROM cheburcheck_results WHERE target=? AND requested_at>=? AND static_status='ok' "
            "AND probe_status IN ('ok','none','rejected') ORDER BY requested_at DESC, id DESC LIMIT 1",
            (target, int(time.time()) - ttl))
        return CcResult.from_row(row, from_cache=True) if row else None

    async def latest(self, target: str) -> CcResult | None:
        row = await self.db.fetchone(
            "SELECT * FROM cheburcheck_results WHERE target=? ORDER BY requested_at DESC, id DESC LIMIT 1", (target,))
        return CcResult.from_row(row) if row else None

    async def get(self, result_id: int) -> CcResult | None:
        row = await self.db.fetchone("SELECT * FROM cheburcheck_results WHERE id=?", (result_id,))
        return CcResult.from_row(row) if row else None

    # ── incident queue ──────────────────────────────────────────────────────

    async def request(self, incident_id: int, server_id: int, targets: list[tuple[str, str]]) -> int:
        """Queue lookups for an incident. Idempotent. Returns the number of queued targets."""
        if not self.enabled or not targets:
            return 0
        now = int(time.time())
        queued = 0
        for target, kind in targets:
            queued += await self.db.insert_ignore(
                "cheburcheck_queue", incident_id=incident_id, server_id=server_id, target=target,
                target_kind=kind, created_at=now, next_attempt_at=now)
        if queued:
            await self.db.update("incidents", {"id": incident_id}, cc_status="pending")
            self._wake.set()
        return queued

    async def pending(self, incident_ids: list[int]) -> int:
        if not incident_ids:
            return 0
        marks = ",".join("?" * len(incident_ids))
        return int(await self.db.scalar(
            f"SELECT COUNT(*) FROM cheburcheck_queue WHERE status='pending' AND incident_id IN ({marks})",
            tuple(incident_ids)) or 0)

    async def wait(self, incident_ids: list[int], timeout: float) -> bool:
        """Wait until every queued lookup of the incidents is finished. True if nothing is pending."""
        deadline = time.monotonic() + max(0.0, timeout)
        while True:
            if await self.pending(incident_ids) == 0:
                return True
            remaining = deadline - time.monotonic()
            if remaining <= 0 or self.backing_off:
                return False
            marks = ",".join("?" * len(incident_ids))
            upcoming = await self.db.scalar(
                f"SELECT MIN(next_attempt_at) FROM cheburcheck_queue WHERE status='pending' "
                f"AND incident_id IN ({marks})", tuple(incident_ids))
            if upcoming and upcoming > time.time() + remaining:
                return False   # the next attempt is scheduled after the deadline: no point in waiting
            async with self._changed:
                try:
                    await asyncio.wait_for(self._changed.wait(), min(remaining, 5.0))
                except asyncio.TimeoutError:
                    pass

    async def incident_results(self, incident_id: int) -> tuple[list[CcResult], list[tuple[str, str]]]:
        """(results obtained so far, targets still pending) for an incident."""
        incident = await self.db.fetchone("SELECT cc_result_ids FROM incidents WHERE id=?", (incident_id,))
        ids = jload(incident["cc_result_ids"], {}) if incident else {}
        results = []
        if isinstance(ids, dict):
            for result_id in ids.values():
                result = await self.get(int(result_id))
                if result is not None:
                    results.append(result)
        rows = await self.db.fetchall(
            "SELECT target, target_kind FROM cheburcheck_queue WHERE incident_id=? AND status='pending' ORDER BY id",
            (incident_id,))
        return results, [(row["target"], row["target_kind"]) for row in rows]

    async def cancel(self, incident_id: int) -> None:
        """Drop lookups that are no longer needed (the incident is over and was never reported)."""
        await self.db.execute(
            "UPDATE cheburcheck_queue SET status='cancelled' WHERE incident_id=? AND status='pending'", (incident_id,))

    # ── manual lookup ───────────────────────────────────────────────────────

    async def lookup_now(self, target: str, kind: str, use_cache: bool = True) -> CcResult:
        """Owner-requested lookup. Never raises: failures are returned as a result."""
        if not self.enabled:
            return CcResult(target, kind, int(time.time()), static_status="disabled")
        if use_cache:
            cached = await self.cached(target)
            if cached is not None:
                return cached
        try:
            result = await self._lookup(target, kind)
        except _RateLimited:
            return CcResult(target, kind, int(time.time()), error="превышен лимит запросов, повторите через минуту")
        except _ServiceDown as exc:
            await self._breaker_fail(exc.error)
            return CcResult(target, kind, int(time.time()), error=str(exc))
        await self._breaker_ok()
        await self._store(result)
        return result

    # ── core lookup ─────────────────────────────────────────────────────────

    async def _count_request(self) -> bool:
        """Account for one HTTP request against the daily budget. False when it is exhausted."""
        key = self._day_key()
        used = self.settings.raw_int(key)
        if used >= int(self.settings.get("cheburcheck_daily_limit")):
            return False
        await self.settings.set_raw(key, used + 1)
        return True

    async def _pace(self, attr: str, interval: float) -> None:
        delay = getattr(self, attr) - time.monotonic()
        if delay > 0:
            await asyncio.sleep(delay)
        setattr(self, attr, time.monotonic() + interval)

    async def _lookup(self, target: str, kind: str) -> CcResult:
        """One static request and, if enabled, one dynamic request. Serialised and paced."""
        async with self._io_lock:
            now = int(time.time())
            result = CcResult(target, kind, now)
            if not await self._count_request():
                result.static_status, result.error = "skipped", "исчерпан суточный лимит запросов к Cheburcheck"
                return result
            await self._pace("_next_check", self.config.cheburcheck_check_interval)
            try:
                raw = await self.client.check(target)
            except CheburcheckError as exc:
                if exc.kind == RATE_LIMITED:
                    self._next_check = time.monotonic() + (exc.retry_after or 30)
                    raise _RateLimited(exc.retry_after or 30) from exc
                if exc.kind == REJECTED:
                    result.static_status, result.error = "rejected", str(exc)
                    return result
                raise _ServiceDown(exc) from exc
            result.static_status = "ok"
            result.summary = {"static": sm.summarize_static(raw)}
            probe_id = raw.get("id")
            if not self.settings.get("cheburcheck_probe"):
                result.probe_status = "skipped"
                return result
            if not isinstance(probe_id, str) or not probe_id:
                result.probe_status, result.error = "none", "сервис не выдал идентификатор для замеров"
                return result
            if not await self._count_request():
                result.probe_status, result.error = "skipped", "исчерпан суточный лимит запросов к Cheburcheck"
                return result
            await self._pace("_next_probe", self.config.cheburcheck_probe_interval)
            try:
                data = await self.client.probe(probe_id)
            except CheburcheckError as exc:
                if exc.kind == RATE_LIMITED:
                    self._next_probe = time.monotonic() + (exc.retry_after or 30)
                if exc.kind == REJECTED:
                    # e.g. a private or reserved address: the service does not measure such targets
                    result.probe_status = "rejected"
                    result.error = "региональные замеры для этой цели сервис не выполняет"
                    return result
                result.probe_status = "unavailable"
                result.error = f"региональные замеры не получены: {exc}"
                if exc.kind == PROTOCOL:
                    await self._note_protocol_error(str(exc))
                return result
            probes = [sm.trim_probe(item) for item in data.results]
            result.summary["probes"] = sm.summarize_probes(probes, data.online, data.done)
            result.summary["probe_list"] = probes
            if not probes:
                result.probe_status = "none"
                result.error = "ни один сканер не ответил"
            elif not data.done or len(probes) < MIN_PROBE_RESPONSES:
                result.probe_status = "partial"
            else:
                result.probe_status = "ok"
            return result

    async def _store(self, result: CcResult) -> int:
        probe_list = result.summary.pop("probe_list", [])
        result.id = await self.db.insert(
            "cheburcheck_results", target=result.target, target_kind=result.kind,
            requested_at=result.requested_at, static_status=result.static_status,
            probe_status=result.probe_status, static_json=jdump(result.static),
            probe_json=jdump(probe_list), summary_json=jdump(result.summary), error=result.error)
        return result.id

    # ── breaker ─────────────────────────────────────────────────────────────

    async def _save_breaker(self) -> None:
        await self.settings.set_raw("cc.breaker", json.dumps(self._breaker))

    async def _note_protocol_error(self, text: str) -> None:
        self._breaker["protocol_streak"] += 1
        if self._breaker["protocol_streak"] >= BREAKER_THRESHOLD and not self._breaker["api_warned"]:
            self._breaker["api_warned"] = 1
            if self.on_api_changed is not None:
                await self.on_api_changed(text)

    async def _breaker_fail(self, error: CheburcheckError) -> None:
        now = int(time.time())
        state = self._breaker
        state["streak"] += 1
        state["last_error"] = str(error)[:120]
        if not state["down_since"]:
            state["down_since"] = now
        if error.kind == PROTOCOL:
            await self._note_protocol_error(str(error))
        if state["streak"] >= BREAKER_THRESHOLD or state["step"] > 0:
            pause = BREAKER_PAUSES[min(state["step"], len(BREAKER_PAUSES) - 1)]
            state["open_until"] = now + pause
            state["step"] += 1
            log.warning("cheburcheck is unavailable (%s); next attempt in %d min", state["last_error"], pause // 60)
        await self._save_breaker()

    async def _breaker_ok(self) -> None:
        state = self._breaker
        was_down = state["step"] > 0
        down_since = int(state["down_since"] or 0)
        changed = bool(state["streak"] or state["step"] or state["down_since"] or state["protocol_streak"])
        state.update(streak=0, open_until=0, step=0, down_since=0, last_error="", protocol_streak=0,
                     api_warned=0, last_ok_at=int(time.time()))
        if changed:
            await self._save_breaker()
        if was_down and self.on_back_online is not None:
            waiting = int(await self.db.scalar(
                "SELECT COUNT(DISTINCT incident_id) FROM cheburcheck_queue WHERE status='pending'") or 0)
            await self.on_back_online(max(0, int(time.time()) - down_since), waiting)

    # ── queue worker ────────────────────────────────────────────────────────

    async def _worker(self) -> None:
        while True:
            try:
                delay = await self._step()
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 - the queue must survive any single failure
                log.exception("cheburcheck queue step failed")
                delay = 30.0
            try:
                await asyncio.wait_for(self._wake.wait(), max(0.05, delay))
            except asyncio.TimeoutError:
                pass
            self._wake.clear()

    async def _notify(self, incident_id: int | None) -> None:
        async with self._changed:
            self._changed.notify_all()
        if incident_id and self.on_incident_update is not None:
            try:
                await self.on_incident_update(incident_id)
            except Exception:  # noqa: BLE001
                log.exception("incident update handler failed")

    async def _finish(self, row: Row, status: str, result_id: int | None) -> None:
        await self.db.update("cheburcheck_queue", {"id": row["id"]}, status=status)
        incident_id = row["incident_id"]
        if incident_id:
            if result_id is not None:
                await self._link(incident_id, row["target"], result_id)
            await self._refresh_incident_status(incident_id)
        await self._notify(incident_id)

    async def _link(self, incident_id: int, target: str, result_id: int) -> None:
        incident = await self.db.fetchone("SELECT cc_result_ids FROM incidents WHERE id=?", (incident_id,))
        if incident is None:
            return
        ids = jload(incident["cc_result_ids"], {})
        if not isinstance(ids, dict):
            ids = {}
        ids[target] = result_id
        await self.db.update("incidents", {"id": incident_id}, cc_result_ids=jdump(ids))

    async def _refresh_incident_status(self, incident_id: int) -> None:
        results, pending = await self.incident_results(incident_id)
        if pending:
            status = "pending"
        elif not results:
            status = "unavailable"
        else:
            kinds = {result.reliability for result in results}
            if kinds <= {sm.FRESH, sm.CACHED, sm.NOT_APPLICABLE}:
                status = "complete"
            elif kinds == {sm.UNAVAILABLE}:
                status = "unavailable"
            else:
                status = "partial"
        await self.db.update("incidents", {"id": incident_id}, cc_status=status)

    async def _step(self) -> float:
        now = int(time.time())
        for row in await self.db.fetchall(
                "SELECT * FROM cheburcheck_queue WHERE status='pending' AND created_at<?", (now - MAX_AGE,)):
            await self._finish(row, "expired", None)
        if not self.enabled:
            for row in await self.db.fetchall("SELECT * FROM cheburcheck_queue WHERE status='pending'"):
                await self._finish(row, "cancelled", None)
            return 60.0
        row = await self.db.fetchone(
            "SELECT * FROM cheburcheck_queue WHERE status='pending' AND next_attempt_at<=? "
            "ORDER BY next_attempt_at, id LIMIT 1", (now,))
        if row is None:
            upcoming = await self.db.scalar(
                "SELECT MIN(next_attempt_at) FROM cheburcheck_queue WHERE status='pending'")
            return float(min(60, max(1, upcoming - now))) if upcoming else 60.0
        if now < self._breaker["open_until"]:
            return float(min(60, max(1, self._breaker["open_until"] - now)))
        await self._process(row)
        return 0.05

    async def _process(self, row: Row) -> None:
        cached = await self.cached(row["target"])
        if cached is not None and cached.id is not None:
            await self._finish(row, "done", cached.id)
            return
        attempts = row["attempts"] + 1
        try:
            result = await self._lookup(row["target"], row["target_kind"])
        except _RateLimited as exc:
            await self.db.update("cheburcheck_queue", {"id": row["id"]},
                                 next_attempt_at=int(time.time() + exc.delay))
            return
        except _ServiceDown as exc:
            await self._breaker_fail(exc.error)
            if attempts >= MAX_ATTEMPTS:
                await self._finish(row, "expired", None)
            else:
                pause = RETRY_PAUSES[min(attempts - 1, len(RETRY_PAUSES) - 1)]
                await self.db.update("cheburcheck_queue", {"id": row["id"]}, attempts=attempts,
                                     next_attempt_at=int(time.time()) + pause)
                if row["incident_id"]:
                    await self.db.update("incidents", {"id": row["incident_id"]}, cc_status="unavailable")
                await self._notify(None)
            return
        await self._breaker_ok()
        result_id = await self._store(result)
        retry_dynamic = result.static_status == "ok" and result.probe_status == "unavailable" and attempts < MAX_ATTEMPTS
        if retry_dynamic:
            # Keep the static part now and come back for the regional measurements later.
            pause = RETRY_PAUSES[min(attempts - 1, len(RETRY_PAUSES) - 1)]
            await self.db.update("cheburcheck_queue", {"id": row["id"]}, attempts=attempts,
                                 next_attempt_at=int(time.time()) + pause)
            if row["incident_id"]:
                await self._link(row["incident_id"], row["target"], result_id)
            await self._notify(None)
            return
        await self._finish(row, "done", result_id)
