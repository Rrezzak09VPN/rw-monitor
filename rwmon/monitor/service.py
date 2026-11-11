"""The monitoring engine: schedule, checks, false-positive guards, state, incidents."""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

from ..checks.e2e import E2EChecker
from ..checks.pipeline import Checker, Target, Timeouts
from ..checks.results import CheckResult
from ..checks.selfhealth import Health, SelfHealth
from ..config import Config
from ..db.database import Database, Row, jdump, jload
from ..settings import Settings
from ..subscription import fetcher as F
from ..subscription.service import ADDRESS_TTL, SubscriptionService, SyncResult
from ..timeutil import fmt_interval
from . import fsm
from .alerts import Alerts

log = logging.getLogger(__name__)

SERVER_SQL = (
    "SELECT s.*, st.state, st.state_since, st.prev_state, st.fail_streak, st.ok_streak, st.partial_streak, "
    "st.partial_notified, st.first_fail_at, st.first_ok_at, st.last_check_at, st.counted_at, st.last_ok_at, st.last_code, "
    "st.last_summary, st.last_latency_ms, st.good_ips_json, st.last_data_probe_at, st.incident_id, "
    "st.next_check_at, st.flapping FROM servers s JOIN server_state st ON st.server_id=s.id "
)
HEARTBEAT_KEY = "runtime.alive"
FROZEN_NOTIFY_AFTER = 60       # the monitor's own problem is reported once it has lasted this long
GUARD_MIN_GAP = 120            # at most one credentials re-check of a subscription per this period
FAR_FUTURE = 4102444800        # 2100-01-01: "until the subscription refreshes successfully"
PANEL_SAID_NO = (F.NO_SERVERS, F.HWID_LIMIT, F.NEEDS_HWID, F.NOT_FOUND, F.BLOCKED)


@dataclass
class RoundSummary:
    kind: str
    started_at: int
    duration: float = 0.0
    checked: int = 0
    ok: int = 0
    failed: int = 0
    unknown: int = 0
    frozen: bool = False
    problem: str = ""
    downs: list[int] = field(default_factory=list)
    recovered: list[int] = field(default_factory=list)
    results: list[tuple[Row, CheckResult, str]] = field(default_factory=list)   # (server, result, state after)


class Monitor:
    def __init__(self, config: Config, db: Database, settings: Settings, subs: SubscriptionService,
                 checker: Checker, health: SelfHealth, e2e: E2EChecker, alerts: Alerts) -> None:
        self.config = config
        self.db = db
        self.settings = settings
        self.subs = subs
        self.checker = checker
        self.health = health
        self.e2e = e2e
        self.alerts = alerts
        self.last_cycle: RoundSummary | None = None
        self.last_health = Health()
        self.next_cycle_at = 0.0
        self.started_at = 0
        self._wake = asyncio.Event()
        self._apply_lock = asyncio.Lock()
        self.manual_lock = asyncio.Lock()     # one owner-requested "check all" at a time
        self._tasks: list[asyncio.Task] = []
        self._frozen_since: int | None = None
        self._frozen_problem = ""
        self._frozen_notified = False
        self._dns_bad_since: int | None = None
        self._dns_notified = False
        self._overruns = 0
        self._was_paused = False
        self._guard_checked: dict[int, float] = {}
        self._guard_last: dict[int, tuple[str, str]] = {}
        self._e2e_warned = False
        self._cycle_running = False
        self.alive_at = time.monotonic()      # progress marker for the systemd watchdog
        self.ready_poll = 10.0                # how often to re-test our own network before the first cycle

    # ── lifecycle ───────────────────────────────────────────────────────────

    async def start(self) -> None:
        now = int(time.time())
        self.started_at = now
        last_alive = self.settings.raw_int(HEARTBEAT_KEY)
        downtime = now - last_alive if last_alive else 0
        if last_alive and downtime > self._stale_after():
            await self._reset_stale_states(now, f"мониторинг не работал {downtime} с")
        await self.e2e.probe_binary()
        counts = await self.state_counts()
        paused, _ = self.settings.pause_state()
        await self.alerts.started({
            "now": now, "last_alive": last_alive, "downtime": downtime, "first_run": not last_alive,
            "servers": sum(counts.values()), "down": counts.get(fsm.DOWN, 0),
            "interval": _fmt_interval(self.settings.get("check_interval")),
            "e2e": self.settings.e2e_enabled and self.e2e.available, "xray": self.e2e.version,
            "e2e_problem": self.e2e.problem if self.settings.e2e_enabled else "выключена в настройках",
            "paused": paused,
        })
        await self._event("started", f"запуск; простой {downtime} с" if last_alive else "первый запуск")
        await self.settings.set_raw(HEARTBEAT_KEY, now)
        self._tasks = [
            asyncio.create_task(self._loop(), name="monitor-loop"),
            asyncio.create_task(self._heartbeat_loop(), name="monitor-heartbeat"),
            asyncio.create_task(self._subscription_loop(), name="subscription-refresh"),
        ]

    async def stop(self) -> None:
        for task in self._tasks:
            task.cancel()
        for task in self._tasks:
            try:
                await task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
        self._tasks = []
        await self.settings.set_raw(HEARTBEAT_KEY, int(time.time()))

    def wake(self) -> None:
        """Re-evaluate the schedule now (settings changed, servers added)."""
        self._wake.set()

    def schedule_cycle_now(self) -> None:
        self.next_cycle_at = 0.0
        self._wake.set()

    # ── helpers ─────────────────────────────────────────────────────────────

    def _stale_after(self) -> int:
        return max(self.config.state_stale_after, 3 * int(self.settings.get("check_interval")))

    def _timeouts(self) -> Timeouts:
        get = self.settings.get
        return Timeouts(dns=float(get("dns_timeout")), tcp=float(get("tcp_timeout")), tls=float(get("tls_timeout")),
                        udp=float(get("quic_timeout")), e2e=float(get("e2e_timeout")))

    async def _event(self, kind: str, text: str, detail: dict[str, Any] | None = None) -> None:
        await self.db.insert("monitor_events", ts=int(time.time()), kind=kind, text=text, detail_json=jdump(detail or {}))

    async def state_counts(self) -> dict[str, int]:
        rows = await self.db.fetchall(
            "SELECT st.state AS state, COUNT(*) AS n FROM servers s JOIN server_state st ON st.server_id=s.id "
            "WHERE s.archived=0 AND s.monitor_enabled=1 GROUP BY st.state")
        return {row["state"]: row["n"] for row in rows}

    async def active_servers(self, now: int | None = None) -> list[Row]:
        now = now or int(time.time())
        await self.db.execute("UPDATE servers SET paused_until=NULL WHERE paused_until IS NOT NULL AND paused_until<=?", (now,))
        return await self.db.fetchall(
            SERVER_SQL + "WHERE s.archived=0 AND s.monitor_enabled=1 AND s.paused_until IS NULL ORDER BY s.id")

    async def get_server(self, server_id: int) -> Row | None:
        return await self.db.fetchone(SERVER_SQL + "WHERE s.id=?", (server_id,))

    async def _reset_stale_states(self, now: int, why: str) -> None:
        """Streaks collected before a long gap say nothing about the present."""
        rows = await self.db.fetchall("SELECT * FROM server_state")
        for row in rows:
            cur = _state_of(row)
            new = fsm.after_downtime(cur, now)
            fields: dict[str, Any] = {"next_check_at": None}
            if new != cur:
                fields.update(_state_fields(new))
                if new.state != cur.state:
                    await self.db.insert("state_events", server_id=row["server_id"], ts=now, from_state=cur.state,
                                         to_state=new.state, code="stale", note=why)
            await self.db.update("server_state", {"server_id": row["server_id"]}, **fields)
        log.info("state streaks were reset: %s", why)

    # ── main loop ───────────────────────────────────────────────────────────

    async def _loop(self) -> None:
        await self._wait_ready()
        while True:
            self.alive_at = time.monotonic()
            try:
                delay = await self._tick()
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 - the scheduler must never die
                log.exception("monitor tick failed")
                await self._event("error", "внутренняя ошибка планировщика (см. журнал)")
                delay = 10.0
            try:
                await asyncio.wait_for(self._wake.wait(), max(0.2, delay))
            except asyncio.TimeoutError:
                pass
            self._wake.clear()

    async def _wait_ready(self) -> None:
        """Do not judge servers until the monitor's own network is known to work."""
        started = int(time.time())
        notified = False
        while True:
            health = await self.health.check(force=True)
            self.last_health = health
            if health.network_ok:
                if notified:
                    await self.alerts.monitor_restored("network", health.problem or self._frozen_problem, started, int(time.time()))
                return
            self._frozen_problem = health.problem
            self.alive_at = time.monotonic()
            if not notified and time.time() - started >= 2 * FROZEN_NOTIFY_AFTER:
                notified = True
                await self.alerts.monitor_problem("network", health.problem, health.details, started)
                await self._event("frozen", health.problem, {"details": health.details})
            await asyncio.sleep(self.ready_poll)

    async def _tick(self) -> float:
        now = time.time()
        paused, _ = self.settings.pause_state(int(now))
        if paused:
            self._was_paused = True
            return 5.0
        if self._was_paused:
            self._was_paused = False
            last = int(await self.db.scalar("SELECT MAX(last_check_at) FROM server_state") or 0)
            if last and now - last > self._stale_after():
                await self._reset_stale_states(int(now), "мониторинг был на паузе")
            self.next_cycle_at = 0.0
        interval = int(self.settings.get("check_interval"))
        if self.next_cycle_at > now + interval:      # the interval was shortened
            self.next_cycle_at = now + interval
        if now >= self.next_cycle_at:
            await self._cycle(interval)
        else:
            due = await self.db.fetchall(
                SERVER_SQL + "WHERE s.archived=0 AND s.monitor_enabled=1 AND s.paused_until IS NULL "
                "AND st.next_check_at IS NOT NULL AND st.next_check_at<=? ORDER BY s.id", (int(now),))
            if due:
                await self._round(due, "recheck")
        now = time.time()
        upcoming = await self.db.scalar(
            "SELECT MIN(st.next_check_at) FROM server_state st JOIN servers s ON s.id=st.server_id "
            "WHERE s.archived=0 AND s.monitor_enabled=1 AND s.paused_until IS NULL AND st.next_check_at IS NOT NULL")
        wake_at = min(self.next_cycle_at, float(upcoming)) if upcoming else self.next_cycle_at
        if self._frozen_since is not None:
            wake_at = min(wake_at, now + 15)       # look for the end of our own outage more often
        return min(30.0, max(0.2, wake_at - now))

    async def _cycle(self, interval: int) -> None:
        started = time.time()
        self.next_cycle_at = started + interval
        servers = await self.active_servers(int(started))
        self._cycle_running = True
        try:
            summary = await self._round(servers, "scheduled")
        finally:
            self._cycle_running = False
        self.last_cycle = summary
        if summary.duration > interval and servers:
            self._overruns += 1
            self.next_cycle_at = time.time()
            if self._overruns == 3:
                await self.alerts.overrun(summary.duration, interval)
                await self._event("overrun", f"цикл {summary.duration:.0f} с при интервале {interval} с")
        else:
            self._overruns = 0
        await self.alerts.check_flapping()

    async def _heartbeat_loop(self) -> None:
        while True:
            await asyncio.sleep(30)
            try:
                await self.settings.set_raw(HEARTBEAT_KEY, int(time.time()))
            except Exception:  # noqa: BLE001
                log.exception("heartbeat write failed")

    # ── health gate ─────────────────────────────────────────────────────────

    async def _freeze(self, health: Health, now: int) -> None:
        if self._frozen_since is None:
            self._frozen_since, self._frozen_problem, self._frozen_notified = now, health.problem, False
            await self._event("frozen", health.problem, {"details": health.details})
            log.warning("monitor frozen: %s (%s)", health.problem, "; ".join(health.details))
        if not self._frozen_notified and now - self._frozen_since >= FROZEN_NOTIFY_AFTER:
            self._frozen_notified = True
            await self.alerts.monitor_problem("network", health.problem, health.details, self._frozen_since)

    async def _unfreeze(self, now: int) -> None:
        if self._frozen_since is None:
            return
        since, self._frozen_since = self._frozen_since, None
        await self._event("unfrozen", f"связь восстановлена через {now - since} с")
        log.info("monitor unfrozen after %d s", now - since)
        if self._frozen_notified:
            await self.alerts.monitor_restored("network", self._frozen_problem, since, now)
        if now - since > self._stale_after():
            await self._reset_stale_states(now, "длительная проблема сети мониторинга")
        self.next_cycle_at = 0.0

    async def _dns_health(self, health: Health, now: int) -> None:
        if not health.dns_ok:
            if self._dns_bad_since is None:
                self._dns_bad_since, self._dns_notified = now, False
            elif not self._dns_notified and now - self._dns_bad_since >= 2 * FROZEN_NOTIFY_AFTER:
                self._dns_notified = True
                await self.alerts.monitor_problem("dns", health.problem, health.details[-1:], self._dns_bad_since)
                await self._event("dns_problem", health.details[-1] if health.details else "")
        elif self._dns_bad_since is not None:
            since, self._dns_bad_since = self._dns_bad_since, None
            if self._dns_notified:
                await self.alerts.monitor_restored("dns", "", since, now)
                await self._event("dns_ok", "")

    @property
    def frozen(self) -> tuple[int | None, str]:
        return self._frozen_since, self._frozen_problem

    # ── checks ──────────────────────────────────────────────────────────────

    async def _target(self, row: Row, now: int, suspended: set[int], links: dict[int, list[int]]) -> Target:
        extra = [item["address"] for item in await self.db.fetchall(
            "SELECT address FROM server_addresses WHERE server_id=? AND address<>? AND last_seen>=?",
            (row["id"], row["address"], now - ADDRESS_TTL))]
        every = int(self.settings.get("e2e_data_probe_every"))
        data_probe = every > 0 and (
            row["state"] != fsm.OK or now - (row["last_data_probe_at"] or 0) >= every)
        subs = links.get(row["id"], [])
        e2e_allowed = not subs or any(sub_id not in suspended for sub_id in subs)
        return Target(
            id=row["id"], name=row["name"], address=row["address"], port=row["port"], l4=row["l4"],
            protocol=row["protocol"], transport=row["transport"], security=row["security"], sni=row["sni"],
            host=row["host"], path=row["path"], params=jload(row["params_json"], {}), extra_addresses=extra,
            cached_ips=jload(row["good_ips_json"], []),
            secret=lambda row=row: self.subs.decrypt_server_secret(row), e2e=e2e_allowed, data_probe=data_probe)

    async def _links(self) -> tuple[dict[int, list[int]], set[int]]:
        links: dict[int, list[int]] = {}
        for row in await self.db.fetchall("SELECT server_id, subscription_id FROM server_subscriptions"):
            links.setdefault(row["server_id"], []).append(row["subscription_id"])
        now = int(time.time())
        suspended = {row["id"] for row in await self.db.fetchall(
            "SELECT id FROM subscriptions WHERE e2e_suspended_until IS NOT NULL AND e2e_suspended_until>?", (now,))}
        return links, suspended

    async def _run_checks(self, servers: list[Row], progress: Callable[[int, int], Awaitable[None]] | None = None,
                          ) -> list[tuple[CheckResult, int]]:
        """Check the servers concurrently. Returns (result, unix time the check finished) per server."""
        now = int(time.time())
        links, suspended = await self._links()
        timeouts = self._timeouts()
        use_e2e = self.settings.e2e_enabled and self.e2e.available
        semaphore = asyncio.Semaphore(int(self.settings.get("check_concurrency")))
        done = 0

        async def one(row: Row) -> tuple[CheckResult, int]:
            nonlocal done
            async with semaphore:
                try:
                    target = await self._target(row, now, suspended, links)
                    result = await self.checker.check(target, timeouts, use_e2e=use_e2e)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:  # noqa: BLE001 - a bug in a check is not a server failure
                    log.exception("check of server %s crashed", row["id"])
                    result = CheckResult(ok=None, code="internal_error")
                    result.notes.append(f"внутренняя ошибка проверки: {exc.__class__.__name__}")
                finished = int(time.time())
            done += 1
            self.alive_at = time.monotonic()
            if progress is not None:
                try:
                    await progress(done, len(servers))
                except Exception:  # noqa: BLE001
                    pass
            return result, finished

        return list(await asyncio.gather(*(one(row) for row in servers)))

    async def _round(self, servers: list[Row], kind: str,
                     progress: Callable[[int, int], Awaitable[None]] | None = None) -> RoundSummary:
        started = time.time()
        now = int(started)
        summary = RoundSummary(kind=kind, started_at=now)
        health = await self.health.check()
        self.last_health = health
        if not health.network_ok:
            await self._freeze(health, now)
            summary.frozen, summary.problem = True, health.problem
            await self._postpone(servers, now)
            summary.duration = time.time() - started
            return summary
        if self.settings.e2e_enabled and not self.e2e.available and not self._e2e_warned:
            self._e2e_warned = True
            await self.alerts.e2e_broken(self.e2e.problem)
        checked = await self._run_checks(servers, progress) if servers else []
        results = [result for result, _ in checked]
        finished_at = [finished for _, finished in checked]
        if any(result.ok is False for result in results):
            # Failures are trusted only if our own network still works after the checks.
            health = await self.health.check(force=True)
            self.last_health = health
            if not health.network_ok:
                await self._freeze(health, int(time.time()))
                summary.frozen, summary.problem = True, health.problem
                await self._postpone(servers, now)
                summary.duration = time.time() - started
                return summary
        await self._unfreeze(now)
        await self._dns_health(health, now)
        if kind in ("scheduled", "manual_all") and results:
            await self._credentials_guard(servers, results, now)

        new_failures = 0
        async with self._apply_lock:
            for row, result, finished in zip(servers, results, finished_at, strict=True):
                fresh = await self.get_server(row["id"]) or row
                if result.ok is False and fresh["state"] in (fsm.OK, fsm.RECOVERED, fsm.UNKNOWN):
                    new_failures += 1
                try:
                    # Timestamps are those of the check itself, so that the pauses between
                    # observations are real even when a round takes long.
                    state, event, incident_id = await self._apply(fresh, result, kind, finished)
                except Exception:  # noqa: BLE001 - one server's storage error must not lose the others
                    log.exception("could not store the check result of server %s", row["id"])
                    continue
                summary.results.append((fresh, result, state))
                summary.checked += 1
                if result.ok:
                    summary.ok += 1
                elif result.ok is False:
                    summary.failed += 1
                else:
                    summary.unknown += 1
                if event == fsm.EV_DOWN and incident_id:
                    summary.downs.append(incident_id)
                elif event == fsm.EV_RECOVERED and incident_id:
                    summary.recovered.append(incident_id)
        if (kind == "scheduled" and new_failures >= self.config.mass_fail_min
                and new_failures * 100 >= self.config.mass_fail_percent * max(1, len(servers))):
            await self._event("mass_failure", f"одновременно отказали {new_failures} из {len(servers)} серверов; "
                              "сеть мониторинга исправна, идёт подтверждение")
        total = len(servers) if kind in ("scheduled", "manual_all") else int(await self.db.scalar(
            "SELECT COUNT(*) FROM servers WHERE archived=0 AND monitor_enabled=1") or 0)
        if summary.downs:
            self.alerts.incidents_down(summary.downs, total)
        if summary.recovered:
            self.alerts.incidents_recovered(summary.recovered)
        summary.duration = time.time() - started
        return summary

    async def _postpone(self, servers: list[Row], now: int) -> None:
        """While frozen, accelerated rechecks keep their turn instead of piling up."""
        for row in servers:
            if row["next_check_at"] is not None:
                await self.db.update("server_state", {"server_id": row["id"]}, next_check_at=now + 15)

    # ── credentials guard ───────────────────────────────────────────────────

    async def _credentials_guard(self, servers: list[Row], results: list[CheckResult], now: int) -> None:
        """Tunnel failures on every server of a subscription point at the subscription, not the servers."""
        links, _ = await self._links()
        by_sub: dict[int, list[int]] = {}
        for index, row in enumerate(servers):
            for sub_id in links.get(row["id"], []):
                by_sub.setdefault(sub_id, []).append(index)
        for sub_id, indexes in by_sub.items():
            ran = [i for i in indexes if results[i].e2e_ran]
            if not ran or any(results[i].ok for i in ran):
                continue
            tunnel_only = [i for i in ran if results[i].ok is False and results[i].stage == "e2e"]
            if not tunnel_only:
                continue
            if time.monotonic() - self._guard_checked.get(sub_id, -1e9) < GUARD_MIN_GAP:
                verdict, reason = self._guard_last.get(sub_id, ("unknown", "подписка проверялась только что"))
            else:
                self._guard_checked[sub_id] = time.monotonic()
                verdict, reason = await self._verify_subscription(sub_id)
                self._guard_last[sub_id] = (verdict, reason)
            if verdict == "valid":
                continue
            for i in tunnel_only:
                result = results[i]
                if verdict == "invalid":
                    result.ok, result.code, result.stage = True, "ok", ""
                    result.notes.append("сквозная проверка приостановлена: подписка не активна")
                else:
                    result.ok, result.code, result.stage = None, "e2e_unverified", "e2e"
                    result.notes.append(
                        "туннель не работает на всех серверах подписки, а проверить саму подписку не удалось: " + reason)
            if verdict == "invalid":
                sub = await self.subs.get(sub_id)
                if sub is not None and not (sub["e2e_suspended_until"] or 0) > now:
                    await self.db.update("subscriptions", {"id": sub_id}, e2e_suspended_until=FAR_FUTURE)
                    await self.alerts.credentials_suspended(sub, reason, len(tunnel_only))
                    await self._event("credentials", f"подписка {sub['url_hint']}: сквозная проверка приостановлена ({reason})")

    async def _verify_subscription(self, sub_id: int) -> tuple[str, str]:
        """Ask the panel whether the subscription is still served. → (valid|invalid|unknown, reason)."""
        try:
            result = await self.subs.refresh(sub_id)
        except Exception as exc:  # noqa: BLE001
            log.warning("subscription re-check failed: %s", exc.__class__.__name__)
            return "unknown", "ошибка при запросе подписки"
        await self.subscription_refreshed(sub_id, result, interactive=False)
        if result.ok:
            return "valid", ""
        if result.status in PANEL_SAID_NO:
            return "invalid", result.message or "панель не выдаёт серверы"
        return "unknown", result.message or "панель недоступна"

    # ── applying a result ───────────────────────────────────────────────────

    async def _apply(self, row: Row, result: CheckResult, kind: str, now: int) -> tuple[str, str, int | None]:
        """Store one check and advance the state machine. → (state, event, incident id)."""
        cur = _state_of(row)
        # Verdicts feed the state machine only when they are spaced in time: N failures within a
        # few seconds (manual checks, a recheck right before a cycle) are one observation, not N.
        first_gap = self.settings.recheck_intervals[0]
        gap = first_gap if kind in ("manual", "manual_all") else max(5, first_gap // 2)
        counted = not row["counted_at"] or now - row["counted_at"] >= gap
        if not row["monitor_enabled"] or row["archived"] or row["paused_until"]:
            counted = False
        transition = fsm.advance(
            cur, result.ok if counted else None, now, int(self.settings.get("fail_threshold")),
            int(self.settings.get("recovery_threshold")), int(self.settings.get("recovered_hold")))
        new = transition.data
        incident_id: int | None = row["incident_id"]
        detail = result.detail()
        summary_text = result.summary
        store_detail = result.ok is not True or result.partial or transition.changed or bool(result.notes)

        async with self.db.tx():
            await self.db.insert(
                "checks", server_id=row["id"], ts=now, kind=kind, ok=None if result.ok is None else int(result.ok),
                code=result.code, stage=result.stage, latency_ms=result.latency_ms,
                detail_json=jdump(detail) if store_detail else None)
            fields: dict[str, Any] = {
                "last_check_at": now, "last_code": result.code, "last_summary": summary_text,
                "last_detail_json": jdump(detail), "last_latency_ms": result.latency_ms,
            }
            if result.ok:
                fields["last_ok_at"] = now
            if result.good_ips:
                fields["good_ips_json"] = jdump(result.good_ips)
            if result.data_probe:
                fields["last_data_probe_at"] = now
            if not counted and kind == "recheck":
                fields["next_check_at"] = (row["counted_at"] or now) + gap
            if counted:
                fields["counted_at"] = now
                fields.update(_state_fields(new))
                mode = fsm.fast_recheck(new)
                if mode == "suspect":
                    fields["next_check_at"] = now + self.settings.recheck_delay(new.fail_streak)
                elif mode == "recovering":
                    fields["next_check_at"] = now + int(self.settings.get("recovery_recheck_interval"))
                else:
                    fields["next_check_at"] = None
            if transition.event == fsm.EV_DOWN:
                detail_inc = dict(detail, fails=new.fail_streak, stage=result.stage)
                incident_id = await self.db.insert(
                    "incidents", server_id=row["id"], started_at=new.first_fail_at or now, confirmed_at=now,
                    code=result.code, summary=summary_text, detail_json=jdump(detail_inc))
                fields["incident_id"] = incident_id
            elif transition.event == fsm.EV_RECOVERED and incident_id:
                incident = await self.db.fetchone("SELECT detail_json FROM incidents WHERE id=?", (incident_id,))
                detail_inc = jload(incident["detail_json"], {}) if incident else {}
                detail_inc["oks"] = new.ok_streak
                await self.db.update("incidents", {"id": incident_id}, resolved_at=new.first_ok_at or now,
                                     recovered_at=now, detail_json=jdump(detail_inc))
                fields["incident_id"] = None
            if new.state != cur.state:
                await self.db.insert(
                    "state_events", server_id=row["id"], ts=now, from_state=cur.state, to_state=new.state,
                    code=result.code, note=summary_text[:300], incident_id=incident_id)
            partial_event = self._partial(row, result, counted, fields)
            await self.db.update("server_state", {"server_id": row["id"]}, **fields)

        if partial_event == "partial":
            await self.alerts.partial(row, result.partial_note, int(self.settings.get("fail_threshold")))
        elif partial_event == "cleared":
            await self.alerts.partial_cleared(row)
        if transition.changed:
            log.info("server %s (%s): %s → %s (%s)", row["id"], row["name"], cur.state, new.state, result.code)
        returned = incident_id if transition.event in (fsm.EV_DOWN, fsm.EV_RECOVERED) else None
        return new.state, transition.event, returned

    def _partial(self, row: Row, result: CheckResult, counted: bool, fields: dict[str, Any]) -> str:
        """Track "works, but some of its addresses do not". Confirmed like any other problem."""
        if not counted or result.ok is None:
            return ""
        streak, notified = row["partial_streak"], row["partial_notified"]
        if result.ok and result.partial:
            streak = streak + 1 if streak >= 0 else 1
            fields["partial_streak"] = streak
            if not notified and streak >= int(self.settings.get("fail_threshold")):
                fields["partial_notified"] = 1
                return "partial"
            return ""
        if result.ok and notified:
            streak = streak - 1 if streak <= 0 else -1
            fields["partial_streak"] = streak
            if -streak >= int(self.settings.get("recovery_threshold")):
                fields["partial_streak"], fields["partial_notified"] = 0, 0
                return "cleared"
            return ""
        if streak:
            fields["partial_streak"] = 0
        if notified and not result.ok:
            fields["partial_notified"] = 0
        return ""

    # ── manual checks ───────────────────────────────────────────────────────

    async def check_now(self, server_id: int) -> tuple[Row, CheckResult, str] | None:
        """Out-of-turn check of one server. Does not disturb the schedule."""
        row = await self.get_server(server_id)
        if row is None:
            return None
        summary = await self._round([row], "manual")
        if summary.frozen or not summary.results:
            result = CheckResult(ok=None, code="monitor_frozen")
            result.notes.append(summary.problem or "проверка не выполнена")
            return row, result, row["state"]
        return summary.results[0]

    async def check_all(self, progress: Callable[[int, int], Awaitable[None]] | None = None) -> RoundSummary:
        servers = await self.active_servers()
        return await self._round(servers, "manual_all", progress)

    # ── exclusions ──────────────────────────────────────────────────────────

    async def _stop_watching(self, server_id: int, now: int, why: str) -> None:
        """A server that is no longer checked has no state; an open incident ends without a notification."""
        row = await self.get_server(server_id)
        if row is None:
            return
        async with self.db.tx():
            await self.db.execute(
                "UPDATE incidents SET recovered_at=?, close_reason='excluded' "
                "WHERE server_id=? AND recovered_at IS NULL AND close_reason=''", (now, server_id))
            if row["state"] != fsm.UNKNOWN:
                await self.db.insert("state_events", server_id=server_id, ts=now, from_state=row["state"],
                                     to_state=fsm.UNKNOWN, code="excluded", note=why)
            await self.db.update(
                "server_state", {"server_id": server_id}, state=fsm.UNKNOWN, prev_state=row["state"],
                state_since=now, fail_streak=0, ok_streak=0, first_fail_at=None, first_ok_at=None,
                incident_id=None, next_check_at=None, partial_streak=0, partial_notified=0, flapping=0)

    async def exclude_server(self, server_id: int) -> None:
        now = int(time.time())
        await self.db.update("servers", {"id": server_id}, monitor_enabled=0, paused_until=None, updated_at=now)
        await self._stop_watching(server_id, now, "сервер исключён из мониторинга")
        await self._event("exclusion", await self._server_label(server_id) + ": исключён из мониторинга")

    async def pause_server(self, server_id: int, seconds: int) -> int:
        now = int(time.time())
        until = now + seconds
        await self.db.update("servers", {"id": server_id}, monitor_enabled=1, paused_until=until, updated_at=now)
        await self._stop_watching(server_id, now, "мониторинг сервера приостановлен")
        await self._event("exclusion", await self._server_label(server_id) + f": пауза на {seconds} с")
        return until

    async def resume_server(self, server_id: int) -> None:
        now = int(time.time())
        await self.db.update("servers", {"id": server_id}, monitor_enabled=1, paused_until=None, updated_at=now)
        await self.db.update("server_state", {"server_id": server_id}, next_check_at=now)
        await self._event("exclusion", await self._server_label(server_id) + ": мониторинг возобновлён")
        self.wake()

    async def mute_server(self, server_id: int, muted: bool) -> None:
        await self.db.update("servers", {"id": server_id}, notify_muted=int(muted), updated_at=int(time.time()))
        await self._event("exclusion", await self._server_label(server_id)
                          + (": уведомления отключены" if muted else ": уведомления включены"))

    async def _server_label(self, server_id: int) -> str:
        return str(await self.db.scalar("SELECT name FROM servers WHERE id=?", (server_id,)) or f"сервер {server_id}")

    async def note(self, kind: str, text: str) -> None:
        """Record an owner action in the event history."""
        await self._event(kind, text)

    # ── subscriptions ───────────────────────────────────────────────────────

    async def subscription_refreshed(self, sub_id: int, result: SyncResult, interactive: bool) -> None:
        """Common follow-up after any subscription refresh."""
        sub = await self.subs.get(sub_id)
        if sub is None:
            return
        if result.ok and (sub["e2e_suspended_until"] or 0) > time.time():
            await self.db.update("subscriptions", {"id": sub_id}, e2e_suspended_until=None)
            await self.alerts.credentials_resumed(sub)
            await self._event("credentials", f"подписка {sub['url_hint']}: сквозная проверка возобновлена")
        if result.ok and result.changed:
            await self._event("subscription", f"подписка {sub['url_hint']}: +{len(result.added) + len(result.restored)} "
                              f"−{len(result.archived)} серверов")
            self.schedule_cycle_now()
        if interactive:
            if result.ok:
                await self.alerts.subscription_expiry(sub, result.expire_at)
            return
        servers = int(await self.db.scalar(
            "SELECT COUNT(*) FROM server_subscriptions ss JOIN servers s ON s.id=ss.server_id "
            "WHERE ss.subscription_id=? AND s.archived=0", (sub_id,)) or 0)
        if await self.alerts.subscription_result(sub, result, servers):
            await self.subs.mark_error_notified(sub_id)
            await self._event("subscription", f"подписка {sub['url_hint']}: ошибка обновления — {result.message}")

    async def _subscription_loop(self) -> None:
        await asyncio.sleep(20)
        while True:
            try:
                interval = int(self.settings.get("subscription_refresh_interval"))
                paused, _ = self.settings.pause_state()
                if interval > 0 and not paused and self._frozen_since is None:
                    now = int(time.time())
                    for sub in await self.subs.list():
                        if not sub["auto_refresh"]:
                            continue
                        if now - (sub["last_fetch_at"] or 0) < interval:
                            continue
                        result = await self.subs.refresh(sub["id"])
                        await self.subscription_refreshed(sub["id"], result, interactive=False)
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                log.exception("subscription auto-refresh failed")
            await asyncio.sleep(60)

    # ── status ──────────────────────────────────────────────────────────────

    async def snapshot(self) -> dict[str, Any]:
        counts = await self.state_counts()
        paused, until = self.settings.pause_state()
        excluded = await self.db.fetchone(
            "SELECT SUM(monitor_enabled=0) AS off, SUM(monitor_enabled=1 AND paused_until IS NOT NULL) AS paused, "
            "SUM(notify_muted=1) AS muted FROM servers WHERE archived=0") or {}
        open_incidents = int(await self.db.scalar(
            "SELECT COUNT(*) FROM incidents WHERE recovered_at IS NULL AND close_reason=''") or 0)
        return {
            "counts": counts, "paused": paused, "paused_until": until, "frozen_since": self._frozen_since,
            "frozen_problem": self._frozen_problem, "health": self.last_health, "last_cycle": self.last_cycle,
            "next_cycle_at": self.next_cycle_at, "cycle_running": self._cycle_running,
            "excluded": int(excluded.get("off") or 0), "server_paused": int(excluded.get("paused") or 0),
            "muted": int(excluded.get("muted") or 0), "open_incidents": open_incidents,
            "e2e": self.settings.e2e_enabled and self.e2e.available, "e2e_problem": self.e2e.problem,
            "xray": self.e2e.version, "started_at": self.started_at,
        }


def _state_of(row: Row) -> fsm.StateData:
    return fsm.StateData(
        state=row["state"], prev_state=row["prev_state"], state_since=row["state_since"],
        fail_streak=row["fail_streak"], ok_streak=row["ok_streak"], first_fail_at=row["first_fail_at"],
        first_ok_at=row["first_ok_at"])


def _state_fields(data: fsm.StateData) -> dict[str, Any]:
    return {
        "state": data.state, "prev_state": data.prev_state, "state_since": data.state_since,
        "fail_streak": data.fail_streak, "ok_streak": data.ok_streak, "first_fail_at": data.first_fail_at,
        "first_ok_at": data.first_ok_at,
    }


def _fmt_interval(seconds: int) -> str:
    return fmt_interval(seconds)

