"""Turns monitoring events into owner notifications.

One incident produces exactly one DOWN message and, later, one RECOVERED
message. Messages are batched (several configurations of one server, mass
failures), suppressed for muted and flapping servers, and enriched with
Cheburcheck data without ever depending on it.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import time
from typing import Any

from ..cheburcheck import summary as sm
from ..cheburcheck.service import CcResult, CheburcheckService
from ..checks.results import reason_text
from ..config import Config, split_csv
from ..db.database import Database, Row, jload
from ..outbox import Outbox
from ..settings import Settings
from ..subscription.model import describe_kind, is_ip
from ..telegram import texts

log = logging.getLogger(__name__)

DIGEST_CC_TARGETS = 10      # Cheburcheck lookups per mass failure, to stay within its limits
EXPIRY_WARNING = 3 * 86400


def server_button(server_id: int) -> list[list[dict[str, str]]]:
    return [[{"text": "🖥 Открыть сервер", "callback_data": f"srv:{server_id}"}]]


def _public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


class Alerts:
    def __init__(self, config: Config, db: Database, settings: Settings, outbox: Outbox,
                 cc: CheburcheckService) -> None:
        self.config = config
        self.db = db
        self.settings = settings
        self.outbox = outbox
        self.cc = cc
        self._jobs: asyncio.Queue[tuple[str, list[int], int]] = asyncio.Queue()
        self._task: asyncio.Task | None = None
        cc.on_incident_update = self._on_cc_update
        cc.on_back_online = self._on_cc_back
        cc.on_api_changed = self._on_cc_api_changed

    # ── lifecycle ───────────────────────────────────────────────────────────

    async def start(self) -> None:
        """Start the worker and pick up incidents whose notifications were interrupted by a restart."""
        rows = await self.db.fetchall(
            "SELECT id FROM incidents WHERE down_notif_id IS NULL AND close_reason='' ORDER BY id")
        if rows:
            self.incidents_down([row["id"] for row in rows], 0, wait=False)
        rows = await self.db.fetchall(
            "SELECT id FROM incidents WHERE recovered_at IS NOT NULL AND up_notif_id IS NULL "
            "AND close_reason='' ORDER BY id")
        if rows:
            self.incidents_recovered([row["id"] for row in rows])
        self._task = asyncio.create_task(self._worker(), name="alerts")

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
            self._task = None

    async def drain(self) -> None:
        """Wait until every queued job has been processed (used by tests)."""
        await self._jobs.join()

    def incidents_down(self, incident_ids: list[int], total_servers: int, wait: bool = True) -> None:
        self._jobs.put_nowait(("down" if wait else "down_nowait", list(incident_ids), total_servers))

    def incidents_recovered(self, incident_ids: list[int]) -> None:
        self._jobs.put_nowait(("up", list(incident_ids), 0))

    async def _worker(self) -> None:
        while True:
            kind, ids, total = await self._jobs.get()
            try:
                if kind in ("down", "down_nowait"):
                    await self._job_down(ids, total, wait=kind == "down")
                else:
                    await self._job_up(ids)
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 - one broken notification must not stop the rest
                log.exception("alert job %s failed", kind)
            finally:
                self._jobs.task_done()

    # ── views ───────────────────────────────────────────────────────────────

    async def _incident_rows(self, incident_ids: list[int]) -> list[Row]:
        if not incident_ids:
            return []
        marks = ",".join("?" * len(incident_ids))
        return await self.db.fetchall(
            "SELECT i.*, s.name, s.aliases_json, s.address, s.port, s.protocol, s.transport, s.security, "
            "s.sni, s.node_key, s.notify_muted, s.archived, st.flapping "
            "FROM incidents i JOIN servers s ON s.id=i.server_id "
            "LEFT JOIN server_state st ON st.server_id=s.id "
            f"WHERE i.id IN ({marks}) ORDER BY i.id", tuple(incident_ids))

    @staticmethod
    def _view(row: Row) -> dict[str, Any]:
        detail = jload(row["detail_json"], {})
        address = row["address"]
        host = f"[{address}]" if ":" in address else address
        return {
            "id": row["id"], "server_id": row["server_id"], "name": row["name"],
            "aliases": jload(row["aliases_json"], []), "address": address, "address_is_ip": is_ip(address),
            "port": row["port"], "endpoint": f"{host}:{row['port']}", "sni": row["sni"],
            "kind": describe_kind(row["protocol"], row["transport"], row["security"]),
            "ips": detail.get("ips") or [], "started_at": row["started_at"], "confirmed_at": row["confirmed_at"],
            "resolved_at": row["resolved_at"] or row["recovered_at"] or row["confirmed_at"],
            "recovered_at": row["recovered_at"], "fails": int(detail.get("fails") or 0),
            "oks": int(detail.get("oks") or 0), "code": row["code"], "stage": detail.get("stage") or "",
            "reason": row["summary"] or reason_text(row["code"]), "reason_short": reason_text(row["code"]),
            "assessment": row["assessment"], "node_key": row["node_key"],
        }

    def _cc_targets(self, view: dict[str, Any]) -> list[tuple[str, str]]:
        wanted = split_csv(self.config.cheburcheck_targets)
        targets: list[tuple[str, str]] = []
        if "ip" in wanted:
            ips = [view["address"]] if view["address_is_ip"] else view["ips"]
            targets += [(ip, "ip") for ip in ips[:2] if _public_ip(ip)]
        if "domain" in wanted and not view["address_is_ip"]:
            targets.append((view["address"], "domain"))
        if ("sni" in wanted and view["sni"] and view["sni"] != view["address"]
                and not is_ip(view["sni"]) and view["code"].startswith("tls_")):
            targets.append((view["sni"], "sni"))
        return targets

    # ── DOWN ────────────────────────────────────────────────────────────────

    async def _job_down(self, incident_ids: list[int], total_servers: int, wait: bool) -> None:
        now = int(time.time())
        active: list[Row] = []
        for row in await self._incident_rows(incident_ids):
            if row["down_notif_id"] is not None:
                continue
            if row["notify_muted"] or row["archived"] or row["flapping"]:
                await self.db.update("incidents", {"id": row["id"]}, down_notif_id=0)
                continue
            recent = int(await self.db.scalar(
                "SELECT COUNT(*) FROM incidents WHERE server_id=? AND confirmed_at>=?",
                (row["server_id"], now - self.config.flap_window)) or 0)
            if recent >= self.config.flap_max_incidents:
                await self.db.update("server_state", {"server_id": row["server_id"]}, flapping=1)
                await self.db.update("incidents", {"id": row["id"]}, down_notif_id=0)
                await self.outbox.add(
                    "flapping", texts.flapping_text(self._view(row), recent, self.config.flap_window),
                    dedup_key=f"flap:{row['id']}", server_id=row["server_id"], incident_id=row["id"],
                    markup=server_button(row["server_id"]))
                continue
            active.append(row)
        if not active:
            return

        digest = len(active) >= self.config.mass_fail_min
        if digest:
            groups = [("d", active)]
        else:
            by_node: dict[str, list[Row]] = {}
            for row in active:
                by_node.setdefault(row["node_key"], []).append(row)
            groups = [("n" if len(rows) > 1 else "s", rows) for rows in by_node.values()]

        for layout, rows in groups:
            key = f"{layout}:{rows[0]['id']}"
            ids = [row["id"] for row in rows]
            marks = ",".join("?" * len(ids))
            await self.db.execute(f"UPDATE incidents SET group_key=? WHERE id IN ({marks})", (key, *ids))
            await self._request_cc(rows, digest)
            if wait and not digest and self.cc.enabled:
                await self.cc.wait(ids, float(self.settings.get("cheburcheck_wait")))
            text = await self._compose_down(key, total_servers)
            markup = server_button(rows[0]["server_id"]) if layout != "d" else None
            notif_id = await self.outbox.add(
                "down", text, dedup_key=f"down:{key}", server_id=rows[0]["server_id"] if layout != "d" else None,
                incident_id=rows[0]["id"], markup=markup)
            if notif_id is None:
                notif_id = await self.db.scalar("SELECT id FROM notifications WHERE dedup_key=?", (f"down:{key}",))
            await self.db.execute(
                f"UPDATE incidents SET down_notif_id=? WHERE id IN ({marks})", (notif_id, *ids))

    async def _request_cc(self, rows: list[Row], digest: bool) -> None:
        if not self.cc.enabled:
            return
        seen: set[str] = set()
        budget = DIGEST_CC_TARGETS if digest else 1000
        ordered = sorted(
            ((row, target, kind) for row in rows for target, kind in self._cc_targets(self._view(row))),
            key=lambda item: {"ip": 0, "domain": 1, "sni": 2}[item[2]])
        per_incident: dict[int, list[tuple[str, str]]] = {}
        for row, target, kind in ordered:
            if target in seen:
                continue
            if budget <= 0:
                break
            seen.add(target)
            budget -= 1
            per_incident.setdefault(row["id"], []).append((target, kind))
        for row in rows:
            targets = per_incident.get(row["id"])
            if targets:
                await self.cc.request(row["id"], row["server_id"], targets)

    async def _group(self, key: str) -> list[Row]:
        ids = [row["id"] for row in await self.db.fetchall("SELECT id FROM incidents WHERE group_key=?", (key,))]
        return await self._incident_rows(ids)

    async def _compose_down(self, key: str, total_servers: int = 0) -> str:
        rows = await self._group(key)
        views = [self._view(row) for row in rows]
        results: list[CcResult] = []
        pending: list[tuple[str, str]] = []
        for view in views:
            found, waiting = await self.cc.incident_results(view["id"])
            by_kind: dict[str, dict[str, Any] | None] = {}
            for result in found:
                if result.static_status == "ok":
                    by_kind.setdefault(result.kind, result.summary)
            view["assessment"] = sm.assess(view["code"], view["stage"], by_kind)
            await self.db.update("incidents", {"id": view["id"]}, assessment=view["assessment"])
            results += [item for item in found if item.target not in {r.target for r in results}]
            pending += [item for item in waiting if item not in pending]
        layout = key.split(":", 1)[0]
        none_reason = ""
        if not results and not pending:
            asked = int(await self.db.scalar(
                f"SELECT COUNT(*) FROM cheburcheck_queue WHERE incident_id IN ({','.join('?' * len(views))})",
                tuple(view["id"] for view in views)) or 0)
            none_reason = "" if asked else "⛔ неприменимо: у сервера нет публичного адреса"
        cc_lines = texts.cc_block(results, pending, self.cc.enabled, self.cc.backing_off, compact=layout == "d",
                                  reference_ts=min(view["confirmed_at"] for view in views), none_reason=none_reason)
        if layout == "d":
            total = total_servers or int(await self.db.scalar(
                "SELECT COUNT(*) FROM servers WHERE archived=0 AND monitor_enabled=1") or len(views))
            return texts.down_digest_text(views, max(total, len(views)), cc_lines)
        if layout == "n":
            return texts.down_node_text(views, cc_lines)
        return texts.down_text(views[0], cc_lines)

    # ── Cheburcheck callbacks ───────────────────────────────────────────────

    async def _on_cc_update(self, incident_id: int) -> None:
        incident = await self.db.fetchone(
            "SELECT id, group_key, down_notif_id FROM incidents WHERE id=?", (incident_id,))
        if incident is None or not incident["down_notif_id"] or not incident["group_key"]:
            return
        key = incident["group_key"]
        rows = await self._group(key)
        ids = [row["id"] for row in rows]
        if await self.cc.pending(ids):
            return
        text = await self._compose_down(key)
        await self.outbox.add("down_edit", text, edit_of=incident["down_notif_id"], incident_id=incident_id)
        statuses = {row["cc_status"] for row in await self._group(key)}
        status = "unavailable" if statuses == {"unavailable"} else "complete"
        assessments = list(dict.fromkeys(row["assessment"] for row in await self._group(key) if row["assessment"]))
        await self.outbox.add(
            "cc_followup",
            texts.cc_followup_text([row["name"] for row in rows], status, assessments[0] if len(assessments) == 1 else ""),
            dedup_key=f"ccfu:{key}", incident_id=incident_id, reply_to=incident["down_notif_id"], silent=True)

    async def _on_cc_back(self, downtime: int, waiting: int) -> None:
        if downtime >= 600 and waiting:
            await self.outbox.add("cc_back", texts.cc_back_text(downtime, waiting),
                                  dedup_key=f"ccback:{int(time.time()) // 600}", silent=True)

    async def _on_cc_api_changed(self, detail: str) -> None:
        await self.outbox.add("cc_api", texts.cc_api_changed_text(detail),
                              dedup_key=f"ccapi:{time.strftime('%Y%m%d')}")

    # ── RECOVERED ───────────────────────────────────────────────────────────

    async def _job_up(self, incident_ids: list[int]) -> None:
        rows = await self._incident_rows(incident_ids)
        unhandled = [row["id"] for row in rows if row["down_notif_id"] is None]
        if unhandled:
            await self._job_down(unhandled, 0, wait=False)
            rows = await self._incident_rows(incident_ids)
        active = []
        for row in rows:
            if row["up_notif_id"] is not None or row["recovered_at"] is None:
                continue
            if not row["down_notif_id"]:
                await self.cc.cancel(row["id"])       # nobody is waiting for these lookups any more
            # Silent while the owner muted the server or it is flapping. A recovery is reported even if
            # the DOWN itself was not (muted or unstable back then): by now the owner wants to know.
            if row["notify_muted"] or row["flapping"] or row["archived"]:
                await self.db.update("incidents", {"id": row["id"]}, up_notif_id=0)
                continue
            active.append(row)
        if not active:
            return
        if len(active) >= self.config.mass_fail_min:
            views = [self._view(row) for row in active]
            notif_id = await self.outbox.add(
                "recovered", texts.recovered_digest_text(views), dedup_key=f"up:d:{active[0]['id']}",
                incident_id=active[0]["id"])
            ids = [row["id"] for row in active]
            marks = ",".join("?" * len(ids))
            await self.db.execute(f"UPDATE incidents SET up_notif_id=? WHERE id IN ({marks})", (notif_id or 0, *ids))
            return
        # Configurations of one server that were reported down together are reported back together.
        groups: dict[str, list[Row]] = {}
        for row in active:
            key = row["group_key"] if row["group_key"].startswith("n:") else f"s:{row['id']}"
            groups.setdefault(key, []).append(row)
        for rows in groups.values():
            views = [self._view(row) for row in rows]
            text = texts.recovered_node_text(views) if len(rows) > 1 else texts.recovered_text(views[0])
            notif_id = await self.outbox.add(
                "recovered", text, dedup_key=f"up:{rows[0]['id']}", server_id=rows[0]["server_id"],
                incident_id=rows[0]["id"], reply_to=rows[0]["down_notif_id"] or None,
                markup=server_button(rows[0]["server_id"]))
            for row in rows:
                await self.db.update("incidents", {"id": row["id"]}, up_notif_id=notif_id or 0)

    # ── flapping ────────────────────────────────────────────────────────────

    async def check_flapping(self) -> None:
        """Re-enable notifications for servers that stayed in one state for the whole window."""
        now = int(time.time())
        window = self.config.flap_window
        rows = await self.db.fetchall(
            "SELECT s.id, s.name, s.address, s.port, st.state, st.state_since FROM servers s "
            "JOIN server_state st ON st.server_id=s.id WHERE st.flapping=1")
        for row in rows:
            last_change = int(await self.db.scalar(
                "SELECT MAX(MAX(confirmed_at), COALESCE(MAX(recovered_at), 0)) FROM incidents WHERE server_id=?",
                (row["id"],)) or 0)
            if now - last_change < window:
                continue
            await self.db.update("server_state", {"server_id": row["id"]}, flapping=0)
            host = f"[{row['address']}]" if ":" in row["address"] else row["address"]
            state = "DOWN" if row["state"] == "DOWN" else "OK"
            await self.outbox.add(
                "stable", texts.stable_text(row["name"], f"{host}:{row['port']}", state, row["state_since"], window),
                dedup_key=f"stable:{row['id']}:{last_change}", server_id=row["id"], markup=server_button(row["id"]))

    # ── partial availability ────────────────────────────────────────────────

    async def partial(self, server: Row, note: str, count: int) -> None:
        if server["notify_muted"]:
            return
        host = f"[{server['address']}]" if ":" in server["address"] else server["address"]
        await self.outbox.add("partial", texts.partial_text(server["name"], f"{host}:{server['port']}", note, count),
                              server_id=server["id"], markup=server_button(server["id"]))

    async def partial_cleared(self, server: Row) -> None:
        if server["notify_muted"]:
            return
        host = f"[{server['address']}]" if ":" in server["address"] else server["address"]
        await self.outbox.add("partial_ok", texts.partial_cleared_text(server["name"], f"{host}:{server['port']}"),
                              server_id=server["id"], silent=True)

    # ── monitor's own events ────────────────────────────────────────────────

    async def started(self, info: dict[str, Any]) -> None:
        await self.outbox.add("started", texts.started_text(info), silent=True)

    async def monitor_problem(self, kind: str, problem: str, details: list[str], since: int) -> None:
        text = (texts.dns_problem_text("; ".join(details), since) if kind == "dns"
                else texts.monitor_problem_text(problem, details, since))
        await self.outbox.add("monitor_problem", text, dedup_key=f"monprob:{kind}:{since}")

    async def monitor_restored(self, kind: str, problem: str, since: int, until: int) -> None:
        text = (texts.dns_restored_text(since, until) if kind == "dns"
                else texts.monitor_restored_text(problem, since, until))
        await self.outbox.add("monitor_restored", text, dedup_key=f"monrest:{kind}:{since}")

    async def overrun(self, duration: float, interval: int) -> None:
        await self.outbox.add("overrun", texts.overrun_text(duration, interval),
                              dedup_key=f"overrun:{time.strftime('%Y%m%d%H')}")

    async def e2e_broken(self, problem: str) -> None:
        await self.outbox.add("e2e_broken", texts.e2e_broken_text(problem),
                              dedup_key=f"e2e:{time.strftime('%Y%m%d')}")

    # ── subscriptions ───────────────────────────────────────────────────────

    async def subscription_result(self, sub: Row, result: Any, servers: int) -> bool:
        """Report the outcome of an automatic refresh. Returns True if an error was reported."""
        hint, title = sub["url_hint"], sub["title"]
        if result.ok:
            if result.recovered:
                await self.outbox.add("sub_ok", texts.subscription_ok_again_text(hint, title), silent=True)
            if result.changed:
                await self.outbox.add("sub_changed", texts.subscription_changed_text(
                    hint, title, result.added, result.restored, result.archived, result.total))
            await self.subscription_expiry(sub, result.expire_at)
            return False
        if result.status == "needs_confirm":
            await self.outbox.add(
                "sub_confirm",
                texts.subscription_needs_confirm_text(hint, title, len(result.pending_removal), servers),
                dedup_key=f"subconfirm:{sub['id']}:{time.strftime('%Y%m%d')}")
            return False
        if result.first_failure:
            await self.outbox.add("sub_error", texts.subscription_error_text(
                hint, title, result.message, sub["last_ok_at"], servers))
            return True
        return False

    async def subscription_expiry(self, sub: Row, expire_at: int | None) -> None:
        now = int(time.time())
        if expire_at and now < expire_at <= now + EXPIRY_WARNING:
            await self.outbox.add(
                "sub_expiring", texts.subscription_expiring_text(sub["url_hint"], sub["title"], expire_at),
                dedup_key=f"subexp:{sub['id']}:{expire_at}")

    async def credentials_suspended(self, sub: Row, reason: str, count: int) -> None:
        await self.outbox.add(
            "sub_credentials", texts.credentials_suspended_text(sub["url_hint"], sub["title"], reason, count),
            dedup_key=f"subcred:{sub['id']}:{int(time.time()) // 3600}")

    async def credentials_resumed(self, sub: Row) -> None:
        await self.outbox.add("sub_credentials_ok", texts.credentials_resumed_text(sub["url_hint"], sub["title"]))
