"""Subscription lifecycle against a fake panel: import, refresh, removal, failures, credentials."""

import base64
import json
from pathlib import Path

from rwmon.subscription import fetcher as F

from ..fakes.panel import vless_link

FIX = Path(__file__).resolve().parent.parent / "fixtures" / "sub"
A, B, C, D = "a.example.com", "b.example.com", "c.example.com", "d.example.com"


async def names(env) -> list[str]:
    rows = await env.db.fetchall("SELECT name FROM servers WHERE archived=0 ORDER BY id")
    return [row["name"] for row in rows]


async def take_down(env, clock, *hosts):
    env.checker.fail(*hosts)
    clock.advance(180)
    await env.cycle(); clock.advance(31); await env.rechecks(); clock.advance(61); await env.rechecks()


async def test_import_stores_everything_and_hides_secrets(env):
    env.panel.links = [vless_link("Germany", A), vless_link("Poland", B, port=8443)]
    result = await env.subs.add(env.panel.url)
    assert result.ok and result.is_new and result.total == 2 and result.added == ["Germany", "Poland"]
    assert result.title == "Test panel" and "base64" in result.formats[0]
    row = await env.db.fetchone("SELECT * FROM servers WHERE name='Poland'")
    assert (row["address"], row["port"], row["protocol"], row["transport"], row["security"], row["sni"]) == (
        B, 8443, "vless", "tcp", "reality", B)
    assert json.loads(row["params_json"])["flow"] == "xtls-rprx-vision"
    link = await env.db.fetchone("SELECT * FROM server_subscriptions WHERE server_id=?", (row["id"],))
    assert link["subscription_id"] == result.sub_id and link["remark"] == "Poland"
    state = await env.db.fetchone("SELECT state FROM server_state WHERE server_id=?", (row["id"],))
    assert state["state"] == "UNKNOWN"
    # nothing sensitive is readable in the database file
    raw = Path(env.config.db_path).read_bytes() + Path(str(env.config.db_path) + "-wal").read_bytes()
    assert env.panel.token.encode() not in raw
    assert b"11111111-2222-4333-8444-555555555555" not in raw            # user UUID
    assert b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" not in raw       # REALITY public key
    secret = env.subs.decrypt_server_secret(row)
    assert secret["secrets"]["id"] == "11111111-2222-4333-8444-555555555555"
    sub = await env.subs.get(result.sub_id)
    assert sub["url_hint"].endswith("3456") and env.panel.token not in sub["url_hint"]


async def test_refresh_adds_new_removes_stale_keeps_history_and_exclusions(env, clock):
    servers = await env.add_servers(A, B, C)
    await env.cycle()
    await env.monitor.exclude_server(servers[1]["id"])                     # B is excluded by the owner
    await env.monitor.mute_server(servers[2]["id"], True)                  # C is muted
    env.panel.links = [vless_link("Srv-1", A), vless_link("Srv-2", B), vless_link("Srv-3", C), vless_link("New", D)]
    result = await env.subs.add(env.panel.url)                             # the same link sent again
    assert result.ok and not result.is_new and result.added == ["New"] and result.unchanged == 3 and not result.archived
    rows = {row["name"]: row for row in await env.db.fetchall("SELECT * FROM servers")}
    assert rows["Srv-2"]["monitor_enabled"] == 0 and rows["Srv-3"]["notify_muted"] == 1      # exclusions survive
    assert rows["New"]["monitor_enabled"] == 1

    env.panel.links = [vless_link("Srv-1", A), vless_link("Srv-2", B), vless_link("New", D)]
    result = await env.subs.refresh(result.sub_id)
    assert result.archived == ["Srv-3"] and await names(env) == ["Srv-1", "Srv-2", "New"]
    assert await env.db.scalar("SELECT COUNT(*) FROM checks WHERE server_id=?", (servers[2]["id"],)) == 1   # history kept
    env.checker.calls.clear()
    clock.advance(180)
    await env.cycle()
    assert sorted(address for address, _ in env.checker.calls) == [A, D]    # removed and excluded are not checked

    env.panel.links.append(vless_link("Srv-3", C))                         # the server returns to the subscription
    result = await env.subs.refresh(result.sub_id)
    assert result.restored == ["Srv-3"]
    restored = await env.db.fetchone("SELECT * FROM servers WHERE name='Srv-3'")
    assert restored["id"] == servers[2]["id"] and restored["notify_muted"] == 1


async def test_renamed_or_rekeyed_server_is_the_same_server(env):
    servers = await env.add_servers(A)
    env.panel.links = [vless_link("Germany renamed", A, uuid="99999999-8888-4777-8666-555555555555")]
    result = await env.subs.refresh((await env.subs.list())[0]["id"])
    assert result.ok and not result.added and not result.archived
    row = await env.db.fetchone("SELECT * FROM servers")
    assert row["id"] == servers[0]["id"] and row["name"] == "Germany renamed"
    assert env.subs.decrypt_server_secret(row)["secrets"]["id"].startswith("99999999")     # new credentials are used


async def test_changed_address_of_the_same_host_is_followed(env, clock):
    """Remnawave may hand out a different address of the same host on every request."""
    env.panel.links = [vless_link("Germany", "de1.pool.example.com", sni="cover.example.com"),
                       vless_link("Poland", B)]
    result = await env.subs.add(env.panel.url)
    first = await env.db.fetchone("SELECT * FROM servers WHERE name='Germany'")
    await env.cycle()
    env.panel.links = [vless_link("Germany", "de2.pool.example.com", sni="cover.example.com"),
                       vless_link("Poland", B)]
    result = await env.subs.refresh(result.sub_id)
    assert result.ok and not result.added and not result.archived      # not "one removed, one added"
    row = await env.db.fetchone("SELECT * FROM servers WHERE name='Germany'")
    assert row["id"] == first["id"] and row["address"] == "de2.pool.example.com"
    known = {item["address"] for item in await env.db.fetchall(
        "SELECT address FROM server_addresses WHERE server_id=?", (row["id"],))}
    assert known == {"de1.pool.example.com", "de2.pool.example.com"}
    assert (await env.db.fetchone("SELECT state FROM server_state WHERE server_id=?", (row["id"],)))["state"] == "OK"
    env.checker.calls.clear()
    clock.advance(180)
    await env.cycle()
    assert ("de2.pool.example.com", True) in env.checker.calls          # checked at the current address


async def test_failed_or_empty_refresh_never_changes_the_list(env):
    await env.add_servers(A, B)
    sub_id = (await env.subs.list())[0]["id"]
    for mode, status in (("error500", F.NETWORK), ("html", F.HTML), ("notfound", F.NOT_FOUND),
                         ("expired", F.NO_SERVERS), ("hwid_limit", F.HWID_LIMIT), ("drop", None)):
        env.panel.mode = mode
        result = await env.subs.refresh(sub_id)
        assert not result.ok and (status is None or result.status == status), (mode, result.status)
        assert await names(env) == ["Srv-1", "Srv-2"], mode
        assert result.message
    env.panel.mode = "expired"
    result = await env.subs.refresh(sub_id)
    assert "Subscription expired" in result.message                        # the panel's own explanation is shown
    sub = await env.subs.get(sub_id)
    assert sub["last_status"] == F.NO_SERVERS and sub["last_ok_at"]


async def test_mass_removal_needs_confirmation(env):
    await env.add_servers(A, B, C, D)
    sub_id = (await env.subs.list())[0]["id"]
    env.panel.links = [vless_link("Srv-1", A)]                             # 3 of 4 servers vanish
    result = await env.subs.refresh(sub_id)
    assert result.status == "needs_confirm" and len(result.pending_removal) == 3
    assert len(await names(env)) == 4
    result = await env.subs.refresh(sub_id, force=True)                    # the owner confirms
    assert result.ok and len(result.archived) == 3 and await names(env) == ["Srv-1"]


async def test_two_subscriptions_share_servers(env):
    await env.add_servers(A, B)
    from ..fakes.panel import FakePanel
    second = await FakePanel().start()
    try:
        second.token = "OTHERtoken99999"
        second.links = [vless_link("B from second", B), vless_link("Only second", C)]
        result = await env.subs.add(second.url)
        assert result.ok and result.added == ["Only second"] and result.unchanged == 1
        assert len(await names(env)) == 3                                  # B is not duplicated
        archived = await env.subs.delete((await env.subs.list())[0]["id"])  # remove the first subscription
        assert archived == ["Srv-1"]                                       # B stays: the second one still has it
        assert sorted(await names(env)) == ["B from second", "Only second"]
    finally:
        await second.stop()


async def test_all_formats_are_merged_from_one_panel(env):
    object.__setattr__(env.config, "subscription_extra_profiles", "json,mihomo")
    env.panel.links = base64.b64decode((FIX / "links.b64").read_bytes()).decode().splitlines()
    env.panel.json_body = (FIX / "xray.json").read_bytes()
    env.panel.mihomo_body = (FIX / "mihomo.yaml").read_bytes()
    result = await env.subs.add(env.panel.url)
    assert result.ok and result.total == 15
    assert result.formats == ["список ссылок (base64)", "Xray JSON", "Mihomo / Clash YAML"]
    assert [request["suffix"] for request in env.panel.requests] == ["", "json", "mihomo"]
    assert all(request["ua"] == "rw-monitor/1.0" for request in env.panel.requests)
    row = await env.db.fetchone("SELECT * FROM servers WHERE address='node01.vpn-example.org'")
    assert json.loads(row["aliases_json"]) and env.subs.decrypt_server_secret(row)["outbound"]["protocol"] == "vless"


async def test_automatic_refresh_failure_is_reported_once(env, clock):
    await env.add_servers(A)
    sub_id = (await env.subs.list())[0]["id"]
    env.panel.mode = "error500"
    for _ in range(3):
        result = await env.subs.refresh(sub_id)
        await env.monitor.subscription_refreshed(sub_id, result, interactive=False)
    errors = await env.messages("sub_error")
    assert len(errors) == 1 and "Не удалось обновить подписку" in errors[0]["text"] and "не изменён" in errors[0]["text"]
    env.panel.mode = "ok"
    result = await env.subs.refresh(sub_id)
    await env.monitor.subscription_refreshed(sub_id, result, interactive=False)
    assert len(await env.messages("sub_ok")) == 1
    env.panel.links.append(vless_link("New", B))
    result = await env.subs.refresh(sub_id)
    await env.monitor.subscription_refreshed(sub_id, result, interactive=False)
    changed = await env.messages("sub_changed")
    assert len(changed) == 1 and "Добавлены (1): New" in changed[0]["text"]


async def test_expired_subscription_is_not_a_server_outage(env, clock):
    """Every tunnel failing at once while the ports answer = dead credentials, not dead servers."""
    await env.add_servers(A, B, C)
    await env.cycle()
    env.checker.fail(A, B, C, code="e2e_failed", stage="e2e", e2e_ran=True)
    env.panel.mode = "expired"
    for _ in range(6):
        clock.advance(180)
        await env.cycle()
        clock.advance(31)
        await env.rechecks()
    assert set((await env.states()).values()) == {"OK"}
    assert await env.messages("down") == [] and await env.db.scalar("SELECT COUNT(*) FROM incidents") == 0
    notices = await env.messages("sub_credentials")
    assert len(notices) == 1 and "Проблема с подпиской, а не с серверами" in notices[0]["text"]
    assert all(not used_e2e for _, used_e2e in env.checker.calls[-3:])       # tunnel checks are suspended

    env.panel.mode = "ok"                                                    # the owner renews the subscription
    sub_id = (await env.subs.list())[0]["id"]
    result = await env.subs.refresh(sub_id)
    await env.monitor.subscription_refreshed(sub_id, result, interactive=False)
    assert len(await env.messages("sub_credentials_ok")) == 1
    env.checker.heal(A, B, C)
    clock.advance(180)
    await env.cycle()
    assert all(used_e2e for _, used_e2e in env.checker.calls[-3:])


async def test_tunnel_failures_with_a_healthy_subscription_are_real(env, clock):
    """The panel confirms the subscription is fine → a protocol-level block must be reported."""
    await env.add_servers(A, B, C)
    await env.cycle()
    env.checker.fail(A, B, C, code="e2e_failed", stage="e2e", e2e_ran=True)
    await take_down(env, clock)
    assert set((await env.states()).values()) == {"DOWN"}
    downs = await env.messages("down")
    assert len(downs) == 1 and "МАССОВАЯ НЕДОСТУПНОСТЬ" in downs[0]["text"] and "туннель не устанавливается" in downs[0]["text"]


async def test_tunnel_failures_with_unreachable_panel_give_no_verdict(env, clock):
    await env.add_servers(A, B)
    await env.cycle()
    env.checker.fail(A, B, code="e2e_failed", stage="e2e", e2e_ran=True)
    env.panel.mode = "error500"
    for _ in range(4):
        clock.advance(180)
        await env.cycle()
    assert set((await env.states()).values()) == {"OK"}
    assert await env.messages("down") == []
    row = await env.db.fetchone("SELECT last_code, last_summary FROM server_state LIMIT 1")
    assert row["last_code"] == "e2e_unverified"
    assert len(await env.messages("sub_error")) == 1                        # the owner learns about the panel instead


async def test_expiry_warning_is_sent_once(env):
    import time
    env.panel.expire = int(time.time()) + 30 * 86400              # far away: no warning
    await env.add_servers(A)
    sub_id = (await env.subs.list())[0]["id"]
    result = await env.subs.refresh(sub_id)
    await env.monitor.subscription_refreshed(sub_id, result, interactive=False)
    assert await env.messages("sub_expiring") == []
    env.panel.expire = int(time.time()) + 2 * 86400               # two days left
    for _ in range(3):
        result = await env.subs.refresh(sub_id)
        await env.monitor.subscription_refreshed(sub_id, result, interactive=False)
    warnings = await env.messages("sub_expiring")
    assert len(warnings) == 1 and "Подписка скоро истекает" in warnings[0]["text"] and "МСК" in warnings[0]["text"]
