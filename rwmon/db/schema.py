"""Database schema. Each entry of MIGRATIONS upgrades ``PRAGMA user_version`` by one."""

from __future__ import annotations

V1 = """
CREATE TABLE settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE subscriptions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    url_enc       BLOB NOT NULL,
    url_hash      TEXT NOT NULL UNIQUE,
    url_hint      TEXT NOT NULL,
    title         TEXT NOT NULL DEFAULT '',
    user_agent    TEXT NOT NULL DEFAULT '',
    use_hwid      INTEGER NOT NULL DEFAULT 0,
    auto_refresh  INTEGER NOT NULL DEFAULT 1,
    last_fetch_at INTEGER,
    last_ok_at    INTEGER,
    last_status   TEXT NOT NULL DEFAULT '',
    last_error    TEXT NOT NULL DEFAULT '',
    last_formats  TEXT NOT NULL DEFAULT '',
    expire_at     INTEGER,
    userinfo_json TEXT NOT NULL DEFAULT '{}',
    error_notified INTEGER NOT NULL DEFAULT 0,
    e2e_suspended_until INTEGER,
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL
);

CREATE TABLE servers (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint   TEXT NOT NULL UNIQUE,
    name          TEXT NOT NULL,
    aliases_json  TEXT NOT NULL DEFAULT '[]',
    address       TEXT NOT NULL,
    port          INTEGER NOT NULL,
    l4            TEXT NOT NULL,
    protocol      TEXT NOT NULL,
    transport     TEXT NOT NULL,
    security      TEXT NOT NULL,
    sni           TEXT NOT NULL DEFAULT '',
    host          TEXT NOT NULL DEFAULT '',
    path          TEXT NOT NULL DEFAULT '',
    params_json   TEXT NOT NULL DEFAULT '{}',
    secret_enc    BLOB,
    node_key      TEXT NOT NULL,
    archived      INTEGER NOT NULL DEFAULT 0,
    archived_at   INTEGER,
    monitor_enabled INTEGER NOT NULL DEFAULT 1,
    paused_until  INTEGER,
    notify_muted  INTEGER NOT NULL DEFAULT 0,
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL
);
CREATE INDEX idx_servers_node ON servers(node_key);

CREATE TABLE server_addresses (
    server_id  INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    address    TEXT NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL,
    PRIMARY KEY (server_id, address)
);

CREATE TABLE server_subscriptions (
    server_id       INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    subscription_id INTEGER NOT NULL REFERENCES subscriptions(id) ON DELETE CASCADE,
    remark          TEXT NOT NULL DEFAULT '',
    first_seen      INTEGER NOT NULL,
    last_seen       INTEGER NOT NULL,
    PRIMARY KEY (server_id, subscription_id)
);

CREATE TABLE server_state (
    server_id       INTEGER PRIMARY KEY REFERENCES servers(id) ON DELETE CASCADE,
    state           TEXT NOT NULL DEFAULT 'UNKNOWN',
    state_since     INTEGER,
    prev_state      TEXT NOT NULL DEFAULT 'UNKNOWN',
    fail_streak     INTEGER NOT NULL DEFAULT 0,
    ok_streak       INTEGER NOT NULL DEFAULT 0,
    partial_streak  INTEGER NOT NULL DEFAULT 0,
    partial_notified INTEGER NOT NULL DEFAULT 0,
    first_fail_at   INTEGER,
    first_ok_at     INTEGER,
    last_check_at   INTEGER,
    counted_at      INTEGER,          -- last check that was fed into the state machine
    last_ok_at      INTEGER,
    last_code       TEXT NOT NULL DEFAULT '',
    last_summary    TEXT NOT NULL DEFAULT '',
    last_detail_json TEXT NOT NULL DEFAULT '{}',
    last_latency_ms INTEGER,
    good_ips_json   TEXT NOT NULL DEFAULT '[]',
    last_data_probe_at INTEGER,
    incident_id     INTEGER,
    next_check_at   INTEGER,
    flapping        INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE checks (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id   INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    ts          INTEGER NOT NULL,
    kind        TEXT NOT NULL,
    ok          INTEGER,
    code        TEXT NOT NULL,
    stage       TEXT NOT NULL DEFAULT '',
    latency_ms  INTEGER,
    detail_json TEXT
);
CREATE INDEX idx_checks_server_ts ON checks(server_id, ts);
CREATE INDEX idx_checks_ts ON checks(ts);

CREATE TABLE incidents (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id    INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    started_at   INTEGER NOT NULL,
    confirmed_at INTEGER NOT NULL,
    resolved_at  INTEGER,
    recovered_at INTEGER,
    code         TEXT NOT NULL,
    summary      TEXT NOT NULL DEFAULT '',
    detail_json  TEXT NOT NULL DEFAULT '{}',
    close_reason TEXT NOT NULL DEFAULT '',
    group_key    TEXT NOT NULL DEFAULT '',
    cc_status    TEXT NOT NULL DEFAULT 'none',
    cc_result_ids TEXT NOT NULL DEFAULT '[]',
    assessment   TEXT NOT NULL DEFAULT '',
    down_notif_id INTEGER,   -- NULL = not handled yet, 0 = deliberately not sent, else notifications.id
    up_notif_id   INTEGER
);
CREATE INDEX idx_incidents_server ON incidents(server_id, started_at);
CREATE INDEX idx_incidents_open ON incidents(recovered_at, close_reason);

CREATE TABLE state_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    server_id   INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    ts          INTEGER NOT NULL,
    from_state  TEXT NOT NULL,
    to_state    TEXT NOT NULL,
    code        TEXT NOT NULL DEFAULT '',
    note        TEXT NOT NULL DEFAULT '',
    incident_id INTEGER
);
CREATE INDEX idx_state_events_ts ON state_events(ts);
CREATE INDEX idx_state_events_server ON state_events(server_id, ts);

CREATE TABLE notifications (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at    INTEGER NOT NULL,
    kind          TEXT NOT NULL,
    dedup_key     TEXT UNIQUE,
    server_id     INTEGER,
    incident_id   INTEGER,
    text          TEXT NOT NULL,
    markup_json   TEXT NOT NULL DEFAULT '',
    silent        INTEGER NOT NULL DEFAULT 0,
    reply_to      INTEGER,            -- notifications.id of the message to reply to
    edit_of       INTEGER,            -- notifications.id of the message to edit instead of sending
    status        TEXT NOT NULL DEFAULT 'pending',
    attempts      INTEGER NOT NULL DEFAULT 0,
    last_error    TEXT NOT NULL DEFAULT '',
    sent_at       INTEGER,
    tg_message_id INTEGER
);
CREATE INDEX idx_notifications_status ON notifications(status, id);
CREATE INDEX idx_notifications_created ON notifications(created_at);

CREATE TABLE cheburcheck_results (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    target        TEXT NOT NULL,
    target_kind   TEXT NOT NULL,
    requested_at  INTEGER NOT NULL,
    static_status TEXT NOT NULL,
    probe_status  TEXT NOT NULL,
    static_json   TEXT NOT NULL DEFAULT '{}',
    probe_json    TEXT NOT NULL DEFAULT '{}',
    summary_json  TEXT NOT NULL DEFAULT '{}',
    error         TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_cc_target ON cheburcheck_results(target, requested_at);

CREATE TABLE cheburcheck_queue (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id     INTEGER,
    server_id       INTEGER,
    target          TEXT NOT NULL,
    target_kind     TEXT NOT NULL,
    created_at      INTEGER NOT NULL,
    attempts        INTEGER NOT NULL DEFAULT 0,
    next_attempt_at INTEGER NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending',
    UNIQUE (incident_id, target)
);
CREATE INDEX idx_cc_queue_status ON cheburcheck_queue(status, next_attempt_at);

CREATE TABLE monitor_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          INTEGER NOT NULL,
    kind        TEXT NOT NULL,
    text        TEXT NOT NULL DEFAULT '',
    detail_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX idx_monitor_events_ts ON monitor_events(ts);
"""

MIGRATIONS: list[str] = [V1]
