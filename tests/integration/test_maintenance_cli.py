"""Retention, backups and the command line."""

import sqlite3
import subprocess
import sys
import time
from pathlib import Path

from rwmon.maintenance import Maintenance
from rwmon.security import SecretBox

from ..conftest import OWNER, TOKEN

ROOT = Path(__file__).resolve().parents[2]
A, B = "a.example.com", "b.example.com"
DAY = 86400


def cli(env_file: Path, *args: str, extra_env: dict | None = None) -> subprocess.CompletedProcess:
    import os
    env = {"PATH": os.environ["PATH"], **(extra_env or {})}
    return subprocess.run([sys.executable, "-m", "rwmon", "--env", str(env_file), *args],
                          cwd=ROOT, env=env, capture_output=True, text=True, timeout=120)


def write_env(tmp_path: Path, **extra: str) -> Path:
    values = {"TELEGRAM_BOT_TOKEN": TOKEN, "TELEGRAM_OWNER_ID": str(OWNER), "SECRET_KEY": SecretBox.generate_key(),
              "DATA_DIR": str(tmp_path / "data"), **extra}
    path = tmp_path / "rwmon.env"
    path.write_text("\n".join(f"{key}={value}" for key, value in values.items()))
    return path


async def test_history_retention(env, clock):
    servers = await env.add_servers(A, B)
    await env.cycle()
    now = int(time.time())
    old = now - 20 * DAY
    for ts in (old, old + 10, now - 5):
        await env.db.insert("checks", server_id=servers[0]["id"], ts=ts, kind="scheduled", ok=1, code="ok")
    await env.db.insert("state_events", server_id=servers[0]["id"], ts=now - 200 * DAY, from_state="OK", to_state="DOWN")
    await env.db.insert("state_events", server_id=servers[0]["id"], ts=now - 10 * DAY, from_state="OK", to_state="DOWN")
    await env.db.insert("monitor_events", ts=now - 200 * DAY, kind="started", text="old")
    await env.db.insert("incidents", server_id=servers[0]["id"], started_at=now - 200 * DAY, confirmed_at=now - 200 * DAY,
                        recovered_at=now - 199 * DAY, code="tcp_timeout")
    await env.db.insert("incidents", server_id=servers[0]["id"], started_at=now - 200 * DAY, confirmed_at=now - 200 * DAY,
                        code="tcp_timeout")                                     # still open: must survive
    await env.db.insert("notifications", created_at=now - 200 * DAY, kind="down", text="old", status="sent")
    await env.db.insert("notifications", created_at=now - 200 * DAY, kind="down", text="stuck", status="pending")
    await env.db.insert("cheburcheck_results", target="1.2.3.4", target_kind="ip", requested_at=now - 100 * DAY,
                        static_status="ok", probe_status="ok")
    await env.settings.set_raw("cc.used.20200101", 5)
    deleted = await Maintenance(env.config, env.db, env.settings).cleanup()
    assert deleted["checks"] == 2 and deleted["state_events"] == 1 and deleted["monitor_events"] == 1
    assert deleted["incidents"] == 1 and deleted["notifications"] == 1 and deleted["cheburcheck_results"] == 1
    assert await env.db.scalar("SELECT COUNT(*) FROM incidents") == 1
    assert await env.db.scalar("SELECT COUNT(*) FROM notifications WHERE status='pending'") == 1     # never dropped
    assert env.settings.raw("cc.used.20200101") == ""
    assert await env.db.scalar("SELECT COUNT(*) FROM servers") == 2                                 # servers untouched


async def test_backup_rotation_and_content(env):
    await env.add_servers(A, B)
    object.__setattr__(env.config, "backup_keep", 2)
    maintenance = Maintenance(env.config, env.db, env.settings)
    paths = []
    for index in range(3):
        path = await maintenance.backup()
        target = path.with_name(f"rwmon-2026010{index + 1}-000000.sqlite3")
        path.rename(target)
        paths.append(target)
    await maintenance.backup()
    kept = maintenance.list_backups()
    assert len(kept) == 2 and paths[0] not in kept
    copy = sqlite3.connect(kept[0])
    assert copy.execute("SELECT COUNT(*) FROM servers").fetchone()[0] == 2
    assert copy.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    copy.close()
    assert oct(kept[0].stat().st_mode & 0o777) == "0o600"


def test_cli_config_errors_are_readable(tmp_path):
    path = tmp_path / "bad.env"
    path.write_text("TELEGRAM_BOT_TOKEN=nonsense\nTELEGRAM_OWNER_ID=@me\nFAIL_THRESHOLD=1\n")
    result = cli(path, "check-config")
    assert result.returncode == 2
    assert "TELEGRAM_BOT_TOKEN" in result.stderr and "TELEGRAM_OWNER_ID" in result.stderr
    assert "SECRET_KEY" in result.stderr and "FAIL_THRESHOLD" in result.stderr
    assert "nonsense" not in result.stderr or "Traceback" not in result.stderr


def test_cli_check_config_genkey_version(tmp_path):
    env_file = write_env(tmp_path, TELEGRAM_PROXY_URL="socks5://user:topsecret@10.0.0.9:1080")
    result = cli(env_file, "check-config")
    assert result.returncode == 0 and "Конфигурация корректна" in result.stdout
    assert "socks5://***@10.0.0.9:1080" in result.stdout and "topsecret" not in result.stdout
    assert TOKEN not in result.stdout and "напрямую, без прокси" in result.stdout
    key = cli(env_file, "genkey").stdout.strip()
    SecretBox(key)                                                 # a valid Fernet key
    assert cli(env_file, "--version").stdout.startswith("rw-monitor 1.")


async def test_cli_backup_restore_and_reset_proxy(env, tmp_path):
    await env.add_servers(A, B)
    await env.settings.set("check_interval", "5m")
    await env.settings.set("telegram_proxy_url", "socks5://127.0.0.1:1")
    env_file = tmp_path / "cli.env"
    env_file.write_text("\n".join([
        f"TELEGRAM_BOT_TOKEN={TOKEN}", f"TELEGRAM_OWNER_ID={OWNER}",
        f"SECRET_KEY={env.config.secret_key.get_secret_value()}", f"DATA_DIR={env.config.data_dir}"]))
    backup = tmp_path / "copy.sqlite3"
    result = cli(env_file, "backup", "--out", str(backup))          # works while the database is in use
    assert result.returncode == 0 and backup.is_file()

    result = cli(env_file, "reset-proxy")
    assert result.returncode == 0 and "удалён" in result.stdout
    await env.settings.load()
    assert not env.settings.is_overridden("telegram_proxy_url") and env.settings.get("check_interval") == 300

    await env.db.execute("DELETE FROM servers")                      # disaster
    await env.db.close()
    garbage = tmp_path / "garbage.sqlite3"
    garbage.write_text("not a database")
    assert cli(env_file, "restore", str(garbage)).returncode == 1
    result = cli(env_file, "restore", str(backup))
    assert result.returncode == 0 and "восстановлена" in result.stdout
    await env.db.open()                                              # the fixture closes it again on teardown
    assert await env.db.scalar("SELECT COUNT(*) FROM servers") == 2
    row = await env.db.fetchone("SELECT * FROM servers LIMIT 1")
    assert env.subs.decrypt_server_secret(row)["secrets"]["id"]      # readable with the same SECRET_KEY
    assert list(Path(env.config.data_dir).glob("rwmon.before-restore-*"))
