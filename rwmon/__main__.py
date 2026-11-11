"""Command line: ``python -m rwmon <command>`` (installed as ``rwmon``)."""

from __future__ import annotations

import argparse
import asyncio
import shutil
import sqlite3
import sys
import time
from pathlib import Path

from pydantic import ValidationError

from . import __version__
from .config import Config, load_config, scrub_proxy_env
from .logging_setup import setup_logging
from .security import SecretBox, mask_proxy

_ERRORS = {
    "missing": "параметр обязателен",
    "int_parsing": "нужно целое число",
    "float_parsing": "нужно число",
    "bool_parsing": "допустимо: true или false",
    "greater_than": "значение должно быть больше {gt}",
    "greater_than_equal": "значение должно быть не меньше {ge}",
    "less_than_equal": "значение должно быть не больше {le}",
}


def _load(args: argparse.Namespace) -> Config | None:
    try:
        return load_config(args.env)
    except ValidationError as exc:
        print("Ошибка конфигурации:", file=sys.stderr)
        for error in exc.errors():
            name = ".".join(str(part) for part in error["loc"]).upper()
            context = error.get("ctx") or {}
            message = _ERRORS.get(error["type"], error["msg"]).format(**context) if error["type"] in _ERRORS else error["msg"]
            print(f"  {name}: {message.removeprefix('Value error, ')}", file=sys.stderr)
        return None


def cmd_run(args: argparse.Namespace) -> int:
    config = _load(args)
    if config is None:
        return 2
    setup_logging(config.log_level)
    from .app import run_app
    return asyncio.run(run_app(config))


def cmd_check_config(args: argparse.Namespace) -> int:
    config = _load(args)
    if config is None:
        return 2
    xray = Path(config.xray_bin)
    rows = [
        ("Владелец (TELEGRAM_OWNER_ID)", str(config.telegram_owner_id)),
        ("Токен бота", "задан"),
        ("Telegram", mask_proxy(config.telegram_proxy_url)),
        ("Проверки серверов", "напрямую, без прокси"),
        ("Cheburcheck", ("выключен" if not config.cheburcheck_enabled else
                         mask_proxy(config.cheburcheck_proxy_url) if config.cheburcheck_proxy_url else "напрямую")),
        ("Подписки", mask_proxy(config.subscription_proxy_url) if config.subscription_proxy_url else "напрямую"),
        ("Каталог данных", str(config.data_dir)),
        ("База данных", str(config.db_path)),
        ("Интервал проверки", f"{config.check_interval} с"),
        ("Пороги DOWN / восстановления", f"{config.fail_threshold} / {config.recovery_threshold}"),
        ("Перепроверки", config.recheck_intervals + " с"),
        ("Сквозная проверка", f"{config.e2e_mode}, Xray: {xray} ({'найден' if xray.is_file() else 'НЕ НАЙДЕН'})"),
    ]
    width = max(len(name) for name, _ in rows)
    for name, value in rows:
        print(f"{name.ljust(width)}  {value}")
    print("\nКонфигурация корректна.")
    return 0


async def _selftest(config: Config) -> int:
    from .app import build_checks
    from .cheburcheck.client import CheburcheckClient, CheburcheckError
    from .db.database import Database
    from .settings import Settings
    from .telegram.bot import BotManager

    failed = 0

    def report(ok: bool | None, title: str, detail: str = "") -> None:
        nonlocal failed
        mark = "OK  " if ok else ("--  " if ok is None else "FAIL")
        failed += ok is False
        print(f"[{mark}] {title}" + (f": {detail}" if detail else ""))

    removed = scrub_proxy_env()
    if removed:
        report(None, "Переменные окружения с прокси удалены", ", ".join(removed))
    resolver, e2e, _, health = build_checks(config)
    state = await health.check(force=True)
    report(state.foreign_ok, "Связь с зарубежными контрольными узлами (напрямую)", state.details[0])
    report(state.ru_ok, "Связь с российскими контрольными узлами (напрямую)", state.details[1])
    report(state.dns_ok, "Системный DNS", state.details[2])
    report(bool(resolver.names), "Резервные DNS-резолверы", ", ".join(resolver.names))
    if config.e2e_mode == "on":
        available = await e2e.probe_binary()
        report(available, "Xray-core для сквозной проверки", e2e.version or e2e.problem)
    else:
        report(None, "Сквозная проверка выключена (E2E_MODE=off)")

    config.data_dir.mkdir(parents=True, exist_ok=True)
    db = Database(config.db_path)
    try:
        await db.open()
        settings = Settings(config, db)
        await settings.load()
        report(True, "База данных", str(config.db_path))
        botman = BotManager(config, settings)
        ok, detail = await botman.probe(botman.proxy_url)
        report(ok, f"Telegram Bot API ({botman.proxy_label})", detail)
        await botman.close()
    except Exception as exc:  # noqa: BLE001
        report(False, "База данных / Telegram", f"{exc.__class__.__name__}: {exc}")
    finally:
        await db.close()

    if config.cheburcheck_enabled:
        client = CheburcheckClient(config.cheburcheck_base_url, config.cheburcheck_proxy_url)
        try:
            data = await client.check("1.1.1.1")
            report(True, "Cheburcheck", f"отвечает, цель 1.1.1.1 — {data.get('target_type', '?')}")
        except CheburcheckError as exc:
            report(None, "Cheburcheck недоступен (на мониторинг не влияет)", str(exc))
        finally:
            await client.close()
    else:
        report(None, "Cheburcheck выключен")
    print("\nИтог:", "есть ошибки" if failed else "всё необходимое работает")
    return 1 if failed else 0


def cmd_selftest(args: argparse.Namespace) -> int:
    config = _load(args)
    if config is None:
        return 2
    setup_logging("WARNING")
    return asyncio.run(_selftest(config))


def cmd_backup(args: argparse.Namespace) -> int:
    config = _load(args)
    if config is None:
        return 2
    if not config.db_path.is_file():
        print(f"База данных не найдена: {config.db_path}", file=sys.stderr)
        return 1
    target = Path(args.out) if args.out else config.backup_dir / f"rwmon-{time.strftime('%Y%m%d-%H%M%S')}.sqlite3"
    target.parent.mkdir(parents=True, exist_ok=True)
    source = sqlite3.connect(f"file:{config.db_path}?mode=ro", uri=True)
    destination = sqlite3.connect(target)
    try:
        source.backup(destination)        # consistent even while the service is running
    finally:
        destination.close()
        source.close()
    target.chmod(0o600)
    print(f"Резервная копия: {target} ({target.stat().st_size // 1024} КБ)")
    print("Для восстановления нужен тот же SECRET_KEY из файла конфигурации — сохраните и его.")
    return 0


def cmd_restore(args: argparse.Namespace) -> int:
    config = _load(args)
    if config is None:
        return 2
    from .app import InstanceLock
    source = Path(args.file)
    if not source.is_file():
        print(f"Файл не найден: {source}", file=sys.stderr)
        return 1
    try:
        probe = sqlite3.connect(f"file:{source}?mode=ro", uri=True)
        verdict = probe.execute("PRAGMA integrity_check").fetchone()[0]
        version = probe.execute("PRAGMA user_version").fetchone()[0]
        probe.close()
    except sqlite3.DatabaseError as exc:
        print(f"Файл не является базой SQLite: {exc}", file=sys.stderr)
        return 1
    if verdict != "ok" or not version:
        print(f"Копия повреждена или это не база rw-monitor (integrity: {verdict}, версия схемы: {version}).", file=sys.stderr)
        return 1
    lock = InstanceLock(config.run_dir)
    if not lock.acquire():
        print("Сервис запущен. Остановите его: sudo systemctl stop rw-monitor", file=sys.stderr)
        return 1
    try:
        config.db_path.parent.mkdir(parents=True, exist_ok=True)
        if config.db_path.is_file():
            previous = config.db_path.with_suffix(f".before-restore-{time.strftime('%Y%m%d-%H%M%S')}")
            shutil.copy2(config.db_path, previous)
            print(f"Текущая база сохранена как {previous}")
        for suffix in ("-wal", "-shm"):
            Path(str(config.db_path) + suffix).unlink(missing_ok=True)
        shutil.copy2(source, config.db_path)
        config.db_path.chmod(0o600)
    finally:
        lock.release()
    print(f"База восстановлена из {source}. Запустите сервис: sudo systemctl start rw-monitor")
    return 0


def cmd_reset_proxy(args: argparse.Namespace) -> int:
    config = _load(args)
    if config is None:
        return 2
    if not config.db_path.is_file():
        print("База данных ещё не создана — сбрасывать нечего.")
        return 0
    connection = sqlite3.connect(config.db_path, timeout=10)
    with connection:
        deleted = connection.execute("DELETE FROM settings WHERE key='telegram_proxy_url'").rowcount
    connection.close()
    print("Прокси Telegram из настроек удалён." if deleted else "В настройках прокси не переопределён.")
    print(f"Будет использоваться значение из файла конфигурации: {mask_proxy(config.telegram_proxy_url)}")
    print("Перезапустите сервис: sudo systemctl restart rw-monitor")
    return 0


def cmd_genkey(args: argparse.Namespace) -> int:
    print(SecretBox.generate_key())
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="rwmon", description="Мониторинг серверов из подписок Remnawave")
    parser.add_argument("--env", help="путь к файлу конфигурации (по умолчанию $RWMON_ENV_FILE или ./.env)")
    parser.add_argument("--version", action="version", version=f"rw-monitor {__version__}")
    commands = parser.add_subparsers(dest="command")
    commands.add_parser("run", help="запустить сервис (по умолчанию)").set_defaults(func=cmd_run)
    commands.add_parser("check-config", help="проверить файл конфигурации").set_defaults(func=cmd_check_config)
    commands.add_parser("selftest", help="проверить сеть, DNS, Xray, Telegram, Cheburcheck").set_defaults(func=cmd_selftest)
    backup = commands.add_parser("backup", help="создать резервную копию базы")
    backup.add_argument("--out", help="путь к файлу копии")
    backup.set_defaults(func=cmd_backup)
    restore = commands.add_parser("restore", help="восстановить базу из копии (сервис должен быть остановлен)")
    restore.add_argument("file")
    restore.set_defaults(func=cmd_restore)
    commands.add_parser("reset-proxy", help="вернуть прокси Telegram из файла конфигурации").set_defaults(func=cmd_reset_proxy)
    commands.add_parser("genkey", help="сгенерировать SECRET_KEY").set_defaults(func=cmd_genkey)
    args = parser.parse_args(argv)
    func = getattr(args, "func", cmd_run)
    try:
        return func(args)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
