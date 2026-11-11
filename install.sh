#!/usr/bin/env bash
# rw-monitor — установка и обновление одной командой (Ubuntu 24.04 LTS).
#
#   bash <(curl -fsSL https://raw.githubusercontent.com/Rrezzak09VPN/rw-monitor/beta/install.sh)
#
# Повторный запуск обновляет существующую установку: файл конфигурации и база
# данных сохраняются, перед переключением делается резервная копия базы, а если
# новая версия не запустилась — возвращается прежняя.
#
# Переменные окружения (все необязательны):
#   TELEGRAM_BOT_TOKEN, TELEGRAM_OWNER_ID, TELEGRAM_PROXY_URL
#                              значения для новой конфигурации (вместо вопросов)
#   RWMON_NONINTERACTIVE=1     ничего не спрашивать
#   RWMON_REPO, RWMON_BRANCH   откуда брать исходники (владелец/репозиторий, ветка)
#   RWMON_SOURCE_DIR           взять исходники из локального каталога
#   XRAY_VERSION, XRAY_ZIP     версия Xray-core или путь к заранее скачанному архиву
#   RWMON_SKIP_XRAY=1          не устанавливать Xray (сквозная проверка работать не будет)
#   RWMON_NO_START=1           не запускать сервис после установки
#   RWMON_ALLOW_UNSUPPORTED_OS=1  продолжить на непроверенной ОС

set -Eeuo pipefail

# Всё тело — в функциях и вызывается последней строкой: если загрузка скрипта
# оборвётся на середине, не выполнится ничего.

RWMON_REPO="${RWMON_REPO:-Rrezzak09VPN/rw-monitor}"
RWMON_BRANCH="${RWMON_BRANCH:-beta}"
XRAY_VERSION="${XRAY_VERSION:-v26.11.9}"

APP_NAME=rw-monitor
APP_DIR=/opt/rw-monitor
RELEASES_DIR="$APP_DIR/releases"
CURRENT_LINK="$APP_DIR/current"
CONF_DIR=/etc/rw-monitor
ENV_FILE="$CONF_DIR/rwmon.env"
DATA_DIR=/var/lib/rw-monitor
RUN_USER=rwmon
SERVICE=rw-monitor
UNIT_FILE="/etc/systemd/system/$SERVICE.service"
XRAY_BIN="$APP_DIR/bin/xray"
WRAPPER=/usr/local/bin/rwmon
KEEP_RELEASES=2
MIN_PYTHON="3.11"
OS_RELEASE_FILE="${RWMON_OS_RELEASE_FILE:-/etc/os-release}"

WORK_DIR=""
NEW_RELEASE=""
PREVIOUS_RELEASE=""
SWITCHED=no
WAS_ACTIVE=no
MODE=install
INTERACTIVE=no

# ── вывод ────────────────────────────────────────────────────────────────────

if [[ -t 1 ]]; then
    C_BOLD=$'\033[1m'; C_RED=$'\033[31m'; C_YELLOW=$'\033[33m'; C_GREEN=$'\033[32m'; C_RESET=$'\033[0m'
else
    C_BOLD=""; C_RED=""; C_YELLOW=""; C_GREEN=""; C_RESET=""
fi
step() { printf '\n%s==> %s%s\n' "$C_BOLD" "$*" "$C_RESET"; }
info() { printf '    %s\n' "$*"; }
ok()   { printf '    %s[ок]%s %s\n' "$C_GREEN" "$C_RESET" "$*"; }
warn() { printf '    %s[!]%s %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; }
die()  { printf '\n%s[ошибка]%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; exit 1; }

# ── служебное ────────────────────────────────────────────────────────────────

cleanup() {
    [[ -n "$WORK_DIR" && -d "$WORK_DIR" ]] && rm -rf "$WORK_DIR"
    [[ -n "${RWMON_SELF_COPY:-}" && -f "${RWMON_SELF_COPY:-}" ]] && rm -f "$RWMON_SELF_COPY"
    return 0
}

on_error() {
    local code=$? line=${1:-?}
    # Ошибка внутри $(…) сначала срабатывает в подоболочке: там только выходим,
    # восстановление выполнит основной процесс.
    (( BASH_SUBSHELL > 0 )) && exit "$code"
    trap - ERR
    printf '\n%s[ошибка]%s Установка прервана (строка %s, код %s).\n' "$C_RED" "$C_RESET" "$line" "$code" >&2
    if [[ "$SWITCHED" == yes ]]; then
        rollback || true
    elif [[ -n "$NEW_RELEASE" && -d "$NEW_RELEASE" ]]; then
        rm -rf "$NEW_RELEASE"
        if [[ "$MODE" == update ]]; then
            printf '    Прежняя версия не затронута и продолжает работать.\n' >&2
        fi
    fi
    exit "$code"
}

version_ge() {  # version_ge 3.12 3.11  → истина, если первая версия не меньше второй
    printf '%s\n%s\n' "$2" "$1" | sort -V -C
}

run_as_service_user() {
    runuser -u "$RUN_USER" -- env RWMON_ENV_FILE="$ENV_FILE" "$@"
}

rwmon_cli() {  # запуск установленной утилиты от имени пользователя сервиса
    run_as_service_user "$CURRENT_LINK/venv/bin/rwmon" "$@"
}

# ── повышение прав ───────────────────────────────────────────────────────────

ensure_root() {
    [[ $EUID -eq 0 ]] && return 0
    command -v sudo >/dev/null 2>&1 || die "Нужны права root. Войдите под root и повторите команду."
    info "Нужны права root — перезапускаю через sudo."
    local preserve="TELEGRAM_BOT_TOKEN,TELEGRAM_OWNER_ID,TELEGRAM_PROXY_URL,RWMON_NONINTERACTIVE,RWMON_REPO,RWMON_BRANCH"
    preserve+=",RWMON_SOURCE_DIR,XRAY_VERSION,XRAY_ZIP,RWMON_SKIP_XRAY,RWMON_NO_START,RWMON_ALLOW_UNSUPPORTED_OS"
    preserve+=",RWMON_SELF_COPY"
    local self="${BASH_SOURCE[0]:-}"
    if [[ -f "$self" && -r "$self" ]]; then
        exec sudo --preserve-env="$preserve" bash "$self" "$@"
    fi
    # Скрипт получен через «bash <(curl …)»: канал уже прочитан, скачиваем копию заново.
    RWMON_SELF_COPY="$(mktemp /tmp/rw-monitor-install.XXXXXX)"
    export RWMON_SELF_COPY
    curl -fsSL "https://raw.githubusercontent.com/$RWMON_REPO/$RWMON_BRANCH/install.sh" -o "$RWMON_SELF_COPY" \
        || die "Не удалось скачать установщик для перезапуска с правами root."
    exec sudo --preserve-env="$preserve" bash "$RWMON_SELF_COPY" "$@"
}

# ── проверки окружения ───────────────────────────────────────────────────────

check_os() {
    step "Проверка системы"
    [[ -r "$OS_RELEASE_FILE" ]] || die "Не найден $OS_RELEASE_FILE — система не поддерживается."
    local id version pretty
    id="$(. "$OS_RELEASE_FILE" && printf '%s' "${ID:-}")"
    version="$(. "$OS_RELEASE_FILE" && printf '%s' "${VERSION_ID:-}")"
    pretty="$(. "$OS_RELEASE_FILE" && printf '%s' "${PRETTY_NAME:-$id $version}")"
    command -v apt-get >/dev/null 2>&1 || die "Нужен дистрибутив с apt (Ubuntu/Debian). Обнаружено: $pretty."

    if [[ "$id" == ubuntu && "$version" == 24.04 ]]; then
        ok "$pretty"
    else
        warn "Обнаружено: $pretty. Установщик проверялся только на Ubuntu 24.04 LTS."
        if [[ "${RWMON_ALLOW_UNSUPPORTED_OS:-}" == 1 ]]; then
            warn "Продолжаю, потому что задано RWMON_ALLOW_UNSUPPORTED_OS=1."
        elif [[ "$INTERACTIVE" == yes ]]; then
            local answer=""
            read -rp "    Продолжить на свой риск? [y/N] " answer < /dev/tty || true
            [[ "$answer" =~ ^[YyДд] ]] || die "Установка отменена."
        else
            die "Чтобы продолжить на этой системе, задайте RWMON_ALLOW_UNSUPPORTED_OS=1."
        fi
    fi

    case "$(uname -m)" in
        x86_64|aarch64) ;;
        *) [[ "${RWMON_SKIP_XRAY:-}" == 1 ]] \
               || die "Архитектура $(uname -m) не поддерживается (нужны x86_64 или aarch64)." ;;
    esac

    if ! command -v systemctl >/dev/null 2>&1 || [[ ! -d /run/systemd/system ]]; then
        die "systemd не запущен. Сервис устанавливается как служба systemd (контейнеры без systemd не поддерживаются)."
    fi
    ok "systemd, архитектура $(uname -m)"
}

install_packages() {
    step "Системные пакеты"
    export DEBIAN_FRONTEND=noninteractive
    local log
    log="$(mktemp /tmp/rw-monitor-apt.XXXXXX)"
    if ! apt-get update -qq >"$log" 2>&1; then
        cat "$log" >&2; rm -f "$log"
        die "apt-get update завершился с ошибкой."
    fi
    if ! apt-get install -y -qq --no-install-recommends python3 python3-venv ca-certificates curl unzip tar >"$log" 2>&1; then
        cat "$log" >&2; rm -f "$log"
        die "Не удалось установить системные пакеты."
    fi
    rm -f "$log"
    local version
    version="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
    version_ge "$version" "$MIN_PYTHON" || die "Нужен Python $MIN_PYTHON или новее, в системе $version."
    ok "Python $version, venv, curl, unzip"
}

create_user_and_dirs() {
    step "Пользователь и каталоги"
    if id -u "$RUN_USER" >/dev/null 2>&1; then
        ok "пользователь $RUN_USER уже есть"
    else
        useradd --system --user-group --home-dir "$DATA_DIR" --no-create-home --shell /usr/sbin/nologin "$RUN_USER"
        ok "создан системный пользователь $RUN_USER (без входа в систему)"
    fi
    install -d -m 0755 -o root -g root "$APP_DIR" "$APP_DIR/bin" "$RELEASES_DIR"
    install -d -m 0750 -o root -g "$RUN_USER" "$CONF_DIR"
    install -d -m 0700 -o "$RUN_USER" -g "$RUN_USER" "$DATA_DIR"
    ok "$APP_DIR, $CONF_DIR, $DATA_DIR"
}

detect_mode() {
    if [[ -L "$CURRENT_LINK" && -x "$CURRENT_LINK/venv/bin/rwmon" ]]; then
        MODE=update
        PREVIOUS_RELEASE="$(readlink -f "$CURRENT_LINK")"
    fi
    if systemctl is-active --quiet "$SERVICE" 2>/dev/null; then
        WAS_ACTIVE=yes
    fi
}

# ── исходники и окружение Python ─────────────────────────────────────────────

fetch_source() {  # → каталог с исходниками в $SOURCE_DIR
    step "Исходный код"
    local script_dir=""
    if [[ -n "${BASH_SOURCE[0]:-}" && -f "${BASH_SOURCE[0]}" ]]; then
        script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    fi
    if [[ -n "${RWMON_SOURCE_DIR:-}" ]]; then
        SOURCE_DIR="$(cd "$RWMON_SOURCE_DIR" && pwd)"
        info "локальный каталог: $SOURCE_DIR"
    elif [[ -n "$script_dir" && -f "$script_dir/pyproject.toml" && -d "$script_dir/rwmon" ]]; then
        SOURCE_DIR="$script_dir"
        info "локальный каталог: $SOURCE_DIR"
    else
        local url="https://codeload.github.com/$RWMON_REPO/tar.gz/refs/heads/$RWMON_BRANCH"
        info "загрузка: github.com/$RWMON_REPO, ветка $RWMON_BRANCH"
        curl -fsSL --retry 3 --max-time 180 -o "$WORK_DIR/source.tar.gz" "$url" \
            || die "Не удалось скачать исходники ($url)."
        mkdir -p "$WORK_DIR/source"
        tar -xzf "$WORK_DIR/source.tar.gz" -C "$WORK_DIR/source" --strip-components=1 \
            || die "Архив с исходниками повреждён."
        SOURCE_DIR="$WORK_DIR/source"
    fi
    local required
    for required in pyproject.toml requirements.txt .env.example rwmon/__main__.py deploy/rw-monitor.service; do
        [[ -e "$SOURCE_DIR/$required" ]] || die "В исходниках нет $required — это не rw-monitor."
    done
    SOURCE_VERSION="$(sed -n 's/^__version__ = "\(.*\)"/\1/p' "$SOURCE_DIR/rwmon/__init__.py")"
    ok "версия ${SOURCE_VERSION:-неизвестна}"
}

build_release() {
    step "Окружение Python и зависимости"
    NEW_RELEASE="$RELEASES_DIR/$(date +%Y%m%d-%H%M%S)"
    install -d -m 0755 "$NEW_RELEASE" "$NEW_RELEASE/src"
    cp -a "$SOURCE_DIR/rwmon" "$SOURCE_DIR/pyproject.toml" "$SOURCE_DIR/requirements.txt" \
          "$SOURCE_DIR/.env.example" "$SOURCE_DIR/deploy" "$NEW_RELEASE/src/"
    local extra
    for extra in README.md LICENSE CHANGELOG.md uninstall.sh; do
        [[ -f "$SOURCE_DIR/$extra" ]] && cp -a "$SOURCE_DIR/$extra" "$NEW_RELEASE/src/"
    done
    find "$NEW_RELEASE/src" -name '__pycache__' -type d -prune -exec rm -rf {} +
    chown -R root:root "$NEW_RELEASE"

    python3 -m venv "$NEW_RELEASE/venv"
    "$NEW_RELEASE/venv/bin/pip" install --quiet --disable-pip-version-check --upgrade pip
    info "установка зависимостей (около минуты)…"
    "$NEW_RELEASE/venv/bin/pip" install --quiet --disable-pip-version-check -r "$NEW_RELEASE/src/requirements.txt"
    "$NEW_RELEASE/venv/bin/pip" install --quiet --disable-pip-version-check --no-deps "$NEW_RELEASE/src"
    local installed
    installed="$("$NEW_RELEASE/venv/bin/rwmon" --version)"
    ok "$installed → $NEW_RELEASE"
}

# ── Xray-core ────────────────────────────────────────────────────────────────

xray_version() { "$XRAY_BIN" version 2>/dev/null | sed -n '1p' || true; }

install_xray() {
    step "Xray-core $XRAY_VERSION (нужен для сквозной проверки туннеля)"
    if [[ "${RWMON_SKIP_XRAY:-}" == 1 ]]; then
        warn "пропущено (RWMON_SKIP_XRAY=1): серверы будут проверяться только по уровням DNS → TCP/QUIC → TLS"
        return 0
    fi
    if [[ -x "$XRAY_BIN" && "$(xray_version)" == "Xray ${XRAY_VERSION#v} "* ]]; then
        ok "уже установлен: $(xray_version)"
        return 0
    fi
    local arch zip="$WORK_DIR/xray.zip"
    case "$(uname -m)" in
        x86_64)  arch=64 ;;
        aarch64) arch=arm64-v8a ;;
    esac
    if [[ -n "${XRAY_ZIP:-}" ]]; then
        cp "$XRAY_ZIP" "$zip"
        info "архив: $XRAY_ZIP"
    else
        local base="https://github.com/XTLS/Xray-core/releases/download/$XRAY_VERSION/Xray-linux-$arch.zip"
        if curl -fsSL --retry 3 --max-time 180 -o "$zip" "$base" \
                && curl -fsSL --retry 3 --max-time 60 -o "$zip.dgst" "$base.dgst"; then
            local expected actual
            expected="$(grep -i 'SHA2-256' "$zip.dgst" | awk -F'= ' '{print $2}' | tr -d '[:space:]')"
            actual="$(sha256sum "$zip" | awk '{print $1}')"
            [[ -n "$expected" && "$expected" == "$actual" ]] || die "Контрольная сумма архива Xray не совпала."
            info "контрольная сумма SHA-256 совпала"
        else
            rm -f "$zip"
            warn "Не удалось скачать Xray с github.com. Сервис будет работать без сквозной проверки."
            warn "Позже: скачайте Xray-linux-$arch.zip и повторите установку с XRAY_ZIP=/путь/к/архиву."
            return 0
        fi
    fi
    unzip -q -o "$zip" xray -d "$WORK_DIR" || die "Архив Xray повреждён."
    install -m 0755 -o root -g root "$WORK_DIR/xray" "$XRAY_BIN"
    ok "$(xray_version)"
}

# ── конфигурация ─────────────────────────────────────────────────────────────

set_env_value() {  # set_env_value КЛЮЧ — значение берётся из переменной окружения RWMON_VALUE
    "$NEW_RELEASE/venv/bin/python" - "$ENV_FILE" "$1" <<'PY'
import os, re, sys
path, key = sys.argv[1], sys.argv[2]
value = os.environ["RWMON_VALUE"]
if any(ch in value for ch in "\r\n"):
    sys.exit("значение содержит перевод строки")
lines = open(path, encoding="utf-8").read().split("\n")
pattern = re.compile(rf"^#?\s*{re.escape(key)}=")
for index, line in enumerate(lines):
    if pattern.match(line):
        lines[index] = f"{key}={value}"
        break
else:
    lines.append(f"{key}={value}")
open(path, "w", encoding="utf-8").write("\n".join(lines))
PY
}

get_env_value() {  # текущее значение ключа из файла конфигурации (пусто, если не задано)
    awk -v key="$1" 'index($0, key "=") == 1 { print substr($0, length(key) + 2); exit }' "$ENV_FILE"
}

prompt_value() {  # prompt_value ИМЯ_ПЕРЕМЕННОЙ "Вопрос" [secret]
    local __name=$1 __prompt=$2 __secret=${3:-} __value=""
    if [[ -n "$__secret" ]]; then
        read -rsp "    $__prompt" __value < /dev/tty || true
        printf '\n' > /dev/tty
    else
        read -rp "    $__prompt" __value < /dev/tty || true
    fi
    __value="${__value#"${__value%%[![:space:]]*}"}"
    __value="${__value%"${__value##*[![:space:]]}"}"
    printf -v "$__name" '%s' "$__value"
}

valid_token()    { [[ "$1" =~ ^[0-9]{6,12}:[A-Za-z0-9_-]{30,}$ ]]; }
valid_owner_id() { [[ "$1" =~ ^[1-9][0-9]{0,14}$ ]]; }
valid_proxy()    { [[ -z "$1" || "$1" =~ ^(socks5h?|socks4|http|https)://[^[:space:]]+:[0-9]{1,5}/?$ ]]; }

collect_required_settings() {
    # Значение, уже записанное в файле, никогда не заменяется: спрашиваем и берём
    # из окружения только то, чего в файле нет.
    local file_token file_owner file_proxy token owner proxy=""
    file_token="$(get_env_value TELEGRAM_BOT_TOKEN)"
    file_owner="$(get_env_value TELEGRAM_OWNER_ID)"
    file_proxy="$(get_env_value TELEGRAM_PROXY_URL)"
    token="${file_token:-${TELEGRAM_BOT_TOKEN:-}}"
    owner="${file_owner:-${TELEGRAM_OWNER_ID:-}}"
    local proxy_given=no
    if [[ -n "$file_proxy" ]]; then
        proxy_given=yes
    elif [[ -n "${TELEGRAM_PROXY_URL+set}" ]]; then
        proxy="$TELEGRAM_PROXY_URL"
        proxy_given=yes
    fi

    if [[ -n "$token" ]] && ! valid_token "$token"; then
        warn "TELEGRAM_BOT_TOKEN не похож на токен бота."
        token=""
    fi
    if [[ -n "$owner" ]] && ! valid_owner_id "$owner"; then
        warn "TELEGRAM_OWNER_ID должен быть числом."
        owner=""
    fi

    if [[ "$INTERACTIVE" == yes ]]; then
        if [[ -z "$token" || -z "$owner" ]]; then
            printf '\n' > /dev/tty
            info "Нужны два обязательных параметра. Вводимый токен на экране не отображается."
        fi
        while [[ -z "$token" ]]; do
            prompt_value token "Токен бота от @BotFather: " secret
            valid_token "$token" || { warn "Ожидается строка вида 123456789:AA…; попробуйте ещё раз (Ctrl+C — отмена)."; token=""; }
        done
        while [[ -z "$owner" ]]; do
            prompt_value owner "Ваш числовой Telegram ID (подскажет @userinfobot): "
            valid_owner_id "$owner" || { warn "Нужно число, например 123456789."; owner=""; }
        done
        if [[ "$proxy_given" == no ]]; then
            info "Прокси для Telegram Bot API (серверы всегда проверяются напрямую, мимо прокси)."
            info "Формат: socks5://user:pass@host:port или http://host:port. Ввод не отображается."
            while :; do
                prompt_value proxy "Прокси для Telegram [Enter — без прокси]: " secret
                valid_proxy "$proxy" && break
                warn "Адрес не распознан. Пример: socks5://user:pass@203.0.113.5:1080"
            done
        fi
    fi
    if [[ -n "$proxy" ]] && ! valid_proxy "$proxy"; then
        warn "TELEGRAM_PROXY_URL не распознан и не записан — укажите его в $ENV_FILE."
        proxy=""
    fi

    local written=()
    if [[ -z "$file_token" && -n "$token" ]]; then
        RWMON_VALUE="$token" set_env_value TELEGRAM_BOT_TOKEN
        written+=(TELEGRAM_BOT_TOKEN)
    fi
    if [[ -z "$file_owner" && -n "$owner" ]]; then
        RWMON_VALUE="$owner" set_env_value TELEGRAM_OWNER_ID
        written+=(TELEGRAM_OWNER_ID)
    fi
    if [[ -z "$file_proxy" && -n "$proxy" ]]; then
        RWMON_VALUE="$proxy" set_env_value TELEGRAM_PROXY_URL
        written+=(TELEGRAM_PROXY_URL)
    fi
    unset RWMON_VALUE
    if (( ${#written[@]} )); then
        ok "записано в конфигурацию: ${written[*]}"
    fi
}

configure() {
    step "Файл конфигурации"
    if [[ -f "$ENV_FILE" ]]; then
        ok "существующий $ENV_FILE сохранён без изменений"
        # Достраиваем только незаполненные обязательные параметры (например, после прерванной установки).
        if [[ -z "$(get_env_value TELEGRAM_BOT_TOKEN)" || -z "$(get_env_value TELEGRAM_OWNER_ID)" ]]; then
            warn "в нём не заполнены обязательные параметры"
            collect_required_settings
        fi
    else
        local key
        key="$("$NEW_RELEASE/venv/bin/rwmon" genkey)"
        ( umask 077; cp "$NEW_RELEASE/src/.env.example" "$ENV_FILE" )
        RWMON_VALUE="$key"      set_env_value SECRET_KEY
        RWMON_VALUE="$DATA_DIR" set_env_value DATA_DIR
        RWMON_VALUE="$XRAY_BIN" set_env_value XRAY_BIN
        unset RWMON_VALUE
        ok "создан $ENV_FILE (ключ шифрования сгенерирован)"
        collect_required_settings
    fi
    chown root:"$RUN_USER" "$ENV_FILE"
    chmod 0640 "$ENV_FILE"
}

config_is_valid() {
    run_as_service_user "$NEW_RELEASE/venv/bin/rwmon" check-config >/dev/null 2>&1
}

# ── служба ───────────────────────────────────────────────────────────────────

install_service_files() {
    step "Служба systemd и команда rwmon"
    install -m 0644 -o root -g root "$NEW_RELEASE/src/deploy/rw-monitor.service" "$UNIT_FILE"
    local runuser_bin
    runuser_bin="$(command -v runuser)"
    cat > "$WRAPPER" <<WRAPPER_EOF
#!/bin/sh
# Запускает rwmon от имени пользователя сервиса с рабочей конфигурацией.
if [ "\$(id -un)" = "$RUN_USER" ]; then
    exec env RWMON_ENV_FILE=$ENV_FILE $CURRENT_LINK/venv/bin/rwmon "\$@"
fi
if [ "\$(id -u)" != "0" ]; then
    echo "Запустите с правами root: sudo rwmon \$*" >&2
    exit 1
fi
exec $runuser_bin -u $RUN_USER -- env RWMON_ENV_FILE=$ENV_FILE $CURRENT_LINK/venv/bin/rwmon "\$@"
WRAPPER_EOF
    chmod 0755 "$WRAPPER"
    if [[ -f "$NEW_RELEASE/src/uninstall.sh" ]]; then
        install -m 0755 -o root -g root "$NEW_RELEASE/src/uninstall.sh" "$APP_DIR/uninstall.sh"
    fi
    systemctl daemon-reload
    systemctl enable "$SERVICE" >/dev/null 2>&1 || warn "не удалось включить автозапуск службы"
    ok "$UNIT_FILE, автозапуск включён"
}

backup_database() {
    [[ -f "$DATA_DIR/rwmon.sqlite3" ]] || return 0
    PRE_UPDATE_BACKUP="$DATA_DIR/backups/pre-update-$(date +%Y%m%d-%H%M%S).sqlite3"
    install -d -m 0700 -o "$RUN_USER" -g "$RUN_USER" "$DATA_DIR/backups"
    if run_as_service_user "$PREVIOUS_RELEASE/venv/bin/rwmon" backup --out "$PRE_UPDATE_BACKUP" >/dev/null 2>&1; then
        ok "резервная копия базы: $PRE_UPDATE_BACKUP"
    else
        PRE_UPDATE_BACKUP=""
        warn "резервную копию базы создать не удалось — обновление продолжается без неё"
    fi
}

switch_release() {
    step "Переключение на новую версию"
    PRE_UPDATE_BACKUP=""
    if [[ "$MODE" == update ]]; then
        backup_database
        if [[ "$WAS_ACTIVE" == yes ]]; then
            systemctl stop "$SERVICE" || warn "служба не остановилась штатно"
        fi
    fi
    ln -sfn "$NEW_RELEASE" "$CURRENT_LINK"
    SWITCHED=yes
    ok "$CURRENT_LINK → $NEW_RELEASE"
}

rollback() {
    [[ "$MODE" == update && -n "$PREVIOUS_RELEASE" && -d "$PREVIOUS_RELEASE" ]] || return 0
    printf '\n%s==> Возврат к прежней версии%s\n' "$C_BOLD" "$C_RESET" >&2
    systemctl stop "$SERVICE" >/dev/null 2>&1 || true
    ln -sfn "$PREVIOUS_RELEASE" "$CURRENT_LINK"
    if [[ -f "$PREVIOUS_RELEASE/src/deploy/rw-monitor.service" ]]; then
        install -m 0644 -o root -g root "$PREVIOUS_RELEASE/src/deploy/rw-monitor.service" "$UNIT_FILE"
        systemctl daemon-reload || true
    fi
    if [[ -n "${PRE_UPDATE_BACKUP:-}" && -f "$PRE_UPDATE_BACKUP" ]]; then
        # Новая версия могла успеть изменить схему базы — возвращаем состояние на момент обновления.
        rm -f "$DATA_DIR/rwmon.sqlite3-wal" "$DATA_DIR/rwmon.sqlite3-shm"
        install -m 0600 -o "$RUN_USER" -g "$RUN_USER" "$PRE_UPDATE_BACKUP" "$DATA_DIR/rwmon.sqlite3"
        printf '    база восстановлена из %s\n' "$PRE_UPDATE_BACKUP" >&2
    fi
    SWITCHED=no
    if [[ "$WAS_ACTIVE" == yes ]]; then
        if systemctl start "$SERVICE"; then
            printf '    прежняя версия запущена\n' >&2
        else
            printf '    %s[!]%s прежняя версия тоже не запустилась: journalctl -u %s -n 50\n' "$C_YELLOW" "$C_RESET" "$SERVICE" >&2
        fi
    fi
    [[ -n "$NEW_RELEASE" && -d "$NEW_RELEASE" ]] && rm -rf "$NEW_RELEASE"
    return 0
}

show_journal() {
    command -v journalctl >/dev/null 2>&1 || return 0
    journalctl -u "$SERVICE" -n "${1:-15}" --no-pager -o cat 2>/dev/null | sed 's/^/      /' || true
}

start_service() {
    SERVICE_STATE=not-started
    if [[ "${RWMON_NO_START:-}" == 1 ]]; then
        warn "служба не запущена (RWMON_NO_START=1)"
        SWITCHED=no
        return 0
    fi
    if ! config_is_valid; then
        SERVICE_STATE=needs-config
        SWITCHED=no
        return 0
    fi

    step "Самопроверка (до минуты)"
    # Сеть, DNS, Xray, Telegram через прокси, Cheburcheck. Результат справочный: если Telegram
    # пока недоступен, сервис всё равно запускается и продолжает попытки.
    local report
    report="$(rwmon_cli selftest 2>&1 || true)"
    printf '%s\n' "$report" | sed 's/^/    /'
    if [[ "$report" == *"Telegram Bot API"*"Unauthorized"* ]]; then
        warn "Telegram отклонил токен бота. Исправьте TELEGRAM_BOT_TOKEN в $ENV_FILE и перезапустите службу."
    elif [[ "$report" == *"[FAIL] Telegram Bot API"* ]]; then
        if [[ -n "$(get_env_value TELEGRAM_PROXY_URL)" ]]; then
            warn "Bot API через заданный прокси недоступен. Проверьте TELEGRAM_PROXY_URL в $ENV_FILE и перезапустите службу."
        else
            warn "Bot API напрямую недоступен. Если сервер в России, задайте TELEGRAM_PROXY_URL в $ENV_FILE и перезапустите службу."
        fi
        warn "Мониторинг при этом работает; уведомления будут ждать в очереди, пока связь не появится."
    fi

    step "Запуск службы"
    if ! systemctl restart "$SERVICE"; then
        warn "служба не запустилась"
        show_journal 25
        if [[ "$MODE" == update ]]; then
            rollback
            die "Новая версия не запустилась, возвращена прежняя. Конфигурация и данные не изменены."
        fi
        SERVICE_STATE=failed
        SWITCHED=no
        return 0
    fi
    local attempt
    for attempt in 1 2 3 4 5 6 7 8 9 10; do
        systemctl is-active --quiet "$SERVICE" && break
        sleep 1
    done
    if systemctl is-active --quiet "$SERVICE"; then
        sleep 3   # сервис должен пережить первые секунды работы
    fi
    if systemctl is-active --quiet "$SERVICE"; then
        SERVICE_STATE=active
        ok "служба $SERVICE работает"
        show_journal 8
    else
        warn "служба остановилась сразу после запуска"
        show_journal 25
        if [[ "$MODE" == update ]]; then
            rollback
            die "Новая версия не запустилась, возвращена прежняя. Конфигурация и данные не изменены."
        fi
        SERVICE_STATE=failed
    fi
    SWITCHED=no
}

prune_releases() {
    local current release
    current="$(readlink -f "$CURRENT_LINK")"
    # Оставляем текущую версию и предыдущую — на случай ручного отката.
    while IFS= read -r release; do
        [[ "$release" == "$current" ]] && continue
        rm -rf "$release"
    done < <(find "$RELEASES_DIR" -mindepth 1 -maxdepth 1 -type d | sort -r | tail -n +"$((KEEP_RELEASES + 1))")
    # Каталоги прежней схемы установки (до версии с каталогом releases).
    rm -rf "$APP_DIR/venv" "$APP_DIR/src" "$APP_DIR/src.old" "$APP_DIR/src.new"
}

summary() {
    local title="Установка завершена"
    [[ "$MODE" == update ]] && title="Обновление завершено"
    step "$title"
    cat <<SUMMARY
    Версия:        $("$CURRENT_LINK/venv/bin/rwmon" --version)
    Конфигурация:  $ENV_FILE
    Данные:        $DATA_DIR
    Программа:     $APP_DIR
SUMMARY
    case "$SERVICE_STATE" in
        active)
            cat <<SUMMARY
    Служба:        работает, автозапуск включён

    Что дальше:
      1. Откройте чат с ботом в Telegram и отправьте /start.
      2. Пришлите боту ссылку на подписку Remnawave.

SUMMARY
            ;;
        needs-config)
            cat <<SUMMARY
    Служба:        НЕ запущена — в конфигурации не заполнены обязательные параметры

    Что дальше:
      1. sudo nano $ENV_FILE
         укажите TELEGRAM_BOT_TOKEN и TELEGRAM_OWNER_ID (при необходимости TELEGRAM_PROXY_URL)
      2. sudo rwmon selftest
      3. sudo systemctl start $SERVICE

SUMMARY
            ;;
        failed)
            cat <<SUMMARY
    Служба:        НЕ запустилась — смотрите журнал: journalctl -u $SERVICE -n 50

SUMMARY
            ;;
        *)
            cat <<SUMMARY
    Служба:        не запускалась (запуск: sudo systemctl start $SERVICE)

SUMMARY
            ;;
    esac
    cat <<SUMMARY
    Полезные команды:
      sudo rwmon selftest                 проверка сети, DNS, Xray, Telegram, Cheburcheck
      sudo systemctl status $SERVICE     состояние службы
      journalctl -u $SERVICE -f          журнал
      sudo nano $ENV_FILE && sudo systemctl restart $SERVICE
    Обновление:  повторите команду установки
    Удаление:    sudo bash $APP_DIR/uninstall.sh
SUMMARY
    [[ "$SERVICE_STATE" == failed ]] && return 1
    return 0
}

main() {
    trap 'on_error $LINENO' ERR
    trap cleanup EXIT

    ensure_root "$@"
    export PATH="$PATH:/usr/local/sbin:/usr/sbin:/sbin"
    umask 022

    if [[ -z "${RWMON_NONINTERACTIVE:-}" ]] && { : < /dev/tty; } 2>/dev/null; then
        INTERACTIVE=yes
    fi

    printf '%s%s — установка%s\n' "$C_BOLD" "$APP_NAME" "$C_RESET"
    check_os
    install_packages
    WORK_DIR="$(mktemp -d /tmp/rw-monitor.XXXXXX)"
    create_user_and_dirs
    detect_mode
    if [[ "$MODE" == update ]]; then
        info "Найдена установленная версия: $("$CURRENT_LINK/venv/bin/rwmon" --version 2>/dev/null || echo неизвестна) — выполняется обновление."
    fi
    fetch_source
    build_release
    install_xray
    configure
    if [[ "$MODE" == update && "$WAS_ACTIVE" == yes ]] && ! config_is_valid; then
        # Работающий сервис не останавливаем ради версии, которая не примет его конфигурацию.
        rm -rf "$NEW_RELEASE"
        NEW_RELEASE=""
        die "Новая версия не принимает текущую конфигурацию ($ENV_FILE). Прежняя версия продолжает работать."
    fi
    install_service_files
    switch_release
    start_service
    prune_releases
    summary || exit 1
}

main "$@"
