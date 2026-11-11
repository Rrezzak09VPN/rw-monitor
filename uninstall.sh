#!/usr/bin/env bash
# rw-monitor — удаление.
#
#   sudo bash /opt/rw-monitor/uninstall.sh            сервис и программа; настройки и данные остаются
#   sudo bash /opt/rw-monitor/uninstall.sh --purge    всё, включая конфигурацию, базу и пользователя
#
# Ключ --yes отключает вопрос о подтверждении.

set -Eeuo pipefail

APP_DIR=/opt/rw-monitor
CONF_DIR=/etc/rw-monitor
DATA_DIR=/var/lib/rw-monitor
RUN_USER=rwmon
SERVICE=rw-monitor
UNIT_FILE="/etc/systemd/system/$SERVICE.service"
WRAPPER=/usr/local/bin/rwmon

main() {
    local purge=no assume_yes=no arg
    for arg in "$@"; do
        case "$arg" in
            --purge) purge=yes ;;
            --yes|-y) assume_yes=yes ;;
            -h|--help)
                sed -n '2,8p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
                exit 0 ;;
            *) echo "Неизвестный параметр: $arg" >&2; exit 2 ;;
        esac
    done

    if [[ $EUID -ne 0 ]]; then
        command -v sudo >/dev/null 2>&1 || { echo "Нужны права root." >&2; exit 1; }
        local self="${BASH_SOURCE[0]:-}"
        if [[ -f "$self" && -r "$self" ]]; then
            exec sudo bash "$self" "$@"
        fi
        # Запуск через «bash <(curl …)»: канал уже прочитан, скачиваем копию заново.
        local copy
        copy="$(mktemp /tmp/rw-monitor-uninstall.XXXXXX)"
        curl -fsSL "https://raw.githubusercontent.com/${RWMON_REPO:-Rrezzak09VPN/rw-monitor}/${RWMON_BRANCH:-beta}/uninstall.sh" -o "$copy" \
            || { echo "Не удалось скачать сценарий удаления; запустите его от root." >&2; exit 1; }
        exec sudo bash "$copy" "$@"
    fi
    export PATH="$PATH:/usr/local/sbin:/usr/sbin:/sbin"

    if [[ "$purge" == yes && "$assume_yes" == no ]]; then
        if { : < /dev/tty; } 2>/dev/null; then
            local answer=""
            echo "Будут удалены конфигурация ($CONF_DIR), база и резервные копии ($DATA_DIR)."
            read -rp "Продолжить? [y/N] " answer < /dev/tty || true
            [[ "$answer" =~ ^[YyДд] ]] || { echo "Отменено."; exit 0; }
        else
            echo "Для полного удаления без терминала добавьте ключ --yes." >&2
            exit 1
        fi
    fi

    if command -v systemctl >/dev/null 2>&1; then
        systemctl disable --now "$SERVICE" >/dev/null 2>&1 || true
    fi
    rm -f "$UNIT_FILE" "$WRAPPER"
    if command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload >/dev/null 2>&1 || true
        systemctl reset-failed "$SERVICE" >/dev/null 2>&1 || true
    fi
    rm -rf "$APP_DIR"
    echo "Сервис $SERVICE остановлен и удалён, программа удалена из $APP_DIR."

    if [[ "$purge" == yes ]]; then
        rm -rf "$CONF_DIR" "$DATA_DIR"
        if id -u "$RUN_USER" >/dev/null 2>&1; then
            userdel "$RUN_USER" >/dev/null 2>&1 || true
        fi
        echo "Конфигурация, данные и пользователь $RUN_USER удалены."
    else
        echo "Сохранены: конфигурация $CONF_DIR и данные $DATA_DIR."
        echo "Полное удаление: повторите с ключом --purge."
    fi
}

main "$@"
