#!/bin/bash
#
# TITLE: (System) Setup Fail2Ban
# SKYNET_HIDDEN: true
#
# Устанавливает и настраивает Fail2Ban на удаленном сервере.
# Принимает SSH_PORT через переменную окружения.

# --- Standard helpers for Skynet plugins ---
set -e # Exit immediately if a command exits with a non-zero status.
C_RESET='\033[0m'; C_RED='\033[0;31m'; C_GREEN='\033[0;32m'; C_YELLOW='\033[1;33m';
info() { echo -e "${C_RESET}[i] $*${C_RESET}"; }
ok()   { echo -e "${C_GREEN}[✓] $*${C_RESET}"; }
warn() { echo -e "${C_YELLOW}[!] $*${C_RESET}"; }
err()  { echo -e "${C_RED}[✗] $*${C_RESET}"; exit 1; }
# --- End of helpers ---

# --- Главная функция ---
run() {

    # --- Проверка переменных ---
    if [[ -z "$SSH_PORT" ]]; then
        warn "ОШИБКА: Переменная SSH_PORT должна быть установлена."
        exit 1
    fi

    info "Настраиваю Fail2Ban..."

    # --- Установка ---
    if ! command -v fail2ban-client &>/dev/null; then
        info "Fail2Ban не найден. Устанавливаю..."
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq >/dev/null
        apt-get install -y -qq fail2ban >/dev/null
        ok "Fail2Ban установлен."
    fi

    # --- Настройка ---
    info "Конфигурирую Fail2Ban..."

    BANTIME="86400"  # 24 часа по умолчанию
    MAXRETRY="3"
    FINDTIME="600"

    JAIL_CONFIG="/etc/fail2ban/jail.local"

    # Бэкап
    if [[ -f "$JAIL_CONFIG" ]]; then
        cp "$JAIL_CONFIG" "${JAIL_CONFIG}.bak_$(date +%s)"
    fi

    # --- Определяем logpath для SSH и backend ---
    local ssh_logpath=""
    local backend_type="auto" # Дефолтный backend

    if [[ -f "/var/log/auth.log" ]] && [[ -r "/var/log/auth.log" ]]; then
        ssh_logpath="/var/log/auth.log"
        backend_type="auto"
elif [[ -f "/var/log/secure" ]] && [[ -r "/var/log/secure" ]]; then
        ssh_logpath="/var/log/secure"
        backend_type="auto"
elif command -v journalctl &>/dev/null; then
        ssh_logpath="SYSLOG" # Специальное значение для systemd-backend
        backend_type="systemd" # Явно указываем systemd
    else
        err "Не удалось найти подходящий лог-файл для SSH или journalctl. Невозможно настроить защиту SSH."
    fi
    ok "Найден лог-файл SSH: $ssh_logpath (backend: $backend_type)."
    
    # Создание временного файла с содержимым jail.local
    local temp_jail_config=$(mktemp)
    cat > "$temp_jail_config" <<EOF_TEMP_JAIL
[DEFAULT]
bantime = $BANTIME
findtime = ${FINDTIME}s
maxretry = $MAXRETRY
backend = $backend_type
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled = true
port = $SSH_PORT
filter = sshd
logpath = $ssh_logpath
EOF_TEMP_JAIL
    
    # Теперь записываем содержимое временного файла в JAIL_CONFIG
    cp "$temp_jail_config" "$JAIL_CONFIG"
    rm "$temp_jail_config" # Удаляем временный файл
    
    ok "Конфигурационный файл jail.local создан с базовой защитой для SSH."
    
    # --- Проверка конфигурации ---
    info "Тестирую конфигурацию Fail2Ban..."
    if ! fail2ban-client -t >/dev/null; then
        err "Тестирование конфигурации Fail2Ban провалено. См. вывод 'fail2ban-client -t'."
    fi
    ok "Конфигурация Fail2Ban успешно протестирована."

# --- Перезапуск сервиса ---
info "Включаю и перезапускаю сервис Fail2Ban..."
systemctl enable fail2ban >/dev/null
systemctl restart fail2ban
sleep 2

if systemctl is-active --quiet fail2ban; then
    ok "Настройка Fail2Ban завершена, сервис активен."
else
    err "Сервис Fail2Ban запустился, но сразу же остановился. Проверьте 'journalctl -u fail2ban'."
fi

} # <<< End of the function

# Вызываем главную функцию
run
