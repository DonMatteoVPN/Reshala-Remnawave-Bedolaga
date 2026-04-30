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
    # Используем порт из переменных или 22
    local current_port="${TARGET_SSH_PORT:-22}"

    info "Настраиваю Fail2Ban на порту $current_port..."

    # --- Установка ---
    if ! command -v fail2ban-client &>/dev/null; then
        info "Fail2Ban не найден. Устанавливаю..."
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq >/dev/null
        apt-get install -y -qq fail2ban >/dev/null
        ok "Fail2Ban установлен."
    fi

    # --- Подготовка Белого Списка (ignoreip) ---
    local ignore_list="127.0.0.1/8 ::1"
    if [[ -n "${GWL_B64:-}" ]]; then
        info "Синхронизирую ignoreip с Глобальным Белым Списком..."
        temp_gwl=$(mktemp)
        echo "$GWL_B64" | base64 -d > "$temp_gwl" 2>/dev/null || true
        
        if [[ -s "$temp_gwl" ]]; then
            ips=$(grep -v '^\s*#' "$temp_gwl" | grep -v '^\s*$' | awk '{print $1}')
            for ip in $ips; do
                ignore_list="${ignore_list} ${ip}"
            done
            ok "Добавлено IP в исключения."
        fi
        rm -f "$temp_gwl"
    fi

    # --- Настройка ---
    JAIL_CONFIG="/etc/fail2ban/jail.local"
    if [[ -f "$JAIL_CONFIG" ]]; then
        cp "$JAIL_CONFIG" "${JAIL_CONFIG}.bak"
    fi

    # Определяем backend
    local backend_type="auto"
    local ssh_logpath="/var/log/auth.log"
    [[ ! -f "$ssh_logpath" ]] && ssh_logpath="/var/log/secure"
    if [[ ! -f "$ssh_logpath" ]] && command -v journalctl &>/dev/null; then
        backend_type="systemd"
        ssh_logpath="SYSLOG"
    fi

    cat > "$JAIL_CONFIG" <<EOF
[DEFAULT]
bantime = 86400
findtime = 600
maxretry = 5
backend = $backend_type
ignoreip = $ignore_list

[sshd]
enabled = true
port = $current_port
filter = sshd
logpath = $ssh_logpath
EOF

    ok "Конфигурация jail.local обновлена (ignoreip синхронизирован)."

    # --- Перезапуск ---
    systemctl enable fail2ban >/dev/null 2>&1 || true
    systemctl restart fail2ban
    ok "Fail2Ban перезапущен и защищает порт $current_port."
}

# Вызываем главную функцию
run
