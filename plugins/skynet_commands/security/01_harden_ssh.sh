#!/bin/bash
#
# TITLE: (System) Harden SSH Server
# SKYNET_HIDDEN: true
#
# Применяет безопасные настройки к sshd_config на удаленном сервере.
# Принимает порт через переменную окружения TARGET_SSH_PORT.

# --- Standard helpers for Skynet plugins ---
set -e # Exit immediately if a command exits with a non-zero status.
C_RESET='\033[0m'; C_RED='\033[0;31m'; C_GREEN='\033[0;32m'; C_YELLOW='\033[1;33m';
info() { echo -e "${C_RESET}[i] $*${C_RESET}"; }
ok()   { echo -e "${C_GREEN}[✓] $*${C_RESET}"; }
warn() { echo -e "${C_YELLOW}[!] $*${C_RESET}"; }
err()  { echo -e "${C_RED}[✗] $*${C_RESET}"; exit 1; }
# --- End of helpers ---

# --- Проверка root ---
# Skynet executor уже запускает плагины через sudo, поэтому явной проверки здесь не требуется.

# --- Основная логика ---
SSH_CONFIG_FILE="/etc/ssh/sshd_config"
BACKUP_FILE="${SSH_CONFIG_FILE}.bak_reshala_$(date +%s)"
TARGET_PORT=${TARGET_SSH_PORT:-22} 

info "Применяю усиление защиты SSH (Harden) на порту $TARGET_PORT..."

if [[ ! -f "$SSH_CONFIG_FILE" ]]; then
    err "sshd_config не найден в $SSH_CONFIG_FILE"
fi

# Backup
cp "$SSH_CONFIG_FILE" "$BACKUP_FILE"
ok "Создана резервная копия: $BACKUP_FILE"

# Settings
declare -A ssh_settings=(
    ["Port"]="$TARGET_PORT"
    ["PermitRootLogin"]="prohibit-password"
    ["PasswordAuthentication"]="no"
    ["PubkeyAuthentication"]="yes"
    ["UsePAM"]="yes"
    ["X11Forwarding"]="no"
    ["PermitEmptyPasswords"]="no"
    ["MaxAuthTries"]="3"
)

for key in "${!ssh_settings[@]}"; do
    value="${ssh_settings[$key]}"
    sed -i -e "/^#*${key}/d" "$SSH_CONFIG_FILE"
    echo "${key} ${value}" >> "$SSH_CONFIG_FILE"
done
ok "sshd_config обновлен."

# Restart SSH
info "Перезапускаю сервис SSH..."
if ! (systemctl restart sshd || systemctl restart ssh); then
    warn "КРИТИЧЕСКАЯ ОШИБКА: SSH не перезапустился. Откат..."
    cp "$BACKUP_FILE" "$SSH_CONFIG_FILE"
    systemctl restart sshd || systemctl restart ssh || true
    err "Не удалось применить Harden-настройки."
fi
ok "Сервис SSH успешно перезапущен."

# --- СИНХРОНИЗАЦИЯ С ГЛОБАЛЬНЫМ БЕЛЫМ СПИСКОМ ---
if command -v ufw &>/dev/null && ufw status | grep -q "active"; then
    info "Синхронизирую доступ через Firewall..."
    ufw allow "$TARGET_PORT"/tcp comment 'SSH' >/dev/null
    
    if [[ -n "${GWL_B64:-}" ]]; then
        temp_gwl=$(mktemp)
        echo "$GWL_B64" | base64 -d > "$temp_gwl" 2>/dev/null || true
        if [[ -s "$temp_gwl" ]]; then
            ips=$(grep -v '^\s*#' "$temp_gwl" | grep -v '^\s*$' | awk '{print $1}')
            for ip in $ips; do
                ufw allow from "$ip" comment 'GWL Trusted' >/dev/null
            done
            ok "Доверенные IP из Глобального списка добавлены в UFW."
        fi
        rm -f "$temp_gwl"
    fi
fi

ok "Усиление защиты SSH успешно применено."
exit 0
