#!/bin/bash
#
# TITLE: (System) Setup UFW Firewall
# SKYNET_HIDDEN: true
#
# Настраивает UFW для роли "Нода".
# Принимает PANEL_IP, ADMIN_IP, SSH_PORT через переменные окружения.

# --- Standard helpers for Skynet plugins ---
set -e # Exit immediately if a command exits with a non-zero status.
C_RESET='\033[0m'; C_RED='\033[0;31m'; C_GREEN='\033[0;32m'; C_YELLOW='\033[1;33m';
info() { echo -e "${C_RESET}[i] $*${C_RESET}"; }
ok()   { echo -e "${C_GREEN}[✓] $*${C_RESET}"; }
warn() { echo -e "${C_YELLOW}[!] $*${C_RESET}"; }
err()  { echo -e "${C_RED}[✗] $*${C_RESET}"; exit 1; }
# --- End of helpers ---

# --- Проверка переменных ---
if [[ -z "$TARGET_SSH_PORT" ]]; then
    TARGET_SSH_PORT=22
fi

info "Настраиваю файрвол UFW (Профиль: Универсальный)..."

# --- Установка UFW ---
if ! command -v ufw &>/dev/null; then
    info "UFW не найден. Устанавливаю..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq >/dev/null
    apt-get install -y -qq ufw >/dev/null
    ok "UFW установлен."
fi

# --- Настройка правил ---
info "Конфигурирую правила UFW..."

# Включаем поддержку IPv6 в конфиге UFW
if [[ -f "/etc/default/ufw" ]]; then
    sed -i 's/^IPV6=.*/IPV6=yes/' "/etc/default/ufw"
fi

# Сброс на случай, если уже что-то было
ufw --force reset >/dev/null

# Базовые правила
ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null

# --- СИНХРОНИЗАЦИЯ ГЛОБАЛЬНОГО БЕЛОГО СПИСКА ---
if [[ -n "${GWL_B64:-}" ]]; then
    info "Синхронизирую Глобальный Белый Список с Мастер-сервера..."
    temp_gwl=$(mktemp)
    echo "$GWL_B64" | base64 -d > "$temp_gwl" 2>/dev/null || true
    
    if [[ -s "$temp_gwl" ]]; then
        # Читаем IP, игнорируя комментарии
        ips=$(grep -v '^\s*#' "$temp_gwl" | grep -v '^\s*$' | awk '{print $1}')
        count=0
        for ip in $ips; do
            ufw allow from "$ip" comment 'GWL Trusted' >/dev/null
            ((count++))
        done
        ok "Добавлено $count IP из Глобального Белого Списка."
    fi
    rm -f "$temp_gwl"
else
    warn "Глобальный Белый Список не передан. Используются только стандартные правила."
fi

# Разрешаем SSH для всех (если не в GWL), иначе можно потерять доступ
# Если GWL был пуст, то это единственный способ зайти.
ufw allow "$TARGET_SSH_PORT"/tcp comment 'SSH Port' >/dev/null
ok "Порт SSH ($TARGET_SSH_PORT) открыт."

# Основной порт для VPN (стандарт Reshala)
ufw allow 443/tcp comment 'VPN/HTTPS' >/dev/null
ufw allow 443/udp comment 'VPN/UDP' >/dev/null
ok "Порты 443 TCP/UDP (VPN) открыты."

# Включаем UFW
echo "y" | ufw enable >/dev/null
ok "UFW активирован и работает (IPv6: ON)."

ok "Настройка файрвола завершена."
exit 0
