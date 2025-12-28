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
if [[ -z "$SSH_PORT" ]]; then
    warn "ОШИБКА: Переменная SSH_PORT должна быть установлена."
    exit 1
fi

info "Настраиваю файрвол UFW по профилю 'Нода'..."

# --- Установка UFW ---
if ! command -v ufw &>/dev/null; then
    info "UFW не найден. Устанавливаю..."
    apt-get update -qq >/dev/null
    apt-get install -y ufw >/dev/null
    ok "UFW установлен."
fi

# --- Настройка правил ---
info "Конфигурирую правила UFW..."

# Сброс на случай, если уже что-то было
ufw --force reset >/dev/null

# Базовые правила
ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null

# Разрешаем SSH
if [[ -n "$ADMIN_IP" ]]; then
    ufw allow from "$ADMIN_IP" to any port "$SSH_PORT" proto tcp comment 'Admin SSH' >/dev/null
    ok "SSH (порт $SSH_PORT) разрешен для админа: $ADMIN_IP"
fi

# Разрешаем доступ для панели
if [[ -n "$PANEL_IP" ]]; then
    ufw allow from "$PANEL_IP" comment 'Panel Full Access' >/dev/null
    ok "Полный доступ разрешен для панели: $PANEL_IP"
fi

if [[ -z "$ADMIN_IP" && -z "$PANEL_IP" ]]; then
    ufw allow "$SSH_PORT"/tcp comment 'SSH' >/dev/null
    warn "SSH (порт $SSH_PORT) открыт для всех. Рекомендуется указать IP админа или панели."
elif [[ -z "$ADMIN_IP" && -n "$PANEL_IP" ]]; then
     ufw allow "$SSH_PORT"/tcp comment 'SSH' >/dev/null
     warn "Порт SSH открыт для всех для гарантии подключения. Ограничьте его вручную при необходимости."
fi

# Основной порт для VPN
ufw allow 443 comment 'VPN/HTTPS' >/dev/null
ok "Порт 443 (VPN/HTTPS) открыт."

# Включаем UFW
echo "y" | ufw enable >/dev/null
ok "UFW активирован."

# Отключаем IPv6, если он не нужен
if [[ -f "/etc/default/ufw" ]] && grep -q "^IPV6=yes" "/etc/default/ufw"; then
    sed -i 's/^IPV6=yes/IPV6=no/' "/etc/default/ufw"
    ufw reload >/dev/null
    ok "IPv6 в UFW отключен."
fi

ok "Настройка файрвола завершена."
exit 0
