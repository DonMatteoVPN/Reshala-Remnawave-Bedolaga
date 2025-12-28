#!/bin/bash
# TITLE: Обновить систему (apt update && upgrade)
# SKYNET_HIDDEN: false
#
# Плагин для Скайнета: запускает apt update && apt upgrade.
#

# --- Стандартные хелперы для плагинов Skynet ---
set -e # Прерывать выполнение при любой ошибке
C_RESET='\033[0m'; C_RED='\033[0;31m'; C_GREEN='\033[0;32m'; C_YELLOW='\033[1;33m';
info() { echo -e "${C_RESET}[i] $*${C_RESET}"; }
ok()   { echo -e "${C_GREEN}[✓] $*${C_RESET}"; }
warn() { echo -e "${C_YELLOW}[!] $*${C_RESET}"; }
err()  { echo -e "${C_RED}[✗] $*${C_RESET}"; exit 1; }
# --- Конец хелперов ---

# Убедимся, что скрипт выполняется от имени root
if [[ $EUID -ne 0 ]]; then
    err "Этот плагин должен выполняться от имени root."
fi

info "Запускаю обновление системы (apt)..."

# Проверяем, что это Debian-based система
if ! command -v apt-get &>/dev/null; then
    warn "Это не Debian/Ubuntu, пропускаю."
    exit 0
fi

# Запускаем обновление. -y чтобы не спрашивал подтверждения.
# -qq для максимальной тишины
if apt-get update -qq && apt-get upgrade -y -qq; then
    ok "Обновление системы завершено."
else
    err "Произошла ошибка во время обновления системы."
fi

exit 0