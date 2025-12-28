#!/bin/bash
#
# TITLE: (System) Change SSH Port
# SKYNET_HIDDEN: true
#
# Безопасно меняет порт SSH на удаленном сервере.
# Принимает OLD_SSH_PORT и NEW_SSH_PORT через переменные окружения.

# --- Standard helpers for Skynet plugins ---
set -e # Exit immediately if a command exits with a non-zero status.
C_RESET='\033[0m'; C_RED='\033[0;31m'; C_GREEN='\033[0;32m'; C_YELLOW='\033[1;33m';
info() { echo -e "${C_RESET}[i] $*${C_RESET}"; }
ok()   { echo -e "${C_GREEN}[✓] $*${C_RESET}"; }
warn() { echo -e "${C_YELLOW}[!] $*${C_RESET}"; }
err()  { echo -e "${C_RED}[✗] $*${C_RESET}"; exit 1; }
# --- End of helpers ---

# --- Проверка root ---
# Skynet executor уже запускает плагины через sudo.

# --- Проверка переменных ---
if [[ -z "$OLD_SSH_PORT" || -z "$NEW_SSH_PORT" ]]; then
    warn "ОШИБКА: Переменные OLD_SSH_PORT и NEW_SSH_PORT должны быть установлены."
    exit 1
fi

if [[ "$OLD_SSH_PORT" == "$NEW_SSH_PORT" ]]; then
    info "Новый порт совпадает со старым. Изменения не требуются."
    exit 0
fi

# --- Основная логика ---
SSH_CONFIG_FILE="/etc/ssh/sshd_config"
info "Меняю порт SSH с $OLD_SSH_PORT на $NEW_SSH_PORT..."

# --- Шаг 1: Открываем новый порт в Firewall ---
if command -v ufw &>/dev/null && ufw status | grep -q "active"; then
    info "Открываю порт $NEW_SSH_PORT в UFW..."
    ufw allow "$NEW_SSH_PORT"/tcp >/dev/null
fi

# --- Шаг 2: Меняем порт в sshd_config ---
info "Обновляю $SSH_CONFIG_FILE..."
backup_file="${SSH_CONFIG_FILE}.bak_$(date +%s)"
cp "$SSH_CONFIG_FILE" "$backup_file"

sed -i -e "s/^#*Port .*/Port $NEW_SSH_PORT/" "$SSH_CONFIG_FILE"
if ! grep -q "^Port " "$SSH_CONFIG_FILE"; then
    echo "Port $NEW_SSH_PORT" >> "$SSH_CONFIG_FILE"
fi

# --- Шаг 3: Перезапуск и проверка ---
info "Перезапускаю сервис SSH..."
if ! (systemctl restart sshd || systemctl restart ssh); then
    warn "ОШИБКА: Не удалось перезапустить сервис SSH. Откатываю изменения..."
    mv "$backup_file" "$SSH_CONFIG_FILE"
    (systemctl restart sshd || systemctl restart ssh) || true
    ufw delete allow "$NEW_SSH_PORT"/tcp >/dev/null 2>/dev/null || true
    err "Не удалось перезапустить SSH после изменения конфига."
fi

# Короткая пауза, чтобы сервис успел запуститься
sleep 2

# Проверяем, слушает ли сервис новый порт
if ! ss -tlnp | grep -q ":$NEW_SSH_PORT"; then
    warn "ОШИБКА: Сервис SSH не слушает новый порт. Откатываю изменения..."
    mv "$backup_file" "$SSH_CONFIG_FILE"
    (systemctl restart sshd || systemctl restart ssh) || true
    ufw delete allow "$NEW_SSH_PORT"/tcp >/dev/null 2>/dev/null || true
    err "Сервис SSH не запустился на новом порту $NEW_SSH_PORT."
fi

ok "Сервис SSH теперь слушает порт $NEW_SSH_PORT."

# --- Шаг 4: Успех! Закрываем старый порт ---
if command -v ufw &>/dev/null && ufw status | grep -q "active"; then
    info "Закрываю старый порт $OLD_SSH_PORT в UFW..."
    ufw delete allow "$OLD_SSH_PORT"/tcp >/dev/null 2>/dev/null || true
fi

ok "Порт SSH успешно изменен на $NEW_SSH_PORT."
exit 0
