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
JAIL_CONFIG="/etc/fail2ban/jail.local"

info "Запуск процесса смены порта: $OLD_SSH_PORT -> $NEW_SSH_PORT..."

# --- Шаг 1: Подготовка Firewall (UFW) ---
if command -v ufw &>/dev/null && ufw status | grep -q "active"; then
    info "Обновляю правила UFW..."
    ufw allow "$NEW_SSH_PORT"/tcp comment 'SSH New Port' >/dev/null
    # Старый пока не закрываем — это наш спасательный круг!
fi

# --- Шаг 2: Обновление Fail2Ban (если есть) ---
if [[ -f "$JAIL_CONFIG" ]]; then
    info "Обновляю порт в Fail2Ban (jail.local)..."
    sed -i "s/^port = .*/port = $NEW_SSH_PORT/" "$JAIL_CONFIG"
    systemctl restart fail2ban || true
fi

# --- Шаг 3: Меняем порт в sshd_config ---
info "Обновляю конфиг SSH..."
backup_file="${SSH_CONFIG_FILE}.bak_$(date +%s)"
cp "$SSH_CONFIG_FILE" "$backup_file"

sed -i -e "s/^#*Port .*/Port $NEW_SSH_PORT/" "$SSH_CONFIG_FILE"

# --- Шаг 4: Перезапуск и проверка ---
info "Перезапускаю сервис SSH..."
if ! (systemctl restart sshd || systemctl restart ssh); then
    warn "КРИТИЧЕСКАЯ ОШИБКА: SSH не перезапустился. Откатываюсь..."
    mv "$backup_file" "$SSH_CONFIG_FILE"
    systemctl restart sshd || systemctl restart ssh || true
    err "Не удалось сменить порт. Конфигурация восстановлена."
fi

sleep 2
if ! ss -tlnp | grep -q ":$NEW_SSH_PORT"; then
    warn "Сервис SSH не слушает новый порт. Откат..."
    mv "$backup_file" "$SSH_CONFIG_FILE"
    systemctl restart sshd || systemctl restart ssh || true
    err "Проверка порта $NEW_SSH_PORT провалена."
fi

ok "SSH успешно переведен на порт $NEW_SSH_PORT."

# --- Шаг 5: Финализация Firewall ---
if command -v ufw &>/dev/null && ufw status | grep -q "active"; then
    info "Закрываю старый порт $OLD_SSH_PORT в UFW..."
    ufw delete allow "$OLD_SSH_PORT"/tcp >/dev/null 2>/dev/null || true
fi

ok "Интеграция завершена: SSH + Firewall + Fail2Ban синхронизированы."
exit 0
