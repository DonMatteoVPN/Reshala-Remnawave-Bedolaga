#!/bin/bash
#   ( РОДИТЕЛЬ | КЛАВИША | НАЗВАНИЕ | ФУНКЦИЯ | ПОРЯДОК | ГРУППА | ОПИСАНИЕ )
# @menu.manifest
# @item( security | 7 | 🔑 Управление портами SSH | show_ssh_ports_menu | 70 | 10 | Добавление и удаление портов SSH с авто-обновлением firewall. )
#
# ssh_manager.sh - Безопасное управление портами SSH
#
# При добавлении/удалении порта автоматически:
#   - Обновляется /etc/ssh/sshd_config
#   - Обновляются правила UFW
#   - Перезапускается sshd
#

[[ "${BASH_SOURCE[0]}" == "${0}" ]] && exit 1

show_ssh_ports_menu() {
    while true; do
        clear
        enable_graceful_ctrlc
        menu_header "🔑 Управление портами SSH"
        printf_description "Добавление/удаление портов с авто-обновлением firewall."

        _ssh_show_current_ports

        echo ""
        printf_menu_option "1" "➕ Добавить SSH порт"
        printf_menu_option "2" "➖ Удалить SSH порт"
        echo ""
        printf_menu_option "b" "Назад"
        echo ""

        local choice
        choice=$(safe_read "Выберите действие" "") || { break; }

        case "$choice" in
            1) _ssh_add_port; wait_for_enter;;
            2) _ssh_remove_port; wait_for_enter;;
            b|B) break;;
            *) warn "Неверный выбор";;
        esac
        disable_graceful_ctrlc
    done
}

_ssh_show_current_ports() {
    print_separator
    info "Активные SSH порты"

    local ports
    ports=$(grep -E "^\s*Port\s+" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')

    if [[ -z "$ports" ]]; then
        printf_description "  ${C_YELLOW}● Порт 22${C_RESET} (по умолчанию)"
    else
        while IFS= read -r port; do
            [[ -z "$port" ]] && continue
            if [[ "$port" == "22" ]]; then
                printf_description "  ${C_YELLOW}● Порт ${C_CYAN}${port}${C_RESET} ${C_GRAY}(стандартный)${C_RESET}"
            else
                printf_description "  ${C_GREEN}● Порт ${C_CYAN}${port}${C_RESET} ${C_GRAY}(кастомный)${C_RESET}"
            fi
        done <<< "$ports"
    fi

    # Статус sshd
    if systemctl is-active --quiet sshd 2>/dev/null || systemctl is-active --quiet ssh 2>/dev/null; then
        printf_description "  Сервис SSH: ${C_GREEN}Работает${C_RESET}"
    else
        printf_description "  Сервис SSH: ${C_RED}Не работает${C_RESET}"
    fi

    print_separator
}

_ssh_add_port() {
    print_separator
    info "Добавление нового SSH порта"
    print_separator

    local new_port
    new_port=$(ask_non_empty "Введите новый SSH порт") || return

    if ! validate_port "$new_port"; then
        err "Некорректный номер порта."
        return
    fi

    # Проверяем, не используется ли порт уже
    if grep -qE "^\s*Port\s+${new_port}\b" /etc/ssh/sshd_config 2>/dev/null; then
        warn "Порт ${new_port} уже настроен в SSH."
        return
    fi

    # Проверяем, свободен ли порт
    if ss -tlnp | grep -q ":${new_port} " 2>/dev/null; then
        warn "Порт ${new_port} уже занят другим сервисом!"
        if ! ask_yes_no "Всё равно добавить?" "n"; then
            return
        fi
    fi

    if ! ask_yes_no "Добавить SSH порт ${new_port}? (Firewall будет обновлен автоматически)"; then
        info "Отмена."
        return
    fi

    # --- Бэкап ---
    run_cmd cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

    # --- Добавляем порт в sshd_config ---
    # Если в конфиге нет ни одной строки Port — добавляем текущий (22) и новый
    if ! grep -qE "^\s*Port\s+" /etc/ssh/sshd_config 2>/dev/null; then
        info "В конфиге нет явного порта. Добавляю Port 22 и Port ${new_port}..."
        run_cmd sed -i "1a Port 22\nPort ${new_port}" /etc/ssh/sshd_config
    else
        # Добавляем после последней строки Port
        local last_port_line
        last_port_line=$(grep -nE "^\s*Port\s+" /etc/ssh/sshd_config | tail -1 | cut -d: -f1)
        run_cmd sed -i "${last_port_line}a Port ${new_port}" /etc/ssh/sshd_config
    fi

    ok "Порт ${new_port} добавлен в sshd_config."

    # --- UFW ---
    if command -v ufw &>/dev/null; then
        info "Обновляю правила firewall..."
        run_cmd ufw allow "${new_port}/tcp" comment "SSH Custom Port"
        ok "UFW: порт ${new_port}/tcp открыт."
    fi

    # --- Fail2Ban ---
    _ssh_update_fail2ban_ports

    # --- Перезапуск SSH ---
    info "Перезапускаю SSH..."
    run_cmd systemctl restart sshd 2>/dev/null || run_cmd systemctl restart ssh 2>/dev/null

    if systemctl is-active --quiet sshd 2>/dev/null || systemctl is-active --quiet ssh 2>/dev/null; then
        ok "SSH перезапущен. Новый порт ${C_CYAN}${new_port}${C_RESET} активен."
        echo ""
        printf_critical_warning "НЕ ЗАКРЫВАЙТЕ текущую сессию! Откройте НОВОЕ окно и проверьте подключение по порту ${new_port}."
    else
        err "SSH не удалось перезапустить! Восстанавливаю бэкап..."
        run_cmd cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
        run_cmd systemctl restart sshd 2>/dev/null || run_cmd systemctl restart ssh 2>/dev/null
        err "Бэкап восстановлен. Порт НЕ добавлен."
    fi
}

_ssh_remove_port() {
    print_separator
    info "Удаление SSH порта"
    print_separator

    # Получаем список текущих портов
    local ports
    mapfile -t ports < <(grep -E "^\s*Port\s+" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')

    if [[ ${#ports[@]} -le 1 ]]; then
        err "Нельзя удалить единственный SSH порт! Сначала добавьте другой."
        return
    fi

    info "Текущие SSH порты:"
    local i=1
    for port in "${ports[@]}"; do
        printf_description "  ${C_WHITE}${i})${C_RESET} Порт ${C_CYAN}${port}${C_RESET}"
        ((i++))
    done

    local del_port
    del_port=$(ask_non_empty "Введите порт для удаления") || return

    # Проверяем, что порт есть в конфиге
    if ! printf '%s\n' "${ports[@]}" | grep -qx "$del_port"; then
        err "Порт ${del_port} не найден в конфиге SSH."
        return
    fi

    # Проверяем, что это не единственный порт
    if [[ ${#ports[@]} -le 1 ]]; then
        err "Нельзя удалить последний SSH порт!"
        return
    fi

    # Предупреждаем если удаляем стандартный порт 22
    if [[ "$del_port" == "22" ]]; then
        warn "Вы удаляете стандартный порт 22! Убедитесь, что знаете другой порт SSH."
    fi

    if ! ask_yes_no "Удалить SSH порт ${del_port}?"; then
        info "Отмена."
        return
    fi

    # --- Бэкап ---
    run_cmd cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

    # --- Удаляем порт ---
    run_cmd sed -i "/^\s*Port\s\+${del_port}\b/d" /etc/ssh/sshd_config
    ok "Порт ${del_port} удален из sshd_config."

    # --- UFW ---
    if command -v ufw &>/dev/null; then
        info "Обновляю правила firewall..."
        run_cmd ufw delete allow "${del_port}/tcp" 2>/dev/null || true
        ok "UFW: правило для порта ${del_port}/tcp удалено."
    fi

    # --- Fail2Ban ---
    _ssh_update_fail2ban_ports

    # --- Перезапуск SSH ---
    info "Перезапускаю SSH..."
    run_cmd systemctl restart sshd 2>/dev/null || run_cmd systemctl restart ssh 2>/dev/null

    if systemctl is-active --quiet sshd 2>/dev/null || systemctl is-active --quiet ssh 2>/dev/null; then
        ok "SSH перезапущен. Порт ${C_CYAN}${del_port}${C_RESET} закрыт."
    else
        err "SSH не удалось перезапустить! Восстанавливаю бэкап..."
        run_cmd cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
        run_cmd systemctl restart sshd 2>/dev/null || run_cmd systemctl restart ssh 2>/dev/null
        err "Бэкап восстановлен."
    fi
}

# Обновляем порт SSH в Fail2Ban jail.local
_ssh_update_fail2ban_ports() {
    if [[ ! -f "/etc/fail2ban/jail.local" ]]; then
        return
    fi

    local ssh_ports
    ssh_ports=$(grep -E "^\s*Port\s+" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | paste -sd "," -)
    ssh_ports=${ssh_ports:-22}

    info "Обновляю порты SSH в Fail2Ban: ${ssh_ports}"
    # Обновляем порт в секции [sshd]
    run_cmd sed -i "/^\[sshd\]/,/^\[/ s/^port\s*=.*/port = ${ssh_ports}/" /etc/fail2ban/jail.local
    run_cmd systemctl reload fail2ban 2>/dev/null || true
}
