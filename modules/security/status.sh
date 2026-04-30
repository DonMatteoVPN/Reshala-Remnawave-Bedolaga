#!/bin/bash
#   ( РОДИТЕЛЬ | КЛАВИША | НАЗВАНИЕ | ФУНКЦИЯ | ПОРЯДОК | ГРУППА | ОПИСАНИЕ )
# @menu.manifest
# @item( security | 6 | 📊 Полный статус защиты | show_full_security_status | 60 | 10 | Сводный отчет по всем компонентам. )
#
# status.sh - Полный статус безопасности
#
# TG_ACTION_PARENT: main
# TG_ACTION_ORDER: 10
# TG_ACTION_TITLE: 📊 Полный статус защиты
# TG_ACTION_CMD: run_module security/status show_full_security_status_bot

show_full_security_status() {
    local LABEL_WIDTH=28 # Define a local width for this screen

    menu_header "📊 Полный статус защиты"
    
    # --- SSH ---
    print_section_title "SSH"
    local ssh_config="/etc/ssh/sshd_config"
    local ssh_ports
    ssh_ports=$(grep -E "^\s*Port\s+" "$ssh_config" 2>/dev/null | awk '{print $2}' | paste -sd ", " -)
    print_key_value "Порт(ы)" "${ssh_ports:-22}" "$LABEL_WIDTH"
    
    if [[ -f "$ssh_config" ]] && grep -qi "^PasswordAuthentication no" "$ssh_config" 2>/dev/null; then
        print_key_value "Вход по паролю" "${C_GREEN}Отключен${C_RESET}" "$LABEL_WIDTH"
    else
        print_key_value "Вход по паролю" "${C_RED}Включен (небезопасно!)${C_RESET}" "$LABEL_WIDTH"
    fi

    # --- Firewall (UFW) ---
    print_section_title "Firewall (UFW)"
    if ! command -v ufw &> /dev/null; then
        print_key_value "Статус" "${C_YELLOW}Не установлен${C_RESET}" "$LABEL_WIDTH"
    elif run_cmd ufw status | grep -q "inactive"; then
        print_key_value "Статус" "${C_RED}Не активен${C_RESET}" "$LABEL_WIDTH"
    else
        local rules_count
        rules_count=$(run_cmd ufw status | grep -c "ALLOW")
        print_key_value "Статус" "${C_GREEN}Активен${C_RESET} (${rules_count} правил)" "$LABEL_WIDTH"
    fi
    
    # --- Fail2Ban ---
    print_section_title "Fail2Ban"
    if ! command -v fail2ban-client &> /dev/null; then
        print_key_value "Статус" "${C_YELLOW}Не установлен${C_RESET}" "$LABEL_WIDTH"
    elif ! systemctl is-active --quiet fail2ban 2>/dev/null; then
        print_key_value "Статус" "${C_RED}Сервис не активен${C_RESET}" "$LABEL_WIDTH"
    else
        local banned
        banned=$(run_cmd fail2ban-client status sshd 2>/dev/null | grep "Currently banned" | awk '{print $4}')
        print_key_value "Статус" "${C_GREEN}Активен${C_RESET}" "$LABEL_WIDTH"
        print_key_value "Сейчас забанено (sshd)" "${banned:-0}" "$LABEL_WIDTH"
    fi

    # --- Geo-Block ---
    print_section_title "Geo-Block"
    if command -v ipset &>/dev/null && ipset list reshala_geoblock &>/dev/null 2>&1; then
        local geo_count
        geo_count=$(ipset list reshala_geoblock 2>/dev/null | grep -c "^[0-9]" || echo "0")
        print_key_value "Статус" "${C_GREEN}Активен${C_RESET}" "$LABEL_WIDTH"
        print_key_value "Заблокировано подсетей" "${geo_count}" "$LABEL_WIDTH"
    else
        print_key_value "Статус" "${C_YELLOW}Не активен${C_RESET}" "$LABEL_WIDTH"
    fi

    # --- Глобальный Белый Список ---
    print_section_title "Глобальный Белый Список"
    if [[ -f "/etc/reshala/global-whitelist.txt" ]]; then
        local wl_count
        wl_count=$(grep -v '^\s*#' /etc/reshala/global-whitelist.txt 2>/dev/null | grep -vc '^\s*$' || echo "0")
        print_key_value "IP в списке" "${C_CYAN}${wl_count}${C_RESET}" "$LABEL_WIDTH"
    else
        print_key_value "Статус" "${C_YELLOW}Не настроен${C_RESET}" "$LABEL_WIDTH"
    fi

    # --- Kernel Hardening ---
    print_section_title "Kernel Hardening"
    if [[ -f "/etc/sysctl.d/99-reshala-hardening.conf" ]]; then
        local syn_cookies
        syn_cookies=$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null)
        if [[ "$syn_cookies" == "1" ]]; then
            print_key_value "Статус" "${C_GREEN}Применен${C_RESET}" "$LABEL_WIDTH"
            print_key_value "  SYN Cookies" "${C_GREEN}Включены${C_RESET}" "$LABEL_WIDTH"
        else
            print_key_value "Статус" "${C_YELLOW}Применен (не все параметры активны)${C_RESET}" "$LABEL_WIDTH"
        fi
    else
        print_key_value "Статус" "${C_YELLOW}Не применялся${C_RESET}" "$LABEL_WIDTH"
    fi
    
    # --- Rkhunter ---
    print_section_title "Сканер руткитов (rkhunter)"
    if ! command -v rkhunter &> /dev/null; then
        print_key_value "Статус" "${C_YELLOW}Не установлен${C_RESET}" "$LABEL_WIDTH"
    else
        if [[ -f "/etc/cron.weekly/reshala-rkhunter-scan" ]]; then
            print_key_value "Еженедельное сканирование" "${C_GREEN}Включено${C_RESET}" "$LABEL_WIDTH"
        else
            print_key_value "Еженедельное сканирование" "${C_RED}Выключено${C_RESET}" "$LABEL_WIDTH"
        fi
    fi
    
    echo ""
}

# Версия для вывода в бот: без заголовков и ожиданий, только текст в Markdown.
show_full_security_status_bot() {
    local output="*📊 Полный статус защиты*\n\n"
    
    # --- SSH ---
    output+="*SSH*\n"
    local ssh_config="/etc/ssh/sshd_config"
    local ssh_port
    ssh_port=$(grep "^Port " "$ssh_config" 2>/dev/null | awk '{print $2}')
    output+="Порт: \`${ssh_port:-22}\`\n"
    
    if [[ -f "$ssh_config" ]] && grep -qi "^PasswordAuthentication no" "$ssh_config" 2>/dev/null; then
        output+="Вход по паролю: *Отключен*\n\n"
    else
        output+="Вход по паролю: *Включен (небезопасно!)*\n\n"
    fi

    # --- Firewall (UFW) ---
    output+="*Firewall (UFW)*\n"
    if ! command -v ufw &> /dev/null; then
        output+="Статус: *Не установлен*\n\n"
    elif ufw status 2>/dev/null | grep -q "inactive"; then
        output+="Статус: *Не активен*\n\n"
    else
        local rules_count
        rules_count=$(ufw status 2>/dev/null | grep -c "ALLOW")
        output+="Статус: *Активен* (${rules_count} правил)\n\n"
    fi
    
    # --- Fail2Ban ---
    output+="*Fail2Ban*\n"
    if ! command -v fail2ban-client &> /dev/null; then
        output+="Статус: *Не установлен*\n\n"
    elif ! systemctl is-active --quiet fail2ban 2>/dev/null; then
        output+="Статус: *Сервис не активен*\n\n"
    else
        local banned
        banned=$(fail2ban-client status sshd 2>/dev/null | grep "Currently banned" | awk '{print $4}')
        output+="Статус: *Активен*\n"
        output+="Сейчас забанено (sshd): \`${banned:-0}\`\n\n"
    fi

    # --- Kernel Hardening ---
    output+="*Kernel Hardening*\n"
    if [[ -f "/etc/sysctl.d/99-reshala-hardening.conf" ]]; then
        output+="Статус: *Применен*\n\n"
    else
        output+="Статус: *Не применялся*\n\n"
    fi
    
    # --- Rkhunter ---
    output+="*Сканер руткитов (rkhunter)*\n"
    if ! command -v rkhunter &> /dev/null; then
        output+="Статус: *Не установлен*\n\n"
    else
        if [[ -f "/etc/cron.weekly/reshala-rkhunter-scan" ]]; then
            output+="Еженедельное сканирование: *Включено*\n"
        else
            output+="Еженедельное сканирование: *Выключено*\n"
        fi
    fi
    
    echo -e "$output"
}