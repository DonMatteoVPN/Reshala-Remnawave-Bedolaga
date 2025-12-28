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
    local ssh_port
    ssh_port=$(grep "^Port " /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    print_key_value "Порт" "${ssh_port:-22}" "$LABEL_WIDTH"
    
    if grep -qi "^PasswordAuthentication no" /etc/ssh/sshd_config;
 then
        print_key_value "Вход по паролю" "${C_GREEN}Отключен${C_RESET}" "$LABEL_WIDTH"
    else
        print_key_value "Вход по паролю" "${C_RED}Включен (небезопасно!)${C_RESET}" "$LABEL_WIDTH"
    fi

    # --- Firewall (UFW) ---
    print_section_title "Firewall (UFW)"
    if ! command -v ufw &> /dev/null;
 then
        print_key_value "Статус" "${C_YELLOW}Не установлен${C_RESET}" "$LABEL_WIDTH"
    elif run_cmd ufw status | grep -q "inactive";
 then
        print_key_value "Статус" "${C_RED}Не активен${C_RESET}" "$LABEL_WIDTH"
    else
        local rules_count
        rules_count=$(run_cmd ufw status | grep -c "ALLOW")
        print_key_value "Статус" "${C_GREEN}Активен${C_RESET} (${rules_count} правил)" "$LABEL_WIDTH"
    fi
    
    # --- Fail2Ban ---
    print_section_title "Fail2Ban"
    if ! command -v fail2ban-client &> /dev/null;
 then
        print_key_value "Статус" "${C_YELLOW}Не установлен${C_RESET}" "$LABEL_WIDTH"
    elif ! systemctl is-active --quiet fail2ban;
 then
        print_key_value "Статус" "${C_RED}Сервис не активен${C_RESET}" "$LABEL_WIDTH"
    else
        local banned
        banned=$(run_cmd fail2ban-client status sshd 2>/dev/null | grep "Currently banned" | awk '{print $4}')
        print_key_value "Статус" "${C_GREEN}Активен${C_RESET}" "$LABEL_WIDTH"
        print_key_value "Сейчас забанено (sshd)" "${banned:-0}" "$LABEL_WIDTH"
    fi

    # --- Kernel Hardening ---
    print_section_title "Kernel Hardening"
    if [[ -f "/etc/sysctl.d/99-reshala-hardening.conf" ]];
 then
        local syn_cookies
        syn_cookies=$(run_cmd sysctl -n net.ipv4.tcp_syncookies 2>/dev/null)
        if [[ "$syn_cookies" == "1" ]];
 then
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
    if ! command -v rkhunter &> /dev/null;
 then
        print_key_value "Статус" "${C_YELLOW}Не установлен${C_RESET}" "$LABEL_WIDTH"
    else
        if [[ -f "/etc/cron.weekly/reshala-rkhunter-scan" ]];
 then
            print_key_value "Еженедельное сканирование" "${C_GREEN}Включено${C_RESET}" "$LABEL_WIDTH"
        else
            print_key_value "Еженедельное сканирование" "${C_RED}Выключено${C_RESET}" "$LABEL_WIDTH"
        fi
    fi
    
    echo ""
    wait_for_enter
}

# Версия для вывода в бот: без заголовков и ожиданий, только текст в Markdown.
show_full_security_status_bot() {
    local output="*📊 Полный статус защиты*\n\n"
    
    # --- SSH ---
    output+="*SSH*\n"
    local ssh_port
    ssh_port=$(grep "^Port " /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    output+="Порт: \`${ssh_port:-22}\`\n"
    
    if grep -qi "^PasswordAuthentication no" /etc/ssh/sshd_config;
 then
        output+="Вход по паролю: *Отключен*\n\n"
    else
        output+="Вход по паролю: *Включен (небезопасно!)*\n\n"
    fi

    # --- Firewall (UFW) ---
    output+="*Firewall (UFW)*\n"
    if ! command -v ufw &> /dev/null;
 then
        output+="Статус: *Не установлен*\n\n"
    elif run_cmd ufw status | grep -q "inactive";
 then
        output+="Статус: *Не активен*\n\n"
    else
        local rules_count
        rules_count=$(run_cmd ufw status | grep -c "ALLOW")
        output+="Статус: *Активен* (${rules_count} правил)\n\n"
    fi
    
    # --- Fail2Ban ---
    output+="*Fail2Ban*\n"
    if ! command -v fail2ban-client &> /dev/null;
 then
        output+="Статус: *Не установлен*\n\n"
    elif ! systemctl is-active --quiet fail2ban;
 then
        output+="Статус: *Сервис не активен*\n\n"
    else
        local banned
        banned=$(run_cmd fail2ban-client status sshd 2>/dev/null | grep "Currently banned" | awk '{print $4}')
        output+="Статус: *Активен*\n"
        output+="Сейчас забанено (sshd): \`${banned:-0}\`\n\n"
    fi

    # --- Kernel Hardening ---
    output+="*Kernel Hardening*\n"
    if [[ -f "/etc/sysctl.d/99-reshala-hardening.conf" ]];
 then
        output+="Статус: *Применен*\n\n"
    else
        output+="Статус: *Не применялся*\n\n"
    fi
    
    # --- Rkhunter ---
    output+="*Сканер руткитов (rkhunter)*\n"
    if ! command -v rkhunter &> /dev/null;
 then
        output+="Статус: *Не установлен*\n\n"
    else
        if [[ -f "/etc/cron.weekly/reshala-rkhunter-scan" ]];
 then
            output+="Еженедельное сканирование: *Включено*\n"
        else
            output+="Еженедельное сканирование: *Выключено*\n"
        fi
    fi
    
    echo -e "$output"
}