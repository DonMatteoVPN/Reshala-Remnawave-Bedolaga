#!/bin/bash
#   ( РОДИТЕЛЬ | КЛАВИША | НАЗВАНИЕ | ФУНКЦИЯ | ПОРЯДОК | ГРУППА | ОПИСАНИЕ )
# @menu.manifest
# @item( security | 2 | 🤖 Fail2Ban | show_fail2ban_menu | 20 | 10 | Автоматическая блокировка атакующих IP. )
#
# fail2ban.sh - Управление Fail2Ban
#

F2B_WHITELIST_FILE="/etc/reshala/fail2ban-whitelist.txt"


show_fail2ban_menu() {
    while true; do
        clear
        enable_graceful_ctrlc
        menu_header "🤖 Управление Fail2Ban"
        
        echo -e "  ${C_CYAN}╔══════════════════════════════════════════════════════════╗${C_RESET}"
        echo -e "  ${C_CYAN}║${C_RESET}  ${C_YELLOW}🤖 Управление Fail2Ban${C_RESET}"
        echo -e "  ${C_CYAN}╠══════════════════════════════════════════════════════════╣${C_RESET}"
        echo -e "  ${C_CYAN}║${C_RESET}  ${C_WHITE}Что это:${C_RESET} Автоматическая защита от перебора паролей."
        echo -e "  ${C_CYAN}║${C_RESET}  ${C_WHITE}Как работает:${C_RESET} Сканирует логи сервисов (SSH, Nginx) и"
        echo -e "  ${C_CYAN}║${C_RESET}  автоматически банит IP-адреса злоумышленников в Firewall"
        echo -e "  ${C_CYAN}║${C_RESET}  при превышении лимита неудачных попыток входа."
        echo -e "  ${C_CYAN}╚══════════════════════════════════════════════════════════╝${C_RESET}"
        echo ""

        echo -e "  ${C_WHITE}📈 МОНИТОРИНГ:${C_RESET}"
        _f2b_check_status
        
        local wl_count=0
        if [[ -f "$F2B_WHITELIST_FILE" ]]; then
            wl_count=$(grep -v '^\s*#' "$F2B_WHITELIST_FILE" | grep -v '^\s*$' | wc -l)
        fi
        # Если локальный список Fail2Ban пуст, проверим Глобальный Белый Список
        if [[ "$wl_count" -eq 0 ]] && command -v global_whitelist_count &>/dev/null; then
            wl_count=$(global_whitelist_count)
        fi
        
        local wl_status="${C_GRAY}[0]${C_RESET}"
        if [[ "$wl_count" -gt 0 ]]; then 
            wl_status="${C_GREEN}[✓ IP: ${wl_count}]${C_RESET}"
        fi

        echo ""
        if ! command -v fail2ban-client &> /dev/null; then
            printf_menu_option "i" "УСТАНОВИТЬ FAIL2BAN" "${C_YELLOW}"
        else
            printf_menu_option "1" "Список забаненных IP"
            printf_menu_option "2" "Разбанить IP"
            printf_menu_option "3" "Забанить IP вручную"
            printf_menu_option "4" "🛡️  Белый список (Whitelist)  ${wl_status}"
            printf_menu_option "5" "⚙️ Настройки (бан, доп. защита)"
            print_separator "-" 40
            printf_menu_option "6" "🔔 Уведомления Telegram"
            echo ""
            printf_menu_option "s" "Перезапустить сервис"
        fi
        
        echo ""
        printf_menu_option "b" "Назад"
        echo ""

        local choice
        choice=$(safe_read "Выберите действие" "") || { break; }
        
        case "$choice" in
            1) _f2b_show_banned; wait_for_enter;;
            2) _f2b_unban_ip; wait_for_enter;;
            3) _f2b_ban_ip; wait_for_enter;;
            4) _f2b_whitelist_menu; wait_for_enter;;
            5) _f2b_settings_menu;;
            6) _f2b_notifications_menu; wait_for_enter;;
            i|I) _f2b_setup; wait_for_enter;;
            s|S)
                if ! command -v fail2ban-client &> /dev/null; then
                    warn "Fail2Ban не установлен."
                else
                    info "Перезапускаю Fail2Ban..."
                    run_cmd systemctl restart fail2ban
                    ok "Сервис перезапущен."
                fi
                wait_for_enter
                ;;
            b | B) break;;
            *) warn "Неверный выбор";;
        esac
        disable_graceful_ctrlc
    done
}

_f2b_settings_menu() {
    while true; do
        clear
        enable_graceful_ctrlc
        menu_header "⚙️ Настройки Fail2Ban"
        printf_description "Управление временем бана и дополнительными модулями защиты."
        
        echo ""
        printf_menu_option "1" "Настройки времени бана"
        printf_menu_option "2" "Расширенная защита (доп. Jails)"
        echo ""
        printf_menu_option "b" "Назад"
        echo ""

        local choice
        choice=$(safe_read "Выберите действие" "") || { break; }
        
        case "$choice" in
            1) _f2b_bantime_menu; wait_for_enter;;
            2) _f2b_extended_menu; wait_for_enter;;
            b|B) break;;
            *) warn "Неверный выбор";;
        esac
        disable_graceful_ctrlc
    done
}

_f2b_check_status() {
    if ! command -v fail2ban-client &> /dev/null; then
        echo -e "    ${C_YELLOW}⚠ Fail2Ban не обнаружен. Нажмите [i] для установки.${C_RESET}"
        return 1
    fi

    if systemctl is-active --quiet fail2ban; then
        local jails_list; jails_list=$(run_cmd fail2ban-client status 2>/dev/null | grep "Jail list:" | cut -d: -f2 | sed 's/,//g' | xargs)
        local jails_count=$(echo "$jails_list" | wc -w)
        
        local bt; bt=$(get_config_var "F2B_BANTIME" "86400")
        local bt_h; if [[ "$bt" == "-1" ]]; then bt_h="Навсегда"; elif [[ "$bt" -lt 3600 ]]; then bt_h="$((bt/60)) мин"; elif [[ "$bt" -lt 86400 ]]; then bt_h="$((bt/3600)) ч"; else bt_h="$((bt/86400)) дн"; fi

        echo -e "    ${C_GREEN}●${C_RESET} ${C_WHITE}Состояние:${C_RESET} ${C_GREEN}Активен${C_RESET} ${C_GRAY}(Всего защит: ${jails_count})${C_RESET}"
        
        for jail in $jails_list; do
            local banned; banned=$(run_cmd fail2ban-client status "$jail" 2>/dev/null | grep "Currently banned" | awk '{print $4}' || echo "0")
            local total; total=$(run_cmd fail2ban-client status "$jail" 2>/dev/null | grep "Total banned" | awk '{print $4}' || echo "0")
            
            local display_name="$jail"
            case "$jail" in
                sshd) display_name="Защита SSH" ;;
                portscan-reshala) display_name="Порт-скан" ;;
                nginx-auth-reshala) display_name="Nginx Auth" ;;
                nginx-bots-reshala) display_name="Nginx Bots" ;;
                nginx-scanners-reshala) display_name="Nginx Scan" ;;
                custom-*) display_name="Кастом: ${jail#custom-}" ;;
            esac

            echo -e "    ${C_GRAY}├──${C_RESET} ${C_WHITE}${display_name}:${C_RESET} ${C_RED}${banned}${C_RESET} ${C_GRAY}бан${C_RESET} / ${C_CYAN}${total}${C_RESET} ${C_GRAY}всего${C_RESET}"
        done
        
        echo -e "    ${C_GRAY}└──${C_RESET} ${C_WHITE}Срок бана:${C_RESET}   ${C_YELLOW}${bt_h}${C_RESET}"
    else
        echo -e "    ${C_RED}✖ СТАТУС: СЕРВИС ВЫКЛЮЧЕН${C_RESET}"
    fi
}

_f2b_show_banned() {
    print_separator
    info "Список забаненных IP (sshd jail)"
    print_separator
    
    local banned_list
    banned_list=$(run_cmd fail2ban-client status sshd 2>/dev/null | grep "Banned IP list" | cut -d: -f2)
    
    if [[ -n "$banned_list" ]]; then
        for ip in $banned_list; do
            printf_description "● $ip"
        done
    else
        ok "Сейчас нет забаненных IP в sshd jail."
    fi
}

_f2b_unban_ip() {
    print_separator
    info "Разбанить IP"
    print_separator

    local ip_to_unban
    ip_to_unban=$(ask_non_empty "Введите IP для разбана") || return
    if ! validate_ip "$ip_to_unban"; then
        err "Некорректный IP адрес."
        return
    fi

    if run_cmd fail2ban-client set sshd unbanip "$ip_to_unban"; then
        ok "IP $ip_to_unban разбанен в sshd jail."
    else
        err "Не удалось разбанить IP $ip_to_unban. Проверьте, забанен ли он."
    fi
}

_f2b_ban_ip() {
    print_separator
    info "Забанить IP вручную"
    print_separator

    local ip_to_ban
    ip_to_ban=$(ask_non_empty "Введите IP для бана") || return
    if ! validate_ip "$ip_to_ban"; then
        err "Некорректный IP адрес."
        return
    fi

    if run_cmd fail2ban-client set sshd banip "$ip_to_ban"; then
        ok "IP $ip_to_ban забанен в sshd jail."
    else
        err "Не удалось забанить IP $ip_to_ban."
    fi
}

_f2b_bantime_menu() {
    print_separator
    info "Настройка времени бана"
    print_separator
    
    local current_bantime
    current_bantime=$(get_config_var "F2B_BANTIME" "86400")

    local current_human
    if [[ "$current_bantime" == "-1" ]]; then
        current_human="Навсегда"
    elif [[ -z "$current_bantime" ]]; then
        current_human="Неизвестно"
    elif [[ "$current_bantime" -lt 60 ]]; then
        current_human="${current_bantime} сек"
    elif [[ "$current_bantime" -lt 3600 ]]; then
        current_human="$((current_bantime / 60)) мин"
    elif [[ "$current_bantime" -lt 86400 ]]; then
        current_human="$((current_bantime / 3600)) ч"
    else
        current_human="$((current_bantime / 86400)) дней"
    fi
    printf_description "Текущее время бана: ${C_CYAN}$current_human${C_RESET}"
    echo ""

    local bantime_options=("1 час" "24 часа" "7 дней" "Навсегда" "⏱️ Указать вручную (в минутах)")
    local bantime_values=("3600" "86400" "604800" "-1" "custom")
    
    local bantime_choice
    bantime_choice=$(ask_selection "Выберите новое время бана:" "${bantime_options[@]}") || return
    local new_bantime=${bantime_values[$((bantime_choice-1))]}

    if [[ "$new_bantime" == "custom" ]]; then
        local custom_mins
        custom_mins=$(safe_read "Введите время бана в минутах (например, 10)") || return
        if [[ ! "$custom_mins" =~ ^[0-9]+$ ]] || [[ "$custom_mins" -lt 1 ]]; then
            err "Ошибка: нужно ввести положительное число."
            return
        fi
        new_bantime=$((custom_mins * 60))
    fi

    if [[ "$current_bantime" == "$new_bantime" ]]; then
        info "Время бана не изменилось."
        return
    fi
    
    set_config_var "F2B_BANTIME" "$new_bantime"
    
    if [[ -f "/etc/fail2ban/jail.local" ]]; then
        info "Обновляю bantime в /etc/fail2ban/jail.local..."
        run_cmd sed -i "s/^bantime = .*/bantime = $new_bantime/" /etc/fail2ban/jail.local
        info "Перезапускаю Fail2Ban для применения изменений..."
        run_cmd systemctl restart fail2ban
        ok "Время бана обновлено."
    else
        warn "Файл /etc/fail2ban/jail.local не найден. Настройка сохранена, но не применена."
        warn "Запустите 'Установить и настроить Fail2Ban', чтобы создать конфиг."
    fi
}

_f2b_update_ignoreip() {
    if [[ ! -f "/etc/fail2ban/jail.local" ]]; then
        return
    fi
    
    local whitelist_ips="127.0.0.1/8 ::1"
    if [[ -f "$F2B_WHITELIST_FILE" ]]; then
        whitelist_ips="$whitelist_ips $(run_cmd cat $F2B_WHITELIST_FILE | grep -v '^\s*#' | grep -v '^\s*$' | tr '\n' ' ')"
    fi
    
    info "Обновляю ignoreip в /etc/fail2ban/jail.local..."
    run_cmd sed -i -e "s,^ignoreip\s*=.*,ignoreip = $whitelist_ips," /etc/fail2ban/jail.local
    run_cmd systemctl reload fail2ban
    ok "Whitelist в Fail2Ban обновлен."
}

_f2b_whitelist_menu() {
    # 1. Проверяем синхронизацию с Глобальным Белым Списком
    local global_file="/etc/reshala/global-whitelist.txt"
    if [[ -f "$global_file" ]]; then
        local is_synced=false
        if [[ -f "$F2B_WHITELIST_FILE" ]]; then
            local local_sum; local_sum=$(grep -v '^\s*#' "$F2B_WHITELIST_FILE" | grep -v '^\s*$' | sort | md5sum | awk '{print $1}')
            local global_sum; global_sum=$(grep -v '^\s*#' "$global_file" | grep -v '^\s*$' | sort | md5sum | awk '{print $1}')
            [[ "$local_sum" == "$global_sum" ]] && is_synced=true
        fi

        if [[ "$is_synced" == "true" ]]; then
            echo -e "  ${C_GREEN}✓ Текущий список синхронизирован с Глобальным Белым Списком.${C_RESET}"
            echo -e "  ${C_GRAY}Изменения в Глобальном списке будут автоматически применяться здесь.${C_RESET}"
            echo ""
        else
            if global_whitelist_offer "Fail2Ban"; then
                info "Копирую IP из Глобального Белого Списка в Fail2Ban..."
                run_cmd cp -f "$global_file" "$F2B_WHITELIST_FILE" 2>/dev/null || true
                _f2b_update_ignoreip
                wait_for_enter
                return
            fi
        fi
    fi

    # Ensure directory exists
    run_cmd mkdir -p /etc/reshala
    # Ensure file exists
    run_cmd touch "$F2B_WHITELIST_FILE"

    while true; do
        clear
        enable_graceful_ctrlc
        menu_header "📋 Whitelist Fail2Ban"
        printf_description "IP-адреса в этом списке никогда не будут забанены."
        
        print_separator
        if [[ -s "$F2B_WHITELIST_FILE" ]]; then
            info "Текущий whitelist:"
            grep -v '^\s*#' "$F2B_WHITELIST_FILE" | grep -v '^\s*$' | while read -r ip; do
                printf_description "● $ip"
            done
        else
            warn "Whitelist пуст."
        fi
        print_separator

        echo ""
        printf_menu_option "1" "Добавить IP в whitelist"
        printf_menu_option "2" "Удалить IP из whitelist"
        echo ""
        printf_menu_option "b" "Назад"
        echo ""

        local choice
        choice=$(safe_read "Выберите действие") || { break; }

        case "$choice" in
            1)
                local ip_to_add
                ip_to_add=$(ask_non_empty "Какой IP добавить?") || continue
                if ! validate_ip "$ip_to_add"; then
                    err "Некорректный IP адрес."
                    continue
                fi
                if grep -q "$ip_to_add" "$F2B_WHITELIST_FILE"; then
                    warn "IP $ip_to_add уже в whitelist."
                else
                    echo "$ip_to_add" | run_cmd tee -a "$F2B_WHITELIST_FILE" > /dev/null
                    ok "IP $ip_to_add добавлен в whitelist."
                    _f2b_update_ignoreip
                fi
                wait_for_enter
                ;;
            2)
                local ip_to_remove
                ip_to_remove=$(ask_non_empty "Какой IP удалить?") || continue
                if ! grep -q "$ip_to_remove" "$F2B_WHITELIST_FILE"; then
                    err "IP $ip_to_remove не найден в whitelist."
                else
                    run_cmd sed -i "/^${ip_to_remove}$/d" "$F2B_WHITELIST_FILE"
                    ok "IP $ip_to_remove удален из whitelist."
                    _f2b_update_ignoreip
                fi
                wait_for_enter
                ;;
            b|B)
                break
                ;;
            *)
                warn "Неверный выбор"
                ;;
        esac
        disable_graceful_ctrlc
    done
}



_f2b_notifications_menu() {
    menu_header "🔔 Уведомления Telegram"
    print_separator
    info "Функционал уведомлений находится в стадии полной переработки."
    printf_description "Будет представлен новый, централизованный модуль Telegram,"
    printf_description "позволяющий гибко настраивать оповещения для всех компонентов системы."
    print_separator
}


_f2b_extended_menu() {
    while true; do
        clear
        enable_graceful_ctrlc
        menu_header "🛡️ Расширенная защита Fail2Ban"
        
        if [[ ! -f "/etc/fail2ban/jail.local" ]]; then
            warn "Файл /etc/fail2ban/jail.local не найден."
            warn "Сначала запустите 'Установить и настроить Fail2Ban'."
            wait_for_enter
            break
        fi

        # Check statuses
        local sshd_status="(${C_RED}выкл${C_RESET})"
        grep -A 2 "\[sshd\]" /etc/fail2ban/jail.local 2>/dev/null | grep -q "enabled\s*=\s*true" && \
            sshd_status="(${C_GREEN}вкл${C_RESET})"

        local portscan_status="(${C_RED}выкл${C_RESET})"
        grep -A 2 "\[portscan-reshala\]" /etc/fail2ban/jail.local 2>/dev/null | grep -q "enabled\s*=\s*true" && \
            portscan_status="(${C_GREEN}вкл${C_RESET})"
        
        local nginx_auth_status="(${C_RED}выкл${C_RESET})"
        grep -A 2 "\[nginx-auth-reshala\]" /etc/fail2ban/jail.local 2>/dev/null | grep -q "enabled\s*=\s*true" && \
            nginx_auth_status="(${C_GREEN}вкл${C_RESET})"
        
        local nginx_bots_status="(${C_RED}выкл${C_RESET})"
        grep -A 2 "\[nginx-bots-reshala\]" /etc/fail2ban/jail.local 2>/dev/null | grep -q "enabled\s*=\s*true" && \
            nginx_bots_status="(${C_GREEN}вкл${C_RESET})"

        local nginx_scanners_status="(${C_RED}выкл${C_RESET})"
        grep -A 2 "\[nginx-scanners-reshala\]" /etc/fail2ban/jail.local 2>/dev/null | grep -q "enabled\s*=\s*true" && \
            nginx_scanners_status="(${C_GREEN}вкл${C_RESET})"

        echo ""
        printf_menu_option "0" "Защита SSH (стандартная) $sshd_status"
        printf_menu_option "1" "Защита от сканирования портов $portscan_status"
        printf_menu_option "2" "Защита от брутфорса Nginx (HTTP auth) $nginx_auth_status"
        printf_menu_option "3" "Блокировка вредоносных ботов Nginx $nginx_bots_status"
        printf_menu_option "4" "Защита Nginx от сканеров (auto-detect) $nginx_scanners_status"
        
        # Scan for custom jails
        local custom_jails=()
        if ls /etc/fail2ban/filter.d/custom-*.conf 1> /dev/null 2>&1; then
            for conf_file in /etc/fail2ban/filter.d/custom-*.conf; do
                local j_name
                j_name=$(basename "$conf_file" .conf)
                custom_jails+=("$j_name")
            done
        fi
        
        if [[ ${#custom_jails[@]} -gt 0 ]]; then
            echo ""
            info "Пользовательские правила (Кастомные Jails):"
            local idx=5
            for j in "${custom_jails[@]}"; do
                local c_status="(${C_RED}выкл${C_RESET})"
                grep -A 2 "\[$j\]" /etc/fail2ban/jail.local 2>/dev/null | grep -q "enabled\s*=\s*true" && \
                    c_status="(${C_GREEN}вкл${C_RESET})"
                printf_menu_option "$idx" "${C_YELLOW}${j}${C_RESET} $c_status"
                ((idx++))
            done
        fi

        echo ""
        printf_menu_option "c" "➕ Создать свой Jail (Кастомная защита)"
        if [[ ${#custom_jails[@]} -gt 0 ]]; then
            printf_menu_option "r" "🗑️ Удалить кастомный Jail"
        fi
        echo ""
        printf_menu_option "a" "Включить все встроенные"
        printf_menu_option "d" "Выключить все встроенные"
        echo ""
        printf_menu_option "b" "Назад"
        echo ""

        local choice
        choice=$(safe_read "Выберите действие") || { break; }

        case "$choice" in
            0)
                local ssh_port; ssh_port=$(grep "^Port " /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
                ssh_port=${ssh_port:-22}
                # Для SSH мы не передаем фильтр (f), так как он стандартный в системе
                _f2b_jail_submenu "sshd" "syslog" "" "$ssh_port" "ufw[name=sshd, port=any, protocol=tcp]" "Стандартная защита SSH-доступа."
                ;;
            1) 
                local f="[Definition]\nfailregex = .*\[UFW BLOCK\] IN=.* SRC=<HOST> .*\nignoreregex ="
                _f2b_jail_submenu "portscan-reshala" "syslog" "$f" "any" "ufw[name=portscan, port=any, protocol=tcp]" "Защита от сканирования портов на основе логов UFW."
                ;;
            2) 
                local f="[Definition]\nfailregex = ^ \[error\] \d+#\d+: \*\d+ user \"\S+\":? (password mismatch|was not found in).*, client: <HOST>, server: \S+, request: \"\S+ \S+ HTTP/\d+\.\d+\", host: \"\S+\"\nignoreregex ="
                _f2b_jail_submenu "nginx-auth-reshala" "nginx-error" "$f" "any" "ufw[name=nginx-auth, port=any, protocol=tcp]" "Защита от подбора паролей HTTP Basic Auth в Nginx."
                ;;
            3) 
                local f="[Definition]\nfailregex = ^<HOST> -.*\"(GET|POST|HEAD).*HTTP.*\"(?:-|.*)\" \"(?:.*)(?:[A-Za-z0-9](?:ndroid|pache|oard|rowser|rawler|curl|iscovery|ownload|ot|enesis|ttp|ndex|ava|raw|ider|rchive|earch|eek|lurp|urvey|ycobot|get|ython|ruby|rust|un|eb|get|ync|pider|can|lurp).*)\"$\nignoreregex ="
                _f2b_jail_submenu "nginx-bots-reshala" "nginx-access" "$f" "any" "ufw[name=nginx-bots, port=any, protocol=tcp]" "Блокировка подозрительных ботов и парсеров в Nginx."
                ;;
            4) 
                local f="[Definition]\nfailregex = ^<HOST> .* \"(GET|POST|HEAD) .*(\\.php|\\.env|\\.git|\\.asp|wp-login|wp-admin|cgi-bin|/admin|/config|/setup|\\.sql|shell|eval|passwd|\\.bak).*\" (400|403|404|444)\n            ^<HOST> .* \"(GET|POST) .*(xmlrpc|wp-cron|wp-json/wp/v2/users).*\" (403|404)\nignoreregex ="
                _f2b_jail_submenu "nginx-scanners-reshala" "nginx-access" "$f" "any" "ufw[name=nginx-scanners, port=any, protocol=tcp]" "Защита от сканирования уязвимостей и админок (404/403 ошибки)."
                ;;
            c|C)
                local custom_name
                custom_name=$(ask_non_empty "Введите имя (только англ. буквы, например: myapp)") || continue
                custom_name=$(echo "$custom_name" | tr -cd 'a-zA-Z0-9_-')
                if [[ -z "$custom_name" ]]; then
                    err "Имя не может быть пустым."
                    continue
                fi
                local jail_name="custom-${custom_name}"
                
                if [[ ! -f "/etc/fail2ban/filter.d/${jail_name}.conf" ]]; then
                    info "Создаю шаблон фильтра для ${jail_name}..."
                    run_cmd tee "/etc/fail2ban/filter.d/${jail_name}.conf" > /dev/null <<EOF
[Definition]
# Укажите регулярное выражение для поиска IP-адреса нарушителя.
# <HOST> - это специальный тег Fail2Ban, который захватывает IP.
failregex = ^<HOST> .* ".*"
ignoreregex =
EOF
                    ok "Создан: /etc/fail2ban/filter.d/${jail_name}.conf"
                fi
                
                # Открываем подменю для нового джейла!
                # Передаем пустое f, так как файл фильтра мы только что создали.
                _f2b_jail_submenu "$jail_name" "syslog" "" "any" "ufw[name=$jail_name, port=any, protocol=tcp]" "Кастомная защита: $jail_name"
                ;;
            r|R)
                if [[ ${#custom_jails[@]} -eq 0 ]]; then
                    warn "Нет кастомных защит для удаления."
                    continue
                fi
                echo ""
                info "Выберите Jail для удаления:"
                local i=1
                for j in "${custom_jails[@]}"; do
                    printf_menu_option "$i" "${C_YELLOW}${j}${C_RESET}"
                    ((i++))
                done
                local rm_choice
                rm_choice=$(safe_read "Номер") || continue
                if [[ "$rm_choice" =~ ^[0-9]+$ ]] && [[ "$rm_choice" -ge 1 ]] && [[ "$rm_choice" -le ${#custom_jails[@]} ]]; then
                    local jail_to_rm="${custom_jails[$((rm_choice-1))]}"
                    if ask_yes_no "Удалить $jail_to_rm (фильтр и конфиг)?"; then
                        run_cmd sed -i "/^\[$jail_to_rm\]/,/^\s*\[/d" /etc/fail2ban/jail.local 2>/dev/null
                        run_cmd rm -f "/etc/fail2ban/filter.d/${jail_to_rm}.conf"
                        run_cmd systemctl reload fail2ban 2>/dev/null
                        ok "Удалено."
                    fi
                else
                    err "Неверный выбор."
                fi
                ;;
            a|A)
                info "Автоматическое включение требует ручного выбора логов для каждого. Используйте пункты 1-4."
                wait_for_enter
                ;;
            d|D)
                info "Выключаю все встроенные защиты..."
                run_cmd sed -i "/^\[portscan-reshala\]/,/^\s*\[/ s/enabled\s*=\s*true/enabled = false/" /etc/fail2ban/jail.local 2>/dev/null
                run_cmd sed -i "/^\[nginx-auth-reshala\]/,/^\s*\[/ s/enabled\s*=\s*true/enabled = false/" /etc/fail2ban/jail.local 2>/dev/null
                run_cmd sed -i "/^\[nginx-bots-reshala\]/,/^\s*\[/ s/enabled\s*=\s*true/enabled = false/" /etc/fail2ban/jail.local 2>/dev/null
                run_cmd sed -i "/^\[nginx-scanners-reshala\]/,/^\s*\[/ s/enabled\s*=\s*true/enabled = false/" /etc/fail2ban/jail.local 2>/dev/null
                run_cmd systemctl reload fail2ban 2>/dev/null
                ;;
            b|B) break ;;
            *)
                # Проверяем, не выбрал ли пользователь кастомный jail
                if [[ "$choice" =~ ^[0-9]+$ ]] && [[ "$choice" -ge 5 ]]; then
                    local custom_idx=$((choice - 5))
                    if [[ "$custom_idx" -lt ${#custom_jails[@]} ]]; then
                        local selected_custom="${custom_jails[$custom_idx]}"
                        _f2b_jail_submenu "$selected_custom" "syslog" "" "any" "ufw[name=$selected_custom, port=any, protocol=tcp]" "Кастомная защита: $selected_custom"
                    else
                        warn "Неверный выбор"
                    fi
                else
                    warn "Неверный выбор"
                fi
                ;;
        esac
        disable_graceful_ctrlc
    done
}

_f2b_setup() {
    print_separator
    info "Первоначальная настройка Fail2Ban"
    print_separator

    if ! ask_yes_no "Это действие установит Fail2Ban (если требуется) и создаст базовый конфиг /etc/fail2ban/jail.local для защиты SSH. Продолжить?"; then
        info "Отмена."
        return
    fi
    
    if ! ensure_package "fail2ban"; then
        err "Не удалось установить Fail2Ban. Выполните установку вручную и попробуйте снова."
        return 1
    fi

    # Устанавливаем python3-systemd для интеграции с Systemd Journal (особенно важно на Debian 12 / Ubuntu 22.04+ без rsyslog)
    if command -v apt-get &>/dev/null; then
        if ! dpkg -l python3-systemd &>/dev/null && ! python3 -c "import systemd" &>/dev/null; then
            info "Устанавливаю пакет python3-systemd для интеграции с журналом systemd..."
            run_cmd apt-get update && run_cmd apt-get install -y python3-systemd
        fi
    elif command -v yum &>/dev/null; then
        if ! rpm -q python3-systemd &>/dev/null && ! python3 -c "import systemd" &>/dev/null; then
            info "Устанавливаю пакет python3-systemd для интеграции с журналом systemd..."
            run_cmd yum install -y python3-systemd
        fi
    fi
    
    if [[ -f "/etc/fail2ban/jail.local" ]]; then
        info "Создаю бэкап существующего jail.local..."
        local backup_file="/etc/fail2ban/jail.local.backup_$(date +%s)"
        run_cmd cp /etc/fail2ban/jail.local "$backup_file"
        ok "Создан бэкап: $backup_file"
    fi
    
    warn "Настройка параметров..."
    
    local bantime_options=("1 час" "24 часа" "7 дней" "Навсегда")
    local bantime_values=("3600" "86400" "604800" "-1")
    
    local bantime_choice; bantime_choice=$(ask_selection "Выберите стандартное время бана:" "${bantime_options[@]}") || return
    local bantime=${bantime_values[$((bantime_choice-1))]}

    local maxretry; maxretry=$(safe_read "Количество попыток до бана" "3") || return
    local findtime; findtime=$(safe_read "Период для подсчета попыток (в секундах)" "600") || return

    set_config_var "F2B_BANTIME" "$bantime"
    set_config_var "F2B_MAXRETRY" "$maxretry"
    set_config_var "F2B_FINDTIME" "$findtime"

    local ssh_port; ssh_port=$(grep "^Port " /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    ssh_port=${ssh_port:-22}
    
    # --- Собираем ignoreip ---
    local ignoreip="127.0.0.1/8 ::1"

    # Берем IP из Глобального Белого Списка, если доступен
    if command -v global_whitelist_get_ips &>/dev/null; then
        local gwl_ips
        gwl_ips=$(global_whitelist_get_ips | tr '\n' ' ')
        if [[ -n "$gwl_ips" ]]; then
            ignoreip="$ignoreip $gwl_ips"
            info "Загружено IP из Глобального Белого Списка: ${C_CYAN}$(echo $gwl_ips | wc -w)${C_RESET}"
        fi
    fi

    # Получаем IP текущей сессии
    local current_ip
    current_ip=$(who -m | awk '{print $5}' | tr -d '()')
    if [[ -n "$current_ip" ]] && validate_ip "$current_ip"; then
        ignoreip="$ignoreip $current_ip"
        info "Ваш текущий IP ${C_CYAN}${current_ip}${C_RESET} будет добавлен в whitelist."
        
        # Добавляем в Глобальный Белый Список
        if command -v global_whitelist_add_ip &>/dev/null; then
            global_whitelist_add_ip "$current_ip" "Auto-added on F2B setup" 2>/dev/null || true
        else
            # Фоллбэк: локальный файл
            run_cmd mkdir -p /etc/reshala
            run_cmd touch "$F2B_WHITELIST_FILE"
            if ! grep -q "$current_ip" "$F2B_WHITELIST_FILE"; then
                echo "$current_ip # Auto-added on setup" | run_cmd tee -a "$F2B_WHITELIST_FILE" > /dev/null
            fi
        fi
    fi
    # ---

    # Выбор механизма отслеживания SSH логов
    local ssh_log_config="logpath = /var/log/auth.log"
    if [[ ! -f "/var/log/auth.log" ]]; then
        if [[ -f "/var/log/secure" ]]; then
            ssh_log_config="logpath = /var/log/secure"
        elif command -v journalctl &>/dev/null; then
            info "Системные лог-файлы не найдены. Настраиваю джейл sshd на использование backend = systemd."
            ssh_log_config="backend = systemd"
        fi
    fi

    info "Создаю /etc/fail2ban/jail.local..."

    run_cmd tee /etc/fail2ban/jail.local > /dev/null <<JAIL
[DEFAULT]
bantime = $bantime
findtime = ${findtime}s
maxretry = $maxretry
backend = auto
ignoreip = $ignoreip

[sshd]
enabled = true
port = any
filter = sshd
$ssh_log_config
action = ufw[name=sshd, port=any, protocol=tcp]
JAIL

    ok "Файл jail.local создан."

    info "Включаю и перезапускаю сервис Fail2Ban..."
    run_cmd systemctl enable fail2ban
    run_cmd systemctl restart fail2ban
    
    if systemctl is-active --quiet fail2ban; then
        ok "Fail2Ban успешно настроен и запущен!"
        
        # Apply Telegram settings if enabled
        if [[ "$(get_config_var "F2B_NOTIFY_MODE")" == "instant" ]]; then
            _f2b_apply_notification_settings "instant"
        fi
    else
        err "Не удалось запустить Fail2Ban. Проверьте 'systemctl status fail2ban'."
    fi
}

# --- Логика автопоиска логов ---
_f2b_detect_nginx_log() {
    local log_type="$1" # "access" or "error"
    F2B_SELECTED_LOG=""
    local found_logs=()

    # Стандартные пути
    local standard_paths=(
        "/var/log/nginx/access.log"
        "/var/log/nginx/error.log"
        "/var/log/nginx/access_stream.log"
        "/var/log/nginx/error_stream.log"
    )
    for p in "${standard_paths[@]}"; do
        if [[ -f "$p" ]] && [[ "$p" == *"$log_type"* ]]; then
            found_logs+=("$p")
        fi
    done

    # Docker volumes (проверяем все контейнеры, включая остановленные)
    local docker_paths
    if command -v docker &>/dev/null; then
        mapfile -t docker_paths < <(docker inspect --format '{{range .Mounts}}{{if eq .Type "bind"}}{{.Source}}{{"\n"}}{{end}}{{end}}' $(docker ps -a -q) 2>/dev/null | grep -i "log\|nginx" | sort -u)
        for dp in "${docker_paths[@]}"; do
            if [[ -d "$dp" ]]; then
                mapfile -t -O ${#found_logs[@]} found_logs < <(find "$dp" -type f \( -name "*${log_type}*" -o -name "${log_type}.log" \) 2>/dev/null | head -5)
            fi
        done
    fi

    # Дополнительный умный поиск по всей системе (для случаев, когда контейнер остановлен или пути кастомные)
    if [[ ${#found_logs[@]} -eq 0 ]]; then
        # Ищем файлы *.log, содержащие в названии "access" или "error", 
        # у которых в полном пути есть nginx, reshala, remnawave, proxy или gate
        mapfile -t found_logs < <(find /var/log /opt /home -type f \( -name "*${log_type}*.log" -o -name "${log_type}.log" \) \( -path "*nginx*" -o -path "*reshala*" -o -path "*remnawave*" -o -path "*proxy*" \) 2>/dev/null | head -15)
    fi

    if [[ ${#found_logs[@]} -gt 0 ]]; then
        info "Подсказка по выбору лог-файла:"
        printf_description " • Если Nginx работает на сервере: ${C_YELLOW}/var/log/nginx/${log_type}.log${C_RESET}"
        printf_description " • Если Nginx в Docker (например, NPM): ищите пути вида ${C_YELLOW}/opt/.../data/logs/${C_RESET} или ${C_YELLOW}/var/lib/docker/volumes/...${C_RESET}"
        printf_description " Важно: Fail2Ban работает на хосте, поэтому путь должен быть доступен с хост-системы!"
        echo ""

        ok "Найдены подходящие логи Nginx (${#found_logs[@]}):"
        local i=1
        for log_file in "${found_logs[@]}"; do
            local size
            size=$(du -h "$log_file" 2>/dev/null | awk '{print $1}')
            printf_description "  ${C_WHITE}${i})${C_RESET} ${log_file} ${C_GRAY}(${size:-?})${C_RESET}"
            ((i++))
        done
        echo ""
        printf_menu_option "m" "Ввести путь вручную"
        echo ""

        local choice
        choice=$(safe_read "Выберите файл лога" "1") || return 1

        if [[ "$choice" == "m" || "$choice" == "M" ]]; then
            F2B_SELECTED_LOG=$(ask_non_empty "Введите полный путь к файлу лога") || return 1
        elif [[ "$choice" =~ ^[0-9]+$ ]] && [[ "$choice" -ge 1 ]] && [[ "$choice" -le ${#found_logs[@]} ]]; then
            F2B_SELECTED_LOG="${found_logs[$((choice-1))]}"
        else
            err "Неверный выбор."
            return 1
        fi
    else
        warn "Логи Nginx не найдены автоматически."
        F2B_SELECTED_LOG=$(ask_non_empty "Введите полный путь к $log_type.log") || return 1
    fi
}

_f2b_detect_syslog() {
    F2B_SELECTED_LOG=""
    local found_logs=()
    if [[ -f "/var/log/syslog" ]]; then found_logs+=("/var/log/syslog"); fi
    if [[ -f "/var/log/messages" ]]; then found_logs+=("/var/log/messages"); fi
    if [[ -f "/var/log/auth.log" ]]; then found_logs+=("/var/log/auth.log"); fi
    if [[ -f "/var/log/secure" ]]; then found_logs+=("/var/log/secure"); fi

    # Если доступен journalctl, добавляем systemd journal как виртуальный лог-источник
    if command -v journalctl &>/dev/null; then
        found_logs+=("systemd")
    fi

    if [[ ${#found_logs[@]} -gt 0 ]]; then
        info "Подсказка по выбору системного лог-файла:"
        printf_description " • В Ubuntu/Debian используется ${C_YELLOW}/var/log/syslog${C_RESET} или ${C_YELLOW}/var/log/auth.log${C_RESET}"
        printf_description " • В CentOS/RHEL/Alma используется ${C_YELLOW}/var/log/messages${C_RESET} или ${C_YELLOW}/var/log/secure${C_RESET}"
        printf_description " • На современных системах без rsyslog рекомендуется использовать ${C_YELLOW}systemd-journald${C_RESET}"
        echo ""

        ok "Найдены системные логи (${#found_logs[@]}):"
        local i=1
        for log_file in "${found_logs[@]}"; do
            if [[ "$log_file" == "systemd" ]]; then
                printf_description "  ${C_WHITE}${i})${C_RESET} systemd-journald ${C_GRAY}(Системный журнал Systemd)${C_RESET}"
            else
                local size
                size=$(du -h "$log_file" 2>/dev/null | awk '{print $1}')
                printf_description "  ${C_WHITE}${i})${C_RESET} ${log_file} ${C_GRAY}(${size:-?})${C_RESET}"
            fi
            ((i++))
        done
        echo ""
        printf_menu_option "m" "Ввести путь вручную"
        echo ""

        local choice
        choice=$(safe_read "Выберите файл лога" "1") || return 1

        if [[ "$choice" == "m" || "$choice" == "M" ]]; then
            F2B_SELECTED_LOG=$(ask_non_empty "Введите полный путь к файлу системного лога") || return 1
        elif [[ "$choice" =~ ^[0-9]+$ ]] && [[ "$choice" -ge 1 ]] && [[ "$choice" -le ${#found_logs[@]} ]]; then
            F2B_SELECTED_LOG="${found_logs[$((choice-1))]}"
        else
            err "Неверный выбор."
            return 1
        fi
    else
        warn "Системные логи не найдены."
        F2B_SELECTED_LOG=$(ask_non_empty "Введите полный путь к системному логу") || return 1
    fi
}

_f2b_jail_submenu() {
    local jail_name="$1"
    local log_type="$2"
    local default_filter="$3"
    local default_port="$4"
    local default_action="$5"
    local menu_title="$6"

    local current_p="$default_port"
    local current_a="$default_action"

    while true; do
        clear
        enable_graceful_ctrlc
        menu_header "🛡️ Управление Jail: $jail_name"
        printf_description "$menu_title"
        print_separator

        local is_enabled="false"
        local current_log="Не задан"
        local current_maxretry="3"
        local filter_file="/etc/fail2ban/filter.d/${jail_name}.conf"

        if grep -q "^\s*\[$jail_name\]" /etc/fail2ban/jail.local 2>/dev/null; then
            if grep -A 10 "^\s*\[$jail_name\]" /etc/fail2ban/jail.local 2>/dev/null | grep -q "enabled\s*=\s*true"; then
                is_enabled="true"
            fi
            local extracted_log
            extracted_log=$(grep -A 10 "^\s*\[$jail_name\]" /etc/fail2ban/jail.local 2>/dev/null | grep "^\s*logpath\s*=" | head -1 | awk -F'=' '{print $2}' | xargs)
            [[ -n "$extracted_log" ]] && current_log="$extracted_log"

            local extracted_backend
            extracted_backend=$(grep -A 10 "^\s*\[$jail_name\]" /etc/fail2ban/jail.local 2>/dev/null | grep "^\s*backend\s*=" | head -1 | awk -F'=' '{print $2}' | xargs)
            if [[ "$extracted_backend" == "systemd" ]]; then
                current_log="systemd"
            fi
            
            local extracted_max
            extracted_max=$(grep -A 10 "^\s*\[$jail_name\]" /etc/fail2ban/jail.local 2>/dev/null | grep "^\s*maxretry\s*=" | head -1 | awk -F'=' '{print $2}' | xargs)
            [[ -n "$extracted_max" ]] && current_maxretry="$extracted_max"

            local extracted_p
            extracted_p=$(grep -A 10 "^\s*\[$jail_name\]" /etc/fail2ban/jail.local 2>/dev/null | grep "^\s*port\s*=" | head -1 | awk -F'=' '{print $2}' | xargs)
            [[ -n "$extracted_p" ]] && current_p="$extracted_p"

            local extracted_a
            extracted_a=$(grep -A 15 "^\s*\[$jail_name\]" /etc/fail2ban/jail.local 2>/dev/null | grep "^\s*action\s*=" | head -1 | awk -F'=' '{print $2}' | xargs)
            [[ -n "$extracted_a" ]] && current_a="$extracted_a"
        fi

        local current_action_desc="Полная изоляция (все порты)"
        if [[ -n "$current_a" ]]; then
            if [[ "$current_a" != *"port=any"* ]]; then
                local act_port; act_port=$(echo "$current_a" | grep -o "port=[^,]*" | cut -d= -f2)
                current_action_desc="Только сервис (порт ${act_port:-?})"
            fi
        fi

        if [[ "$is_enabled" == "true" ]]; then
            printf_description "Статус: ${C_GREEN}Включен${C_RESET}"
        else
            printf_description "Статус: ${C_RED}Выключен${C_RESET}"
        fi
        
        if [[ "$current_log" == "systemd" ]]; then
            printf_description "Файл лога: ${C_CYAN}systemd-journald (Systemd)${C_RESET}"
        else
            printf_description "Файл лога: ${C_CYAN}$current_log${C_RESET}"
        fi
        
        printf_description "Попыток (maxretry): ${C_CYAN}$current_maxretry${C_RESET}"
        printf_description "Метод блокировки: ${C_CYAN}$current_action_desc${C_RESET}"
        
        echo ""
        if [[ "$is_enabled" == "true" ]]; then
            printf_menu_option "1" "🔴 Выключить защиту"
        else
            printf_menu_option "1" "🟢 Включить защиту"
        fi
        printf_menu_option "2" "📝 Изменить количество попыток (maxretry)"
        printf_menu_option "3" "📂 Изменить путь к лог-файлу"
        printf_menu_option "4" "👁️ Просмотреть/Отредактировать правила (Regex)"
        printf_menu_option "5" "🛡️ Изменить метод блокировки"
        echo ""
        printf_menu_option "b" "Назад"
        echo ""

        local choice
        choice=$(safe_read "Выберите действие") || { break; }

        case "$choice" in
            1)
                if [[ "$is_enabled" == "true" ]]; then
                    run_cmd sed -i "/^\[$jail_name\]/,/^\s*\[/ s/enabled\s*=\s*true/enabled = false/" /etc/fail2ban/jail.local
                    ok "Защита '$jail_name' выключена."
                    run_cmd systemctl reload fail2ban 2>/dev/null || run_cmd systemctl restart fail2ban
                else
                    if [[ "$current_log" == "Не задан" ]]; then
                        warn "Сначала необходимо выбрать лог-файл (опция 3)."
                        wait_for_enter
                        continue
                    fi
                    if [[ ! -f "$filter_file" ]]; then
                        info "Создаю стандартный файл фильтра..."
                        echo -e "$default_filter" | run_cmd tee "$filter_file" > /dev/null
                    fi
                    if ! grep -q "^\s*\[$jail_name\]" /etc/fail2ban/jail.local 2>/dev/null; then
                        info "Добавляю секцию в jail.local..."
                        if [[ "$current_log" == "systemd" ]]; then
                            cat <<JAIL | run_cmd tee -a /etc/fail2ban/jail.local > /dev/null

[$jail_name]
enabled = true
port = $current_p
filter = $jail_name
backend = systemd
maxretry = $current_maxretry
findtime = 600
bantime = 86400
action = $current_a
JAIL
                        else
                            cat <<JAIL | run_cmd tee -a /etc/fail2ban/jail.local > /dev/null

[$jail_name]
enabled = true
port = $current_p
filter = $jail_name
logpath = $current_log
maxretry = $current_maxretry
findtime = 600
bantime = 86400
action = $current_a
JAIL
                        fi
                    else
                        run_cmd sed -i "/^\[$jail_name\]/,/^\s*\[/ s/enabled\s*=\s*false/enabled = true/" /etc/fail2ban/jail.local
                    fi
                    ok "Защита '$jail_name' включена."
                    run_cmd systemctl reload fail2ban 2>/dev/null || run_cmd systemctl restart fail2ban
                fi
                wait_for_enter
                ;;
            2)
                local new_maxretry
                new_maxretry=$(safe_read "Введите новое количество попыток (текущее: $current_maxretry)" "$current_maxretry") || continue
                if [[ "$new_maxretry" =~ ^[0-9]+$ ]]; then
                    if grep -q "^\s*\[$jail_name\]" /etc/fail2ban/jail.local 2>/dev/null; then
                        if grep -A 10 "^\s*\[$jail_name\]" /etc/fail2ban/jail.local | grep -q "^\s*maxretry\s*="; then
                            run_cmd sed -i "/^\[$jail_name\]/,/^\s*\[/ s/^\s*maxretry\s*=.*/maxretry = $new_maxretry/" /etc/fail2ban/jail.local
                        else
                            run_cmd sed -i "/^\[$jail_name\]/a maxretry = $new_maxretry" /etc/fail2ban/jail.local
                        fi
                        ok "maxretry обновлен до $new_maxretry"
                        [[ "$is_enabled" == "true" ]] && run_cmd systemctl reload fail2ban
                    else
                        warn "Сначала включите защиту, чтобы конфигурация была создана."
                    fi
                else
                    err "Должно быть числом."
                fi
                wait_for_enter
                ;;
            3)
                if [[ "$log_type" == "nginx-access" ]]; then
                    _f2b_detect_nginx_log "access"
                elif [[ "$log_type" == "nginx-error" ]]; then
                    _f2b_detect_nginx_log "error"
                elif [[ "$log_type" == "syslog" ]]; then
                    _f2b_detect_syslog
                else
                    F2B_SELECTED_LOG=$(ask_non_empty "Введите путь к логу") || continue
                fi
                
                if [[ -n "$F2B_SELECTED_LOG" ]] && { [[ "$F2B_SELECTED_LOG" == "systemd" ]] || [[ -f "$F2B_SELECTED_LOG" ]]; }; then
                    if grep -q "^\s*\[$jail_name\]" /etc/fail2ban/jail.local 2>/dev/null; then
                        if [[ "$F2B_SELECTED_LOG" == "systemd" ]]; then
                            # Удаляем logpath
                            run_cmd sed -i "/^\[$jail_name\]/,/^\s*\[/ {/^\s*logpath\s*=/d}" /etc/fail2ban/jail.local
                            # Добавляем или обновляем backend = systemd
                            if grep -A 10 "^\s*\[$jail_name\]" /etc/fail2ban/jail.local | grep -q "^\s*backend\s*="; then
                                run_cmd sed -i "/^\[$jail_name\]/,/^\s*\[/ s|^\s*backend\s*=.*|backend = systemd|" /etc/fail2ban/jail.local
                            else
                                run_cmd sed -i "/^\[$jail_name\]/a backend = systemd" /etc/fail2ban/jail.local
                            fi
                        else
                            # Удаляем backend = systemd
                            run_cmd sed -i "/^\[$jail_name\]/,/^\s*\[/ {/^\s*backend\s*=\s*systemd/d}" /etc/fail2ban/jail.local
                            # Добавляем или обновляем logpath
                            if grep -A 10 "^\s*\[$jail_name\]" /etc/fail2ban/jail.local | grep -q "^\s*logpath\s*="; then
                                run_cmd sed -i "/^\[$jail_name\]/,/^\s*\[/ s|^\s*logpath\s*=.*|logpath = ${F2B_SELECTED_LOG}|" /etc/fail2ban/jail.local
                            else
                                run_cmd sed -i "/^\[$jail_name\]/a logpath = ${F2B_SELECTED_LOG}" /etc/fail2ban/jail.local
                            fi
                        fi
                        ok "Лог обновлен."
                        [[ "$is_enabled" == "true" ]] && run_cmd systemctl reload fail2ban
                    else
                        # Store in temp var until enabled
                        current_log="$F2B_SELECTED_LOG"
                        ok "Лог выбран. Включите защиту для применения."
                    fi
                fi
                wait_for_enter
                ;;
            4)
                if [[ ! -f "$filter_file" ]]; then
                    info "Создаю стандартный файл фильтра..."
                    echo -e "$default_filter" | run_cmd tee "$filter_file" > /dev/null
                fi
                run_cmd nano "$filter_file"
                ok "Если вы внесли изменения, они будут применены."
                [[ "$is_enabled" == "true" ]] && run_cmd systemctl reload fail2ban 2>/dev/null
                ;;
            5)
                echo -e "\n  ${C_CYAN}Выберите метод блокировки:${C_RESET}"
                echo -e "  1. ${C_GREEN}Полная изоляция${C_RESET} (Блокировать все порты - РЕКОМЕНДУЕТСЯ)"
                echo -e "  2. ${C_YELLOW}Ограниченная блокировка${C_RESET} (Только порты этого сервиса)"
                echo ""
                local m_choice
                m_choice=$(safe_read "Выбор" "1") || continue
                
                local new_p_val="any"
                local new_a_val
                
                if [[ "$m_choice" == "1" ]]; then
                    new_p_val="any"
                elif [[ "$m_choice" == "2" ]]; then
                    new_p_val=$(safe_read "Введите порты для блокировки (например, 80,443 или 22)" "$current_p") || continue
                else
                    continue
                fi
                
                new_a_val="ufw[name=${jail_name//-/_}, port=${new_p_val}, protocol=tcp]"
                
                if grep -q "^\s*\[$jail_name\]" /etc/fail2ban/jail.local 2>/dev/null; then
                    run_cmd sed -i "/^\[$jail_name\]/,/^\s*\[/ s|^\s*port\s*=.*|port = ${new_p_val}|" /etc/fail2ban/jail.local
                    run_cmd sed -i "/^\[$jail_name\]/,/^\s*\[/ s|^\s*action\s*=.*|action = ${new_a_val}|" /etc/fail2ban/jail.local
                    ok "Метод блокировки обновлен в конфигурации."
                    [[ "$is_enabled" == "true" ]] && run_cmd systemctl reload fail2ban
                fi
                
                # Обновляем локальные переменные для корректного отображения и будущего включения
                current_p="$new_p_val"
                current_a="$new_a_val"
                
                ok "Метод блокировки выбран: $new_p_val"
                wait_for_enter
                ;;
            b|B) break ;;
            *) warn "Неверный выбор" ;;
        esac
        disable_graceful_ctrlc
    done
}

