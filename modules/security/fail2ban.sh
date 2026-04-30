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

        _f2b_check_status
        
        echo ""
        if ! command -v fail2ban-client &> /dev/null; then
            printf_menu_option "i" "УСТАНОВИТЬ FAIL2BAN" "${C_YELLOW}"
        else
            printf_menu_option "1" "Список забаненных IP"
            printf_menu_option "2" "Разбанить IP"
            printf_menu_option "3" "Забанить IP вручную"
            printf_menu_option "4" "Whitelist (доверенные IP)"
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
    print_separator
    info "Статус Fail2Ban"

    if ! command -v fail2ban-client &> /dev/null; then
        warn "Fail2Ban не установлен или не в PATH."
        printf_description "Вы можете установить его, выбрав пункт 'i' в меню."
        print_separator
        return 1
    fi
    
    if systemctl is-active --quiet fail2ban 2>/dev/null; then
        printf_description "Сервис: ${C_GREEN}Активен${C_RESET}"
        
        local banned
        banned=$(run_cmd fail2ban-client status sshd 2>/dev/null | grep "Currently banned" | awk '{print $4}')
        local total
        total=$(run_cmd fail2ban-client status sshd 2>/dev/null | grep "Total banned" | awk '{print $4}')
            
        printf_description "Защита SSH (sshd jail):"
        printf_description "  - Сейчас забанено: ${C_CYAN}${banned:-0}${C_RESET}"
        printf_description "  - Всего банов: ${C_CYAN}${total:-0}${C_RESET}"

        # Показываем время бана
        local bantime
        bantime=$(get_config_var "F2B_BANTIME" "86400") # Default to 24h
        local bantime_human
        if [[ "$bantime" == "-1" ]]; then
            bantime_human="Навсегда"
        elif [[ -z "$bantime" || "$bantime" -lt 3600 ]]; then
            bantime_human="${bantime} сек"
        else
            bantime_human="$((bantime / 3600)) ч"
        fi
        printf_description "Время бана: ${C_CYAN}$bantime_human${C_RESET}"

    else
        printf_description "Сервис: ${C_RED}Не активен${C_RESET}"
    fi
    print_separator
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
    elif [[ -z "$current_bantime" || "$current_bantime" -lt 3600 ]]; then
        current_human="${current_bantime} сек"
    else
        current_human="$((current_bantime / 3600)) ч"
    fi
    printf_description "Текущее время бана: ${C_CYAN}$current_human${C_RESET}"
    echo ""

    local bantime_options=("1 час" "24 часа" "7 дней" "Навсегда")
    local bantime_values=("3600" "86400" "604800" "-1")
    
    local bantime_choice
    bantime_choice=$(ask_selection "Выберите новое время бана:" "${bantime_options[@]}") || return
    local new_bantime=${bantime_values[$((bantime_choice-1))]}

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
    # Предлагаем Глобальный Белый Список
    if command -v global_whitelist_offer &>/dev/null; then
        if global_whitelist_offer "Fail2Ban"; then
            info "Fail2Ban будет использовать Глобальный Белый Список."
            global_whitelist_sync_all 2>/dev/null || true
            wait_for_enter
            return
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

_f2b_manage_jail() {
    local jail_name="$1"
    local filter_content="$2"
    local jail_content="$3"

    local is_enabled="false"
    if grep -q "^\s*\[$jail_name\]" /etc/fail2ban/jail.local 2>/dev/null && grep -A 3 "^\s*\[$jail_name\]" /etc/fail2ban/jail.local 2>/dev/null | grep -q "enabled\s*=\s*true"; then
        is_enabled="true"
    fi

    if [[ "$is_enabled" == "true" ]]; then
        if ask_yes_no "Защита '$jail_name' включена. Выключить?"; then
            run_cmd sed -i "/^\[$jail_name\]/,/^\s*\[/ s/enabled\s*=\s*true/enabled = false/" /etc/fail2ban/jail.local
            ok "Защита '$jail_name' выключена."
            run_cmd systemctl reload fail2ban
        fi
    else
        if ask_yes_no "Защита '$jail_name' выключена. Включить?"; then
            # Шаг 1: Создаем фильтр, если его нет
            local filter_file="/etc/fail2ban/filter.d/${jail_name}.conf"
            if [[ ! -f "$filter_file" ]]; then
                info "Создаю файл фильтра: $filter_file"
                echo -e "$filter_content" | run_cmd tee "$filter_file" > /dev/null
            fi
            
            # Шаг 2: Добавляем секцию в jail.local, если ее нет
            if ! grep -q "^\s*\[$jail_name\]" /etc/fail2ban/jail.local 2>/dev/null; then
                info "Добавляю секцию [$jail_name] в jail.local..."
                echo -e "\n$jail_content" | run_cmd tee -a /etc/fail2ban/jail.local > /dev/null
            fi

            # Шаг 3: Включаем защиту
            run_cmd sed -i "/^\[$jail_name\]/,/^\s*\[/ s/enabled\s*=\s*false/enabled = true/" /etc/fail2ban/jail.local
            ok "Защита '$jail_name' включена."
            run_cmd systemctl reload fail2ban
        fi
    fi
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
        local portscan_status="(${C_RED}выкл${C_RESET})"
        grep -A 2 "\[portscan-reshala\]" /etc/fail2ban/jail.local 2>/dev/null | grep -q "enabled = true" && \
            portscan_status="(${C_GREEN}вкл${C_RESET})"
        
        local nginx_auth_status="(${C_RED}выкл${C_RESET})"
        grep -A 2 "\[nginx-auth-reshala\]" /etc/fail2ban/jail.local 2>/dev/null | grep -q "enabled = true" && \
            nginx_auth_status="(${C_GREEN}вкл${C_RESET})"
        
        local nginx_bots_status="(${C_RED}выкл${C_RESET})"
        grep -A 2 "\[nginx-bots-reshala\]" /etc/fail2ban/jail.local 2>/dev/null | grep -q "enabled = true" && \
            nginx_bots_status="(${C_GREEN}вкл${C_RESET})"

        local nginx_scanners_status="(${C_RED}выкл${C_RESET})"
        grep -A 2 "\[nginx-scanners-reshala\]" /etc/fail2ban/jail.local 2>/dev/null | grep -q "enabled = true" && \
            nginx_scanners_status="(${C_GREEN}вкл${C_RESET})"

        echo ""
        printf_menu_option "1" "Защита от сканирования портов $portscan_status"
        printf_menu_option "2" "Защита от брутфорса Nginx (HTTP auth) $nginx_auth_status"
        printf_menu_option "3" "Блокировка вредоносных ботов Nginx $nginx_bots_status"
        printf_menu_option "4" "Защита Nginx от сканеров (auto-detect) $nginx_scanners_status"
        echo ""
        printf_menu_option "a" "Включить все"
        printf_menu_option "d" "Выключить все"
        echo ""
        printf_menu_option "b" "Назад"
        echo ""

        local choice
        choice=$(safe_read "Выберите действие") || { break; }

        case "$choice" in
            1) _f2b_toggle_jail "portscan-reshala" && run_cmd systemctl reload fail2ban ;;
            2) _f2b_toggle_jail "nginx-auth-reshala" && run_cmd systemctl reload fail2ban ;;
            3) _f2b_toggle_jail "nginx-bots-reshala" && run_cmd systemctl reload fail2ban ;;
            4) _f2b_setup_nginx_scanners; wait_for_enter ;;
            a|A)
                info "Включаю все расширенные защиты..."
                _f2b_toggle_jail "portscan-reshala" "true"
                _f2b_toggle_jail "nginx-auth-reshala" "true"
                _f2b_toggle_jail "nginx-bots-reshala" "true"
                run_cmd systemctl reload fail2ban
                ;;
            d|D)
                info "Выключаю все расширенные защиты..."
                _f2b_toggle_jail "portscan-reshala" "false"
                _f2b_toggle_jail "nginx-auth-reshala" "false"
                _f2b_toggle_jail "nginx-bots-reshala" "false"
                run_cmd systemctl reload fail2ban
                ;;
            b|B) break ;;
            *) warn "Неверный выбор" ;;
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
port = $ssh_port
filter = sshd
logpath = /var/log/auth.log
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

# --- Nginx Scanners Jail с автопоиском логов ---
_f2b_setup_nginx_scanners() {
    print_separator
    info "Защита Nginx от сканеров (nginx-scanners)"
    print_separator

    if [[ ! -f "/etc/fail2ban/jail.local" ]]; then
        err "Fail2Ban не настроен. Сначала установите его."
        return
    fi

    # Автопоиск файлов логов nginx
    info "Автопоиск файлов логов Nginx..."
    local found_logs=()

    # Стандартные пути
    local standard_paths=(
        "/var/log/nginx/access.log"
        "/var/log/nginx/error.log"
        "/var/log/nginx/access_stream.log"
        "/var/log/nginx/error_stream.log"
    )
    for p in "${standard_paths[@]}"; do
        [[ -f "$p" ]] && found_logs+=("$p")
    done

    # Docker volumes
    local docker_paths
    if command -v docker &>/dev/null; then
        mapfile -t docker_paths < <(docker inspect --format '{{range .Mounts}}{{if eq .Type "bind"}}{{.Source}}{{"\n"}}{{end}}{{end}}' $(docker ps -q) 2>/dev/null | grep -i "log\|nginx" | sort -u)
        for dp in "${docker_paths[@]}"; do
            [[ -d "$dp" ]] && mapfile -t -O ${#found_logs[@]} found_logs < <(find "$dp" -name "*access*" -o -name "*error*" 2>/dev/null | head -5)
        done
    fi

    # Дополнительный поиск
    if [[ ${#found_logs[@]} -eq 0 ]]; then
        mapfile -t found_logs < <(find /var/log /opt /home -name "*nginx*access*" -o -name "*nginx*error*" 2>/dev/null | head -10)
    fi

    local selected_log=""
    if [[ ${#found_logs[@]} -gt 0 ]]; then
        ok "Найдены файлы логов Nginx (${#found_logs[@]}):"
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
        choice=$(safe_read "Выберите файл лога" "1") || return

        if [[ "$choice" == "m" || "$choice" == "M" ]]; then
            selected_log=$(ask_non_empty "Введите полный путь к файлу лога") || return
        elif [[ "$choice" =~ ^[0-9]+$ ]] && [[ "$choice" -ge 1 ]] && [[ "$choice" -le ${#found_logs[@]} ]]; then
            selected_log="${found_logs[$((choice-1))]}"
        else
            err "Неверный выбор."
            return
        fi
    else
        warn "Файлы логов Nginx не найдены автоматически."
        selected_log=$(ask_non_empty "Введите полный путь к access.log") || return
    fi

    if [[ ! -f "$selected_log" ]]; then
        err "Файл ${selected_log} не существует."
        return
    fi

    ok "Выбран файл: ${C_CYAN}${selected_log}${C_RESET}"

    # Создаём фильтр
    info "Создаю фильтр для nginx-scanners..."
    cat <<'FILTER' | run_cmd tee /etc/fail2ban/filter.d/nginx-scanners-reshala.conf > /dev/null
[Definition]
failregex = ^<HOST> .* "(GET|POST|HEAD) .*(\.php|\.env|\.git|\.asp|wp-login|wp-admin|cgi-bin|/admin|/config|/setup|\.sql|shell|eval|passwd|\.bak).*" (400|403|404|444)
            ^<HOST> .* "(GET|POST) .*(xmlrpc|wp-cron|wp-json/wp/v2/users).*" (403|404)
ignoreregex =
FILTER

    # Добавляем/обновляем jail
    if grep -q "\[nginx-scanners-reshala\]" /etc/fail2ban/jail.local 2>/dev/null; then
        # Обновляем существующий
        run_cmd sed -i "/\[nginx-scanners-reshala\]/,/^\[/{
            s|^logpath.*|logpath = ${selected_log}|
            s|^enabled.*|enabled = true|
        }" /etc/fail2ban/jail.local
        ok "Jail nginx-scanners-reshala обновлён."
    else
        # Добавляем новый
        cat <<JAIL | run_cmd tee -a /etc/fail2ban/jail.local > /dev/null

[nginx-scanners-reshala]
enabled = true
port = http,https
filter = nginx-scanners-reshala
logpath = ${selected_log}
maxretry = 3
findtime = 600
bantime = 86400
action = ufw[name=nginx-scanners, port=http, protocol=tcp]
JAIL
        ok "Jail nginx-scanners-reshala создан."
    fi

    run_cmd systemctl reload fail2ban 2>/dev/null || run_cmd systemctl restart fail2ban
    ok "Nginx Scanners защита активирована! Логфайл: ${C_CYAN}${selected_log}${C_RESET}"
}

