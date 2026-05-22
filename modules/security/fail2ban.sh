#!/bin/bash
#   ( РОДИТЕЛЬ | КЛАВИША | НАЗВАНИЕ | ФУНКЦИЯ | ПОРЯДОК | ГРУППА | ОПИСАНИЕ )
# @menu.manifest
# @item( security | 2 | 🤖 Fail2Ban | show_fail2ban_menu | 20 | 10 | Автоматическая блокировка атакующих IP. )
#
# fail2ban.sh - Управление Fail2Ban
#

F2B_WHITELIST_FILE="/etc/reshala/fail2ban-whitelist.txt"

_f2b_is_service_active() {
    # Check via systemctl first
    if run_cmd systemctl is-active --quiet fail2ban &>/dev/null; then
        return 0
    fi
    # Fallback to fail2ban-client ping
    if command -v fail2ban-client &>/dev/null; then
        local ping_res
        ping_res=$(run_cmd fail2ban-client ping 2>/dev/null)
        if [[ "$ping_res" == *"Server replied: pong"* ]]; then
            return 0
        fi
    fi
    return 1
}

_f2b_get_jail_var() {
    local jail="$1"
    local var="$2"
    local file="/etc/fail2ban/jail.local"
    [[ ! -f "$file" ]] && return 1
    
    local target_section="[${jail,,}]"
    local target_var="${var,,}"
    
    awk -v sec="$target_section" -v var="$target_var" '
    BEGIN { current_sec = "" }
    /^[ \t]*\[[^\]]+\]/ {
        # Extract section name and normalize
        match($0, /\[[^\]]+\]/)
        current_sec = tolower(substr($0, RSTART, RLENGTH))
        # Remove all spaces inside section brackets for matching
        gsub(/[ \t]/, "", current_sec)
        next
    }
    current_sec == sec {
        # Parse variable assignment
        if ($0 ~ /^[ \t]*[a-zA-Z0-9_-]+[ \t]*=/) {
            split($0, parts, "=")
            vname = parts[1]
            gsub(/^[ \t]+|[ \t]+$/, "", vname)
            if (tolower(vname) == var) {
                # Re-join parts if there were multiple "=" in the value
                val = ""
                for (i=2; i<=length(parts); i++) {
                    if (i > 2) val = val "="
                    val = val parts[i]
                }
                # Strip leading/trailing whitespace
                gsub(/^[ \t]+|[ \t]+$/, "", val)
                # Strip comments starting with # or ;
                sub(/[ \t]*[#;].*$/, "", val)
                gsub(/^[ \t]+|[ \t]+$/, "", val)
                print val
                exit
            }
        }
    }
    ' "$file"
}

_f2b_is_jail_enabled() {
    local val
    val=$(_f2b_get_jail_var "$1" "enabled")
    if [[ "${val,,}" == "true" ]]; then
        return 0
    fi
    return 1
}


show_fail2ban_menu() {
    while true; do
        clear
        enable_graceful_ctrlc
        menu_header "🤖 Управление Fail2Ban"
        
        echo -e "  ${C_CYAN}╔══════════════════════════════════════════════════════════${C_RESET}"
        echo -e "  ${C_CYAN}║${C_RESET}  ${C_YELLOW}🤖 Управление Fail2Ban${C_RESET}"
        echo -e "  ${C_CYAN}╠══════════════════════════════════════════════════════════${C_RESET}"
        echo -e "  ${C_CYAN}║${C_RESET}  ${C_WHITE}Что это:${C_RESET} Автоматическая защита от перебора паролей."
        echo -e "  ${C_CYAN}║${C_RESET}  ${C_WHITE}Как работает:${C_RESET} Сканирует логи сервисов (SSH, Nginx) и"
        echo -e "  ${C_CYAN}║${C_RESET}  автоматически банит IP-адреса злоумышленников в Firewall"
        echo -e "  ${C_CYAN}║${C_RESET}  при превышении лимита неудачных попыток входа."
        echo -e "  ${C_CYAN}╚══════════════════════════════════════════════════════════${C_RESET}"
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

    if _f2b_is_service_active; then
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
    
    # Сверхнадежное обновление ignoreip с помощью Python
    python3 - "$whitelist_ips" <<'PYEOF'
import sys
import re

fpath = "/etc/fail2ban/jail.local"
ignoreip_val = sys.argv[1]

try:
    with open(fpath, "r") as f:
        content = f.read()

    # Ищем ignoreip (любые отступы, опциональный комментарий #)
    pattern = re.compile(r"^[ \t]*#?[ \t]*ignoreip[ \t]*=[ \t]*.*$", re.MULTILINE | re.IGNORECASE)

    if pattern.search(content):
        content = pattern.sub(f"ignoreip = {ignoreip_val}", content)
    else:
        # Если нет, ищем [DEFAULT]
        default_pattern = re.compile(r"^\[DEFAULT\]", re.MULTILINE | re.IGNORECASE)
        if default_pattern.search(content):
            content = default_pattern.sub(f"[DEFAULT]\nignoreip = {ignoreip_val}", content, 1)
        else:
            content = f"[DEFAULT]\nignoreip = {ignoreip_val}\n\n" + content

    with open(fpath, "w") as f:
        f.write(content)
except Exception as e:
    sys.stderr.write(f"Error updating jail.local: {e}\n")
    sys.exit(1)
PYEOF

    _f2b_reload_or_start
    ok "Whitelist в Fail2Ban обновлен."
}

_f2b_whitelist_menu() {
    # 1. Проверяем синхронизацию с Глобальным Белым Списком
    local global_file="/etc/reshala/global-whitelist.txt"
    while true; do
        local is_synced=false
        if [[ -f "$global_file" ]]; then
            if [[ -f "$F2B_WHITELIST_FILE" ]]; then
                local local_sum; local_sum=$(grep -v '^\s*#' "$F2B_WHITELIST_FILE" | grep -v '^\s*$' | sort | md5sum | awk '{print $1}')
                local global_sum; global_sum=$(grep -v '^\s*#' "$global_file" | grep -v '^\s*$' | sort | md5sum | awk '{print $1}')
                [[ "$local_sum" == "$global_sum" ]] && is_synced=true
            fi
        fi

        clear
        enable_graceful_ctrlc
        menu_header "📋 Whitelist Fail2Ban"
        printf_description "IP-адреса в этом списке никогда не будут забанены."
        
        print_separator
        if [[ -f "$global_file" ]]; then
            if [[ "$is_synced" == "true" ]]; then
                echo -e "  ${C_GREEN}✓ Текущий список синхронизирован с Глобальным Белым Списком.${C_RESET}"
                echo -e "  ${C_GRAY}Изменения в Глобальном списке будут автоматически применяться здесь.${C_RESET}"
                echo ""
            else
                echo -e "  ${C_YELLOW}⚠ Внимание: список Fail2Ban отличается от Глобального Белого Списка.${C_RESET}"
                echo -e "  ${C_GRAY}Рекомендуется выполнить принудительную синхронизацию в Глобальном меню.${C_RESET}"
                echo ""
                if global_whitelist_offer "Fail2Ban"; then
                    info "Копирую IP из Глобального Белого Списка в Fail2Ban..."
                    run_cmd cp -f "$global_file" "$F2B_WHITELIST_FILE" 2>/dev/null || true
                    _f2b_update_ignoreip
                    is_synced=true
                    wait_for_enter
                    continue
                fi
            fi
        fi

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
                
                # Если у нас есть глобальный файл и они синхронизированы, то добавляем через глобальный менеджер!
                if [[ -f "$global_file" && "$is_synced" == "true" ]] && command -v global_whitelist_add_ip &>/dev/null; then
                    global_whitelist_add_ip "$ip_to_add" "Added via Fail2Ban menu"
                else
                    if grep -q "$ip_to_add" "$F2B_WHITELIST_FILE"; then
                        warn "IP $ip_to_add уже в whitelist."
                    else
                        echo "$ip_to_add" | run_cmd tee -a "$F2B_WHITELIST_FILE" > /dev/null
                        ok "IP $ip_to_add добавлен в whitelist."
                        _f2b_update_ignoreip
                    fi
                fi
                wait_for_enter
                ;;
            2)
                local ip_to_remove
                ip_to_remove=$(ask_non_empty "Какой IP удалить?") || continue
                
                # Если у нас есть глобальный файл и они синхронизированы, то удаляем через глобальный менеджер!
                if [[ -f "$global_file" && "$is_synced" == "true" ]] && command -v global_whitelist_remove_ip &>/dev/null; then
                    global_whitelist_remove_ip "$ip_to_remove"
                else
                    if ! grep -q "$ip_to_remove" "$F2B_WHITELIST_FILE"; then
                        err "IP $ip_to_remove не найден в whitelist."
                    else
                        run_cmd sed -i "/^${ip_to_remove}$/d" "$F2B_WHITELIST_FILE"
                        ok "IP $ip_to_remove удален из whitelist."
                        _f2b_update_ignoreip
                    fi
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
        _f2b_is_jail_enabled "sshd" && sshd_status="(${C_GREEN}вкл${C_RESET})"

        local portscan_status="(${C_RED}выкл${C_RESET})"
        _f2b_is_jail_enabled "portscan-reshala" && portscan_status="(${C_GREEN}вкл${C_RESET})"
        
        local nginx_auth_status="(${C_RED}выкл${C_RESET})"
        _f2b_is_jail_enabled "nginx-auth-reshala" && nginx_auth_status="(${C_GREEN}вкл${C_RESET})"
        
        local nginx_bots_status="(${C_RED}выкл${C_RESET})"
        _f2b_is_jail_enabled "nginx-bots-reshala" && nginx_bots_status="(${C_GREEN}вкл${C_RESET})"

        local nginx_scanners_status="(${C_RED}выкл${C_RESET})"
        _f2b_is_jail_enabled "nginx-scanners-reshala" && nginx_scanners_status="(${C_GREEN}вкл${C_RESET})"

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
                _f2b_is_jail_enabled "$j" && c_status="(${C_GREEN}вкл${C_RESET})"
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
    
    if _f2b_is_service_active; then
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
    local selected_flags=()

    # 1. Стандартные пути
    local standard_paths=(
        "/var/log/nginx/access.log"
        "/var/log/nginx/error.log"
        "/var/log/nginx/access_stream.log"
        "/var/log/nginx/error_stream.log"
    )
    for p in "${standard_paths[@]}"; do
        if [[ -f "$p" ]]; then
            found_logs+=("$p")
        fi
    done

    # 2. Docker volumes (проверяем все контейнеры, включая остановленные)
    if command -v docker &>/dev/null; then
        local docker_paths
        mapfile -t docker_paths < <(docker inspect --format '{{range .Mounts}}{{if eq .Type "bind"}}{{.Source}}{{"\n"}}{{end}}{{end}}' $(docker ps -a -q) 2>/dev/null | grep -i "log\|nginx" | sort -u)
        for dp in "${docker_paths[@]}"; do
            if [[ -d "$dp" ]]; then
                local d_logs=()
                mapfile -t d_logs < <(find "$dp" -maxdepth 3 -type f -name "*.log" 2>/dev/null | head -10)
                for dl in "${d_logs[@]}"; do
                    if [[ ! " ${found_logs[*]} " =~ " ${dl} " ]]; then
                        found_logs+=("$dl")
                    fi
                done
            fi
        done
    fi

    # 3. Умный поиск по всей системе (включая кастомные и stream логи)
    local extra_logs=()
    mapfile -t extra_logs < <(find /var/log /opt /home -maxdepth 4 -type f -name "*.log" \( -path "*nginx*" -o -path "*reshala*" -o -path "*remnawave*" -o -path "*proxy*" \) 2>/dev/null | head -25)
    for el in "${extra_logs[@]}"; do
        if [[ ! " ${found_logs[*]} " =~ " ${el} " ]]; then
            found_logs+=("$el")
        fi
    done

    # Если логи уже настроены в джейле, парсим их и добавляем в список
    if [[ -n "$current_log" && "$current_log" != "Не задан" && "$current_log" != "systemd" ]]; then
        for cl in $current_log; do
            if [[ ! " ${found_logs[*]} " =~ " ${cl} " ]]; then
                found_logs+=("$cl")
            fi
        done
    fi

    # Инициализация чекбоксов
    for i in "${!found_logs[@]}"; do
        local fpath="${found_logs[$i]}"
        local is_sel="false"
        if [[ -n "$current_log" && "$current_log" != "Не задан" && "$current_log" != "systemd" ]]; then
            if [[ " $current_log " == *" $fpath "* ]]; then
                is_sel="true"
            fi
        elif [[ "$fpath" == *"$log_type"* ]]; then
            is_sel="true"
        fi
        selected_flags+=("$is_sel")
    done

    while true; do
        clear
        menu_header "📂 Выбор лог-файлов Nginx"
        info "Подсказка по выбору лог-файла:"
        printf_description " • Рекомендуемый тип лога: ${C_YELLOW}$log_type${C_RESET}"
        printf_description " • Вы можете выбрать ${C_GREEN}несколько${C_RESET} лог-файлов одновременно!"
        printf_description " • Перед выбором вы можете просмотреть содержимое любого лога."
        print_separator
        echo ""

        if [[ ${#found_logs[@]} -gt 0 ]]; then
            ok "Найденные файлы логов (${#found_logs[@]}):"
            for i in "${!found_logs[@]}"; do
                local log_file="${found_logs[$i]}"
                local size
                size=$(du -h "$log_file" 2>/dev/null | awk '{print $1}')
                local chk="[ ]"
                if [[ "${selected_flags[$i]}" == "true" ]]; then
                    chk="[${C_GREEN}✓${C_RESET}]"
                else
                    chk="[ ]"
                fi
                
                # Подсвечиваем файлы, соответствующие ожидаемому типу
                local hl_path="$log_file"
                if [[ "$log_file" == *"$log_type"* ]]; then
                    hl_path="${C_WHITE}$log_file${C_RESET}"
                else
                    hl_path="${C_GRAY}$log_file${C_RESET}"
                fi

                printf_description "  $chk ${C_WHITE}$((i+1)))${C_RESET} $hl_path ${C_GRAY}(${size:-?})${C_RESET}"
            done
        else
            warn "Логи Nginx не найдены автоматически."
        fi

        echo ""
        printf_menu_option "m" "Ввести путь вручную"
        if [[ ${#found_logs[@]} -gt 0 ]]; then
            printf_menu_option "ok" "Подтвердить выбор и выйти (Enter)"
        fi
        printf_menu_option "b" "Назад"
        echo ""
        
        local choice
        choice=$(safe_read "Введите номер для переключения, v[номер] для просмотра или команду" "ok") || return 1

        if [[ "$choice" == "b" || "$choice" == "B" ]]; then
            return 1
        elif [[ "$choice" == "m" || "$choice" == "M" ]]; then
            local manual_path
            manual_path=$(ask_non_empty "Введите полный путь к файлу лога") || continue
            found_logs+=("$manual_path")
            selected_flags+=("true")
        elif [[ "$choice" == "ok" || "$choice" == "OK" || -z "$choice" ]]; then
            local sel=""
            for i in "${!found_logs[@]}"; do
                if [[ "${selected_flags[$i]}" == "true" ]]; then
                    sel="$sel ${found_logs[$i]}"
                fi
            done
            sel=$(echo "$sel" | xargs)
            if [[ -z "$sel" ]]; then
                err "Не выбрано ни одного лога!"
                wait_for_enter
                continue
            fi
            F2B_SELECTED_LOG="$sel"
            break
        elif [[ "$choice" =~ ^[vV]([0-9]+)$ ]]; then
            local idx="${BASH_REMATCH[1]}"
            if [[ "$idx" -ge 1 && "$idx" -le ${#found_logs[@]} ]]; then
                _f2b_live_view_log "${found_logs[$((idx-1))]}"
            else
                err "Неверный индекс лога."
                wait_for_enter
            fi
        elif [[ "$choice" =~ ^[0-9]+$ ]]; then
            local idx="$choice"
            if [[ "$idx" -ge 1 && "$idx" -le ${#found_logs[@]} ]]; then
                local current_flag="${selected_flags[$((idx-1))]}"
                if [[ "$current_flag" == "true" ]]; then
                    selected_flags[$((idx-1))]="false"
                else
                    selected_flags[$((idx-1))]="true"
                fi
            else
                err "Неверный выбор."
                wait_for_enter
            fi
        else
            err "Неверная команда."
            wait_for_enter
        fi
    done
    return 0
}

_f2b_detect_syslog() {
    F2B_SELECTED_LOG=""
    local found_logs=()
    local selected_flags=()

    if [[ -f "/var/log/syslog" ]]; then found_logs+=("/var/log/syslog"); fi
    if [[ -f "/var/log/messages" ]]; then found_logs+=("/var/log/messages"); fi
    if [[ -f "/var/log/auth.log" ]]; then found_logs+=("/var/log/auth.log"); fi
    if [[ -f "/var/log/secure" ]]; then found_logs+=("/var/log/secure"); fi

    # Если доступен journalctl, добавляем systemd journal как виртуальный лог-источник
    if command -v journalctl &>/dev/null; then
        found_logs+=("systemd")
    fi

    # Парсим текущие логи
    if [[ -n "$current_log" && "$current_log" != "Не задан" ]]; then
        for cl in $current_log; do
            if [[ ! " ${found_logs[*]} " =~ " ${cl} " ]]; then
                found_logs+=("$cl")
            fi
        done
    fi

    # Инициализация чекбоксов
    for i in "${!found_logs[@]}"; do
        local fpath="${found_logs[$i]}"
        local is_sel="false"
        if [[ -n "$current_log" && "$current_log" != "Не задан" ]]; then
            if [[ " $current_log " == *" $fpath "* ]]; then
                is_sel="true"
            fi
        else
            if [[ $i -eq 0 ]]; then
                is_sel="true"
            fi
        fi
        selected_flags+=("$is_sel")
    done

    while true; do
        clear
        menu_header "📂 Выбор системных лог-файлов"
        info "Подсказка по выбору системного лога:"
        printf_description " • На современных системах рекомендуется использовать ${C_YELLOW}systemd${C_RESET}."
        printf_description " • Вы можете выбрать ${C_GREEN}несколько${C_RESET} лог-файлов одновременно!"
        printf_description " • Перед выбором вы можете просмотреть содержимое любого лога."
        print_separator
        echo ""

        ok "Найденные системные логи (${#found_logs[@]}):"
        for i in "${!found_logs[@]}"; do
            local log_file="${found_logs[$i]}"
            local chk="[ ]"
            if [[ "${selected_flags[$i]}" == "true" ]]; then
                chk="[${C_GREEN}✓${C_RESET}]"
            else
                chk="[ ]"
            fi

            if [[ "$log_file" == "systemd" ]]; then
                printf_description "  $chk ${C_WHITE}$((i+1)))${C_RESET} systemd-journald ${C_GRAY}(Системный журнал Systemd)${C_RESET}"
            else
                local size
                size=$(du -h "$log_file" 2>/dev/null | awk '{print $1}')
                printf_description "  $chk ${C_WHITE}$((i+1)))${C_RESET} ${log_file} ${C_GRAY}(${size:-?})${C_RESET}"
            fi
        done

        echo ""
        printf_menu_option "m" "Ввести путь вручную"
        printf_menu_option "ok" "Подтвердить выбор и выйти (Enter)"
        printf_menu_option "b" "Назад"
        echo ""

        local choice
        choice=$(safe_read "Введите номер для переключения, v[номер] для просмотра или команду" "ok") || return 1

        if [[ "$choice" == "b" || "$choice" == "B" ]]; then
            return 1
        elif [[ "$choice" == "m" || "$choice" == "M" ]]; then
            local manual_path
            manual_path=$(ask_non_empty "Введите полный путь к файлу системного лога") || continue
            found_logs+=("$manual_path")
            selected_flags+=("true")
        elif [[ "$choice" == "ok" || "$choice" == "OK" || -z "$choice" ]]; then
            local sel=""
            for i in "${!found_logs[@]}"; do
                if [[ "${selected_flags[$i]}" == "true" ]]; then
                    sel="$sel ${found_logs[$i]}"
                fi
            done
            sel=$(echo "$sel" | xargs)
            if [[ -z "$sel" ]]; then
                err "Не выбрано ни одного лога!"
                wait_for_enter
                continue
            fi
            F2B_SELECTED_LOG="$sel"
            break
        elif [[ "$choice" =~ ^[vV]([0-9]+)$ ]]; then
            local idx="${BASH_REMATCH[1]}"
            if [[ "$idx" -ge 1 && "$idx" -le ${#found_logs[@]} ]]; then
                _f2b_live_view_log "${found_logs[$((idx-1))]}"
            else
                err "Неверный индекс лога."
                wait_for_enter
            fi
        elif [[ "$choice" =~ ^[0-9]+$ ]]; then
            local idx="$choice"
            if [[ "$idx" -ge 1 && "$idx" -le ${#found_logs[@]} ]]; then
                local current_flag="${selected_flags[$((idx-1))]}"
                if [[ "$current_flag" == "true" ]]; then
                    selected_flags[$((idx-1))]="false"
                else
                    selected_flags[$((idx-1))]="true"
                fi
            else
                err "Неверный выбор."
                wait_for_enter
            fi
        else
            err "Неверная команда."
            wait_for_enter
        fi
    done
    return 0
}

_f2b_reload_or_start() {
    if _f2b_is_service_active; then
        info "Перезагружаю конфигурацию Fail2Ban..."
        run_cmd systemctl reload fail2ban 2>/dev/null || run_cmd systemctl restart fail2ban
    else
        info "Сервис Fail2Ban не активен. Пытаюсь запустить его..."
        if run_cmd systemctl start fail2ban; then
            ok "Сервис Fail2Ban успешно запущен!"
        else
            err "Не удалось запустить Fail2Ban. Проверьте конфигурацию с помощью 'fail2ban-client -d'."
        fi
    fi
}

_f2b_save_jail_option() {
    local jail="$1"
    local option="$2"
    local value="$3"
    
    python3 - "$jail" "$option" "$value" <<'PYEOF'
import sys
import os
import re

fpath = "/etc/fail2ban/jail.local"
jail = sys.argv[1]
option = sys.argv[2]
value = sys.argv[3]

if not os.path.exists(fpath):
    os.makedirs(os.path.dirname(fpath), exist_ok=True)
    with open(fpath, "w", encoding="utf-8") as f:
        f.write("# Fail2Ban local configuration\n")

try:
    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()
except Exception as e:
    sys.stderr.write(f"Error reading file: {e}\n")
    sys.exit(1)

section_pattern = re.compile(rf"^\[{re.escape(jail)}\]", re.IGNORECASE)
next_section_pattern = re.compile(r"^\[[^\]]+\]")

section_start = -1
next_section_start = -1

for idx, line in enumerate(lines):
    if section_pattern.match(line.strip()):
        section_start = idx
        continue
    if section_start != -1 and next_section_pattern.match(line.strip()):
        next_section_start = idx
        break

if section_start == -1:
    if lines and not lines[-1].endswith("\n"):
        lines.append("\n")
    lines.append(f"\n[{jail}]\n")
    if value:
        lines.append(f"{option} = {value}\n")
else:
    if next_section_start == -1:
        next_section_start = len(lines)

    option_pattern = re.compile(rf"^[ \t]*#?[ \t]*{re.escape(option)}[ \t]*=", re.IGNORECASE)
    option_idx = -1
    for idx in range(section_start + 1, next_section_start):
        if option_pattern.match(lines[idx]):
            option_idx = idx
            break

    if option_idx != -1:
        if value:
            lines[option_idx] = f"{option} = {value}\n"
        else:
            del lines[option_idx]
    else:
        if value:
            lines.insert(section_start + 1, f"{option} = {value}\n")

try:
    with open(fpath, "w", encoding="utf-8") as f:
        f.writelines(lines)
except Exception as e:
    sys.stderr.write(f"Error writing file: {e}\n")
    sys.exit(1)
PYEOF
}

_f2b_live_view_log() {
    local log_file="$1"
    clear
    menu_header "👁️ Просмотр лога в реальном времени"
    printf_description "Файл: ${C_YELLOW}$log_file${C_RESET}"
    printf_description "Нажмите ${C_GREEN}ENTER${C_RESET} или ${C_GREEN}Ctrl+C${C_RESET} для возврата в меню."
    print_separator
    echo ""

    if [[ "$log_file" == "systemd" ]]; then
        journalctl -n 50 -f &
    else
        if [[ ! -f "$log_file" ]]; then
            err "Файл '$log_file' не существует или не является файлом."
            wait_for_enter
            return
        fi
        tail -n 50 -f "$log_file" &
    fi
    local tail_pid=$!

    # Локальный trap для перехвата Ctrl+C во время просмотра логов
    local old_trap
    old_trap=$(trap -p SIGINT)
    trap 'kill $tail_pid 2>/dev/null; wait $tail_pid 2>/dev/null; eval "$old_trap"; return' SIGINT

    # Ожидание нажатия клавиши в неблокирующем цикле
    while kill -0 "$tail_pid" 2>/dev/null; do
        if read -t 0.5 -n 1 -r -s; then
            break
        fi
    done

    kill "$tail_pid" 2>/dev/null
    wait "$tail_pid" 2>/dev/null
    
    eval "$old_trap"
    
    ok "Просмотр завершен."
    sleep 0.5
}

_f2b_validate_log_path() {
    local full_path="$1"
    [[ -z "$full_path" ]] && return 1
    [[ "$full_path" == "systemd" ]] && return 0

    # Проверяем каждый путь из разделенных пробелом
    for path in $full_path; do
        [[ "$path" == "systemd" ]] && continue
        
        # Проверка масок / wildcards
        if [[ "$path" == *"*"* ]]; then
            local files
            files=$(ls $path 2>/dev/null)
            if [[ -z "$files" ]]; then
                warn "Файлы по маске '$path' не найдены."
                if ! ask_yes_no "Использовать этот путь все равно?"; then
                    return 1
                fi
            fi
            continue
        fi

        # Проверка обычного файла
        if [[ ! -f "$path" ]]; then
            warn "Файл лога '$path' не найден на сервере."
            if ! ask_yes_no "Использовать этот путь все равно?"; then
                return 1
            fi
        fi
    done
    return 0
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
    local is_enabled="false"
    local current_log="Не задан"
    local current_maxretry="3"

    while true; do
        clear
        enable_graceful_ctrlc
        menu_header "🛡️ Управление Jail: $jail_name"
        printf_description "$menu_title"
        print_separator

        local filter_file="/etc/fail2ban/filter.d/${jail_name}.conf"

        is_enabled="false"

        if [[ -f "/etc/fail2ban/jail.local" ]]; then
            if _f2b_is_jail_enabled "$jail_name"; then
                is_enabled="true"
            else
                is_enabled="false"
            fi
            local extracted_log
            extracted_log=$(_f2b_get_jail_var "$jail_name" "logpath")
            [[ -n "$extracted_log" ]] && current_log="$extracted_log"

            local extracted_backend
            extracted_backend=$(_f2b_get_jail_var "$jail_name" "backend")
            if [[ "${extracted_backend,,}" == "systemd" ]]; then
                current_log="systemd"
            fi
            
            local extracted_max
            extracted_max=$(_f2b_get_jail_var "$jail_name" "maxretry")
            [[ -n "$extracted_max" ]] && current_maxretry="$extracted_max"

            local extracted_p
            extracted_p=$(_f2b_get_jail_var "$jail_name" "port")
            [[ -n "$extracted_p" ]] && current_p="$extracted_p"

            local extracted_a
            extracted_a=$(_f2b_get_jail_var "$jail_name" "action")
            [[ -n "$extracted_a" ]] && current_a="$extracted_a"
        fi

        local current_action_desc="Полная изоляция (все порты)"
        if [[ -n "$current_a" ]]; then
            if [[ "$current_a" == *"ufw"* ]]; then
                local act_port=""
                if [[ "$current_a" == *"port="* ]]; then
                    act_port=$(echo "$current_a" | grep -o "port=[^,]*" | cut -d= -f2 | tr -d ']"')
                fi
                
                if [[ -z "$act_port" || "$act_port" == "%(port)s" ]]; then
                    act_port="$current_p"
                fi
                
                if [[ "$act_port" == "any" || -z "$act_port" ]]; then
                    current_action_desc="Полная изоляция (все порты)"
                else
                    current_action_desc="Только сервис (порт $act_port)"
                fi
            else
                current_action_desc="Стандартный Fail2Ban (${current_a})"
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
            read -ra log_paths <<< "$current_log"
            if [[ ${#log_paths[@]} -gt 1 ]]; then
                printf_description "Файлы логов:"
                for path in "${log_paths[@]}"; do
                    printf "             • %b%b\n" "${C_CYAN}${path}${C_RESET}"
                done
            else
                printf_description "Файл лога: ${C_CYAN}$current_log${C_RESET}"
            fi
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
                    _f2b_save_jail_option "$jail_name" "enabled" "false"
                    ok "Защита '$jail_name' выключена."
                    _f2b_reload_or_start
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
                    
                    info "Сохраняю конфигурацию защиты в jail.local..."
                    _f2b_save_jail_option "$jail_name" "enabled" "true"
                    _f2b_save_jail_option "$jail_name" "port" "$current_p"
                    _f2b_save_jail_option "$jail_name" "filter" "$jail_name"
                    if [[ "$current_log" == "systemd" ]]; then
                        _f2b_save_jail_option "$jail_name" "backend" "systemd"
                        _f2b_save_jail_option "$jail_name" "logpath" ""
                    else
                        _f2b_save_jail_option "$jail_name" "backend" ""
                        _f2b_save_jail_option "$jail_name" "logpath" "$current_log"
                    fi
                    _f2b_save_jail_option "$jail_name" "maxretry" "$current_maxretry"
                    _f2b_save_jail_option "$jail_name" "findtime" "600"
                    _f2b_save_jail_option "$jail_name" "bantime" "86400"
                    _f2b_save_jail_option "$jail_name" "action" "$current_a"
                    
                    ok "Защита '$jail_name' включена."
                    _f2b_reload_or_start
                fi
                wait_for_enter
                ;;
            2)
                local new_maxretry
                new_maxretry=$(safe_read "Введите новое количество попыток (текущее: $current_maxretry)" "$current_maxretry") || continue
                if [[ "$new_maxretry" =~ ^[0-9]+$ ]]; then
                    if grep -q "^\s*\[$jail_name\]" /etc/fail2ban/jail.local 2>/dev/null; then
                        _f2b_save_jail_option "$jail_name" "maxretry" "$new_maxretry"
                        ok "maxretry обновлен до $new_maxretry"
                        [[ "$is_enabled" == "true" ]] && _f2b_reload_or_start
                    else
                        current_maxretry="$new_maxretry"
                        ok "Количество попыток выбрано: $new_maxretry. Включите защиту для применения."
                    fi
                else
                    err "Должно быть числом."
                fi
                wait_for_enter
                ;;
            3)
                if [[ "$log_type" == "nginx-access" ]]; then
                    _f2b_detect_nginx_log "access" || continue
                elif [[ "$log_type" == "nginx-error" ]]; then
                    _f2b_detect_nginx_log "error" || continue
                elif [[ "$log_type" == "syslog" ]]; then
                    _f2b_detect_syslog || continue
                else
                    F2B_SELECTED_LOG=$(ask_non_empty "Введите путь к логу") || continue
                fi
                
                if ! _f2b_validate_log_path "$F2B_SELECTED_LOG"; then
                    wait_for_enter
                    continue
                fi

                if [[ -n "$F2B_SELECTED_LOG" ]]; then
                    if grep -q "^\s*\[$jail_name\]" /etc/fail2ban/jail.local 2>/dev/null; then
                        if [[ "$F2B_SELECTED_LOG" == "systemd" ]]; then
                            _f2b_save_jail_option "$jail_name" "logpath" ""
                            _f2b_save_jail_option "$jail_name" "backend" "systemd"
                        else
                            _f2b_save_jail_option "$jail_name" "backend" ""
                            _f2b_save_jail_option "$jail_name" "logpath" "$F2B_SELECTED_LOG"
                        fi
                        ok "Лог обновлен."
                        [[ "$is_enabled" == "true" ]] && _f2b_reload_or_start
                    else
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
                [[ "$is_enabled" == "true" ]] && _f2b_reload_or_start
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
                    _f2b_save_jail_option "$jail_name" "port" "${new_p_val}"
                    _f2b_save_jail_option "$jail_name" "action" "${new_a_val}"
                    ok "Метод блокировки обновлен в конфигурации."
                    [[ "$is_enabled" == "true" ]] && _f2b_reload_or_start
                fi
                
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

