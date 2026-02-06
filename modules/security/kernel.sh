#!/bin/bash
#   ( РОДИТЕЛЬ | КЛАВИША | НАЗВАНИЕ | ФУНКЦИЯ | ПОРЯДОК | ГРУППА | ОПИСАНИЕ )
# @menu.manifest
# @item( security | 3 | 🧠 Kernel Hardening | show_kernel_menu | 30 | 10 | Усиление защиты ядра от сетевых атак. )
#
# kernel.sh - Kernel Hardening (sysctl)
#

SYSCTL_CONF_FILE="/etc/sysctl.d/99-reshala-hardening.conf"

_kernel_has_wt0_interface() {
    ip link show wt0 > /dev/null 2>&1
}

_kernel_resolve_iface_name() {
    local iface="$1"
    local resolved
    [[ -n "$iface" ]] || return 1

    resolved=$(ip -o link show "$iface" 2>/dev/null | awk -F': ' 'NR==1 {print $2}')
    resolved="${resolved%%@*}"
    [[ -n "$resolved" ]] || return 1
    echo "$resolved"
}

_kernel_interface_exists() {
    local iface="$1"
    local resolved
    [[ -n "$iface" ]] || return 1
    resolved=$(_kernel_resolve_iface_name "$iface") || return 1
    [[ -n "$resolved" ]]
}

_kernel_get_default_interface() {
    local iface
    local resolved_iface
    iface=$(ip -o route show default 2>/dev/null | awk '{print $5; exit}')
    iface="${iface%%@*}"
    if [[ -z "$iface" ]]; then
        return 0
    fi
    resolved_iface=$(_kernel_resolve_iface_name "$iface" 2>/dev/null || true)
    echo "${resolved_iface:-$iface}"
}

_kernel_get_active_public_interfaces() {
    ip -o link show up 2>/dev/null \
        | awk -F': ' '{print $2}' \
        | cut -d'@' -f1 \
        | grep -Ev '^(lo|wt0)$'
}

_kernel_select_public_interface() {
    local default_iface="$1"
    local -a detected_interfaces=()
    local -a ordered_interfaces=()
    local -a unique_interfaces=()
    local iface
    local canonical_iface
    local existing_iface
    local already_added
    local idx=1
    local default_idx=1
    local choice

    mapfile -t detected_interfaces < <(_kernel_get_active_public_interfaces)

    if [[ -n "$default_iface" && "$default_iface" != "lo" && "$default_iface" != "wt0" ]]; then
        canonical_iface=$(_kernel_resolve_iface_name "$default_iface" 2>/dev/null || true)
        ordered_interfaces+=("${canonical_iface:-$default_iface}")
    fi

    for iface in eth0 ens3; do
        if _kernel_interface_exists "$iface"; then
            canonical_iface=$(_kernel_resolve_iface_name "$iface" 2>/dev/null || true)
            ordered_interfaces+=("${canonical_iface:-$iface}")
        fi
    done

    for iface in "${detected_interfaces[@]}"; do
        canonical_iface=$(_kernel_resolve_iface_name "$iface" 2>/dev/null || true)
        ordered_interfaces+=("${canonical_iface:-$iface}")
    done

    for iface in "${ordered_interfaces[@]}"; do
        [[ -z "$iface" || "$iface" == "lo" || "$iface" == "wt0" ]] && continue

        already_added="0"
        for existing_iface in "${unique_interfaces[@]}"; do
            if [[ "$existing_iface" == "$iface" ]]; then
                already_added="1"
                break
            fi
        done

        [[ "$already_added" == "0" ]] && unique_interfaces+=("$iface")
    done

    if [[ ${#unique_interfaces[@]} -eq 0 ]]; then
        >&2 warn "Не удалось автоматически найти внешний интерфейс."
        return 1
    fi

    if [[ ${#unique_interfaces[@]} -eq 1 ]]; then
        >&2 info "Найден основной интерфейс: ${unique_interfaces[0]}"
        echo "${unique_interfaces[0]}"
        return 0
    fi

    >&2 info "Обнаружено несколько интерфейсов. Выбери основной публичный интерфейс:"
    for iface in "${unique_interfaces[@]}"; do
        if [[ "$iface" == "$default_iface" ]]; then
            default_idx="$idx"
        fi
        >&2 printf "   [%d] %s\n" "$idx" "$iface"
        idx=$((idx + 1))
    done

    choice=$(ask_number_in_range "Номер интерфейса" 1 "${#unique_interfaces[@]}" "$default_idx") || return 1
    echo "${unique_interfaces[$((choice - 1))]}"
}

show_kernel_menu() {
    while true; do
        clear
        enable_graceful_ctrlc
        menu_header "🧠 Kernel Hardening"
        printf_description "Усиление защиты и оптимизация ядра"

        _kernel_check_status
        
        echo ""
        printf_menu_option "1" "Применить безопасные настройки"
        printf_menu_option "2" "Откатить изменения"
        echo ""
        printf_menu_option "b" "Назад"
        echo ""

        local choice
        choice=$(safe_read "Выберите действие" "") || { break; }
        
        case "$choice" in
            1) _kernel_apply; wait_for_enter;;
            2) _kernel_revert; wait_for_enter;;
            b|B) break;;
            *) warn "Неверный выбор";;
        esac
        disable_graceful_ctrlc
    done
}

_kernel_check_status() {
    print_separator
    info "Статус Kernel Hardening"

    if [[ -f "$SYSCTL_CONF_FILE" ]]; then
        printf_description "Конфиг: ${C_GREEN}Применен${C_RESET} ($SYSCTL_CONF_FILE)"
        
        # Проверяем ключевые параметры
        local syn_cookies
        syn_cookies=$(run_cmd sysctl -n net.ipv4.tcp_syncookies 2>/dev/null)
        
        local rp_filter_all
        rp_filter_all=$(run_cmd sysctl -n net.ipv4.conf.all.rp_filter 2>/dev/null)

        local rp_filter_default
        rp_filter_default=$(run_cmd sysctl -n net.ipv4.conf.default.rp_filter 2>/dev/null)

        local default_iface
        default_iface=$(_kernel_get_default_interface)

        local rp_filter_main_iface=""
        if [[ -n "$default_iface" ]]; then
            rp_filter_main_iface=$(run_cmd sysctl -n "net.ipv4.conf.${default_iface}.rp_filter" 2>/dev/null || true)
        fi

        local rp_filter_wt0=""
        if _kernel_has_wt0_interface; then
            rp_filter_wt0=$(run_cmd sysctl -n net.ipv4.conf.wt0.rp_filter 2>/dev/null || true)
        fi

        local aslr
        aslr=$(run_cmd sysctl -n kernel.randomize_va_space 2>/dev/null)

        local rp_filter_status
        if [[ "$rp_filter_all" == "1" && "$rp_filter_default" == "1" ]]; then
            rp_filter_status="  - RP Filter (Anti-Spoofing): ${C_GREEN}Strict (all/default=1)${C_RESET}"
        elif [[ "$rp_filter_all" == "0" && "$rp_filter_default" == "0" && "$rp_filter_wt0" == "2" ]]; then
            if [[ -n "$default_iface" && "$rp_filter_main_iface" == "1" ]]; then
                rp_filter_status="  - RP Filter (Anti-Spoofing): ${C_GREEN}NetBird profile (wt0=2, ${default_iface}=1)${C_RESET}"
            else
                rp_filter_status="  - RP Filter (Anti-Spoofing): ${C_GREEN}NetBird profile (wt0=2)${C_RESET}"
            fi
        else
            rp_filter_status="  - RP Filter (Anti-Spoofing): ${C_YELLOW}Нестандартный профиль (all=${rp_filter_all:-?}, default=${rp_filter_default:-?})${C_RESET}"
        fi

        echo ""
        info "Ключевые параметры:"
        
        [[ "$syn_cookies" == "1" ]] && printf_description "  - SYN Cookies: ${C_GREEN}Включены${C_RESET}" || printf_description "  - SYN Cookies: ${C_RED}Отключены${C_RESET}"
        printf_description "$rp_filter_status"
        [[ "$aslr" == "2" ]] && printf_description "  - ASLR (Address Space Randomization): ${C_GREEN}Полный${C_RESET}" || printf_description "  - ASLR (Address Space Randomization): ${C_YELLOW}Частичный или выкл${C_RESET}"

    else
        printf_description "Конфиг: ${C_YELLOW}Не применялся${C_RESET}"
    fi
    print_separator
}

_kernel_apply() {
    print_separator
    info "Применение Kernel Hardening"
    print_separator

    if ! ask_yes_no "Это действие создаст файл $SYSCTL_CONF_FILE и применит системные настройки. Продолжить?"; then
        info "Отмена."
        return
    fi
    
    local backup_dir
    backup_dir="${SCRIPT_DIR}/modules/security/backups"
    run_cmd mkdir -p "$backup_dir"
    
    info "Создаю бэкап текущих sysctl настроек..."
    run_cmd sysctl -a > "$backup_dir/sysctl.backup_$(date +%s)" 2>/dev/null
    ok "Бэкап создан в $backup_dir"

    local default_iface
    default_iface=$(_kernel_get_default_interface)

    local main_public_iface=""
    local rp_filter_comment="# rp_filter: strict (стандартный профиль для серверов без NetBird)"
    local rp_filter_all="1"
    local rp_filter_default="1"
    local rp_filter_main_line=""
    local rp_filter_wt0_line=""

    if _kernel_has_wt0_interface; then
        info "Обнаружен интерфейс wt0 (NetBird)."
        main_public_iface=$(_kernel_select_public_interface "$default_iface") || {
            err "Не удалось определить основной публичный интерфейс. Применение отменено."
            return
        }

        rp_filter_comment="# rp_filter: loose/точечно, чтобы не ломать policy routing (NetBird fwmark)"
        rp_filter_all="0"
        rp_filter_default="0"
        rp_filter_main_line="net.ipv4.conf.${main_public_iface}.rp_filter = 1"
        rp_filter_wt0_line="net.ipv4.conf.wt0.rp_filter = 2"

        info "Включаю NetBird-совместимый профиль RP Filter."
        printf_description "Основной интерфейс: ${C_GREEN}${main_public_iface}${C_RESET}"
    elif [[ -n "$default_iface" ]]; then
        info "wt0 не найден. Оставляю strict-профиль RP Filter (интерфейс по умолчанию: ${default_iface})."
    else
        info "wt0 не найден. Оставляю strict-профиль RP Filter."
    fi

    info "Создаю конфигурационный файл..."
    run_cmd tee "$SYSCTL_CONF_FILE" > /dev/null << SYSCTL
# Generated by Reshala Security Module
#
# Kernel Hardening & Performance Tuning
#

# --- SYN Flood Protection ---
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_max_syn_backlog = 4096
net.core.somaxconn = 4096
net.core.netdev_max_backlog = 4096

# --- IP Spoofing & Network Attack Protection ---
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
${rp_filter_comment}
net.ipv4.conf.all.rp_filter = ${rp_filter_all}
net.ipv4.conf.default.rp_filter = ${rp_filter_default}
${rp_filter_main_line}
${rp_filter_wt0_line}
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# --- TCP Tuning ---
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_intvl = 15

# --- Kernel Security ---
kernel.randomize_va_space = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1
fs.protected_symlinks = 1
fs.protected_hardlinks = 1

# IP Forwarding is intentionally left untouched for VPN compatibility
SYSCTL
    
    ok "Конфигурационный файл создан."
    
    info "Применяю настройки..."
    if run_cmd sysctl -p "$SYSCTL_CONF_FILE"; then
        ok "Настройки Kernel Hardening успешно применены."
    else
        err "Произошла ошибка при применении настроек."
    fi
}

_kernel_revert() {
    print_separator
    info "Откат Kernel Hardening"
    print_separator
    
    if [[ ! -f "$SYSCTL_CONF_FILE" ]]; then
        warn "Настройки Kernel Hardening не применялись (файл не найден)."
        return
    fi
    
    if ! ask_yes_no "Это действие удалит файл $SYSCTL_CONF_FILE и вернет стандартные системные настройки. Продолжить?"; then
        info "Отмена."
        return
    fi
    
    info "Удаляю конфигурационный файл..."
    run_cmd rm -f "$SYSCTL_CONF_FILE"
    
    info "Перезагружаю системные правила sysctl..."
    if run_cmd sysctl --system; then
        ok "Настройки Kernel Hardening откачены."
    else
        err "Произошла ошибка при откате настроек."
    fi
}
