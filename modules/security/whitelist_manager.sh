#!/bin/bash
#   ( РОДИТЕЛЬ | КЛАВИША | НАЗВАНИЕ | ФУНКЦИЯ | ПОРЯДОК | ГРУППА | ОПИСАНИЕ )
# @menu.manifest
# @item( security | w | 🌍 Глобальный Белый Список | show_global_whitelist_menu | 5 | 5 | Единый whitelist для всех модулей защиты. )
#
# whitelist_manager.sh - Глобальный Белый Список (Unified Whitelist)
#
# Центральный менеджер IP-адресов, которым доверяют ВСЕ модули:
#   - eBPF Шейпер (whitelist_map)
#   - Fail2Ban (ignoreip)
#   - UFW before.rules (обход Anti-DDoS лимитов)
#   - Geo-block ipset (обход блокировки стран)
#
# API для других модулей:
#   global_whitelist_get_ips  — Получить массив IP из глобального списка
#   global_whitelist_add_ip   — Добавить IP и синхронизировать
#   global_whitelist_remove_ip — Удалить IP и синхронизировать
#   global_whitelist_sync_all — Принудительная полная синхронизация
#   global_whitelist_offer    — Предложить использовать глобальный список (вызывается из модулей)
#

[[ "${BASH_SOURCE[0]}" == "${0}" ]] && exit 1

# --- Конфигурация ---
GLOBAL_WHITELIST_DIR="/etc/reshala"
GLOBAL_WHITELIST_FILE="${GLOBAL_WHITELIST_DIR}/global-whitelist.txt"

# ============================================================ #
#                         ПУБЛИЧНЫЙ API                        #
# ============================================================ #

# Инициализирует директорию и файл белого списка
_gwl_ensure_file() {
    if [[ ! -d "$GLOBAL_WHITELIST_DIR" ]]; then
        run_cmd mkdir -p "$GLOBAL_WHITELIST_DIR"
    fi
    if [[ ! -f "$GLOBAL_WHITELIST_FILE" ]]; then
        run_cmd touch "$GLOBAL_WHITELIST_FILE"
        run_cmd chmod 644 "$GLOBAL_WHITELIST_FILE"
        # Создаем шаблон
        cat <<'TEMPLATE' | run_cmd tee "$GLOBAL_WHITELIST_FILE" > /dev/null
# ══════════════════════════════════════════════════════════
# Глобальный Белый Список IP (Reshala Unified Whitelist)
# ══════════════════════════════════════════════════════════
# Все IP из этого файла автоматически получают обход:
#   ✓ eBPF Шейпер      — без ограничений скорости
#   ✓ Fail2Ban         — игнорирование банов
#   ✓ UFW Anti-DDoS    — обход CONN/RATE лимитов
#   ✓ Geo-Block        — обход блокировки стран
#
# Формат: IP # Комментарий
# Пример:
# 185.100.200.50 # Панель управления
# 91.200.100.25  # Мой домашний IP
#
TEMPLATE
    fi
}

# Возвращает список IP (без комментариев и пустых строк)
# Использование: mapfile -t ips < <(global_whitelist_get_ips)
global_whitelist_get_ips() {
    _gwl_ensure_file
    grep -v '^\s*#' "$GLOBAL_WHITELIST_FILE" | grep -v '^\s*$' | awk '{print $1}' | grep -E '^[0-9a-fA-F]'
}

# Возвращает количество IP в списке
global_whitelist_count() {
    local count
    count=$(global_whitelist_get_ips | wc -l)
    echo "${count:-0}"
}

# Добавить IP в глобальный список и синхронизировать
# Использование: global_whitelist_add_ip "1.2.3.4" "Комментарий"
global_whitelist_add_ip() {
    local ip="$1"
    local comment="${2:-Manual}"
    _gwl_ensure_file

    if ! validate_ip "$ip"; then
        err "Некорректный IP адрес: $ip"
        return 1
    fi

    # Проверяем дубликаты
    if grep -q "^${ip}" "$GLOBAL_WHITELIST_FILE" 2>/dev/null; then
        warn "IP ${ip} уже в Глобальном Белом Списке."
        return 0
    fi

    echo "${ip} # ${comment}" | run_cmd tee -a "$GLOBAL_WHITELIST_FILE" > /dev/null
    ok "IP ${C_CYAN}${ip}${C_RESET} добавлен в Глобальный Белый Список."
    global_whitelist_sync_all
    return 0
}

# Удалить IP из глобального списка и синхронизировать
global_whitelist_remove_ip() {
    local ip="$1"
    _gwl_ensure_file

    if ! grep -q "^${ip}" "$GLOBAL_WHITELIST_FILE" 2>/dev/null; then
        err "IP ${ip} не найден в Глобальном Белом Списке."
        return 1
    fi

    run_cmd sed -i "/^${ip}/d" "$GLOBAL_WHITELIST_FILE"
    ok "IP ${C_CYAN}${ip}${C_RESET} удален из Глобального Белого Списка."
    global_whitelist_sync_all
    return 0
}

# Полная синхронизация всех подсистем
global_whitelist_sync_all() {
    _gwl_ensure_file
    info "Синхронизация Глобального Белого Списка..."

    local ips
    mapfile -t ips < <(global_whitelist_get_ips)
    local count=${#ips[@]}

    # --- 1. Fail2Ban ignoreip ---
    _gwl_sync_fail2ban "${ips[@]}"

    # --- 2. eBPF Шейпер ---
    _gwl_sync_shaper

    # --- 3. Geo-block ipset ---
    _gwl_sync_geoblock "${ips[@]}"

    ok "Синхронизация завершена. Подключено IP: ${C_CYAN}${count}${C_RESET}"
}

# Предложить использовать глобальный список (для модулей)
# Использование: global_whitelist_offer "shaper"
# Возвращает: 0 = использовать глобальный, 1 = оставить свой
global_whitelist_offer() {
    local module_name="$1"
    _gwl_ensure_file

    local count
    count=$(global_whitelist_count)

    if [[ "$count" -eq 0 ]]; then
        return 1 # Нет глобального списка
    fi

    echo ""
    echo -e "  ${C_CYAN}╔══════════════════════════════════════════════════════════╗${C_RESET}"
    echo -e "  ${C_CYAN}║${C_RESET}  ${C_YELLOW}🌍 Обнаружен Глобальный Белый Список (${count} IP)${C_RESET}"
    echo -e "  ${C_CYAN}╠══════════════════════════════════════════════════════════╣${C_RESET}"
    echo -e "  ${C_CYAN}║${C_RESET}  Этот единый список автоматически применяется ко всем"
    echo -e "  ${C_CYAN}║${C_RESET}  модулям защиты (Шейпер, Fail2Ban, UFW, Geo-Block)."
    echo -e "  ${C_CYAN}╠══════════════════════════════════════════════════════════╣${C_RESET}"
    echo -e "  ${C_CYAN}║${C_RESET}  ${C_WHITE}Текущие IP:${C_RESET}"

    local ips
    mapfile -t ips < <(global_whitelist_get_ips)
    for ip in "${ips[@]}"; do
        echo -e "  ${C_CYAN}║${C_RESET}    ${C_GREEN}●${C_RESET} ${ip}"
    done

    echo -e "  ${C_CYAN}╚══════════════════════════════════════════════════════════╝${C_RESET}"
    echo ""

    if ask_yes_no "Использовать Глобальный Белый Список для модуля '${module_name}'?" "y"; then
        return 0
    fi
    return 1
}

# ============================================================ #
#                    СИНХРОНИЗАЦИЯ ПОДСИСТЕМ                    #
# ============================================================ #

# Синхронизация с Fail2Ban
_gwl_sync_fail2ban() {
    local ips=("$@")
    if [[ ! -f "/etc/fail2ban/jail.local" ]]; then
        debug_log "GWL_SYNC: Fail2Ban jail.local не найден, пропуск."
        return
    fi

    local ignoreip="127.0.0.1/8 ::1"
    for ip in "${ips[@]}"; do
        ignoreip="$ignoreip $ip"
    done

    run_cmd sed -i -e "s,^ignoreip\s*=.*,ignoreip = $ignoreip," /etc/fail2ban/jail.local
    run_cmd systemctl reload fail2ban 2>/dev/null || true
    debug_log "GWL_SYNC: Fail2Ban ignoreip обновлен."
}

# Синхронизация с eBPF Шейпером
_gwl_sync_shaper() {
    # Ищем конфиг шейпера
    local shaper_config_dir="/etc/reshala/traffic_limiter"
    local shaper_whitelist="${shaper_config_dir}/global-whitelist.txt"
    local ctrl_py="${SCRIPT_DIR}/modules/local/reshala_ctrl.py"
    local pin_dir="/sys/fs/bpf/reshala/maps"

    if [[ ! -f "$ctrl_py" ]]; then
        debug_log "GWL_SYNC: reshala_ctrl.py не найден, пропуск шейпера."
        return
    fi

    # Копируем глобальный список в файл шейпера (для истории)
    if [[ -d "$shaper_config_dir" ]]; then
        run_cmd cp -f "$GLOBAL_WHITELIST_FILE" "$shaper_whitelist" 2>/dev/null || true
    fi

    # Синхронизируем BPF-карту, если движок активен
    if [[ -d "$pin_dir" ]]; then
        python3 "$ctrl_py" --pin-dir "$pin_dir" whitelist-sync --file "$GLOBAL_WHITELIST_FILE" 2>/dev/null || true
        debug_log "GWL_SYNC: eBPF whitelist_map обновлена."
    else
        debug_log "GWL_SYNC: eBPF pin_dir не существует (движок не запущен), пропуск."
    fi
}

# Синхронизация с Geo-block ipset
_gwl_sync_geoblock() {
    local ips=("$@")

    if ! command -v ipset &>/dev/null; then
        debug_log "GWL_SYNC: ipset не установлен, пропуск Geo-block."
        return
    fi

    # Нам нужно два сета, так как ipset не смешивает v4 и v6
    for family in "inet" "inet6"; do
        local set_name="reshala_geo_whitelist"
        [[ "$family" == "inet6" ]] && set_name="reshala_geo_whitelist6"

        if ! ipset list "$set_name" &>/dev/null; then
            run_cmd ipset create "$set_name" hash:ip family "$family" hashsize 256 maxelem 1024 2>/dev/null || true
        fi
        run_cmd ipset flush "$set_name" 2>/dev/null || true
    done

    # Распределяем IP по сетам
    for ip in "${ips[@]}"; do
        if [[ "$ip" == *":"* ]]; then
            run_cmd ipset add reshala_geo_whitelist6 "$ip" 2>/dev/null || true
        else
            run_cmd ipset add reshala_geo_whitelist "$ip" 2>/dev/null || true
        fi
    done

    debug_log "GWL_SYNC: Geo-block whitelist (v4/v6) обновлен."
}

# ============================================================ #
#                           МЕНЮ                               #
# ============================================================ #

show_global_whitelist_menu() {
    _gwl_ensure_file

    while true; do
        clear
        enable_graceful_ctrlc
        menu_header "🌍 Глобальный Белый Список"
        printf_description "Единый whitelist для ВСЕХ модулей защиты."

        print_separator
        info "Файл: ${C_CYAN}${GLOBAL_WHITELIST_FILE}${C_RESET}"

        # Показываем текущий список
        local ips
        mapfile -t ips < <(global_whitelist_get_ips)
        local count=${#ips[@]}

        if [[ "$count" -gt 0 ]]; then
            info "Доверенные IP (${C_CYAN}${count}${C_RESET}):"
            local i=1
            while IFS= read -r line; do
                [[ -z "$line" ]] && continue
                [[ "$line" =~ ^[[:space:]]*# ]] && continue
                local ip comment
                ip=$(echo "$line" | awk '{print $1}')
                comment=$(echo "$line" | sed 's/^[^ ]* *# *//' | sed 's/^[^ ]*$//')
                printf_description "${C_WHITE}${i})${C_RESET} ${C_CYAN}${ip}${C_RESET}${comment:+  ${C_GRAY}(${comment})${C_RESET}}"
                ((i++))
            done < <(grep -v '^\s*#' "$GLOBAL_WHITELIST_FILE" | grep -v '^\s*$')
        else
            warn "Список пуст. Добавьте IP для защиты от блокировок."
        fi

        # Показываем статус синхронизации
        echo ""
        info "Статус синхронизации:"
        # Fail2Ban
        if [[ -f "/etc/fail2ban/jail.local" ]]; then
            printf_description "  ${C_GREEN}✓${C_RESET} Fail2Ban (ignoreip)"
        else
            printf_description "  ${C_GRAY}○${C_RESET} Fail2Ban (не установлен)"
        fi
        # Шейпер
        if [[ -d "/sys/fs/bpf/reshala/maps" ]]; then
            printf_description "  ${C_GREEN}✓${C_RESET} eBPF Шейпер (whitelist_map)"
        else
            printf_description "  ${C_GRAY}○${C_RESET} eBPF Шейпер (движок не запущен)"
        fi
        # Geo-block
        if command -v ipset &>/dev/null && ipset list reshala_geo_whitelist &>/dev/null; then
            printf_description "  ${C_GREEN}✓${C_RESET} Geo-Block (ipset)"
        else
            printf_description "  ${C_GRAY}○${C_RESET} Geo-Block (не активен)"
        fi

        print_separator

        echo ""
        printf_menu_option "1" "➕ Добавить IP"
        printf_menu_option "2" "➖ Удалить IP"
        printf_menu_option "3" "🔄 Принудительная синхронизация"
        printf_menu_option "4" "📋 Авто-определить мой IP"
        printf_menu_option "5" "📝 Ручное редактирование (Editor)"
        echo ""
        printf_menu_option "b" "Назад"
        echo ""

        local choice
        choice=$(safe_read "Выберите действие" "") || { break; }

        case "$choice" in
            1)
                local new_ip new_comment
                while true; do
                    new_ip=$(ask_non_empty "Введите IP адрес (или 'q' для отмены)") || break
                    [[ "$new_ip" == "q" ]] && break
                    
                    if validate_ip "$new_ip"; then
                        new_comment=$(safe_read "Комментарий (имя/описание)" "Manual") || break
                        global_whitelist_add_ip "$new_ip" "$new_comment"
                        break
                    else
                        warn "Некорректный IP: $new_ip. Попробуй еще раз (пример: 1.2.3.4)"
                    fi
                done
                wait_for_enter
                ;;
            2)
                if [[ "$count" -eq 0 ]]; then
                    warn "Список пуст, нечего удалять."
                    wait_for_enter
                    continue
                fi
                local del_ip
                del_ip=$(ask_non_empty "Введите IP для удаления") || continue
                global_whitelist_remove_ip "$del_ip"
                wait_for_enter
                ;;
            3)
                global_whitelist_sync_all
                wait_for_enter
                ;;
            4)
                _gwl_autodetect_ip
                wait_for_enter
                ;;
            5)
                info "Открываю список в редакторе..."
                sleep 1
                nano "$GLOBAL_WHITELIST_FILE"
                ok "Изменения сохранены. Запускаю синхронизацию..."
                global_whitelist_sync_all
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

# Авто-определение IP текущей сессии
_gwl_autodetect_ip() {
    print_separator
    info "Авто-определение IP"
    print_separator

    local my_ip
    # Способ 1: из SSH-сессии
    my_ip=$(who -m 2>/dev/null | awk '{print $5}' | tr -d '()')
    
    # Способ 2: через внешний сервис
    if [[ -z "$my_ip" ]] || ! validate_ip "$my_ip"; then
        info "Определяю внешний IP..."
        my_ip=$(curl -s --max-time 5 ifconfig.me 2>/dev/null)
    fi

    if [[ -n "$my_ip" ]] && validate_ip "$my_ip"; then
        ok "Ваш текущий IP: ${C_CYAN}${my_ip}${C_RESET}"

        if grep -q "^${my_ip}" "$GLOBAL_WHITELIST_FILE" 2>/dev/null; then
            info "Этот IP уже есть в Глобальном Белом Списке."
            return
        fi

        if ask_yes_no "Добавить ${my_ip} в Глобальный Белый Список?" "y"; then
            global_whitelist_add_ip "$my_ip" "Auto-detected ($(date +%Y-%m-%d))"
        fi
    else
        err "Не удалось определить IP. Добавьте его вручную."
    fi
}
