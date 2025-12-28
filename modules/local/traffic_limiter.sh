#!/bin/bash
# ============================================================ #
# ==                 МОДУЛЬ ШЕЙПЕРА ТРАФИКА                 == #
# ============================================================ #
#
# Отвечает за настройку и управление лимитами скорости для
# отдельных портов с помощью tc + u32 hashing (Stable Mode).
#  ( РОДИТЕЛЬ | КЛАВИША | НАЗВАНИЕ | ФУНКЦИЯ | ПОРЯДОК | ГРУППА | ОПИСАНИЕ )
# @menu.manifest
#
# @item( main | 2 | 🚦 Шейпер трафика ${C_GREEN}(Персональный лимит)${C_RESET} | show_traffic_limiter_menu | 2 | 0 | Ограничение скорости для каждого пользователя на порту. )
#
# @item( traffic_limiter | 1 | 📊 Текущий статус (Топ-5) | _tl_show_status | 10 | 1 | Показывает активные правила и топ потребителей. )
# @item( traffic_limiter | 2 | ➕ Добавить/изменить лимит | _tl_apply_limit_wizard | 20 | 1 | Запускает мастер настройки для порта. )
# @item( traffic_limiter | 3 | ➖ Удалить лимит(ы) | _show_delete_submenu | 30 | 1 | Позволяет выбрать и удалить один или все лимиты. )
# @item( traffic_limiter | 4 | 📜 Посмотреть лог сервиса | _tl_view_service_log | 40 | 2 | Показывает системный журнал для службы шейпера. )
# @item( traffic_limiter | 5 | 📈 Мониторинг трафика (iftop) | _tl_monitor_traffic | 50 | 2 | Запуск утилиты iftop для просмотра текущей скорости. )
# @item( traffic_limiter | 6 | 🔄 Перезагрузить (Сброс статы) | _tl_restart_service | 60 | 2 | Перезапуск сервиса обнуляет счетчики трафика. )
# @item( traffic_limiter | 7 | 💾 Бэкап / Восстановление | _tl_backup_menu | 70 | 2 | Сохранение и восстановление конфигурации. )
#
# @item( traffic_limiter_delete | 1 | 🗑️ Удалить лимит для порта | _tl_clear_one_limit | 10 | 1 )
# @item( traffic_limiter_delete | 2 | ☠️ Удалить ВСЕ лимиты | _tl_clear_all_limits | 20 | 1 )
#

[[ "${BASH_SOURCE[0]}" == "${0}" ]] && exit 1 # Защита от прямого запуска

# Подключаем ядро и зависимости
source "$SCRIPT_DIR/modules/core/common.sh"
source "$SCRIPT_DIR/modules/core/dependencies.sh"

# --- КОНФИГУРАЦИЯ ---
if [[ -z "${TL_CONFIG_DIR:-}" ]]; then
    readonly TL_CONFIG_DIR="/etc/reshala/traffic_limiter"
    readonly TL_BACKUP_DIR="/root/reshala_backups/traffic_limiter"
    readonly TL_APPLY_SCRIPT_PATH="/usr/local/bin/reshala-traffic-limiter-apply.sh"
    readonly TL_SERVICE_NAME="reshala-traffic-limiter.service"
    readonly TL_SERVICE_PATH="/etc/systemd/system/${TL_SERVICE_NAME}"
    readonly TL_MAX_BUCKETS="256"
fi

# ============================================================ #
# ==                      ГЛАВНОЕ МЕНЮ                      == #
# ============================================================ #

show_traffic_limiter_menu() {
    ensure_package "tc" "iproute2"
    
    # 1. Автоматическое лечение старых конфигов
    _tl_auto_repair_configs

    enable_graceful_ctrlc
    while true; do
        clear
        menu_header "🚦 Шейпер трафика (Персональные лимиты)"
        printf_description "Этот модуль создает персональный лимит скорости для КАЖДОГО пользователя."
        echo

        # Проверка статуса: смотрим и на сервис, и на наличие файлов
        local is_active="false"
        if systemctl is-active --quiet ${TL_SERVICE_NAME}; then is_active="true"; fi
        
        local config_count
        config_count=$(find "${TL_CONFIG_DIR}" -maxdepth 1 -name "port-*.conf" -type f 2>/dev/null | wc -l)

        local status_icon
        if [[ "$is_active" == "true" && "$config_count" -gt 0 ]]; then
            status_icon="${C_GREEN}[✓ Работает: $config_count портов]${C_RESET}"
        elif [[ "$config_count" -gt 0 ]]; then
            status_icon="${C_YELLOW}[⚠ Конфиги есть, сервис стоит]${C_RESET}"
        else
            status_icon="${C_GRAY}[∅ Не настроен]${C_RESET}"
        fi
        
        printf_menu_option "1" "📊 Текущий статус (Топ-5) ${status_icon}"
        printf_description "Показывает активные правила и топ потребителей."
        printf_menu_option "2" "➕ Добавить/изменить лимит"
        printf_description "Запускает мастер настройки для порта."
        printf_menu_option "3" "➖ Удалить лимит(ы)"
        printf_description "Позволяет выбрать и удалить один или все лимиты."
        printf_menu_option "4" "📜 Посмотреть лог сервиса"
        printf_description "Показывает системный журнал для службы шейпера."
        printf_menu_option "5" "📈 Мониторинг трафика (iftop)"
        printf_description "Запуск утилиты iftop для просмотра текущей скорости."
        printf_menu_option "6" "🔄 Перезагрузить (Сброс статы)"
        printf_description "Перезапуск сервиса обнуляет счетчики трафика."
        printf_menu_option "7" "💾 Бэкап / Восстановление"
        printf_description "Сохранение и восстановление конфигурации."
        
        echo; printf_menu_option "b" "🔙 Назад"; print_separator "-" 60

        local choice; choice=$(safe_read "Твой выбор") || break
        if [[ "$choice" == "b" || "$choice" == "B" ]]; then break; fi
        
        case "$choice" in
            1) _tl_show_status ;;
            2) _tl_apply_limit_wizard ;; 
            3) _show_delete_submenu ;; 
            4) _tl_view_service_log ;; 
            5) _tl_monitor_traffic ;;
            6) _tl_restart_service ;;
            7) _tl_backup_menu ;; 
            *) warn "Нет такого пункта." ;; 
        esac
        wait_for_enter
    done
    disable_graceful_ctrlc
}

_show_delete_submenu() {
    enable_graceful_ctrlc
    while true; do
        clear; menu_header "Удаление лимитов"; printf_description "Выбери, как именно ты хочешь снести правила."
        echo; render_menu_items "traffic_limiter_delete"
        echo; printf_menu_option "b" "🔙 Назад"; print_separator "-" 60
        local choice; choice=$(safe_read "Твой выбор") || break
        if [[ "$choice" == "b" || "$choice" == "B" ]]; then break; fi
        local action; action=$(get_menu_action "traffic_limiter_delete" "$choice")
        if [[ -n "$action" ]]; then 
            eval "$action"
            wait_for_enter
        else 
            err "Нет такого пункта."
        fi
    done
    disable_graceful_ctrlc
}

# ============================================================ #
# ==                  ЛОГИКА И ПОДМЕНЮ                      == #
# ============================================================ #

_tl_backup_menu() {
    while true; do
        clear; menu_header "Бэкап и Восстановление"
        printf_description "Папка бэкапов: ${C_GRAY}${TL_BACKUP_DIR}${C_RESET}"
        echo
        printf_menu_option "1" "💾 Создать бэкап текущих настроек"
        printf_menu_option "2" "📥 Восстановить из бэкапа"
        echo; printf_menu_option "b" "🔙 Назад"; print_separator "-" 60
        
        local choice; choice=$(safe_read "Твой выбор") || return
        if [[ "$choice" == "b" || "$choice" == "B" ]]; then return; fi
        
        case "$choice" in
            1)
                run_cmd mkdir -p "$TL_BACKUP_DIR"
                local filename="backup_$(date +%Y%m%d_%H%M%S).tar.gz"
                if run_cmd tar -czf "${TL_BACKUP_DIR}/${filename}" -C "${TL_CONFIG_DIR}" .; then
                    ok "Бэкап создан: ${filename}"
                else
                    err "Ошибка создания бэкапа."
                fi
                wait_for_enter
                ;;
            2)
                local backups=($(ls "${TL_BACKUP_DIR}"/*.tar.gz 2>/dev/null))
                if [[ ${#backups[@]} -eq 0 ]]; then
                    warn "Бэкапов не найдено."
                else
                    local b_choice; b_choice=$(ask_selection "Выберите бэкап:" "${backups[@]}") || continue
                    local selected_backup="${backups[$((b_choice-1))]}"
                    
                    if ask_yes_no "Это ЗАМЕНИТ все текущие настройки. Продолжить?"; then
                        run_cmd rm -rf "${TL_CONFIG_DIR:?}"/*
                        run_cmd tar -xzf "$selected_backup" -C "$TL_CONFIG_DIR"
                        ok "Настройки восстановлены. Перезапускаю сервис..."
                        _tl_restart_service
                    fi
                fi
                wait_for_enter
                ;;
        esac
    done
}

_tl_restart_service() {
    # Принудительно пересоздаем скрипт применения перед рестартом
    _tl_ensure_service_installed
    
    info "Перезапускаю сервис шейпера..."
    run_cmd systemctl restart "${TL_SERVICE_NAME}"
    if systemctl is-active --quiet "${TL_SERVICE_NAME}"; then
        ok "Сервис перезапущен. Статистика сброшена."
    else
        err "Ошибка при перезапуске."
    fi
}

_tl_monitor_traffic() {
    ensure_package "iftop"
    clear
    menu_header "Мониторинг трафика (iftop)"
    
    printf_description "Выбери интерфейс для прослушивания:"
    local iface; iface=$(_tl_select_interface) || return

    info "Запускаю iftop на интерфейсе ${C_CYAN}${iface}${C_RESET}..."
    info "Нажми ${C_BOLD}q${C_RESET}, чтобы выйти из iftop."
    sleep 1
    
    run_cmd iftop -n -i "$iface"
}

_tl_auto_repair_configs() {
    if [[ ! -d "${TL_CONFIG_DIR}" ]]; then mkdir -p "${TL_CONFIG_DIR}"; return; fi
    local repaired=0
    while IFS= read -r file; do
        local changed=0
        if ! grep -q "MAX_USERS=" "$file"; then echo 'MAX_USERS="256"' >> "$file"; changed=1; fi
        if ! grep -q "TYPE=" "$file"; then echo 'TYPE="u32-hash"' >> "$file"; changed=1; fi
        if ! grep -q "TOTAL_LIMIT=" "$file"; then echo 'TOTAL_LIMIT="10000mbit"' >> "$file"; changed=1; fi
        
        if [[ "$changed" -eq 1 ]]; then ((repaired++)); fi
    done < <(find "${TL_CONFIG_DIR}" -maxdepth 1 -name "port-*.conf" -type f)
    if [[ "$repaired" -gt 0 ]]; then debug_log "Auto-repaired $repaired config files."; fi
}

_tl_apply_limit_wizard() {
    clear; menu_header "Шаг 1: Выбор сетевого интерфейса"
    printf_description "Выбери основной сетевой интерфейс (обычно ${C_YELLOW}eth0${C_RESET} или ${C_YELLOW}ens...${C_RESET})"
    local iface; iface=$(_tl_select_interface) || { return; }

    clear; menu_header "Шаг 2: Выбор порта"
    _tl_show_listening_ports_smart; echo
    
    local port_choice; port_choice=$(safe_read "Введи порт для ограничения (можно ввести вручную, даже если его нет в списке)" "") || return
    local port;
    if [[ "$port_choice" =~ ^[0-9]+$ ]] && [ "$port_choice" -ge 1 ] && [ "$port_choice" -le 65535 ]; then
        port="$port_choice"
    else
        err "Неверный формат порта. Введи число от 1 до 65535."
        wait_for_enter
        return
    fi

    if [[ -f "${TL_CONFIG_DIR}/port-${port}.conf" ]]; then
        printf_critical_warning "ВНИМАНИЕ: Для порта ${port} уже настроен лимит!"
        if ! ask_yes_no "Хочешь ПЕРЕЗАПИСАТЬ существующие настройки? (y/n)" "n"; then warn "Операция отменена."; return; fi
    fi

    clear; menu_header "Шаг 3: Лимит на ПОЛЬЗОВАТЕЛЯ"
    local down_rate_num; down_rate_num=$(ask_number_in_range "Лимит СКАЧИВАНИЯ на юзера (Мбит/с)" 1 10000 4) || return
    local up_rate_num; up_rate_num=$(ask_number_in_range "Лимит ЗАГРУЗКИ на юзера (Мбит/с)" 1 10000 4) || return

    clear; menu_header "Шаг 4: Общий лимит на ПОРТ"
    printf_description "Максимальная скорость, которую могут занять ВСЕ юзеры вместе взятые."
    printf_description "Оставь пустым или введи 0, чтобы не ограничивать (будет 10 Гбит)."
    local total_rate_num; total_rate_num=$(safe_read "Общий лимит (Мбит/с) [безлимит]" "")
    
    local total_limit="10000mbit"
    if [[ "$total_rate_num" =~ ^[0-9]+$ ]] && [ "$total_rate_num" -gt 0 ]; then
        total_limit="${total_rate_num}mbit"
    fi

    local down_limit="${down_rate_num}mbit"; local up_limit="${up_rate_num}mbit"

    clear; menu_header "Подтверждение настроек"; 
    print_key_value "Интерфейс" "${C_CYAN}${iface}${C_RESET}" 28; 
    print_key_value "Порт" "${C_CYAN}${port}${C_RESET}" 28; 
    print_key_value "Лимит DL (User)" "${C_GREEN}${down_limit}${C_RESET}" 28; 
    print_key_value "Лимит UL (User)" "${C_YELLOW}${up_limit}${C_RESET}" 28; 
    print_key_value "Лимит ПОРТА (Total)" "${C_RED}${total_limit}${C_RESET}" 28;
    print_key_value "Макс. активных юзеров" "${C_CYAN}${TL_MAX_BUCKETS}${C_RESET}" 28;
    echo
    if ! ask_yes_no "Применить эти настройки? (y/n)" "n"; then warn "Операция отменена."; return; fi

    info "Создаю конфигурацию..."; run_cmd mkdir -p "${TL_CONFIG_DIR}"
    cat << EOF | run_cmd tee "${TL_CONFIG_DIR}/port-${port}.conf" > /dev/null
IFACE="${iface}"
PORT="${port}"
DOWN_LIMIT="${down_limit}"
UP_LIMIT="${up_limit}"
TOTAL_LIMIT="${total_limit}"
MAX_USERS="${TL_MAX_BUCKETS}"
TYPE="u32-hash"
EOF
    info "Устанавливаю и запускаю сервис..."; _tl_ensure_service_installed; run_cmd systemctl restart "${TL_SERVICE_NAME}"
    
    sleep 2 # Даем время на запуск
    if systemctl is-active --quiet "${TL_SERVICE_NAME}"; then 
        ok "Лимит для порта ${port} успешно применён!"
    else 
        err "Не удалось запустить сервис. Проверь 'journalctl -u ${TL_SERVICE_NAME}'"
        if ask_yes_no "Показать системный журнал для сервиса? (y/n)" "y"; then
            _tl_view_service_log
        fi
    fi
}

_tl_clear_one_limit() {
    if ! ls -A "${TL_CONFIG_DIR}"/*.conf >/dev/null 2>&1; then warn "Активных лимитов не найдено."; return; fi
    clear; menu_header "Удаление конкретного лимита"
    local options=(); local files=(); while IFS= read -r file; do if [[ -f "$file" ]]; then source "$file"; options+=("Порт ${PORT} (${DOWN_LIMIT}/${UP_LIMIT}) на ${IFACE}"); files+=("$file"); fi; done < <(find "${TL_CONFIG_DIR}" -name "port-*.conf")
    local choice; choice=$(ask_selection "Активные лимиты:" "${options[@]}") || return
    local file_to_delete="${files[$((choice-1))]}"
    if ! ask_yes_no "Точно снести этот лимит? (y/n)" "n"; then warn "Отмена."; return; fi
    info "Удаляю конфигурацию..."; run_cmd rm -f "$file_to_delete"; run_cmd systemctl restart "${TL_SERVICE_NAME}"; ok "Лимит удалён."
}

_tl_clear_all_limits() {
    if ! ls -A "${TL_CONFIG_DIR}"/*.conf >/dev/null 2>&1; then warn "Активных лимитов нет."; return; fi
    if ! ask_yes_no "Точно снести ВСЕ настроенные лимиты?"; then warn "Отмена."; return; fi
    info "Полностью вычищаю все конфиги и правила..."; _tl_uninstall_service; ok "Все ограничения сняты."
}

_tl_show_status() {
    clear; menu_header "Статус шейпера трафика"
    
    local config_count
    config_count=$(find "${TL_CONFIG_DIR}" -maxdepth 1 -name "port-*.conf" -type f 2>/dev/null | wc -l)

    if [[ "$config_count" -eq 0 ]]; then 
        warn "Шейпер не настроен (нет конфигурационных файлов)."
        return
    fi

    local is_active; is_active=$(systemctl is-active --quiet ${TL_SERVICE_NAME} && echo "true" || echo "false")
    
    local status_str
    if [[ "$is_active" == "true" ]]; then
        status_str="${C_GREEN}АКТИВЕН${C_RESET}"
    else
        status_str="${C_RED}НЕ АКТИВЕН${C_RESET}"
    fi
    print_key_value "Сервис systemd" "$status_str" 20
    echo

    print_section_title "АКТИВНЫЕ ЛИМИТЫ"
    local port_idx=1
    while IFS= read -r file; do 
        if [[ -f "$file" ]]; then 
            source "$file"
            printf "  - Порт ${C_YELLOW}%-5s${C_RESET}: ${C_GREEN}%-8s${C_RESET} DL / ${C_YELLOW}%-8s${C_RESET} UL на ${C_CYAN}%s${C_RESET}\n" "$PORT" "$DOWN_LIMIT" "$UP_LIMIT" "$IFACE"
            if [[ "${TOTAL_LIMIT:-10000mbit}" != "10000mbit" ]]; then
                printf "    ${C_RED}⚠ Общий лимит порта: %s${C_RESET}\n" "$TOTAL_LIMIT"
            fi
            
            if [[ "$is_active" == "true" ]]; then
                # U32 ID Scheme (Math based):
                # DL Parent: 1:10 (hex) for idx 1
                local dl_parent_class="1:$(printf "%x" $((port_idx * 16)))"
                
                # --- ОБЩАЯ СТАТИСТИКА ПОРТА ---
                local stats
                stats=$(tc -s class show dev "$IFACE" | grep -A 1 "class htb ${dl_parent_class} " | grep "Sent")
                if [[ -n "$stats" ]]; then
                    local rus_stats
                    rus_stats=$(echo "$stats" | awk '{
                        bytes=$2; pkts=$4; dropped=$7;
                        gsub(/,/, "", dropped);
                        printf "Отправлено: %s байт, Пакетов: %s, Потерь: %s", bytes, pkts, dropped
                    }')
                    printf "    ↳ ${C_GRAY}Всего: %s${C_RESET}\n" "$rus_stats"
                else
                    printf "    ↳ ${C_GRAY}(нет данных о трафике)${C_RESET}\n"
                fi

                # --- ТОП 5 ПОТРЕБИТЕЛЕЙ (BUCKETS) ---
                printf "    ↳ ${C_BOLD}Топ-5 активных потоков (Buckets):${C_RESET}\n"
                
                local top_users
                top_users=$(tc -s class show dev "$IFACE" | \
                    awk -v parent="${dl_parent_class}" ' 
                        $1=="class" && $2=="htb" && $4=="parent" && $5==parent {
                            current_id=$3
                        }
                        $1=="Sent" && current_id!="" {
                            print current_id, $2
                            current_id=""
                        }
                    ' | sort -k2 -nr | head -n 5)
                
                if [[ -n "$top_users" ]]; then
                    while read -r class_id bytes; do
                        local human_bytes
                        human_bytes=$(numfmt --to=iec-i --suffix=B "$bytes" 2>/dev/null || echo "${bytes} B")
                        printf "      • Поток ${C_CYAN}%-8s${C_RESET}: ${C_YELLOW}%s${C_RESET}\n" "$class_id" "$human_bytes"
                    done <<< "$top_users"
                else
                    printf "      ${C_GRAY}(нет активных пользователей)${C_RESET}\n"
                fi
            fi
            echo ""
            ((port_idx++))
        fi
    done < <(find "${TL_CONFIG_DIR}" -maxdepth 1 -name "port-*.conf" -type f | sort)
    
    if [[ "$is_active" == "false" ]]; then 
        if ask_yes_no "Сервис не запущен, хотя конфиги есть! Попробовать перезапустить? (y/n)" "n"; then 
            _tl_restart_service
        fi
    fi
}

_tl_view_service_log() {
    if ! [[ -f "${TL_SERVICE_PATH}" ]]; then
        warn "Сервис шейпера не установлен. Лог пуст."
        return
    fi
    info "Смотрю лог для ${TL_SERVICE_NAME}... (Нажми 'q' для выхода)"
    echo
    journalctl -u ${TL_SERVICE_NAME} --no-pager -n 50
}

_tl_handle_legacy_cleanup() { 
    clear; menu_header "Обнаружена старая версия шейпера"
    if ! ask_yes_no "Рекомендуется провести полную зачистку старой версии. Сделать это сейчас? (y/n)"; then 
        err "Очистка отменена."; wait_for_enter; return
    fi
    info "Начинаю зачистку..."
    run_cmd systemctl disable --now "${TL_SERVICE_NAME}" 2>/dev/null || true
    run_cmd rm -f "${TL_SERVICE_PATH}" "/usr/local/bin/reshala-traffic-limiter.sh"
    run_cmd systemctl daemon-reload
    
    local ifaces; ifaces=$(ip -o link show up | awk -F': ' '{print $2}' | grep -v '^lo$')
    for iface in $ifaces; do 
        run_cmd tc qdisc del dev "$iface" root 2>/dev/null
        run_cmd tc qdisc del dev "$iface" ingress 2>/dev/null
    done
    run_cmd tc qdisc del dev ifb0 root 2>/dev/null
    
    ok "Старая версия удалена."
    wait_for_enter
}

_tl_select_interface() { local interfaces; mapfile -t interfaces < <(ip -o link show up | awk -F': ' '{print $2}' | grep -v '^lo$'); if [[ ${#interfaces[@]} -eq 0 ]]; then err "Нет активных сетевых интерфейсов."; return 1; fi; >&2 info "Доступные интерфейсы:"; local i=1; for iface_name in "${interfaces[@]}"; do >&2 printf "   [%d] %s\n" "$i" "$iface_name"; ((i++)); done; local choice; choice=$(ask_number_in_range "Выбери номер" 1 ${#interfaces[@]}) || return 1; echo "${interfaces[$((choice-1))]}"; }

_tl_show_listening_ports_smart() {
    ensure_package "ss" "iproute2"
    info "Сканирую открытые TCP порты..."
    local temp_file; temp_file=$(mktemp)
    
    while read -r line; do
        local listen_addr; listen_addr=$(echo "$line" | awk '{print $4}')
        local process_info; process_info=$(echo "$line" | awk '{$1=$2=$3=$4=$5=""; print $0}' | xargs)
        local port; port=$(echo "$listen_addr" | awk -F: '{print $NF}')
        [[ "$port" =~ ^[0-9]+$ ]] || continue
        
        local bind_addr_full
        bind_addr_full=$(echo "$listen_addr" | sed 's/:[^:]*$//')
        local bind_addr
        bind_addr=$(echo "$bind_addr_full" | sed 's/[[//g; s/]//g; s/%.*//' | xargs)
        
        local type_str="SPECIFIC"; local sort_key=3
        if [[ "$bind_addr" == "127.0.0.1" || "$bind_addr" == "::1" || "$bind_addr" == "localhost" || "$bind_addr" =~ ^127\.0\.0\.[0-9]+$ ]]; then
            type_str="${C_YELLOW}LOCAL${C_RESET}"; sort_key=3
        elif [[ "$bind_addr" == "*" || "$bind_addr" == "0.0.0.0" || "$bind_addr" == "::" ]]; then
            type_str="${C_GREEN}EXTERNAL${C_RESET}"; sort_key=2
        else
             type_str="${C_CYAN}SPECIFIC (${bind_addr})${C_RESET}"; sort_key=3
        fi
        local proc_str="N/A"
        if [[ "$process_info" == *"docker-proxy"* ]]; then
            proc_str="${C_BLUE}🐳 Docker${C_RESET}"
        elif [[ "$process_info" == *"users"* ]]; then
            proc_str=$(echo "$process_info" | grep -oP '(?<="").+?(?=",)' | head -1)
            if [[ "$proc_str" == "rw-core" && "$sort_key" == "2" ]]; then sort_key="1"; fi
        fi
        local shaper_mark=""
        if [[ -f "${TL_CONFIG_DIR}/port-${port}.conf" ]]; then shaper_mark="${C_RED}ДА${C_RESET}"; fi
        printf "%s|%s|%s|%s|%s\n" "$sort_key" "$port" "$type_str" "$proc_str" "$shaper_mark" >> "$temp_file"
    done < <(ss -tlpn 2>/dev/null | awk '$1 == "LISTEN"')

    printf "\n   %-10s %-25s %-20s %s\n" "Порт" "Статус" "Процесс" "Лимит"
    printf "   %-10s %-25s %-20s %s\n" "----------" "-------------------------" "--------------------" "--------"
    sort -t'|' -k1,1n -k2,2n "$temp_file" | while IFS="|" read -r _sort_key port type_str proc_str shaper_mark; do
        printf "   %-10s %-25b %-20b %b\n" "$port" "$type_str" "$proc_str" "$shaper_mark"
    done
    rm -f "$temp_file"
    echo
    printf_description "${C_GRAY}(EXTERNAL: со всех IP, LOCAL: только с 127.0.0.1, SPECIFIC: только с указанного IP)${C_RESET}"
}

_tl_ensure_service_installed() { 
    info "Создаю/обновляю скрипт применения правил..."
    _tl_generate_master_apply_script | run_cmd tee "${TL_APPLY_SCRIPT_PATH}" > /dev/null
    run_cmd chmod +x "${TL_APPLY_SCRIPT_PATH}"

    if [[ ! -f "${TL_SERVICE_PATH}" ]]; then 
        info "Создаю systemd сервис..."
        _tl_generate_systemd_service | run_cmd tee "${TL_SERVICE_PATH}" > /dev/null
        run_cmd systemctl daemon-reload
        run_cmd systemctl enable "${TL_SERVICE_NAME}"
    fi
}

_tl_uninstall_service() { 
    run_cmd systemctl disable --now "${TL_SERVICE_NAME}" 2>/dev/null || true
    run_cmd rm -f "${TL_SERVICE_PATH}" "${TL_APPLY_SCRIPT_PATH}"
    run_cmd rm -rf "${TL_CONFIG_DIR}"
    run_cmd systemctl daemon-reload
    
    local ifaces; ifaces=$(ip -o link show up | awk -F': ' '{print $2}' | grep -v '^lo$')
    for iface in $ifaces; do 
        run_cmd tc qdisc del dev "$iface" root 2>/dev/null
        run_cmd tc qdisc del dev "$iface" ingress 2>/dev/null
    done
    run_cmd tc qdisc del dev ifb0 root 2>/dev/null
}

# ============================================================ #
# ==           ГЕНЕРАТОР СКРИПТА ПРИМЕНЕНИЯ (U32 MODE)      == #
# ============================================================ #

_tl_generate_master_apply_script() {
    cat << 'EOF'
#!/bin/bash
set -u
readonly CONFIG_DIR="/etc/reshala/traffic_limiter"
readonly IFB_DEV="ifb0"

log() { echo "[$(date '+%H:%M:%S')] - $1"; }

run_tc() {
    local cmd="$*"
    local out
    if ! out=$($cmd 2>&1); then
        log "❌ $cmd"
        log "   Ответ: $out"
        exit 1
    fi
}

log "🚀 Запуск Reshala Traffic Limiter (U32 Hash Mode)..."

# === ПРОВЕРКА ДОСТУПНОСТИ HTB ===
if ! tc qdisc add dev lo root handle 999: htb &>/dev/null; then
    KERNEL_VERSION=$(uname -r)
    log "⚠️ Модуль sch_htb недоступен на ядре: $KERNEL_VERSION"
    log "Пытаюсь установить модули..."
    
    # Определение дистрибутива
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        if [[ "$ID" == "debian" ]]; then
            log "Обнаружен Debian. Устанавливаю модули..."
            apt update &>/dev/null
            apt install -y linux-image-$(uname -r) &>/dev/null || \
            apt install -y linux-image-amd64 &>/dev/null
        elif [[ "$ID" == "ubuntu" ]]; then
            log "Обнаружен Ubuntu. Устанавливаю модули..."
            apt update &>/dev/null
            apt install -y linux-modules-extra-$(uname -r) &>/dev/null
        fi
    fi
    
    # Попытка загрузки
    modprobe sch_htb &>/dev/null || true
    
    # Финальная проверка
    if ! tc qdisc add dev lo root handle 999: htb &>/dev/null; then
        log "❌ ОШИБКА: HTB недоступен!"
        log ""
        log "Текущее ядро: $KERNEL_VERSION"
        
        # Проверка конфигурации ядра
        if zcat /proc/config.gz 2>/dev/null | grep -q "CONFIG_NET_SCH_HTB is not set"; then
            log "Причина: HTB выключен в конфигурации ядра"
        elif [[ ! -d "/lib/modules/$KERNEL_VERSION/kernel/net/sched" ]]; then
            log "Причина: Модули TC отсутствуют для этого ядра"
        fi
        
        log ""
        log "РЕШЕНИЕ для Debian:"
        log "  1. Установи стандартное ядро:"
        log "     apt update && apt install -y linux-image-amd64"
        log "  2. Перезагрузись: reboot"
        log "  3. Выбери новое ядро в GRUB"
        log "  4. Запусти сервис снова"
        log ""
        log "Если используешь кастомное ядро (BBR3):"
        log "  - Пересобери с CONFIG_NET_SCH_HTB=m"
        exit 1
    fi
fi
tc qdisc del dev lo root &>/dev/null || true
log "✅ Модуль HTB доступен"

# Загрузка остальных модулей
modprobe ifb numifbs=1 &>/dev/null || true
modprobe sch_htb &>/dev/null || true
modprobe sch_sfq &>/dev/null || true
modprobe cls_u32 &>/dev/null || true
modprobe act_mirred &>/dev/null || true

# 1. Очистка
log "🧹 Очищаю старые правила..."
ip -o link show up | awk -F': ' '{print $2}' | grep -v '^lo$' | while read -r iface; do
    tc qdisc del dev "$iface" root &>/dev/null || true
    tc qdisc del dev "$iface" ingress &>/dev/null || true
done
tc qdisc del dev "$IFB_DEV" root &>/dev/null || true

# 2. Проверка конфигов
mapfile -t conf_files < <(find "${CONFIG_DIR}" -maxdepth 1 -name "port-*.conf" -type f | sort)
if [[ ${#conf_files[@]} -eq 0 ]]; then
    log "🤷 Нет конфигов."
    exit 0
fi
log "📁 Найдено ${#conf_files[@]} конфигов."

# 3. Подготовка IFB
ip link set dev "$IFB_DEV" up &>/dev/null || true

# 4. Инициализация корневых дисциплин
declare -A handled_ifaces
for conf_file in "${conf_files[@]}"; do
    source "$conf_file"
    if [[ -z "${handled_ifaces[$IFACE]:-}" ]]; then
        log "🌐 Инициализация $IFACE..."
        
        # Egress (Download)
        run_tc tc qdisc add dev "$IFACE" root handle 1: htb default 9999
        run_tc tc class add dev "$IFACE" parent 1: classid 1:9999 htb rate 10gbit
        
        # Ingress (Upload) -> IFB
        run_tc tc qdisc add dev "$IFACE" handle ffff: ingress
        run_tc tc filter add dev "$IFACE" parent ffff: protocol ip prio 1 u32 \
            match u32 0 0 action mirred egress redirect dev "$IFB_DEV"
        
        handled_ifaces[$IFACE]=1
    fi
done

# IFB Root
if ! tc qdisc show dev "$IFB_DEV" | grep -q "htb"; then
    run_tc tc qdisc add dev "$IFB_DEV" root handle 2: htb default 9999
    run_tc tc class add dev "$IFB_DEV" parent 2: classid 2:9999 htb rate 10gbit
fi

# 5. Применение правил (U32 HASH METHOD - HYBRID VERSION)
PORT_IDX=1

for conf_file in "${conf_files[@]}"; do
    source "$conf_file"
    
    PORT_TOTAL_LIMIT="${TOTAL_LIMIT:-10000mbit}"
    MAX_USERS="${MAX_USERS:-256}"
    
    # МАТЕМАТИЧЕСКАЯ генерация ID (безопасно до 15 портов)
    DL_PARENT_MINOR=$((0x10 * PORT_IDX))
    DL_BUCKET_BASE=$((0x1000 * PORT_IDX))
    DL_HASH_HANDLE=$(printf "%x" $((0x100 + PORT_IDX)))
    
    UL_PARENT_MINOR=$((0x20 * PORT_IDX))
    UL_BUCKET_BASE=$((0x2000 * PORT_IDX))
    UL_HASH_HANDLE=$(printf "%x" $((0x200 + PORT_IDX)))
    
    log "🔌 Порт $PORT на $IFACE (Idx:$PORT_IDX)"
    log "   DL: Parent=1:$(printf %x $DL_PARENT_MINOR), Buckets=$(printf %x $DL_BUCKET_BASE)-$(printf %x $((DL_BUCKET_BASE + 255))), HashTable=$DL_HASH_HANDLE:"
    log "   UL: Parent=2:$(printf %x $UL_PARENT_MINOR), Buckets=$(printf %x $UL_BUCKET_BASE)-$(printf %x $((UL_BUCKET_BASE + 255))), HashTable=$UL_HASH_HANDLE:"
    log "   Лимиты: DL $DOWN_LIMIT / UL $UP_LIMIT (Max: $MAX_USERS, Total: $PORT_TOTAL_LIMIT)"

    # ============================================================ 
    # DOWNLOAD (EGRESS на $IFACE)
    # ============================================================    
    # 1. Родительский класс
    run_tc tc class add dev "$IFACE" parent 1: classid "1:$(printf %x $DL_PARENT_MINOR)" \
        htb rate "$PORT_TOTAL_LIMIT" ceil "$PORT_TOTAL_LIMIT" quantum 60000
    
    # 2. U32 Hash Table
    run_tc tc filter add dev "$IFACE" parent 1: protocol ip prio 1 \
        handle "${DL_HASH_HANDLE}:" u32 divisor 256
    
    # 3. Фильтр: Трафик ПОРТА -> Hash table
    run_tc tc filter add dev "$IFACE" parent 1: protocol ip prio 1 u32 \
        match ip sport "$PORT" 0xffff \
        hashkey mask 0x000000ff at 16 \
        link "${DL_HASH_HANDLE}:"
    
    # 4. Создание per-IP классов
    for bucket in $(seq 0 $((MAX_USERS - 1))); do
        CLASS_ID_DEC=$((DL_BUCKET_BASE + bucket))
        CLASS_ID="1:$(printf %x $CLASS_ID_DEC)"
        BUCKET_HEX=$(printf "%02x" $bucket)
        
        # Дочерний класс
        run_tc tc class add dev "$IFACE" parent "1:$(printf %x $DL_PARENT_MINOR)" \
            classid "$CLASS_ID" htb rate "$DOWN_LIMIT" ceil "$DOWN_LIMIT" quantum 1500
        
        # SFQ
        run_tc tc qdisc add dev "$IFACE" parent "$CLASS_ID" sfq perturb 10
        
        # Фильтр в hash table
        run_tc tc filter add dev "$IFACE" parent 1: protocol ip prio 1 u32 \
            ht "${DL_HASH_HANDLE}:${BUCKET_HEX}:" \
            match ip dst 0.0.0.0/0 \
            flowid "$CLASS_ID"
    done

    # ============================================================ 
    # UPLOAD (INGRESS на $IFB_DEV)
    # ============================================================    
    # 1. Родительский класс
    run_tc tc class add dev "$IFB_DEV" parent 2: classid "2:$(printf %x $UL_PARENT_MINOR)" \
        htb rate "$PORT_TOTAL_LIMIT" ceil "$PORT_TOTAL_LIMIT" quantum 60000
    
    # 2. U32 Hash Table
    run_tc tc filter add dev "$IFB_DEV" parent 2: protocol ip prio 1 \
        handle "${UL_HASH_HANDLE}:" u32 divisor 256
    
    # 3. Фильтр: Трафик ПОРТА -> Hash table
    run_tc tc filter add dev "$IFB_DEV" parent 2: protocol ip prio 1 u32 \
        match ip dport "$PORT" 0xffff \
        hashkey mask 0x000000ff at 12 \
        link "${UL_HASH_HANDLE}:"
    
    # 4. Создание per-IP классов
    for bucket in $(seq 0 $((MAX_USERS - 1))); do
        CLASS_ID_DEC=$((UL_BUCKET_BASE + bucket))
        CLASS_ID="2:$(printf %x $CLASS_ID_DEC)"
        BUCKET_HEX=$(printf "%02x" $bucket)
        
        run_tc tc class add dev "$IFB_DEV" parent "2:$(printf %x $UL_PARENT_MINOR)" \
            classid "$CLASS_ID" htb rate "$UP_LIMIT" ceil "$UP_LIMIT" quantum 1500
        
        run_tc tc qdisc add dev "$IFB_DEV" parent "$CLASS_ID" sfq perturb 10
        
        # Фильтр в hash table
        run_tc tc filter add dev "$IFB_DEV" parent 2: protocol ip prio 1 u32 \
            ht "${UL_HASH_HANDLE}:${BUCKET_HEX}:" \
            match ip src 0.0.0.0/0 \
            flowid "$CLASS_ID"
    done

    PORT_IDX=$((PORT_IDX + 1))
done

log "✅ Правила успешно применены!"
EOF
}

_tl_generate_systemd_service() { cat << EOF
[Unit]
Description=Reshala Traffic Limiter Service
After=network.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=${TL_APPLY_SCRIPT_PATH}
RemainAfterExit=yes
StandardOutput=journal
StandardError=journal
[Install]
WantedBy=multi-user.target
EOF
}
