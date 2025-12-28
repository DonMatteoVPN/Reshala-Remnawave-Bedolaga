#!/bin/bash
# ============================================================ #
# ==             SKYNET: ИСПОЛНЕНИЕ КОМАНД (EXECUTOR)       == #
# ============================================================ #
#
# Модуль отвечает за доставку и запуск плагинов на удаленных
# серверах через SSH.
#
[[ "${BASH_SOURCE[0]}" == "${0}" ]] && exit 1 # Защита от прямого запуска

# Выполнить выбранный плагин Skynet на одном сервере
_skynet_run_plugin_on_server() {
    local plugin="$1" name="$2" user="$3" ip="$4" port="$5" key_path="$6"
    printf "\n"; warn "--- Сервер: $name ---"
    # Лечим ключ хоста на случай, если сервер был переустановлен
    _skynet_heal_host_key "$ip" "$port"
    # Копируем плагин на удалённую машину, выполняем через bash (не требуем +x) и удаляем
    scp -q -P "$port" -i "$key_path" -o StrictHostKeyChecking=no "$plugin" "${user}@${ip}:/tmp/reshala_plugin.sh"
    ssh -t -p "$port" -i "$key_path" -o StrictHostKeyChecking=no "${user}@${ip}" "bash /tmp/reshala_plugin.sh; rm -f /tmp/reshala_plugin.sh"
}

# Запуск плагина Skynet на ОДНОМ сервере с дополнительными переменными окружения
_skynet_run_plugin_on_server_with_env() {
    local plugin="$1" env_vars="$2" name="$3" user="$4" ip="$5" port="$6" key_path="$7"
    printf "\n"; warn "--- Сервер: $name ---"
    # Лечим ключ хоста на случай, если сервер был переустановлен
    _skynet_heal_host_key "$ip" "$port"
    scp -q -P "$port" -i "$key_path" -o StrictHostKeyChecking=no "$plugin" "${user}@${ip}:/tmp/reshala_plugin.sh"
    # env_vars – это строка наподобие "VAR1=val1 VAR2=val2"
    ssh -t -p "$port" -i "$key_path" -o StrictHostKeyChecking=no "${user}@${ip}" "${env_vars} bash /tmp/reshala_plugin.sh; rm -f /tmp/reshala_plugin.sh"
}

# Запуск плагина Skynet для захвата вывода (без TTY и без лишних сообщений)
_skynet_run_plugin_for_capture() {
    local plugin="$1"
    local env_vars="$2"
    local name="$3"
    local user="$4"
    local ip="$5"
    local port="$6"
    local key_path="$7"
    local temp_plugin_path="/tmp/reshala_plugin_$$_${RANDOM}"

    # Копируем плагин
    if ! scp -q -P "$port" -i "$key_path" -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o BatchMode=yes "$plugin" "${user}@${ip}:${temp_plugin_path}" 2>/dev/null; then
        # Не выводим ошибку, просто возвращаем пустоту, т.к. это может быть простая недоступность хоста
        return 1
    fi
    
    # Выполняем и захватываем вывод. Без -t для чистого вывода.
    local output
    output=$(ssh -p "$port" -i "$key_path" -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o BatchMode=yes "${user}@${ip}" "${env_vars} bash ${temp_plugin_path}; rm -f ${temp_plugin_path}" 2>/dev/null)
    
    echo "$output"
}

_run_fleet_command() {
    local PLUGINS_DIR="${SCRIPT_DIR}/plugins/skynet_commands"
    if [[ ! -d "$PLUGINS_DIR" || -z "$(find "$PLUGINS_DIR" -type f -name '*.sh')" ]]; then
        printf_error "Папка с плагинами пуста или не существует (${PLUGINS_DIR})"; return
    fi
    
    enable_graceful_ctrlc
    while true; do
        clear; menu_header "☢️ Выполнение команды на флоте"
        
        # FIX: Use local -A to ensure arrays are reset on each loop iteration.
        # FIX: Aggressively unset arrays to prevent duplication bug.
        unset categories
        unset plugin_paths

        local -A categories
        local -A plugin_paths
        local total_plugins=0

        # Находим все плагины и разбираем их по категориям
        while IFS= read -r p; do
            if [[ -f "$p" ]]; then
                local hidden
                hidden=$(grep -m1 '^# SKYNET_HIDDEN:' "$p" 2>/dev/null | sed 's/^# SKYNET_HIDDEN:[[:space:]]*//')
                if [[ "$hidden" == "true" || "$hidden" == "1" ]]; then
                    continue
                fi

                local category
                category=$(basename "$(dirname "$p")")
                if [[ "$category" == "skynet_commands" ]]; then
                    category="Общие"
                fi
                
                local title
                title=$(grep -m1 '^# TITLE:' "$p" 2>/dev/null | sed 's/^# TITLE:[[:space:]]*//')
                if [[ -z "$title" ]]; then
                    title="$(basename "$p" | sed 's/^[0-9]*_//;s/.sh$//')"
                fi
                
                total_plugins=$((total_plugins + 1))
                categories["$category"]+="${total_plugins}:::${title}\n"
                plugin_paths["$total_plugins"]="$p"
            fi
        done < <(find "$PLUGINS_DIR" -type f -name '*.sh' | sort)

        if [[ "$total_plugins" -eq 0 ]]; then
            printf_warning "Не найдено ни одной видимой команды в ${PLUGINS_DIR}"; wait_for_enter; break
        fi

        # Выводим сгруппированное меню
        local sorted_categories
        sorted_categories=$(for category in "${!categories[@]}"; do echo "$category"; done | sort)

        for category in $sorted_categories; do
            print_section_title "${category^}"
            
            local sorted_plugins
            sorted_plugins=$(echo -e "${categories[$category]}" | sort -n)
            
            while IFS=":::" read -r idx title; do
                if [[ -n "$idx" && -n "$title" ]]; then
                    # FIX: Defensively remove '::' from title before printing, as its source is unclear.
                    local clean_title
                    clean_title=$(echo "$title" | sed 's/::\s*//g')
                    printf_menu_option "$idx" "$clean_title"
                fi
            done <<< "$sorted_plugins"
        done
        
        echo ""
        printf_menu_option "b" "Назад"
        
        # FIX: Add colon back to the prompt.
        local choice; choice=$(safe_read "Какую команду выполнить?" "") || { _LAST_CTRLC_SIGNALED=0; break; }
        if [[ "$choice" == "b" ]]; then break; fi
        
        if [[ -z "$choice" || ! -v "plugin_paths[$choice]" ]]; then
            printf_error "Неверный выбор."
            sleep 1
            continue
        fi
        
        local selected_plugin="${plugin_paths[$choice]}"

        echo ""
        printf_info "Где выполнять команду?"
        printf_menu_option "1" "На ВСЁМ флоте"
        printf_menu_option "2" "На ОДНОМ выбранном сервере"
        local scope; scope=$(safe_read "Выбор (1/2): " "1") || { _LAST_CTRLC_SIGNALED=0; continue; }

        if [[ "$scope" == "2" ]]; then
            if [[ ! -s "$FLEET_DATABASE_FILE" ]]; then
                printf_error "База флота пуста. Сначала добавь серверы."
                wait_for_enter
                continue
            fi

            local servers=(); local idx=1
            echo ""
            printf_info "Доступные сервера:"
            while IFS='|' read -r name user ip port key_path sudo_pass; do
                servers[$idx]="$name|$user|$ip|$port|$key_path"
                printf "   [%d] %s (%s@%s:%s)\n" "$idx" "$name" "$user" "$ip" "$port"
                ((idx++))
            done < "$FLEET_DATABASE_FILE"

            local s_choice
            s_choice=$(ask_number_in_range "Номер сервера: " 1 "$((idx-1))" "") || continue
            if [[ -n "${servers[$s_choice]:-}" ]]; then
                IFS='|' read -r name user ip port key_path <<< "${servers[$s_choice]}"
                printf_warning "Выполняю '${selected_plugin##*/}' на сервере '$name'."
                if ask_yes_no "Начать? (y/n): " "n"; then
                    _skynet_run_plugin_on_server "$selected_plugin" "$name" "$user" "$ip" "$port" "$key_path"
                    printf_ok "Команда выполнена."; wait_for_enter
                fi
            fi
        else
            printf_warning "Выполняю '${selected_plugin##*/}' на ВСЁМ флоте. Это может занять время."
            if ask_yes_no "Начать? (y/n): " "n"; then
                while IFS='|' read -r name user ip port key_path sudo_pass; do
                    _skynet_run_plugin_on_server "$selected_plugin" "$name" "$user" "$ip" "$port" "$key_path"
                done < "$FLEET_DATABASE_FILE"
                printf_ok "Команда выполнена на всём флоте."; wait_for_enter
            fi
        fi
    done
    disable_graceful_ctrlc
}