#!/bin/bash
# ============================================================ #
# ==             SKYNET: УПРАВЛЕНИЕ SSH-КЛЮЧАМИ             == #
# ============================================================ #
#
# Модуль отвечает за генерацию, хранение и распространение
# SSH-ключей для доступа к удаленным серверам.
#
[[ "${BASH_SOURCE[0]}" == "${0}" ]] && exit 1 # Защита от прямого запуска

# Подключаем модуль для работы с базой данных
source "${SCRIPT_DIR}/modules/skynet/db.sh"


# Проверяет/создаёт главный мастер-ключ
# ВАЖНО: ВСЁ, что идёт в stdout, должно быть ТОЛЬКО путём до ключа,
# чтобы можно было безопасно писать $( _ensure_master_key ).
_ensure_master_key() {
    local key_path="${HOME}/.ssh/${SKYNET_MASTER_KEY_NAME}"
    if [[ ! -f "$key_path" ]]; then
        printf_info "🔑 Генерирую МАСТЕР-КЛЮЧ (${SKYNET_MASTER_KEY_NAME})..." >&2
        ssh-keygen -t ed25519 -f "$key_path" -N "" -q
    fi
    echo "$key_path"
}

# Генерирует уникальный ключ для конкретного сервера
# Аналогично: stdout = только путь до ключа.
_generate_unique_key() {
    local name="$1"
    local ip="$2" # New argument
    local safe_name_part; safe_name_part=$(echo "$name" | tr -cd '[:alnum:]_-')
    local safe_ip_part; safe_ip_part=$(echo "$ip" | tr '.' '_') # Replace dots with underscores for filename safety

    local key_filename="${SKYNET_UNIQUE_KEY_PREFIX}${safe_name_part}_${safe_ip_part}"
    local key_path="${HOME}/.ssh/${key_filename}"

    if [ ! -f "$key_path" ]; then
        printf_info "🔑 Генерирую УНИКАЛЬНЫЙ ключ для '${name}' (${ip})..." >&2
        ssh-keygen -t ed25519 -f "$key_path" -N "" -q
    fi
    echo "$key_path"
}

# Лечит ошибку "Host key verification failed", если сервер был переустановлен
_skynet_heal_host_key() {
    local ip="$1" 
    local port="$2"
    # Подавляем вывод, т.к. ошибка, если ключа нет, - это нормально
    ssh-keygen -R "$ip" >/dev/null 2>&1
    ssh-keygen -R "[$ip]:$port" >/dev/null 2>&1
}

# Закидывает ключ на удалённый сервер, с лечением доступа
_deploy_key_to_host() {
    local ip="$1" port="$2" user="$3" key_path="$4"

    # Лечим ошибку "Host key verification failed", если сервер был переустановлен
    _skynet_heal_host_key "$ip" "$port"

    printf "   👉 %s@%s:%s... " "$user" "$ip" "$port"
    # Сначала пробуем тихо войти по ключу, вдруг доступ уже есть
    if ssh -q -o BatchMode=yes -o ConnectTimeout=3 -o StrictHostKeyChecking=no -i "$key_path" -p "$port" "${user}@${ip}" exit; then
        ok "ДОСТУП ЕСТЬ!"
        return 0
    fi

    printf "\n"; warn "🔓 Вводи пароль (один раз), чтобы закинуть ключ..."
    if ssh-copy-id -o StrictHostKeyChecking=no -i "${key_path}.pub" -p "$port" "${user}@${ip}"; then
        ok "Ключ установлен!"
        return 0
    else
        err "Не удалось (неверный пароль или SSH недоступен)"
        return 1
    fi
}

# Returns a comma-separated list of server names using the provided key_path
_get_servers_using_key() {
    local target_key_path="$1"
    local server_names=""
    local server_line
    if [ -f "$FLEET_DATABASE_FILE" ]; then
        while IFS='|' read -r name user ip port key_path sudo_pass; do
            if [[ "$key_path" == "$target_key_path" ]]; then
                if [[ -z "$server_names" ]]; then
                    server_names="$name"
                else
                    server_names="$server_names, $name"
                fi
            fi
        done < "$FLEET_DATABASE_FILE"
    fi
    echo "$server_names"
}




# Returns "server_name|server_ip" for a given key_path, or empty if not found.
_get_server_info_by_key_path() {
    local target_key_path="$1"
    local server_info=""
    if [ -f "$FLEET_DATABASE_FILE" ]; then
        while IFS='|' read -r name user ip port key_path sudo_pass; do
            if [[ "$key_path" == "$target_key_path" ]]; then
                server_info="${name}|${ip}"
                break
            fi
        done < "$FLEET_DATABASE_FILE"
    fi
    echo "$server_info"
}



# Presents a list of all managed SSH keys and allows user to select one.
# Returns the full path to the selected private key.
_select_existing_ssh_key() {
    local available_keys=()
    local key_map_choice_to_path=()
    local i=1

    # Redirect all menu output to stderr
    clear >&2
    menu_header "🔑 ВЫБОР СУЩЕСТВУЮЩЕГО SSH КЛЮЧА" >&2
    echo "" >&2
    printf_description "Выбери один из доступных ключей, или [b] Назад для отмены." >&2
    echo "" >&2
    print_separator "-" 50 >&2

    # 1. Мастер-ключ
    local master_path="${HOME}/.ssh/${SKYNET_MASTER_KEY_NAME}"
    if [ -f "$master_path" ]; then
        printf "   [%d] %bMASTER KEY%b (Основной)\n" "$i" "${C_GREEN}" "${C_RESET}" >&2
        key_map_choice_to_path[$i]="$master_path"
        ((i++))
    fi

    # 2. Уникальные и Импортированные ключи
    for k in "${HOME}/.ssh/${SKYNET_UNIQUE_KEY_PREFIX}"* "${HOME}/.ssh/reshala_imported_"*; do
        if [[ -f "$k" ]] && [[ "$k" != *.pub ]]; then
            local k_name_full=$(basename "$k")
            local display_label="$k_name_full"

            if [[ "$k_name_full" == "${SKYNET_UNIQUE_KEY_PREFIX}"* ]]; then
                local server_info=$(_get_server_info_by_key_path "$k")
                if [[ -n "$server_info" ]]; then
                    IFS='|' read -r s_name s_ip <<< "$server_info"
                    display_label="UNIQUE KEY (Для сервера: ${s_name} IP: ${s_ip})"
                else
                    display_label="UNIQUE KEY (не назначен серверу)"
                fi
            elif [[ "$k_name_full" == "reshala_imported_"* ]]; then
                display_label="Импортированный ключ (${k_name_full#reshala_imported_})"
            fi
            
            printf "   [%d] %b%s%b\n" "$i" "${C_YELLOW}" "$display_label" "${C_RESET}" >&2
            key_map_choice_to_path[$i]="$k"
            ((i++))
        fi
    done
    
    if [ "$i" -eq 1 ]; then
        printf_warning "Нет доступных ключей для выбора." >&2
        sleep 1
        return 1 # Indicate no key was selected
    fi

    print_separator "-" 50 >&2
    printf_menu_option "b" "Назад" >&2
    echo "" >&2

    local choice_num
    choice_num=$(safe_read "Выбери номер ключа: ") || return 1

    if [[ "$choice_num" == "b" || "$choice_num" == "B" ]]; then
        return 1 # User chose to go back
    fi

    if [[ "$choice_num" =~ ^[0-9]+$ ]] && [ -n "${key_map_choice_to_path[$choice_num]:-}" ]; then
        echo "${key_map_choice_to_path[$choice_num]}" # Return the selected key path to STDOUT
        return 0
    else
        printf_error "Неверный выбор." >&2
        sleep 1
        return 1
    fi
}

# Deletes SSH key files and updates fleet database entries
_delete_ssh_key() {
    local key_path="$1"
    local key_description="$2"
    
    printf_warning "Ты пытаешься удалить ключ: %s (%s)" "$key_description" "$key_path"
    if ask_yes_no "Ты ТОЧНО хочешь удалить этот ключ? (y/n): " "n"; then
        if [ -f "$key_path" ]; then
            rm -f "$key_path" # Delete private key
            printf_ok "Приватный ключ удален: %s" "$key_path"
        fi
        if [ -f "${key_path}.pub" ]; then
            rm -f "${key_path}.pub" # Delete public key
            printf_ok "Публичный ключ удален: %s" "${key_path}.pub"
        fi

        # Update fleet database entries
        # _remove_key_path_from_fleet_db needs to be implemented in db.sh
        _remove_key_path_from_fleet_db "$key_path"

        printf_ok "Ключ '%s' удален и записи в базе флота обновлены." "$key_description"
    else
        printf_info "Удаление ключа отменено."
    fi
    sleep 1
}

# Imports an existing SSH key pair into Reshala's management using nano
_import_ssh_key() {
    clear
    menu_header "📥 ИМПОРТ СВОЕГО SSH КЛЮЧА"
    echo ""
    printf_description "Вы можете вставить содержимое вашего ПРИВАТНОГО ключа через редактор."
    printf_description "Публичная часть (.pub) будет создана автоматически."
    echo ""

    local key_name
    key_name=$(ask_non_empty "Придумай имя для ключа (латиница, цифры)") || return
    
    # Очистка имени от мусора
    key_name=$(echo "$key_name" | tr -cd '[:alnum:]_-')

    local target_private_path="${HOME}/.ssh/reshala_imported_${key_name}"
    local target_public_path="${target_private_path}.pub"

    if [[ -f "$target_private_path" ]]; then
        printf_warning "Ключ с таким именем уже существует."
        if ! ask_yes_no "Перезаписать существующий ключ? (y/n): " "n"; then
            printf_info "Импорт отменен."
            sleep 1
            return
        fi
    fi

    # Создаем временный файл
    local tmp_file; tmp_file=$(mktemp)
    
    printf_info "Сейчас откроется редактор 'nano'."
    printf_description "1. Вставь содержимое своего ПРИВАТНОГО ключа."
    printf_description "2. Нажми Ctrl+O, затем Enter (Сохранить)."
    printf_description "3. Нажми Ctrl+X (Выйти)."
    echo ""
    printf_warning "ВНИМАНИЕ: Обязательно вставляй ключ целиком, включая BEGIN/END строки."
    
    wait_for_enter "Нажми Enter, чтобы открыть редактор..."
    
    nano "$tmp_file"

    if [[ ! -s "$tmp_file" ]]; then
        printf_error "Файл пуст. Импорт отменен."
        rm -f "$tmp_file"
        sleep 2
        return
    fi

    # Проверка валидности ключа перед сохранением
    if ! ssh-keygen -y -f "$tmp_file" >/dev/null 2>&1; then
        printf_error "Ошибка: вставлен невалидный приватный ключ или неверный формат."
        printf_description "Reshala поддерживает форматы OpenSSH, RSA, ED25519."
        rm -f "$tmp_file"
        sleep 3
        return
    fi

    # Перемещаем в целевую директорию
    mkdir -p "${HOME}/.ssh"
    mv "$tmp_file" "$target_private_path"
    chmod 600 "$target_private_path"

    # Генерируем публичную часть
    ssh-keygen -y -f "$target_private_path" > "$target_public_path"
    chmod 644 "$target_public_path"

    printf_ok "Ключ успешно импортирован!"
    printf_info "Имя в системе: reshala_imported_${key_name}"
    printf_info "Путь: ${target_private_path}"
    
    sleep 3
}


# Меню для просмотра и управления ключами
_show_keys_menu() {
    enable_graceful_ctrlc
    while true; do
        clear
        menu_header "🔑 УПРАВЛЕНИЕ SSH КЛЮЧАМИ"
        echo ""
        printf_description "Здесь можно посмотреть, импортировать или удалить SSH-ключи."
        printf_description "Осторожно: удаление ключа, используемого сервером, заблокирует доступ."
        echo ""

        local keys=()
        local formatted_key_lines=()
        local i=1

        # 1. Мастер-ключ
        local master_path="${HOME}/.ssh/${SKYNET_MASTER_KEY_NAME}"
        if [ -f "$master_path" ]; then
            keys[$i]="${master_path}|MASTER KEY (Основной)"
            local users_of_master_key=$(_get_servers_using_key "$master_path")
            local line_content="   [${i}] ${C_GREEN}MASTER KEY${C_RESET} (Используется на: ${users_of_master_key:-'0'} серверах)"
            formatted_key_lines+=("$line_content")
            ((i++))
        fi

        # 2. Уникальные и Импортированные ключи
        for k in "${HOME}/.ssh/${SKYNET_UNIQUE_KEY_PREFIX}"* "${HOME}/.ssh/reshala_imported_"*; do
            if [[ -f "$k" ]] && [[ "$k" != *.pub ]]; then
                local k_name_full=$(basename "$k")
                local display_label="$k_name_full"
                local key_type_color="${C_YELLOW}"
                local key_type_label="UNIQUE KEY"
                
                if [[ "$k_name_full" == "reshala_imported_"* ]]; then
                    key_type_color="${C_CYAN}"
                    key_type_label="IMPORTED KEY"
                    display_label="(${k_name_full#reshala_imported_})"
                fi

                local server_info=$(_get_server_info_by_key_path "$k")
                local server_text=""
                if [[ -n "$server_info" ]]; then
                    IFS='|' read -r s_name s_ip <<< "$server_info"
                    server_text="(Сервер: ${s_name} | IP: ${s_ip})"
                fi

                keys[$i]="$k|$k_name_full"
                local line_content="   [${i}] ${key_type_color}${key_type_label}${C_RESET} ${display_label} ${server_text}"
                formatted_key_lines+=("$line_content")
                ((i++))
            fi
        done
        
        local max_width=60
        # Determine max width for the separator
        for line in "${formatted_key_lines[@]}"; do
            local visible_len=$(_get_visible_length "$line")
            if (( visible_len > max_width )); then
                max_width=$visible_len
            fi
        done

        print_separator "-" $((max_width + 4))
        if [ ${#formatted_key_lines[@]} -gt 0 ]; then
            # Print the collected key lines
            for line in "${formatted_key_lines[@]}"; do
                echo -e "$line"
            done
        else
            printf_info "Не найдено ключей, управляемых Reshala."
            printf_info "Сгенерируй Мастер-ключ или импортируй свой."
        fi
        print_separator "-" $((max_width + 4))

        printf_menu_option "g" "Создать/Проверить Мастер-ключ"
        printf_description "     - Гарантирует наличие основного ключа для новых серверов."
        printf_menu_option "i" "Импортировать свой ключ"
        printf_description "     - Добавляет ваш существующий ключ в управление Reshala."
        printf_menu_option "d" "Удалить ключ по номеру"
        printf_description "     - Стирает выбранный ключ с диска и из базы."
        printf_menu_option "b" "Назад"
        echo ""

        local choice
        choice=$(safe_read "Выбор (или номер ключа для просмотра)" "") || { _LAST_CTRLC_SIGNALED=0; continue; }

        case "$choice" in
            [bB]) break ;;
            [gG]) 
                _ensure_master_key >/dev/null # Ensure it exists, ignore output
                printf_ok "Мастер-ключ проверен/создан."
                sleep 1
                ;;
            [iI]) _import_ssh_key ;;
            [dD])
                local del_num
                del_num=$(safe_read "Номер ключа для УДАЛЕНИЯ: ")
                if [[ "$del_num" =~ ^[0-9]+$ ]] && [ -n "${keys[$del_num]:-}" ]; then
                    IFS='|' read -r k_path k_desc <<< "${keys[$del_num]}"
                    _delete_ssh_key "$k_path" "$k_desc"
                else
                    printf_error "Неверный номер."
                    sleep 1
                fi
                ;;
            *)
                if [[ "$choice" =~ ^[0-9]+$ ]] && [ -n "${keys[$choice]:-}" ]; then
                    IFS='|' read -r k_path k_desc <<< "${keys[$choice]}"
                    
                    clear
                    menu_header "🔍 ПРОСМОТР КЛЮЧА: ${k_desc}"
                    
                    local users=$(_get_servers_using_key "$k_path")
                    if [[ -n "$users" ]]; then
                        printf_info "Используется на серверах: ${users}"
                    else
                        printf_warning "Этот ключ сейчас не используется ни одним сервером."
                    fi
                    echo ""

                    printf_info "Что показать?"
                    printf_menu_option "1" "Публичный ключ (для authorized_keys)"
                    printf_menu_option "2" "Приватный ключ (СЕКРЕТ!)"
                    printf_menu_option "b" "Назад"
                    echo ""
                    local type_choice; type_choice=$(safe_read "Выбор: " "")

                    case "$type_choice" in
                        1)
                            echo ""
                            info "Содержимое публичного ключа (.pub):"
                            printf "${C_GREEN}%s${C_RESET}\n" "$(cat "${k_path}.pub" 2>/dev/null)"
                            wait_for_enter
                            ;;
                        2)
                            echo ""
                            err "☢️  ВНИМАНИЕ! ЭТО СЕКРЕТНЫЙ КЛЮЧ! ☢️"
                            warn "Никому не показывай. Скопируй и сразу очисти экран."
                            wait_for_enter
                            cat "$k_path"
                            echo ""
                            print_separator "-" 50
                            wait_for_enter
                            ;;
                        *) continue ;;
                    esac
                else
                    printf_error "Неверный выбор."
                    sleep 1
                fi
                ;;
        esac
    done
    disable_graceful_ctrlc
}