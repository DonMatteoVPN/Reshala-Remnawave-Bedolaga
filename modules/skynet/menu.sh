#!/bin/bash
# ============================================================ #
# ==             SKYNET: ЦЕНТР УПРАВЛЕНИЯ ФЛОТОМ            == #
# ============================================================ #
#
#   ( РОДИТЕЛЬ | КЛАВИША | НАЗВАНИЕ | ФУНКЦИЯ | ПОРЯДОК | ГРУППА | ОПИСАНИЕ )
# @menu.manifest
#
# @item( main | 0 | 🌐 Управление флотом ${C_GREEN}(Skynet Mode)${C_RESET} | show_fleet_menu | 0 | 0 | Добавление/удаление серверов, выполнение команд. )
#
# @item( skynet | a | ➕ Добавить новый сервер | _skynet_add_server_wizard | 10 | 1 | Запускает мастер добавления сервера в базу. )
# @item( skynet | d | 🗑️  Удалить сервер | _skynet_delete_server_wizard | 20 | 1 | Удаляет выбранный сервер из базы данных. )
# @item( skynet | k | 🔑 Управление ключами | _show_keys_menu | 30 | 2 | Просмотр, импорт и удаление SSH-ключей. )
# @item( skynet | c | ☢️  Выполнить команду на флоте | _run_fleet_command | 40 | 2 | Запускает плагины на всех или выбранных серверах. )
# @item( skynet | m | 📝 Ручной редактор базы | _skynet_manual_edit_db | 80 | 3 | Открывает файл базы данных в 'nano' для правок. )
# @item( skynet | s | ⚙️  Авто-скан SSH | _skynet_toggle_autoscan | 90 | 3 | Включает/выключает проверку доступности серверов. )
#
# @item( skynet_server | 1 | 🚀 Подключиться к терминалу | _sm_connect | 10 | 1 )
# @item( skynet_server | 2 | 🛡️ Управление безопасностью | _sm_security | 20 | 1 )
# @item( skynet_server | 3 | 📝 Редактировать запись | _sm_edit | 30 | 1 )
# @item( skynet_server | 4 | 🗑️ Удалить сервер | _sm_delete | 40 | 1 )
#
# @item( skynet_server_security | 0 | 🔎 Статус безопасности | _sss_get_status | 10 | 1 | Показывает общую сводку по безопасности. )
# @item( skynet_server_security | 1 | 🔒 Усилить SSH | _sss_harden_ssh | 20 | 2 | Отключает вход по паролю, меняет порт и т.д. )
# @item( skynet_server_security | 2 | 🔢 Сменить порт SSH | _sss_change_port | 30 | 2 | Меняет порт SSH на случайный или указанный. )
# @item( skynet_server_security | 3 | 🔥 Настроить Firewall | _sss_setup_ufw | 40 | 3 | Устанавливает и настраивает UFW. )
# @item( skynet_server_security | 4 | 🔨 Настроить Fail2Ban | _sss_setup_f2b | 50 | 3 | Устанавливает и настраивает Fail2Ban. )
# @item( skynet_server_security | 5 | 🧠 Применить настройки ядра | _sss_apply_kernel | 60 | 4 | Применяет безопасные sysctl-настройки. )
# @item( skynet_server_security | 6 | 🔔 Уведомления о входе | _sss_setup_login_notify | 70 | 4 | Настраивает уведомления в Telegram о SSH-входе. )
#

[[ "${BASH_SOURCE[0]}" == "${0}" ]] && exit 1

# Подключаем компоненты
source "${SCRIPT_DIR}/modules/skynet/keys.sh"
source "${SCRIPT_DIR}/modules/skynet/db.sh"
source "${SCRIPT_DIR}/modules/skynet/executor.sh"
source "${SCRIPT_DIR}/modules/core/self_update.sh"

_skynet_is_local_newer() {
    # Возвращает 0, если локальная версия ($1) новее удаленной ($2)
    _self_update_is_remote_newer "$2" "$1"
}

# ============================================================ #
#                ДЕЙСТВИЯ МЕНЮ SKYNET                          #
# ============================================================ #

_skynet_add_server_wizard() {
    echo
    printf_info "--- НОВЫЙ БОЕЦ ---"
    local s_name; s_name=$(ask_non_empty "Имя сервера: ") || return
    local s_ip; s_ip=$(ask_non_empty "IP адрес: ") || return
    local s_user; s_user=$(safe_read "Пользователь: " "$SKYNET_DEFAULT_USER")
    local s_port; s_port=$(safe_read "SSH порт: " "$SKYNET_DEFAULT_PORT")
    local s_pass=""
    if [[ "$s_user" != "root" ]]; then
        s_pass=$(ask_password "Пароль sudo (или Enter): ")
    fi

    echo
    printf_info "Выбери SSH ключ для этого сервера:"
    printf_menu_option "1" "Использовать общий Мастер-ключ"
    printf_menu_option "2" "Создать новый УНИКАЛЬНЫЙ ключ"
    printf_menu_option "3" "Выбрать из списка существующих"
    printf_menu_option "4" "Указать ПОЛНЫЙ ПУТЬ к ключу"
    
    local k_choice; k_choice=$(safe_read "Выбор (1-4): " "1")
    local final_key=""

    case "$k_choice" in
        1)
            final_key=$(_ensure_master_key)
            ;;
        2)
            final_key=$(_generate_unique_key "$s_name" "$s_ip")
            ;;
        3)
            final_key=$(_select_existing_ssh_key)
            ;;
        4)
            printf_info "Как ты хочешь добавить свой ключ?"
            printf_menu_option "1" "Указать ПОЛНЫЙ ПУТЬ"
            printf_menu_option "2" "Вставить СОДЕРЖИМОЕ ключа"
            local input_method; input_method=$(safe_read "Выбор (1/2): " "1")
            local custom_key_path=""

            if [[ "$input_method" == "1" ]]; then
                custom_key_path=$(ask_non_empty "Введи ПОЛНЫЙ путь к приватному ключу: ")
            else
                printf_info "Вставь содержимое приватного ключа. Для завершения введи 'ENDKEY' на новой строке."
                local pasted_key=""
                while IFS= read -r line; do
                    if [[ "$line" == "ENDKEY" ]]; then break; fi
                    pasted_key+="$line\n"
                done
                
                if [[ -n "$pasted_key" ]]; then
                    custom_key_path="${HOME}/.ssh/reshala_pasted_key_$(date +%s)"
                    printf "%b" "$pasted_key" > "$custom_key_path"
                    chmod 600 "$custom_key_path"
                    printf_ok "Ключ сохранен в: $custom_key_path"
                fi
            fi

            if [[ -z "$custom_key_path" ]]; then
                final_key=""
            elif [[ ! -f "$custom_key_path" || ! -r "$custom_key_path" ]]; then
                printf_error "Файл ключа не найден или нет прав на чтение."
                final_key=""
            else
                final_key="$custom_key_path"
                if [[ ! -f "${custom_key_path}.pub" ]]; then
                    printf_warning "Публичный ключ (.pub) не найден. Пробую создать его..."
                    if ssh-keygen -y -f "$custom_key_path" > "${custom_key_path}.pub"; then
                        printf_ok "Публичный ключ создан."
                    else
                        printf_error "Не удалось создать публичный ключ."
                    fi
                fi
            fi
            ;;
        *)
            printf_error "Неверный выбор. Использую Мастер-ключ."
            final_key=$(_ensure_master_key)
            ;;
    esac

    if [[ -z "$final_key" ]]; then
        printf_warning "Выбор ключа отменен."
        return
    fi

    echo
    printf_info "🚀 Пробуем закинуть ключ на сервер..."
    if _deploy_key_to_host "$s_ip" "$s_port" "$s_user" "$final_key"; then
        echo "$s_name|$s_user|$s_ip|$s_port|$final_key|$s_pass" >> "$FLEET_DATABASE_FILE"
        printf_ok "Сервер '${s_name}' добавлен в флот."
        
        # Проверяем соединение и предлагаем усилить безопасность
        if ssh -q -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no -i "$final_key" -p "$s_port" "${s_user}@${s_ip}" "echo OK" &>/dev/null; then
            printf_ok "Тестовое подключение по ключу прошло успешно."
            if ask_yes_no "Вырубаем вход по паролю и оставляем только ключи? (y/n)"; then
                local harden_cmd="sed -i.bak -E 's/^#?PasswordAuthentication\s+.*/PasswordAuthentication no/' /etc/ssh/sshd_config && (systemctl reload sshd 2>/dev/null || systemctl reload ssh 2>/dev/null || service sshd restart 2>/dev/null || service ssh restart 2>/dev/null)"
                if [[ "$s_user" == "root" ]]; then
                    ssh -t -o StrictHostKeyChecking=no -i "$final_key" -p "$s_port" "${s_user}@${s_ip}" "$harden_cmd"
                    stty sane
                else
                    if [[ -n "$s_pass" ]]; then
                        ssh -t -o StrictHostKeyChecking=no -i "$final_key" -p "$s_port" "${s_user}@${s_ip}" "echo '$s_pass' | sudo -S -p '' bash -c '$harden_cmd'"
                        stty sane
                    else
                        printf_warning "Пароль sudo не указан."
                    fi
                fi
            fi
        fi
    else
        printf_error "Не удалось добавить сервер. Проверь данные."
    fi
    wait_for_enter
}

_skynet_delete_server_wizard() {
    mapfile -t s < <(grep . "$FLEET_DATABASE_FILE")
    if [[ ${#s[@]} -eq 0 ]]; then
        warn "База пуста."
        wait_for_enter
        return
    fi
    local n
    n=$(ask_number_in_range "Номер сервера для удаления: " 1 ${#s[@]}) || return
    local d="${s[$((n-1))]}"
    IFS='|' read -r name _ <<< "$d"
    if ask_yes_no "Удалить сервер '${name}'?" "n"; then
        sed -i "${n}d" "$FLEET_DATABASE_FILE"
        ok "Сервер '${name}' удален."
        IFS='|' read -r _ _ _ _ key_path _ <<< "$d"
        if [[ "$key_path" == *"$SKYNET_UNIQUE_KEY_PREFIX"* ]] && ask_yes_no "Удалить связанный уникальный SSH ключ?" "y"; then
            rm -f "$key_path" "${key_path}.pub" &>/dev/null
            ok "Ключ удален."
        fi
    else
        info "Отмена."
    fi
    wait_for_enter
}
_skynet_manual_edit_db() { ensure_package "nano"; nano "$FLEET_DATABASE_FILE"; }
_skynet_toggle_autoscan() { local a; a=$(get_config_var "SKYNET_AUTO_SSH_SCAN" "on"); if [[ "$a" == "on" ]]; then set_config_var "SKYNET_AUTO_SSH_SCAN" "off"; warn "Авто-скан выключен."; else set_config_var "SKYNET_AUTO_SSH_SCAN" "on"; ok "Авто-скан включен."; fi; sleep 1; }

# ============================================================ #
#                ГЛАВНОЕ МЕНЮ УПРАВЛЕНИЯ ФЛОТОМ                #
# ============================================================ #
show_fleet_menu() {
    touch "$FLEET_DATABASE_FILE"; enable_graceful_ctrlc
    
    local tmp_dir; tmp_dir=$(mktemp -d)
    local pids=() # Массив для хранения PID-ов фоновых процессов

    while true; do
        clear
        _sanitize_fleet_database
        local auto_scan; auto_scan=$(get_config_var "SKYNET_AUTO_SSH_SCAN" "on")
        mapfile -t raw_lines < <(grep . "$FLEET_DATABASE_FILE")

        if [[ "$auto_scan" == "on" && ${#raw_lines[@]} -gt 0 ]]; then
            local i=1
            for line in "${raw_lines[@]}"; do
                if [[ ! -f "$tmp_dir/$i" ]]; then
                    echo "..." > "$tmp_dir/$i"
                    IFS='|' read -r _ user ip port key _ <<< "$line"
                    # Лечим ключ хоста перед проверкой
                    _skynet_heal_host_key "$ip" "$port"
                    # Запускаем в фоне и сохраняем PID
                    ( timeout 3 ssh -n -q -o BatchMode=yes -o ConnectTimeout=3 -o StrictHostKeyChecking=no -i "$key" -p "$port" "$user@$ip" exit &>/dev/null && echo "ON" > "$tmp_dir/$i" || echo "OFF" > "$tmp_dir/$i" ) &
                    pids+=($!)
                fi
                ((i++))
            done
        fi

        menu_header "🌐 SKYNET: ЦЕНТР УПРАВЛЕНИЯ ФЛОТОМ"
        printf_description "Здесь ты управляешь базой серверов и запускаешь команды на флоте."
        printf "\n   Авто-скан SSH: ${C_YELLOW}%s${C_RESET} (переключить [s])\n\n" "$auto_scan"
        info "📂 База данных: ${C_GRAY}${FLEET_DATABASE_FILE}${C_RESET}"; printf "\n"; print_separator "-"
        
        if [ ${#raw_lines[@]} -eq 0 ]; then
            printf_info "(Пусто)"
        else
            local i=1
            for line in "${raw_lines[@]}"; do
                IFS='|' read -r name user ip port key_path sudo_pass <<< "$line"
                local status_text=" выкл"
                if [[ "$auto_scan" == "on" ]]; then
                    if [[ -f "$tmp_dir/$i" ]]; then status_text=$(cat "$tmp_dir/$i"); else status_text="?"; fi
                fi
                local status_color="${C_YELLOW}"
                case "$status_text" in
                    "ON")  status_color="${C_GREEN}" ;;
                    "OFF") status_color="${C_RED}" ;;
                    "...") status_color="${C_CYAN}" ;;
                esac
                local kp_display="Master"; [[ "$key_path" == *"$SKYNET_UNIQUE_KEY_PREFIX"* ]] && kp_display="Unique"
                local pass_icon=""; if [[ "$user" != "root" && -n "$sudo_pass" ]]; then pass_icon="🔑"; fi
                printf "   [%d] [%b%s%b] %b%-15s%b -> %s@%s:%s [%s] %s\n" "$i" "$status_color" "$status_text" "${C_RESET}" "${C_WHITE}" "$name" "${C_RESET}" "$user" "$ip" "$port" "$kp_display" "$pass_icon"
                ((i++))
            done
        fi
        
        print_separator "-"; render_menu_items "skynet"; echo ""; printf_menu_option "b" "🔙  Назад"; print_separator "-"

        local choice; choice=$(safe_read "Выбор (или номер сервера): " "") || break
        if [[ "$choice" =~ ^[0-9]+$ ]] && [ -n "${raw_lines[$((choice-1))]:-}" ]; then
             _show_server_management_menu "$choice" "${raw_lines[$((choice-1))]}"
        elif [[ "$choice" == "b" || "$choice" == "B" ]]; then
            break
        else
            local action; action=$(get_menu_action "skynet" "$choice")
            if [[ -n "$action" ]]; then eval "$action"; else
                info "Обновляю статусы..."; sleep 0.5
            fi
        fi
    done

    # При выходе из меню убиваем все фоновые процессы, которые мы запустили
    if [[ ${#pids[@]} -gt 0 ]]; then
        kill "${pids[@]}" &>/dev/null || true
    fi
    # И только потом удаляем временную директорию
    rm -rf -- "$tmp_dir"
    disable_graceful_ctrlc
}

_show_server_management_menu() {
    local server_idx="$1"; local server_data="$2"; enable_graceful_ctrlc
    local s_name s_user s_ip s_port s_key s_pass; IFS='|' read -r s_name s_user s_ip s_port s_key s_pass <<< "$server_data"
    
    _sm_connect() {
        # Лечим ключ хоста на случай, если он изменился
        _skynet_heal_host_key "$s_ip" "$s_port"
        
        clear
        printf_info "🚀 SKYNET UPLINK: Подключаюсь к ${s_name}..."

        # Проверяем, работает ли вход по ключу. Если нет - предлагаем закинуть ключ.
        if ! ssh -q -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=no -i "$s_key" -p "$s_port" "${s_user}@${s_ip}" exit; then
            printf_warning "Не удалось войти по ключу. Возможно, сервер был переустановлен."
            if ask_yes_no "Хочешь закинуть ключ на сервер сейчас (потребуется пароль)?"; then
                if ! ssh-copy-id -o StrictHostKeyChecking=no -i "${s_key}.pub" -p "$s_port" "${s_user}@${s_ip}"; then
                    err "Не удалось установить ключ. Проверь пароль или доступность SSH."
                    wait_for_enter
                    return
                fi
                ok "Ключ успешно установлен!"
            else
                info "Отмена. Дальнейшие операции могут потребовать пароль."
            fi
        fi

        if [[ "$s_user" != "root" && -z "$s_pass" ]]; then
            s_pass=$(ask_password "Введи пароль для '$s_user': ")
            if [[ -n "$s_pass" ]] && ask_yes_no "Сохранить пароль в базу?" "n"; then
                server_data="$s_name|$s_user|$s_ip|$s_port|$s_key|$s_pass"
                _update_fleet_record "$server_idx" "$server_data"
                ok "Пароль сохранён."
            fi
        fi

        run_remote() {
            local cmd_to_run="$1"
            if [[ "$s_user" == "root" ]]; then
                ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -i "$s_key" -p "$s_port" "$s_user@$s_ip" "$cmd_to_run"
            else
                ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -i "$s_key" -p "$s_port" "$s_user@$s_ip" "echo '$s_pass' | sudo -S -p '' bash -c '$cmd_to_run'"
            fi
        }

        printf "   📡 Проверка агента... "
        local remote_ver_cmd="grep 'readonly VERSION' $INSTALL_PATH 2>/dev/null | cut -d'\"' -f2"
        local remote_ver; remote_ver=$(run_remote "$remote_ver_cmd" | tail -n1 | tr -d '\r')

        if [[ -z "$remote_ver" ]] || _skynet_is_local_newer "$VERSION" "$remote_ver"; then
            warn "Требуется установка/обновление агента..."
            # Экспортируем переменную, чтобы она была доступна для `bash /tmp/i.sh` даже внутри `sudo bash -c '...'`
            local install_cmd="export RESHALA_NO_AUTOSTART=1; wget -qO /tmp/i.sh ${INSTALLER_URL_RAW} && bash /tmp/i.sh"
            if ! run_remote "$install_cmd"; then err "Не удалось развернуть агента."; wait_for_enter; return; fi
            ok "Агент развёрнут."
        else
            ok "Агент готов: (${remote_ver})"
        fi
        
        printf_info "Вхожу в удалённый терминал..."
        local ssh_opts=(-t -o StrictHostKeyChecking=no -i "$s_key" -p "$s_port")
        local remote_target="${s_user}@${s_ip}"
        # Исполняем команду через 'bash -l -c' и по абсолютному пути, чтобы гарантировать корректный $PATH
        local remote_exec_command="bash -l -c 'SKYNET_MODE=1 /opt/reshala/reshala.sh'"

        if [[ "$s_user" == "root" ]]; then
            ssh "${ssh_opts[@]}" "$remote_target" "$remote_exec_command"
        else
            local sudo_wrapper_command="echo '$s_pass' | sudo -S -p '' ${remote_exec_command}"
            ssh "${ssh_opts[@]}" "$remote_target" "$sudo_wrapper_command"
        fi
        
        stty sane
        info "🔙 Связь с ${s_name} завершена."
    }
    _sm_security() { _show_server_security_menu "$server_idx" "$server_data"; }
    _sm_edit() {
        info "Редактирование: ${s_name}"; local n; n=$(safe_read "Имя" "$s_name")||return; local u; u=$(safe_read "Пользователь" "$s_user")||return; local i; i=$(safe_read "IP" "$s_ip")||return; local p; p=$(safe_read "Порт" "$s_port")||return; local k; k=$(safe_read "Ключ" "$s_key")||return; local pw; pw=$(ask_password "Пароль sudo (Enter, чтобы оставить):"); if [[ -z "$pw" ]]; then pw=$s_pass; fi
        server_data="${n}|${u}|${i}|${p}|${k}|${pw}"; _update_fleet_record "$server_idx" "$server_data"; s_name=$n; s_user=$u; s_ip=$i; s_port=$p; s_key=$k; s_pass=$pw; ok "Запись обновлена."; wait_for_enter
    }
    _sm_delete() { 
        if ask_yes_no "Удалить сервер '${s_name}'?" "n"; then 
            sed -i "${server_idx}d" "$FLEET_DATABASE_FILE"; ok "Сервер удален."; 
            if [[ "$s_key" == *"$SKYNET_UNIQUE_KEY_PREFIX"* ]] && ask_yes_no "Удалить связанный ключ?" "y"; then 
                rm -f "$s_key" "${s_key}.pub"&>/dev/null; ok "Ключ удален."; 
            fi; 
            return 1; # Signal to exit this menu after deletion
        else 
            info "Отмена."; 
        fi; 
        wait_for_enter; 
    }

    while true; do
        clear; menu_header "Управление: ${s_name}"; printf_description "${s_user}@${s_ip}:${s_port}";
        
        # --- Ручная отрисовка меню ---
        echo ""
        printf_menu_option "1" "🚀 Подключиться к терминалу"
        printf_menu_option "2" "🛡️ Управление безопасностью"
        printf_menu_option "3" "📝 Редактировать запись"
        printf_menu_option "4" "🗑️ Удалить сервер"
        echo ""
        printf_menu_option "b" "Назад"
        echo ""

        local choice; choice=$(safe_read "Действие") || break
        
        case "$choice" in
            1) _sm_connect ;;
            2) _sm_security ;;
            3) _sm_edit ;;
            4) _sm_delete && break ;; # Если удалили, выходим из меню
            b|B) break ;;
            *) warn "Неверный выбор" ;;
        esac
    done
    disable_graceful_ctrlc
}

_show_server_security_menu() {
    local server_idx="$1"
    local server_data="$2"
    enable_graceful_ctrlc

    local s_name s_user s_ip s_port s_key s_pass
    IFS='|' read -r s_name s_user s_ip s_port s_key s_pass <<< "$server_data"

    # --- Внутренние функции-действия ---
    _sss_get_status() {
        _skynet_run_plugin_on_server "security/00_get_security_status.sh" "$s_name" "$s_user" "$s_ip" "$s_port" "$s_key" "$s_pass"
    }
    _sss_harden_ssh() {
        _skynet_run_plugin_on_server "security/01_harden_ssh.sh" "$s_name" "$s_user" "$s_ip" "$s_port" "$s_key" "$s_pass"
    }
    _sss_change_port() {
        _skynet_run_plugin_on_server "security/02_change_ssh_port.sh" "$s_name" "$s_user" "$s_ip" "$s_port" "$s_key" "$s_pass"
    }
    _sss_setup_ufw() {
        _skynet_run_plugin_on_server "security/03_setup_ufw.sh" "$s_name" "$s_user" "$s_ip" "$s_port" "$s_key" "$s_pass"
    }
    _sss_setup_f2b() {
        _skynet_run_plugin_on_server "security/04_setup_fail2ban.sh" "$s_name" "$s_user" "$s_ip" "$s_port" "$s_key" "$s_pass"
    }
    _sss_apply_kernel() {
        _skynet_run_plugin_on_server "security/05_apply_kernel.sh" "$s_name" "$s_user" "$s_ip" "$s_port" "$s_key" "$s_pass"
    }
    _sss_setup_login_notify() {
        _skynet_run_plugin_on_server "security/06_setup_ssh_login_notify.sh" "$s_name" "$s_user" "$s_ip" "$s_port" "$s_key" "$s_pass"
    }
    # --- Конец внутренних функций ---

    while true; do
        clear
        menu_header "🛡️ Безопасность: ${s_name}"
        printf_description "Выбери действие для применения на удаленном сервере."
        echo ""

        render_menu_items "skynet_server_security"
        
        echo ""
        printf_menu_option "b" "Назад"
        print_separator "-"

        local choice
        choice=$(safe_read "Твой выбор, босс") || break

        if [[ "$choice" == "b" || "$choice" == "B" ]]; then
            break
        fi

        local action
        action=$(get_menu_action "skynet_server_security" "$choice")

        if [[ -n "$action" ]]; then
            # Выполняем локальную функцию (_sss_... ), которая уже знает о сервере
            "$action"
            wait_for_enter
        else
            warn "Неверный выбор"
        fi
    done

    disable_graceful_ctrlc
}