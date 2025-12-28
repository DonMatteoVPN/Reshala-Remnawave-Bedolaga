#!/bin/bash
#   ( РОДИТЕЛЬ | КЛАВИША | НАЗВАНИЕ | ФУНКЦИЯ | ПОРЯДОК | ГРУППА | ОПИСАНИЕ )
# @menu.manifest
# @item( security | 5 | 💾 Бэкап и восстановление | show_backup_menu | 50 | 10 | Сохранение и откат конфигураций безопасности. )
#
# backup.sh - Бэкап и восстановление конфигураций безопасности
#

BACKUP_DIR_SEC="${SCRIPT_DIR}/modules/security/backups"
SYSCTL_CONF_FILE="/etc/sysctl.d/99-reshala-hardening.conf"
F2B_WHITELIST_FILE="/etc/reshala/fail2ban-whitelist.txt"

show_backup_menu() {
    run_cmd mkdir -p "$BACKUP_DIR_SEC"
    while true; do
        clear
        enable_graceful_ctrlc
        menu_header "💾 Бэкап и Восстановление"
        printf_description "Резервное копирование конфигов безопасности"

        echo ""
        printf_menu_option "1" "Создать бэкап"
        printf_menu_option "2" "Список бэкапов"
        printf_menu_option "3" "Восстановить из бэкапа"
        printf_menu_option "4" "Удалить старые бэкапы"
        echo ""
        printf_menu_option "b" "Назад"
        echo ""

        local choice
        choice=$(safe_read "Выберите действие" "") || { break; }
        
        case "$choice" in
            1) _backup_create; wait_for_enter;;
            2) _backup_list; wait_for_enter;;
            3) _backup_restore; wait_for_enter;;
            4) _backup_cleanup; wait_for_enter;;
            b|B) break;;
            *) warn "Неверный выбор";;
        esac
        disable_graceful_ctrlc
    done
}

_backup_create() {
    print_separator
    info "Создание бэкапа конфигураций безопасности"
    print_separator

    local backup_name="reshala-security-backup-$(date +%Y%m%d_%H%M%S)"
    local temp_backup_path="/tmp/$backup_name"
    run_cmd mkdir -p "$temp_backup_path"

    info "Собираю файлы для бэкапа..."

    # Список файлов и директорий для бэкапа
    local files_to_backup=(
        "/etc/ssh/sshd_config"
        "/etc/fail2ban/jail.local"
        "$SYSCTL_CONF_FILE"
        "$F2B_WHITELIST_FILE"
        "${SCRIPT_DIR}/config/reshala.conf"
        "/root/.ssh/authorized_keys"
    )
    local dirs_to_backup=(
        "/etc/ufw"
    )

    for file in "${files_to_backup[@]}"; do
        if [[ -f "$file" ]]; then
            run_cmd cp "$file" "$temp_backup_path/"
            ok "  + $file"
        fi
    done

    for dir in "${dirs_to_backup[@]}"; do
        if [[ -d "$dir" ]]; then
            run_cmd cp -r "$dir" "$temp_backup_path/"
            ok "  + $dir"
        fi
    done
    
    info "Создаю архив..."
    local final_archive_path="$BACKUP_DIR_SEC/${backup_name}.tar.gz"
    if run_cmd tar -czf "$final_archive_path" -C "/tmp" "$backup_name"; then
        run_cmd rm -rf "$temp_backup_path"
        ok "Бэкап успешно создан:"
        printf_description "$final_archive_path"
    else
        err "Не удалось создать архив."
        run_cmd rm -rf "$temp_backup_path"
    fi
}

_backup_list() {
    print_separator
    info "Доступные бэкапы безопасности"
    print_separator

    if [[ ! -d "$BACKUP_DIR_SEC" ]] || [[ -z "$(ls -A "$BACKUP_DIR_SEC"/*.tar.gz 2>/dev/null)" ]]; then
        warn "Бэкапы не найдены."
        return 1
    fi
    
    local i=1
    for backup in "$BACKUP_DIR_SEC"/*.tar.gz; do
        local name
        name=$(basename "$backup")
        local size
        size=$(run_cmd du -h "$backup" | cut -f1)
        local date
        date=$(run_cmd stat -c %y "$backup" | cut -d'.' -f1)
        
        printf_description "${C_WHITE}${i})${C_RESET} $name ${C_CYAN}($size)${C_RESET} - $date"
        ((i++))
    done
    return 0
}

_backup_restore() {
    if ! _backup_list; then return; fi
    echo ""

    local choice
    choice=$(ask_non_empty "Введите номер бэкапа для восстановления") || return
    
    local i=1
    local chosen_backup=""
    for backup in "$BACKUP_DIR_SEC"/*.tar.gz; do
        if [[ $i -eq $choice ]]; then
            chosen_backup=$backup
            break
        fi
        ((i++))
    done

    if [[ -z "$chosen_backup" ]]; then
        err "Неверный номер бэкапа."
        return
    fi
    
    if ! ask_yes_no "Вы уверены, что хотите восстановить конфиги из $(basename "$chosen_backup")? Текущие файлы будут заменены."; then
        info "Отмена."
        return
    fi

    local temp_restore_path="/tmp/restore_$$"
    run_cmd mkdir -p "$temp_restore_path"
    info "Распаковываю бэкап..."
    run_cmd tar -xzf "$chosen_backup" -C "$temp_restore_path"
    
    local backup_dir_name
    backup_dir_name=$(run_cmd ls "$temp_restore_path")
    local restore_source="$temp_restore_path/$backup_dir_name"
    
    # --- Начинаем восстановление ---
    warn "Начинаю восстановление... Сервисы будут перезапущены."
    
    # UFW
    if [[ -d "$restore_source/ufw" ]]; then
        run_cmd cp -r "$restore_source/ufw/." /etc/ufw/
        run_cmd ufw reload > /dev/null
        ok "Правила UFW восстановлены."
    fi

    # SSH
    if [[ -f "$restore_source/sshd_config" ]]; then
        run_cmd cp "$restore_source/sshd_config" /etc/ssh/
        run_cmd systemctl restart ssh sshd
        ok "Конфигурация SSH восстановлена."
    fi
    
    # Fail2Ban
    if [[ -f "$restore_source/jail.local" ]]; then
        run_cmd cp "$restore_source/jail.local" /etc/fail2ban/
    fi
    if [[ -f "$restore_source/fail2ban-whitelist.txt" ]]; then
        run_cmd mkdir -p /etc/reshala
        run_cmd cp "$restore_source/fail2ban-whitelist.txt" "$F2B_WHITELIST_FILE"
    fi
    run_cmd systemctl restart fail2ban
    ok "Конфигурация Fail2Ban восстановлена."

    # Kernel
    if [[ -f "$restore_source/99-reshala-hardening.conf" ]]; then
        run_cmd cp "$restore_source/99-reshala-hardening.conf" /etc/sysctl.d/
        run_cmd sysctl -p "$SYSCTL_CONF_FILE"
        ok "Настройки ядра восстановлены."
    fi
    
    # Reshala config
    if [[ -f "$restore_source/reshala.conf" ]]; then
        run_cmd cp "$restore_source/reshala.conf" "${SCRIPT_DIR}/config/"
        ok "Главный конфиг reshala.conf восстановлен."
    fi

    # SSH Keys
    if [[ -f "$restore_source/authorized_keys" ]]; then
        run_cmd mkdir -p /root/.ssh
        run_cmd cp "$restore_source/authorized_keys" /root/.ssh/authorized_keys
        run_cmd chmod 600 /root/.ssh/authorized_keys
        ok "Ключи SSH (authorized_keys) восстановлены."
    fi
    
    run_cmd rm -rf "$temp_restore_path"
    ok "Восстановление завершено."
}

_backup_cleanup() {
    local keep
    keep=$(safe_read "Сколько последних бэкапов оставить?" "5") || return
    
    info "Удаляю старые бэкапы, оставляю $keep последних..."
    
    local backups_to_delete
    backups_to_delete=$(ls -t "$BACKUP_DIR_SEC"/reshala-security-backup-*.tar.gz 2>/dev/null | tail -n +$((keep + 1)))

    if [[ -z "$backups_to_delete" ]]; then
        ok "Нет старых бэкапов для удаления."
        return
    fi

    echo "$backups_to_delete" | while read -r file; do
        run_cmd rm -f "$file"
        warn "  - $file"
    done
    
    ok "Очистка завершена."
}
