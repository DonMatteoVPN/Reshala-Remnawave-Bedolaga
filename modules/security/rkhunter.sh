#!/bin/bash
#   ( РОДИТЕЛЬ | КЛАВИША | НАЗВАНИЕ | ФУНКЦИЯ | ПОРЯДОК | ГРУППА | ОПИСАНИЕ )
# @menu.manifest
# @item( security | 4 | 🔍 Сканер Rootkit | show_rkhunter_menu | 40 | 10 | Поиск вредоносного ПО и руткитов. )
#
# rkhunter.sh - Управление сканером руткитов (rkhunter)
#

RKHUNTER_CRON_FILE="/etc/cron.weekly/reshala-rkhunter-scan"
RKHUNTER_LOG_FILE="/var/log/rkhunter.log"

show_rkhunter_menu() {
    while true; do
        clear
        enable_graceful_ctrlc
        menu_header "🔍 Сканер руткитов"
        printf_description "Поиск вредоносного ПО с помощью rkhunter"

        _rkh_check_status
        
        echo ""
        if ! command -v rkhunter &> /dev/null; then
            printf_menu_option "i" "УСТАНОВИТЬ RKHUNTER" "${C_YELLOW}"
        else
            printf_menu_option "1" "Включить/Выключить еженедельное сканирование"
            printf_menu_option "2" "Запустить сканирование сейчас"
            printf_menu_option "3" "Обновить базы rkhunter"
            printf_menu_option "4" "Показать лог сканирования"
        fi
        
        echo ""
        printf_menu_option "b" "Назад"
        echo ""

        local choice
        choice=$(safe_read "Выберите действие" "") || { break; }
        
        case "$choice" in
            1) _rkh_toggle_cron; wait_for_enter;;
            2) _rkh_run_scan; wait_for_enter;;
            3) _rkh_update_db; wait_for_enter;;
            4)
                if [[ -f "$RKHUNTER_LOG_FILE" ]]; then
                    run_cmd less "$RKHUNTER_LOG_FILE"
                else
                    warn "Лог-файл не найден."
                fi
                ;;
            i|I) _rkh_setup; wait_for_enter;;
            b|B) break;;
            *) warn "Неверный выбор";;
        esac
        disable_graceful_ctrlc
    done
}

_rkh_check_status() {
    print_separator
    info "Статус rkhunter"

    if ! command -v rkhunter &> /dev/null; then
        warn "rkhunter не установлен."
        printf_description "Вы можете установить его, выбрав пункт 'i'."
    else
        ok "rkhunter установлен."
        if [[ -f "$RKHUNTER_CRON_FILE" ]]; then
            printf_description "Еженедельное сканирование: ${C_GREEN}Включено${C_RESET}"
        else
            printf_description "Еженедельное сканирование: ${C_RED}Выключено${C_RESET}"
        fi
        if [[ -f "$RKHUNTER_LOG_FILE" ]]; then
            local last_scan
            last_scan=$(run_cmd stat -c %y "$RKHUNTER_LOG_FILE" 2>/dev/null | cut -d'.' -f1)
            printf_description "Последнее сканирование: ${C_CYAN}$last_scan${C_RESET}"
        fi
    fi
    print_separator
}

_rkh_setup() {
    print_separator
    info "Установка и настройка rkhunter"
    print_separator
    
    if ! ask_yes_no "Установить и настроить rkhunter?"; then
        info "Отмена."
        return
    fi
    
    if ! ensure_package "rkhunter"; then
        err "Не удалось установить rkhunter. Попробуйте вручную."
        return 1
    fi
    
    info "Обновляю базы rkhunter..."
    run_cmd rkhunter --update
    info "Создаю снимок файловой системы..."
    run_cmd rkhunter --propupd
    
    ok "rkhunter успешно установлен и настроен."
    warn "Не забудьте включить еженедельное сканирование, если требуется."
}

_rkh_toggle_cron() {
    if [[ -f "$RKHUNTER_CRON_FILE" ]]; then
        if ask_yes_no "Еженедельное сканирование включено. Выключить?"; then
            run_cmd rm -f "$RKHUNTER_CRON_FILE"
            ok "Еженедельное сканирование отключено."
        fi
    else
        if ask_yes_no "Еженедельное сканирование выключено. Включить?"; then
            info "Включаю еженедельное сканирование..."
            run_cmd tee "$RKHUNTER_CRON_FILE" > /dev/null << 'CRON'
#!/bin/bash
# Reshala Security Module: Weekly rkhunter scan
(
rkhunter --update --quiet
rkhunter --check --cronjob --report-warnings-only
) &> /var/log/reshala_rkhunter_last.log
CRON
            run_cmd chmod +x "$RKHUNTER_CRON_FILE"
            ok "Еженедельное сканирование включено."
            warn "Результаты будут сохраняться в /var/log/reshala_rkhunter_last.log"
        fi
    fi
}

_rkh_run_scan() {
    if ! command -v rkhunter &> /dev/null; then
        err "rkhunter не установлен. Сначала установите его (пункт 'i')."
        return
    fi
    
    if ! ask_yes_no "Сканирование может занять несколько минут. Начать?"; then
        info "Отмена."
        return
    fi
    
    print_separator
    info "Запускаю сканирование rkhunter..."
    run_cmd rkhunter --check --skip-keypress --report-warnings-only
    
    ok "Сканирование завершено."
    warn "Внимательно просмотрите вывод на предмет предупреждений (Warnings)."
}

_rkh_update_db() {
    if ! command -v rkhunter &> /dev/null; then
        err "rkhunter не установлен. Сначала установите его (пункт 'i')."
        return
    fi
    
    info "Обновляю базы данных rkhunter..."
    run_cmd rkhunter --update
    ok "Базы данных обновлены."
}
