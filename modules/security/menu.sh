#!/bin/bash
#   ( РОДИТЕЛЬ | КЛАВИША | НАЗВАНИЕ | ФУНКЦИЯ | ПОРЯДОК | ГРУППА | ОПИСАНИЕ )
# menu.sh - Главное меню модуля Безопасности
#
# @menu.manifest
# @item( main | 1 | 🛡️ Безопасность ${C_GREEN}(Firewall, Fail2Ban и др.)${C_RESET} | show_security_menu | 0 | 0 | Управление защитой локального сервера. )
#

[[ "${BASH_SOURCE[0]}" == "${0}" ]] && exit 1

show_security_menu() {
    enable_graceful_ctrlc
    while true; do
        clear
        menu_header "🛡️ Безопасность"
        printf_description "Управление защитой локального сервера."
        echo ""

        # Динамически рендерим меню на основе манифестов дочерних модулей
        render_menu_items "security"

        echo ""
        printf_menu_option "b" "Назад"
        echo ""

        local choice
        choice=$(safe_read "Выберите действие" "") || break

        if [[ "$choice" == "b" || "$choice" == "B" ]]; then
            break
        fi

        # Ищем действие в динамических пунктах
        local action
        action=$(get_menu_action "security" "$choice")
        
        if [[ -n "$action" ]]; then
            # Выполняем найденное действие (которое содержит run_module)
            eval "$action"
            local ret=$?
            # Пауза после выполнения действия, чтобы пользователь мог прочитать вывод, если не был выполнен возврат назад
            [[ $ret -ne 2 ]] && wait_for_enter
        else
            warn "Неверный выбор"
            sleep 1
        fi
    done
    disable_graceful_ctrlc
}