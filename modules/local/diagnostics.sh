#!/bin/bash
# ============================================================ #
# ==                МОДУЛЬ ДИАГНОСТИКИ                      == #
# ============================================================ #
#
# Отвечает за просмотр логов и управление Docker.
#  ( РОДИТЕЛЬ | КЛАВИША | НАЗВАНИЕ | ФУНКЦИЯ | ПОРЯДОК | ГРУППА | ОПИСАНИЕ )
# @menu.manifest
#
# @item( main | 5 | 📜 Диагностика и Логи ${C_YELLOW}(Решала, Панель, Нода, Бот)${C_RESET} | show_diagnostics_menu | 30 | 2 | Быстрый просмотр логов основных компонентов системы. )
#

[[ "${BASH_SOURCE[0]}" == "${0}" ]] && exit 1 # Защита от прямого запуска

# ============================================================ #
#                  ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ                     #
# ============================================================ #
# --- Меню логов ---
show_diagnostics_menu() {
    enable_graceful_ctrlc
    while true; do
        run_module core/state_scanner scan_remnawave_state
        clear
        menu_header "📜 Диагностика и Логи"
        printf_description "Быстрый просмотр логов основных компонентов системы (выйти: CTRL+C)."
        echo ""; printf_menu_option "1" "📒 Журнал «Решалы»"
        if [[ "$SERVER_TYPE" == *"Панель"* ]]; then printf_menu_option "2" "📊 Логи Панели"; fi
        if [[ "$SERVER_TYPE" == *"Нода"* ]]; then printf_menu_option "3" "📡 Логи Ноды"; fi
        if [ "${BOT_DETECTED:-0}" -eq 1 ]; then printf_menu_option "4" "🤖 Логи Бота"; fi
        echo ""; printf_menu_option "b" "🔙 Назад"; print_separator "-" 60
        local choice; choice=$(safe_read "Какой лог курим?: " "") || break
        case "$choice" in
            1) view_logs_realtime "$LOGFILE" "Решалы" ;;
            2) if [[ "$SERVER_TYPE" == *"Панель"* ]]; then view_docker_logs "$PANEL_NODE_PATH" "Панели"; else printf_error "Панели нет."; fi;;
            3) if [[ "$SERVER_TYPE" == *"Нода"* ]]; then view_docker_logs "$PANEL_NODE_PATH" "Ноды"; else printf_error "Ноды нет."; fi;;
            4) if [ "${BOT_DETECTED:-0}" -eq 1 ]; then view_docker_logs "${BOT_PATH}/docker-compose.yml" "Бота"; else printf_error "Бота нет."; fi;;
            [bB]) break ;;
        esac
    done
    disable_graceful_ctrlc
}
