#!/bin/bash
# ============================================================ #
# ==      ИНСТРУМЕНТ «РЕШАЛА» v2.999 - РЕФАКТОРИНГ МЕНЮ        == #
# ============================================================ #
#
# Точка входа. Этот скрипт — прораб. Он только отдаёт команды
# модулям и отрисовывает главное меню.
#
# @menu.manifest
#
# @item( main | d | 🗑️  Снести Решалу | _reshala_uninstall_wrapper | 90 | 90 | Удаляет все файлы и конфигурацию Решалы. )
#

set -uo pipefail

# Определяем РЕАЛЬНОЕ местоположение скрипта, даже если он запущен через симлинк
SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ]; do
  DIR="$( cd -P "$( dirname "$SOURCE" )" && pwd )"
  SOURCE="$(readlink "$SOURCE")"
  [[ $SOURCE != /* ]] && SOURCE="$DIR/$SOURCE"
done
export SCRIPT_DIR="$( cd -P "$( dirname "$SOURCE" )" && pwd )"

readonly VERSION="v2.999"

# ============================================================ #
#              ПОДГОТОВКА И ЗАГРУЗКА КОМПОНЕНТОВ               #
# ============================================================ #

# Загружаем конфигурацию
if [ -f "${SCRIPT_DIR}/config/reshala.conf" ]; then
    source "${SCRIPT_DIR}/config/reshala.conf"
else
    echo "[FATAL ERROR] Configuration file config/reshala.conf not found."
    exit 1
fi

# Загружаем общие инструменты
if [ -f "${SCRIPT_DIR}/modules/core/common.sh" ]; then
    source "${SCRIPT_DIR}/modules/core/common.sh"
else
    echo "[FATAL ERROR] Common tools module modules/core/common.sh not found."
    exit 1
fi

# Загружаем НОВЫЙ генератор меню
debug_log "Загрузка menu_generator.sh..."
source "${SCRIPT_DIR}/modules/core/menu_generator.sh"
source_exit_code=$?
debug_log "Загрузка menu_generator.sh завершена с кодом: $source_exit_code"
if [[ $source_exit_code -ne 0 ]]; then
    echo -e "\n\n[FATAL] КРИТИЧЕСКАЯ ОШИБКА: Не удалось загрузить ядро меню (menu_generator.sh). Скрипт не может продолжаться."
    exit 1
fi
if ! command -v render_menu_items &>/dev/null; then
    echo -e "\n\n[FATAL] КРИТИЧЕСКАЯ ОШИБКА: Функция render_menu_items не определена даже после загрузки. Проблема в файле menu_generator.sh."
    exit 1
fi

# ============================================================ #
#                     ДЕЙСТВИЯ ГЛАВНОГО МЕНЮ                   #
# ============================================================ #

# Это функции-обертки для действий, определенных в манифесте
# этого файла. Они позволяют вызывать логику из других модулей.
_reshala_uninstall_wrapper() {
    run_module core/self_update uninstall_script
}

# ============================================================ #
#                     ГЛАВНАЯ ЛОГИКА                           #
# ============================================================ #

# Универсальный загрузчик и запускатор модулей
run_module() {
    local module_name="$1"
    shift
    local module_path="${SCRIPT_DIR}/modules/${module_name}.sh"

    if [ -f "$module_path" ]; then
        source "$module_path"
        # Если функция существует в загруженном файле, вызываем ее
        if command -v "$1" &>/dev/null; then
            "$@"
        else
            log "Ошибка вызова: функция '$1' не найдена в модуле '${module_name}'."
            printf_error "Ошибка: функция '$1' не найдена в модуле '${module_name}'."
        fi
    else
        log "Критическая ошибка: модуль '${module_name}' не найден."
        printf_error "Модуль '${module_name}' отсутствует. Установка повреждена."
    fi
}

# Главное меню
show_main_menu() {
    # Перехватываем Ctrl+C только в главном меню, чтобы вывести сообщение
    trap 'printf "\n%b\n" "Для выхода из Решалы используй [q]." >&2' SIGINT

    while true; do
        run_module ui/dashboard show
        
        if [[ ${UPDATE_AVAILABLE:-0} -eq 1 ]]; then
            printf_critical_warning "ДОСТУПНО ОБНОВЛЕНИЕ! ${VERSION} -> ${LATEST_VERSION}"
        fi
        
        printf "\n%s\n\n" "Чё делать будем, босс?"
        
        # 1. Рендерим все пункты меню из 'main'
        render_menu_items "main"

        echo ""

        # 3. Обрабатываем специальные, контекстно-зависимые пункты
        if [[ ${UPDATE_AVAILABLE:-0} -eq 1 ]]; then
            printf_menu_option "u" "‼️ ОБНОВИТЬ РЕШАЛУ ‼️" "${C_BOLD}${C_YELLOW}"
        fi
        
        if [ "${SKYNET_MODE:-0}" -eq 1 ]; then
            printf_menu_option "q" "🔙 ВЕРНУТЬСЯ В ЦУП" "${C_CYAN}"
        else
            printf_menu_option "q" "🚪 Выйти из решалы" "${C_CYAN}"
        fi
        print_separator "-" 60

        local choice
        choice=$(safe_read "Твой выбор, босс") || {
            _LAST_CTRLC_SIGNALED=0;
            printf "\r\033[K%b" "${C_RED}🛑 Жми [q], чтобы выйти из главного меню!${C_RESET}\n";
            continue;
        }
        
        # --- ОБРАБОТЧИК НАЖАТИЙ ---
        local action
        # Сначала ищем действие в основных пунктах
        action=$(get_menu_action "main" "$choice")
        
        if [[ -n "$action" ]]; then
            # Спец-обработка для Skynet (запрет вложенности)
            if [[ "$choice" == "0" && "${SKYNET_MODE:-0}" -eq 1 ]]; then
                printf_error "Ты уже в матрице."
            else
                # Выполняем команду, собранную генератором
                eval "$action"
            fi
        else
            # Если действие не найдено в манифестах, проверяем специальные случаи
            case "$choice" in
                u|U)
                    if [[ ${UPDATE_AVAILABLE:-0} -eq 1 ]]; then
                        if [[ -n "${LATEST_COMMIT_MESSAGE:-}" ]]; then
                            clear
                            local width=68
                            local line_top=$(printf "%.0s═" $(seq 1 $width))
                            local line_mid=$(printf "%.0s─" $(seq 1 $width))
                            
                            echo -e "  ${C_CYAN}${line_top}${C_RESET}"
                            echo -e "  ${C_YELLOW}⚡ ЧТО НОВОГО В ЭТОМ ОБНОВЛЕНИИ?${C_RESET} (${LATEST_VERSION})"
                            echo -e "  ${C_CYAN}${line_mid}${C_RESET}"
                            echo
                            # Динамический перенос слов строго в ширину линеек
                            echo "$LATEST_COMMIT_MESSAGE" | fold -s -w "$width" | while read -r line; do
                                [[ -z "${line// /}" ]] && continue
                                echo -e "  ${C_WHITE}${line}${C_RESET}"
                            done
                            echo
                            echo -e "  ${C_CYAN}${line_top}${C_RESET}"
                            echo
                            echo -e "  👇 Нажми ${C_BOLD}[Enter]${C_RESET}, чтобы подтвердить и начать обновление..."
                            read -r _
                        fi
                        run_module core/self_update run_update
                    else
                        printf_error "Нет такого пункта."
                    fi
                    ;;
                q|Q)
                    if [ "${SKYNET_MODE:-0}" -eq 1 ]; then
                        exit 0
                    else
                        echo "Был рад помочь. Не обосрись. 🥃"
                        exit 0
                    fi
                    ;;
                *)
                    printf_error "Нет такого пункта."
                    ;;
            esac
        fi
    done
}

# ============================================================ #
#                       ТОЧКА ВХОДА                            #
# ============================================================ #
main() {
    init_logger

    if [[ $EUID -ne 0 ]]; then
        printf_error "Этот скрипт должен быть запущен от имени root или через sudo."
        exit 1
    fi

    if [[ "${1:-}" == "install" ]]; then
        source "${SCRIPT_DIR}/modules/core/self_update.sh" && install_script
        ensure_package "sudo"
        exit 0
    fi

    log "Запуск фреймворка Решала ${VERSION}"
    run_module core/self_update check_for_updates
    show_main_menu
}

main "$@"
