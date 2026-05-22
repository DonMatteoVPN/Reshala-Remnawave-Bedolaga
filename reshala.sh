#!/bin/bash
# ============================================================ #
# ==      ИНСТРУМЕНТ «РЕШАЛА» v3.094                        == #
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

# Гарантируем валидный CWD — после self-update старая директория может быть удалена,
# что приводит к "chdir: error: getcwd: cannot access parent directories"
cd "$SCRIPT_DIR" 2>/dev/null || cd / || true

readonly VERSION="v3.094"

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

# Загружаем систему миграций
if [ -f "${SCRIPT_DIR}/modules/utils/migrations.sh" ]; then
    source "${SCRIPT_DIR}/modules/utils/migrations.sh"
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

# Помощник для кликабельных ссылок в терминале
_printf_link() {
    local text="$1"
    local url="$2"
    local color="${3:-$C_CYAN}"
    # Используем OSC 8 для создания настоящей кликабельной гиперссылки, 
    # а рядом оставляем саму ссылку серым текстом для визуальной ясности.
    printf "  ${C_MAGENTA}║${C_RESET}     %b\e]8;;%s\e\\%s\e]8;;\e\\%b %b(%s)%b\n" "$color" "$url" "$text" "$C_RESET" "$C_GRAY" "$url" "$C_RESET"
}

# Страница поддержки разработчика
show_support_page() {
    # === ПАНЕЛЬ УПРАВЛЕНИЯ (1 = Показать, 0 = Скрыть) ===
    local SHOW_USDT=1
    local SHOW_BTC=1
    local SHOW_TON=0
    local SHOW_PLATEGA=0     # По умолчанию скрыто, как ты просил
    local SHOW_TRIBUT=1      # Донат через Tribut (Telegram)
    local SHOW_GROUP=1       # Группа ТГ Решалы
    local SHOW_SITE=1        # Сайт Решалы
    
    # === НАСТРОЙКИ (Просто поменяй значения ниже) ===
    local DON_USDT_ADDR="TKPnnmtJcDM7B2uCoLQciwZmS7f8ckMNx9" 
    local DON_BTC_ADDR="bc1q235adg3dd4t43jmkpqka0hj305la43md38fc0n" 
    local DON_TON_ADDR="UQ..." 
    local DON_PLATEGA_URL="https://platega.com/secret"
    local DON_TRIBUT_URL="https://t.me/tribute/app?startapp=dxrn"
    
    local LINK_GROUP_URL="https://t.me/reshala_prod"
    local LINK_SITE_URL="https://github.com/DonMatteoVPN/Reshala-Remnawave-Bedolaga"
    # ========================================================

    clear
    # Логотип РЕШАЛА с градиентом
    echo -e "  ${C_CYAN}  ██████╗ ███████╗███████╗██╗  ██╗ █████╗ ██╗      █████╗ ${C_RESET}"
    echo -e "  ${C_CYAN}  ██╔══██╗██╔════╝██╔════╝██║  ██║██╔══██╗██║     ██╔══██╗${C_RESET}"
    echo -e "  ${C_BLUE}  ██████╔╝█████╗  ███████╗███████║███████║██║     ███████║${C_RESET}"
    echo -e "  ${C_BLUE}  ██╔══██╗██╔══╝  ╚════██║██╔══██║██╔══██║██║     ██╔══██║${C_RESET}"
    echo -e "  ${C_RED}  ██║  ██║███████╗███████║██║  ██║██║  ██║███████╗██║  ██║${C_RESET}"
    echo -e "  ${C_RED}  ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝${C_RESET}"
    echo
    echo -e "           ${C_BOLD}${C_WHITE}от ${C_YELLOW}DonMatteo${C_WHITE} с любовью блять!${C_RESET}"
    echo
    
    echo -e "  ${C_MAGENTA}╔═════════════════════════════════════════════════════════════════╗${C_RESET}"
    echo -e "  ${C_MAGENTA}║${C_RESET}  ${C_YELLOW}🚀 ПОДДЕРЖИ ПРОЕКТ — ВДОХНОВИ НА НОВЫЕ ФИЧИ!${C_RESET}"
    echo -e "  ${C_MAGENTA}╠═════════════════════════════════════════════════════════════════╝${C_RESET}"
    echo -e "  ${C_MAGENTA}║${C_RESET}"
    
    if [[ "$SHOW_USDT" == "1" ]]; then
        echo -e "  ${C_MAGENTA}║${C_RESET}  ${C_GREEN}💎 USDT (TRC20):${C_RESET}"
        echo -e "  ${C_MAGENTA}║${C_RESET}     ${C_WHITE}${DON_USDT_ADDR}${C_RESET}"
        echo -e "  ${C_MAGENTA}║${C_RESET}"
    fi

    if [[ "$SHOW_BTC" == "1" ]]; then
        echo -e "  ${C_MAGENTA}║${C_RESET}  ${C_GREEN}💰 Bitcoin (BTC):${C_RESET}"
        echo -e "  ${C_MAGENTA}║${C_RESET}     ${C_WHITE}${DON_BTC_ADDR}${C_RESET}"
        echo -e "  ${C_MAGENTA}║${C_RESET}"
    fi

    if [[ "$SHOW_TON" == "1" ]]; then
        echo -e "  ${C_MAGENTA}║${C_RESET}  ${C_GREEN}💎 TON (Kripta):${C_RESET}"
        echo -e "  ${C_MAGENTA}║${C_RESET}     ${C_WHITE}${DON_TON_ADDR}${C_RESET}"
        echo -e "  ${C_MAGENTA}║${C_RESET}"
    fi

    if [[ "$SHOW_PLATEGA" == "1" ]]; then
        echo -e "  ${C_MAGENTA}║${C_RESET}  ${C_GREEN}💳 Platega (Bank Card):${C_RESET}"
        _printf_link "🚀 Донейт через Platega" "${DON_PLATEGA_URL}" "${C_CYAN}"
        echo -e "  ${C_MAGENTA}║${C_RESET}"
    fi

    if [[ "$SHOW_TRIBUT" == "1" ]]; then
        echo -e "  ${C_MAGENTA}║${C_RESET}  ${C_GREEN}📱 Донат через Tribut (Telegram):${C_RESET}"
        _printf_link "💎 Кнопка доната Tribut" "${DON_TRIBUT_URL}" "${C_CYAN}"
        echo -e "  ${C_MAGENTA}║${C_RESET}"
    fi

    if [[ "$SHOW_GROUP" == "1" || "$SHOW_SITE" == "1" ]]; then
        echo -e "  ${C_MAGENTA}╠═════════════════════════════════════════════════════════════════╗${C_RESET}"
        echo -e "  ${C_MAGENTA}║${C_RESET}  ${C_YELLOW}🔗 ПОЛЕЗНЫЕ ССЫЛКИ:${C_RESET}"
        echo -e "  ${C_MAGENTA}╠═════════════════════════════════════════════════════════════════╝${C_RESET}"
        echo -e "  ${C_MAGENTA}║${C_RESET}"
        
        if [[ "$SHOW_GROUP" == "1" ]]; then
            echo -e "  ${C_MAGENTA}║${C_RESET}  ${C_GREEN}🚀 Группа ТГ Решалы:${C_RESET}"
            _printf_link "✈️ Вступить в сообщество" "${LINK_GROUP_URL}" "${C_CYAN}"
            echo -e "  ${C_MAGENTA}║${C_RESET}"
        fi

        if [[ "$SHOW_SITE" == "1" ]]; then
            echo -e "  ${C_MAGENTA}║${C_RESET}  ${C_GREEN}🌐 Официальный Репозиторий:${C_RESET}"
            _printf_link "🌍 Перейти на GitHub" "${LINK_SITE_URL}" "${C_CYAN}"
            echo -e "  ${C_MAGENTA}║${C_RESET}"
        fi
    fi

    echo -e "  ${C_MAGENTA}╚═════════════════════════════════════════════════════════════════${C_RESET}"
    echo
    echo -e "  ${C_GRAY}Для возврата в меню нажми [Enter]${C_RESET}"
    read -r _
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

        # Проверка критических миграций (Professional Docker Fix и др.)
        if command -v get_pending_migrations_count &>/dev/null; then
            local pending_mig; pending_mig=$(get_pending_migrations_count)
            if [[ $pending_mig -gt 0 ]]; then
                printf_critical_warning "🔥 ЕСТЬ КРИТИЧЕСКИЕ ОБНОВЛЕНИЯ БЕЗОПАСНОСТИ ($pending_mig)!"
            fi
        fi
        
        printf "\n%s\n\n" "Чё делать будем, босс?"
        
        # 1. Рендерим все пункты меню из 'main'
        render_menu_items "main"

        echo ""

        # 3. Обрабатываем специальные, контекстно-зависимые пункты
        if [[ ${UPDATE_AVAILABLE:-0} -eq 1 ]]; then
            printf_menu_option "u" "‼️ ОБНОВИТЬ РЕШАЛУ ‼️" "${C_BOLD}${C_YELLOW}"
        fi

        # Пункт меню для миграций (динамический)
        if command -v get_pending_migrations_count &>/dev/null; then
            if [[ $(get_pending_migrations_count) -gt 0 ]]; then
                printf_menu_option "m" "🚀 ПРИМЕНИТЬ КРИТИЧЕСКИЕ ПАТЧИ 🚀" "${C_BOLD}${C_RED}"
            fi
        fi
        
        if [ "${SKYNET_MODE:-0}" -eq 1 ]; then
            printf_menu_option "q" "🔙 ВЕРНУТЬСЯ В ЦУП" "${C_CYAN}"
        else
            printf_menu_option "q" "🚪 Выйти из решалы" "${C_CYAN}"
        fi

        # Кнопка поддержки (Стильно и заметно)
        printf_menu_option "s" " 🌟 ПОДДЕРЖИ РАЗРАБОТЧИКА 🌟" "${C_BOLD}${C_YELLOW}"

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
                m|M)
                    if command -v show_critical_updates_wizard &>/dev/null; then
                        show_critical_updates_wizard
                    fi
                    ;;
                u|U)
                    if [[ ${UPDATE_AVAILABLE:-0} -eq 1 ]]; then
                        if [[ -n "${LATEST_COMMIT_MESSAGE:-}" ]]; then
                            clear
                            local CW=54   # ширина текста в символах (НЕ байтах)
                            local BW=58   # внутренняя ширина рамки (CW + 4 для отступов)
                            local _leq; _leq=$(printf '═%.0s' $(seq 1 $BW))
                            local _ldsh; _ldsh=$(printf '─%.0s' $(seq 1 $BW))

                            # Печатает строку внутри рамки с правильным правым бордером
                            _bbox() {
                                local color="${1}" text="${2:-}"
                                # Обрезаем до CW символов если длиннее
                                if [[ ${#text} -gt $CW ]]; then text="${text:0:$CW}"; fi
                                local rpad=$(( BW - ${#text} - 2 ))
                                printf "  ${C_CYAN}║${C_RESET}  ${color}%s${C_RESET}%${rpad}s${C_CYAN}║${C_RESET}\n" "$text" ""
                            }

                            # UTF-8 перенос слов — bash ${#var} считает символы, не байты
                            _bwrap() {
                                local color="${1}" indent="${2}" text="${3}"
                                local -a words; read -ra words <<< "$text"
                                local line="$indent"
                                for word in "${words[@]}"; do
                                    local cand="${line}${line:+ }${word}"
                                    if [[ ${#cand} -le $CW ]]; then
                                        line="$cand"
                                    else
                                        _bbox "$color" "$line"
                                        line="${indent}${word}"
                                    fi
                                done
                                [[ -n "$line" ]] && _bbox "$color" "$line"
                            }

                            echo ""
                            echo -e "  ${C_CYAN}╔${_leq}╗${C_RESET}"
                            _bbox "${C_YELLOW}${C_BOLD}" "⚡  ЧТО НОВОГО В ОБНОВЛЕНИИ ${LATEST_VERSION}"
                            echo -e "  ${C_CYAN}╠${_ldsh}╣${C_RESET}"
                            _bbox "" ""

                            local _skip_first=1
                            while IFS= read -r raw_line; do
                                # Первая строка (subject коммита) — показываем как подзаголовок
                                if [[ $_skip_first -eq 1 ]]; then
                                    _skip_first=0
                                    _bwrap "${C_WHITE}${C_BOLD}" "" "$raw_line"
                                    continue
                                fi

                                # Пустая строка
                                if [[ -z "${raw_line// /}" ]]; then
                                    _bbox "" ""
                                    continue
                                fi

                                # Строки-разделители (━━━ ═══ ───) → рамочный делитель
                                local _stripped; _stripped=$(echo "$raw_line" | tr -d '━─═ \t')
                                if [[ -z "$_stripped" ]]; then
                                    echo -e "  ${C_CYAN}╠${_ldsh}╣${C_RESET}"
                                    continue
                                fi

                                # Заголовок секции с эмодзи
                                if [[ "$raw_line" =~ ^[[:space:]]*(🚀|🔧|🐛|✨|🛠|💡|⚡|🔒|🧹|📦|🗑️|♻️|🌐|💾|🎯|🆕|⚙️|🔥|✅|📋|🏎️|🛡️|🔍|🗑|🌐|⚠️) ]]; then
                                    _bwrap "${C_CYAN}${C_BOLD}" "" "${raw_line#"${raw_line%%[! ]*}"}"
                                    continue
                                fi

                                # Строки с отступом (sub-items, имена файлов)
                                if [[ "$raw_line" =~ ^[[:space:]]+ ]]; then
                                    _bwrap "${C_GRAY}" "  " "${raw_line#"${raw_line%%[! ]*}"}"
                                    continue
                                fi

                                # Обычный текст — перенос слов с учётом Unicode
                                _bwrap "${C_WHITE}" "" "$raw_line"

                            done <<< "$LATEST_COMMIT_MESSAGE"

                            _bbox "" ""
                            echo -e "  ${C_CYAN}╚${_leq}╝${C_RESET}"
                            echo ""
                            echo -e "  👇 Нажми ${C_BOLD}[Enter]${C_RESET}, чтобы подтвердить и начать обновление..."
                            read -r _
                        fi

                        run_module core/self_update run_update
                    else
                        printf_error "Нет такого пункта."
                    fi
                    ;;
                s|S)
                    show_support_page
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
