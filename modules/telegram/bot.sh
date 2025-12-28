#!/bin/bash
# ============================================================ #
# ==           TELEGRAM: BOT INTERACTIVE LOGIC              == #
# ============================================================ #
#
# Этот модуль содержит логику для интерактивного бота,
# работающего в режиме long-polling.
#
[[ "${BASH_SOURCE[0]}" == "${0}" ]] && exit 1 # Защита от прямого запуска

# Подключаем все зависимости
source "${SCRIPT_DIR}/modules/core/common.sh"
source "${SCRIPT_DIR}/modules/telegram/core.sh"
source "${SCRIPT_DIR}/modules/telegram/menu_generator.sh"

BOT_PID_FILE="/tmp/reshala_bot.pid"

# Главная функция-обработчик.
# Принимает:
#   $1: "start", "stop", "status"
#
handle_bot_process() {
    case "$1" in
        start)
            if [ -f "$BOT_PID_FILE" ] && ps -p "$(cat "$BOT_PID_FILE")" > /dev/null; then
                err "Процесс бота уже запущен с PID $(cat "$BOT_PID_FILE")."
                return 1
            fi
            info "Запускаю процесс бота в фоновом режиме..."
            # Запускаем _bot_main_loop в фоне
            _bot_main_loop &
            # Сохраняем PID фонового процесса
            echo $! > "$BOT_PID_FILE"
            sleep 1
            if ps -p "$(cat "$BOT_PID_FILE")" > /dev/null; then
                ok "Бот успешно запущен с PID $(cat "$BOT_PID_FILE")."
            else
                err "Не удалось запустить процесс бота."
            fi
            ;;;;
        stop)
            if [ ! -f "$BOT_PID_FILE" ] || ! ps -p "$(cat "$BOT_PID_FILE")" > /dev/null; then
                warn "Процесс бота не запущен."
                rm -f "$BOT_PID_FILE"
                return
            fi
            local pid; pid=$(cat "$BOT_PID_FILE")
            info "Останавливаю процесс бота с PID $pid..."
            if kill "$pid"; then
                rm -f "$BOT_PID_FILE"
                ok "Процесс бота остановлен."
            else
                err "Не удалось остановить процесс бота с PID $pid."
            fi
            ;;;;
        status)
            if [ -f "$BOT_PID_FILE" ] && ps -p "$(cat "$BOT_PID_FILE")" > /dev/null; then
                ok "Бот активен. PID: $(cat "$BOT_PID_FILE")"
            else
                warn "Бот не активен."
            fi
            ;;;;
        *)
            err "Неизвестная команда: $1. Используйте start, stop или status."
            ;;
    esac
}


# Основной цикл long-polling
_bot_main_loop() {
    local token; token=$(get_config_var "TG_BOT_TOKEN")
    if [[ -z "$token" ]]; then
        log "TG Bot: Бот не может быть запущен, так как токен не настроен."
        exit 1
    fi

    local offset=0
    log "TG Bot: Процесс запущен. Начинаю слушать команды..."

    while true; do
        # Получаем обновления
        local updates; updates=$(curl -s -X POST "https://api.telegram.org/bot${token}/getUpdates" \
            -d "offset=${offset}" \
            -d "timeout=60" \
            -d "allowed_updates=[\"message\",\"callback_query\"]")

        # Проверяем, что ответ - валидный JSON
        if ! echo "$updates" | jq -e . > /dev/null 2>&1; then
            log "TG Bot: Невалидный JSON ответ от API: $updates"
            sleep 5
            continue
        fi

        # Проходим по каждому обновлению
        local results_count; results_count=$(echo "$updates" | jq '.result | length')
        if [[ "$results_count" -eq 0 ]]; then continue; fi

        for (( i=0; i < results_count; i++ )); do
            local update; update=$(echo "$updates" | jq ".result[$i]")
            
            # Обновляем offset
            offset=$(echo "$update" | jq '.update_id' | awk '{print $1+1}')
            
            # --- Обработка Callback Query (нажатия на кнопки) ---
            if echo "$update" | jq -e '.callback_query' > /dev/null; then
                local callback_query; callback_query=$(echo "$update" | jq '.callback_query')
                local callback_id; callback_id=$(echo "$callback_query" | jq -r '.id')
                local chat_id; chat_id=$(echo "$callback_query" | jq -r '.message.chat.id')
                local data; data=$(echo "$callback_query" | jq -r '.data')

                # Отвечаем на callback, чтобы убрать "часики" с кнопки
                curl -s -X POST "https://api.telegram.org/bot${token}/answerCallbackQuery" -d "callback_query_id=${callback_id}" > /dev/null
                
                # Парсим callback_data
                local action; action=$(echo "$data" | cut -d':' -f1)
                local command; command=$(echo "$data" | cut -d':' -f2-)
                # Возвращаем двоеточия
                command=${command//;/;}

                if [[ "$action" == "exec" ]]; then
                    log "TG Bot: Выполняю команду '$command' для чата $chat_id"
                    # Выполняем команду и захватываем вывод
                    local output
                    # Важно: запускаем команду в subshell, чтобы переменные окружения не протекли
                    output=$( (eval "$command") 2>&1 )
                    
                    # Очищаем от ANSI-кодов
                    local clean_output; clean_output=$(echo "$output" | sed 's/\x1b\[[0-9;]*m//g')
                    
                    # Отправляем результат
                    tg_send_message "$chat_id" "\
$command\
\n${clean_output}" "0" "" "Markdown"
                fi
            
            # --- Обработка сообщений (команда /start) ---
            elif echo "$update" | jq -e '.message.text' | grep -q "/start"; then
                local message; message=$(echo "$update" | jq '.message')
                local chat_id; chat_id=$(echo "$message" | jq -r '.chat.id')

                log "TG Bot: Получена команда /start от чата $chat_id"
                local welcome_text="Добро пожаловать в панель управления Reshala! Выберите действие:"
                local keyboard; keyboard=$(tg_generate_keyboard_json "main")
                
                tg_send_message "$chat_id" "$welcome_text" "0" "$keyboard"
            fi
        done
        sleep 1
    done
}