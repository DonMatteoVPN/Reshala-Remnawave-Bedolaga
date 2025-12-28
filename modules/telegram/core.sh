#!/bin/bash
# ============================================================ #
# ==           TELEGRAM: CORE API FUNCTIONS                 == #
# ============================================================ #
#
# Этот модуль содержит низкоуровневые функции для взаимодействия
# с Telegram Bot API. Он не вызывается напрямую, а используется
# другими модулями для отправки сообщений.
#
[[ "${BASH_SOURCE[0]}" == "${0}" ]] && exit 1 # Защита от прямого запуска

# Главная функция отправки сообщения
# Принимает:
#   $1: ID чата (обязательно)
#   $2: Текст сообщения (обязательно)
#   $3: ID топика (опционально, 0 для основного чата)
#   $4: JSON клавиатуры (опционально)
#   $5: Режим парсинга (Markdown/HTML, опционально)
#
# Возвращает 0 при успехе, 1 при ошибке.
#
tg_send_message() {
    local chat_id="$1"
    local text="$2"
    local topic_id="${3:-0}"
    local keyboard_json="${4:-}"
    local parse_mode="${5:-Markdown}"

    local token
    token=$(get_config_var "TG_BOT_TOKEN")

    if [[ -z "$token" ]]; then
        log "TG Core: Невозможно отправить сообщение, TG_BOT_TOKEN не установлен."
        return 1
    fi
    
    if [[ -z "$chat_id" ]]; then
        log "TG Core: Невозможно отправить сообщение, chat_id не указан."
        return 1
    fi

    # Убедимся, что jq доступен для URL-кодирования
    if ! command -v jq &>/dev/null; then
        if command -v ensure_package &>/dev/null; then
            ensure_package "jq"
        else
            log "TG Core: JQ не установлен и функция ensure_package недоступна."
            return 1
        fi
    fi

    # URL-кодирование текста сообщения для безопасной передачи
    local encoded_text
    encoded_text=$(printf %s "$text" | jq -s -R -r @uri)

    local api_url="https://api.telegram.org/bot${token}/sendMessage"
    local curl_opts=("-s" "-X" "POST" "$api_url")
    
    curl_opts+=("-d" "chat_id=${chat_id}")
    curl_opts+=("-d" "text=${encoded_text}")
    curl_opts+=("-d" "parse_mode=${parse_mode}")
    
    if [[ -n "$topic_id" && "$topic_id" -ne 0 ]]; then
        curl_opts+=("-d" "message_thread_id=${topic_id}")
    fi
    
    if [[ -n "$keyboard_json" ]]; then
        curl_opts+=("-d" "reply_markup=${keyboard_json}")
    fi

    local response
    response=$(curl "${curl_opts[@]}")

    if echo "$response" | grep -q '"ok":true'; then
        log "TG Core: Сообщение успешно отправлено в чат $chat_id."
        return 0
        else
            log "TG Core: Ошибка отправки сообщения. Ответ API: $response"
            return 1
        fi
    }
    
    # Обертка для отправки уведомлений по имени адресата.
    # Ищет в конфиге переменные TG_CHAT_ID_NAME и TG_TOPIC_ID_NAME.
    # Если не находит, использует TG_DEFAULT_CHAT_ID.
    #
    # Принимает:
    #       : Имя адресата (например, "FAIL2BAN", "DEFAULT")
    #   $2: Текст сообщения
    #
    tg_notify() {
        local dest_name="    "
        local text="$2"
    
        # Конвертируем имя в верхний регистр для ключа конфига
        local dest_key; dest_key=$(echo "$dest_name" | tr '[:lower:]' '[:upper:]')
    
        local chat_id; chat_id=$(get_config_var "TG_CHAT_ID_${dest_key}")
        local topic_id; topic_id=$(get_config_var "TG_TOPIC_ID_${dest_key}")
    
        # Откат на адресата по умолчанию
        if [[ -z "$chat_id" ]]; then
            log "TG Notify: Адресат '$dest_name' не найден, использую адресата по умолчанию."
            chat_id=$(get_config_var "TG_DEFAULT_CHAT_ID")
            topic_id=$(get_config_var "TG_DEFAULT_TOPIC_ID")
        fi
    
        if [[ -z "$chat_id" ]]; then
            log "TG Notify: Не удалось найти chat_id для адресата '$dest_name' или адресата по умолчанию."
            return 1
        fi
        
        # Вызываем основную функцию отправки
        tg_send_message "$chat_id" "$text" "${topic_id:-0}"
    }
    