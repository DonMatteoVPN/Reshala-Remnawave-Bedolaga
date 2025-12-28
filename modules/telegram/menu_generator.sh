#!/bin/bash
# ============================================================ #
# ==        TELEGRAM: DYNAMIC MENU GENERATOR                == #
# ============================================================ #
#
# Сканирует модули проекта на предмет метаданных TG_ACTION_* и строит
# на их основе JSON для inline-клавиатур Telegram.
#
[[ "${BASH_SOURCE[0]}" == "${0}" ]] && exit 1 # Защита от прямого запуска

# Главная функция.
# Принимает:
#   $1: ID родительского меню (на данный момент поддерживается только "main")
# Возвращает (echo): JSON-строку для 'reply_markup'.
#
tg_generate_keyboard_json() {
    local parent_id="${1:-main}"
    local -a menu_items=()

    # Ищем во всех .sh файлах в модулях и плагинах
    while IFS= read -r file; do
        local content; content=$(cat "$file")
        
        # Проверяем, есть ли в файле упоминание TG_ACTION_PARENT, чтобы не читать всё подряд
        if ! echo "$content" | grep -q "# TG_ACTION_PARENT: ${parent_id}"; then
            continue
        fi

        # Используем awk для парсинга блоков метаданных
        local items; items=$(echo "$content" | awk -v parent="$parent_id" ' 
            BEGIN { RS = ""; FS = "\n" } 
            {
                parent_match = 0
                title = ""
                order = "999"
                cmd = ""

                for (i = 1; i <= NF; i++) {
                    if ($i ~ /^# TG_ACTION_PARENT:[[:space:]]*/) {
                        gsub(/^# TG_ACTION_PARENT:[[:space:]]*/, "", $i)
                        if ($i == parent) {
                            parent_match = 1
                        }
                    }
                    if ($i ~ /^# TG_ACTION_TITLE:[[:space:]]*/) {
                        gsub(/^# TG_ACTION_TITLE:[[:space:]]*/, "", $i)
                        title = $i
                    }
                    if ($i ~ /^# TG_ACTION_ORDER:[[:space:]]*/) {
                        gsub(/^# TG_ACTION_ORDER:[[:space:]]*/, "", $i)
                        order = $i
                    }
                    if ($i ~ /^# TG_ACTION_CMD:[[:space:]]*/) {
                        gsub(/^# TG_ACTION_CMD:[[:space:]]*/, "", $i)
                        cmd = $i
                    }
                }

                if (parent_match && title != "" && cmd != "") {
                    # Формат callback_data: "exec:команда".
                    # Двоеточия в команде заменяем на другой символ, чтобы не было конфликтов.
                    gsub(/:/, ";", cmd)
                    print order " | " title " | exec:" cmd
                }
            }
        ')
        
        if [[ -n "$items" ]]; then
            while IFS= read -r item; do
                menu_items+=("$item")
            done <<< "$items"
        fi
    done < <(find "${SCRIPT_DIR}/modules" "${SCRIPT_DIR}/plugins" -name "*.sh")

    if [ ${#menu_items[@]} -eq 0 ]; then
        echo ""
        return
    fi
    
    # Сортируем массив по номеру (первое поле)
    local IFS=$'\n'
    local sorted_items; sorted_items=($(sort -n <<<"${menu_items[*]}"))
    unset IFS

    # Строим JSON
    local json='{"inline_keyboard":['
    local row=""
    local count=0
    
    for item in "${sorted_items[@]}"; do
        local title; title=$(echo "$item" | cut -d'|' -f2 | xargs)
        local callback; callback=$(echo "$item" | cut -d'|' -f3 | xargs)
        
        # Экранируем кавычки в названии кнопки
        title=${title//\"/\\\"}

        # Каждая кнопка - в новой строке для лучшей читаемости на мобильных
        row="[{\"text\":\"$title\",\"callback_data\":\"$callback\"}]"
        
        if [[ "$count" -gt 0 ]]; then
            json+=,"
        fi
        json+="$row"
        count=$((count + 1))
    done

    json+=']}'
    echo "$json"
}
