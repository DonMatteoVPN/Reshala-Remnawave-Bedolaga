#!/bin/bash
# ============================================================ #
# ==           CORE: ГЕНЕРАТОР ДИНАМИЧЕСКОГО МЕНЮ v3.0        == #
# ============================================================ #
#
# Новая, переработанная версия генератора меню.
# Сканирует все *.sh файлы в проекте на наличие блока-манифеста
# "@menu.manifest" и строит на его основе все меню в системе.
# Результаты сканирования кэшируются в памяти при первом вызове.
#
[[ "${BASH_SOURCE[0]}" == "${0}" ]] && exit 1 # Защита от прямого запуска

# ============================================================ #
#                  ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ И КЭШ                 #
# ============================================================ #

# Флаг, который показывает, было ли уже проведено сканирование.
# 0 = нет, 1 = да.
_MENU_SYSTEM_SCANNED=0

# Ассоциативные массивы для хранения полной структуры меню.
# Ключ - уникальный ID в формате "РОДИТЕЛЬ|КЛАВИША".
declare -A _MENU_ITEMS_PARENT
declare -A _MENU_ITEMS_KEY
declare -A _MENU_ITEMS_TITLE
declare -A _MENU_ITEMS_ACTION
declare -A _MENU_ITEMS_ORDER
declare -A _MENU_ITEMS_GROUP
declare -A _MENU_ITEMS_DESC

# ============================================================ #
#                  СИСТЕМНЫЕ ФУНКЦИИ (ВНУТРЕННИЕ)              #
# ============================================================ #

#
# _parse_manifest_file <file_path> <action_prefix>
#
# Внутренний парсер одного файла.
# - file_path: Полный путь к файлу для парсинга.
# - action_prefix: Префикс, который добавляется к имени функции,
#   чтобы создать исполняемую команду. Для модулей это "run_module ...".
#
_parse_manifest_file() {
    local file="$1"
    local action_prefix="$2"
    debug_log "PARSER: Processing file: $file"

    # Проверяем, есть ли в файле наш маркер манифеста. Если нет, выходим.
    if ! grep -q -m 1 "@menu.manifest" "$file"; then
        debug_log "PARSER: Manifest marker NOT FOUND in $file"
        return
    fi
    debug_log "PARSER: Manifest marker FOUND in $file"

    # Основная магия парсинга с помощью awk.
    # Конструкция 'while ... done < <(awk...)' используется, чтобы избежать
    # создания subshell, в котором терялись бы значения переменных.
    local awk_script='
    function trim(s) {
        sub(/^[[:space:]]+/, "", s);
        sub(/[[:space:]]+$/, "", s);
        return s;
    }
    /^[[:space:]]*# @[iI][tT][eE][mM]\(/{ # Матчим полную строку, начинающуюся с # @item(
        line = $0;
        # Удаляем префикс "# @item(" и конечную ")"
        sub(/^[[:space:]]*# @[iI][tT][eE][mM]\(/, "", line);
        sub(/\)[[:space:]]*$/, "", line);
        
        # Разделяем строку по разделителю "|" с опциональными пробелами
        split(line, fields, /[[:space:]]*[|][[:space:]]*/);
        
        # Выводим 7 полей, разделяя их непечатаемым символом-разграничителем (\x1F)
        # Убеждаемся, что всегда выводим 7 полей, даже если некоторые пусты
        printf "%s\x1F%s\x1F%s\x1F%s\x1F%s\x1F%s\x1F%s\n", trim(fields[1]), trim(fields[2]), trim(fields[3]), trim(fields[4]), trim(fields[5]), trim(fields[6]), trim(fields[7]);
    }'

    while IFS=$'\x1F' read -r parent key title func order group desc; do
        # Пропускаем некорректно заполненные строки
        if [[ -z "$parent" || -z "$key" || -z "$title" || -z "$func" ]]; then
            continue
        fi
        
        local item_id="${parent}|${key}"
        local full_action
        
        # Собираем полную команду для выполнения.
        # Если префикс задан (для модулей), добавляем его.
        if [[ -n "$action_prefix" ]]; then
            full_action="${action_prefix} ${func}"
        else
            full_action="$func" # Для локальных функций в reshala.sh
        fi

        # Заполняем кэш-массивы
        _MENU_ITEMS_PARENT["$item_id"]="$parent"
        _MENU_ITEMS_KEY["$item_id"]="$key"
        _MENU_ITEMS_TITLE["$item_id"]="$title"
        _MENU_ITEMS_ACTION["$item_id"]="$full_action"
        _MENU_ITEMS_ORDER["$item_id"]="${order:-999}"
        _MENU_ITEMS_GROUP["$item_id"]="${group:-999}"
        _MENU_ITEMS_DESC["$item_id"]="$desc"
    done < <(awk "$awk_script" "$file")
}


#
# _scan_and_build_menu_cache
#
# Главная функция-сканер. Выполняется только один раз.
#
_scan_and_build_menu_cache() {
    _MENU_SYSTEM_SCANNED=1

    # 1. Сканируем главный файл reshala.sh.
    # Действия из него будут вызываться напрямую, без префикса.
    _parse_manifest_file "${SCRIPT_DIR}/reshala.sh" ""

    # 2. Сканируем все модули в папке /modules.
    while IFS= read -r file; do
        # Вычисляем относительный путь для команды "run_module"
        # Например: /path/to/project/modules/skynet/menu.sh -> skynet/menu
        local module_path_for_run_module="${file#${SCRIPT_DIR}/modules/}"
        module_path_for_run_module="${module_path_for_run_module%.sh}"
        
        # Вызываем парсер с префиксом для действия
        _parse_manifest_file "$file" "run_module ${module_path_for_run_module}"

    done < <(find "${SCRIPT_DIR}/modules" -name "*.sh")
}


# ============================================================ #
#                  ПУБЛИЧНЫЕ ФУНКЦИИ (API)                     #
# ============================================================ #

#
# render_menu_items <parent_id>
#
# Отрисовывает меню для указанного родителя.
#
render_menu_items() {
    local parent_id="$1"

    # Если кэш пуст, заполняем его
    if [[ "$_MENU_SYSTEM_SCANNED" -eq 0 ]]; then
        _scan_and_build_menu_cache
    fi

    local items_to_render=()
    # Собираем ID всех дочерних элементов
    for item_id in "${!_MENU_ITEMS_PARENT[@]}"; do
        if [[ "${_MENU_ITEMS_PARENT[$item_id]}" == "$parent_id" ]]; then
            # Формат "ГРУППА:ПОРЯДОК:ID" для мульти-сортировки
            items_to_render+=( "${_MENU_ITEMS_GROUP[$item_id]}:${_MENU_ITEMS_ORDER[$item_id]}:${item_id}" )
        fi
    done

    # Сортируем: сначала по номеру группы, потом по номеру порядка
    IFS=$'\n' sorted_items=($(sort -t: -k1,1n -k2,2n <<<"${items_to_render[*]}"))
    unset IFS

    local prev_group_id=""
    # Перебираем отсортированные ID и выводим меню
    for sorted_id in "${sorted_items[@]}"; do
        local item_id="${sorted_id#*:*:}"
        
        local key="${_MENU_ITEMS_KEY[$item_id]}"
        
        # Фильтр для режима агента: не показывать управление флотом внутри агента
        if [[ "${SKYNET_MODE:-0}" -eq 1 && "$key" == "0" && "$parent_id" == "main" ]]; then
            continue
        fi

        local title="${_MENU_ITEMS_TITLE[$item_id]}"
        local desc="${_MENU_ITEMS_DESC[$item_id]}"
        local current_group_id="${_MENU_ITEMS_GROUP[$item_id]}"

        # Печатаем разделитель, если группа сменилась
        if [[ -n "$prev_group_id" && "$current_group_id" != "$prev_group_id" && "$prev_group_id" != "999" ]]; then
            echo ""
        fi

        # Подставляем переменные цвета в название
        eval "title=\"$title\""
        
        printf_menu_option "$key" "$title"
        if [[ -n "$desc" ]]; then
            printf_description "${C_GRAY}${desc}${C_RESET}"
        fi
        
        prev_group_id="$current_group_id"
    done
}

#
# get_menu_action <parent_id> <key>
#
# Возвращает исполняемую команду для выбранного пункта меню.
#
get_menu_action() {
    local parent_id="$1"
    local key="$2"
    local item_id="${parent_id}|${key}"
    
    echo "${_MENU_ITEMS_ACTION[$item_id]:-}"
}

#
# get_key_for_menu_action <target_function> [parent_id]
#
# Ищет в кэше меню и возвращает КЛАВИШУ для первого найденного
# пункта, который вызывает указанную функцию. 
# Опционально можно фильтровать по ID родительского меню.
#
get_key_for_menu_action() {
    local target_func="$1"
    local parent_filter="${2:-}"

    # Убедимся, что кэш меню построен
    if [[ "$_MENU_SYSTEM_SCANNED" -eq 0 ]]; then
        _scan_and_build_menu_cache
    fi

    # Перебираем все известные пункты меню
    for item_id in "${!_MENU_ITEMS_ACTION[@]}"; do
        local action="${_MENU_ITEMS_ACTION[$item_id]}"
        local parent="${_MENU_ITEMS_PARENT[$item_id]}"
        local func_name="${action##* }"

        if [[ "$func_name" == "$target_func" ]]; then
            if [[ -n "$parent_filter" && "$parent" != "$parent_filter" ]]; then
                continue
            fi
            
            echo "${_MENU_ITEMS_KEY[$item_id]}"
            return 0
        fi
    done

    echo "?"
    return 1
}
