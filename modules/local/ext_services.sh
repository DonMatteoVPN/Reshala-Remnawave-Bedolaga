#!/bin/bash
# ============================================================ #
# ==         МОДУЛЬ: СТОРОННИЕ СЕРВИСЫ И СКРИПТЫ            == #
# ============================================================ #
#
# Этот модуль — личный гараж с инструментами. Храни тут любые
# сторонние bash-скрипты: они запускаются в пару кликов.
#
# Как добавить СВОЙ скрипт прямо в код (постоянно):
#   В функцию _ext_seed_defaults() добавь строку вида:
#   _ext_save_entry "Имя скрипта" "команда для запуска"
#   Например:
#   _ext_save_entry "Мой тест" "bash <(curl -sL https://example.com/test.sh)"
#
# Через меню: Войди в модуль -> [+] Добавить -> введи имя и команду.
#
# @menu.manifest
# @item( local_care | 7 | 🧩 Сторонние сервисы | show_ext_services_menu | 70 | 3 | Коллекция внешних диагностических скриптов. Управляй, добавляй, сортируй. )
#

[[ "${BASH_SOURCE[0]}" == "${0}" ]] && exit 1 # Защита от прямого запуска

# ============================================================ #
#                  КОНФИГУРАЦИЯ И ХРАНИЛИЩЕ                    #
# ============================================================ #

_EXT_DB_DIR="/etc/reshala/ext_services"
_EXT_DB_FILE="${_EXT_DB_DIR}/scripts.db"

# Инициализирует директорию и файл БД при первом запуске
_ext_init() {
    if [[ ! -d "$_EXT_DB_DIR" ]]; then
        run_cmd mkdir -p "$_EXT_DB_DIR"
    fi
    if [[ ! -f "$_EXT_DB_FILE" ]]; then
        run_cmd touch "$_EXT_DB_FILE"
        _ext_seed_defaults
    fi
}

# Формат каждой строки в БД:
#   ORDER|NAME|COMMAND
# ORDER — число для сортировки (10, 20, 30...)

# Добавляет запись в БД
_ext_save_entry() {
    local name="$1"
    local cmd="$2"
    local next_order
    next_order=$(( $(_ext_get_max_order) + 10 ))
    echo "${next_order}|${name}|${cmd}" | run_cmd tee -a "$_EXT_DB_FILE" > /dev/null
}

# Возвращает максимальный ORDER из БД (для авто-нумерации)
_ext_get_max_order() {
    if [[ ! -f "$_EXT_DB_FILE" ]] || [[ ! -s "$_EXT_DB_FILE" ]]; then
        echo "0"
        return
    fi
    awk -F'|' '{print $1}' "$_EXT_DB_FILE" | sort -n | tail -1
}

# Возвращает количество записей
_ext_count() {
    if [[ ! -f "$_EXT_DB_FILE" ]]; then echo "0"; return; fi
    grep -c '|' "$_EXT_DB_FILE" 2>/dev/null || echo "0"
}

# Возвращает отсортированный список строк (ORDER|NAME|COMMAND)
_ext_get_sorted() {
    if [[ ! -f "$_EXT_DB_FILE" ]]; then return; fi
    sort -t'|' -k1,1n "$_EXT_DB_FILE"
}

# Получить поле по индексу (1-based, из отсортированного списка)
_ext_get_by_index() {
    local idx="$1"
    _ext_get_sorted | sed -n "${idx}p"
}

# Удалить запись по индексу
_ext_delete_by_index() {
    local idx="$1"
    local line
    line=$(_ext_get_by_index "$idx")
    if [[ -z "$line" ]]; then return 1; fi
    # Экранируем спецсимволы для sed
    local escaped_line
    escaped_line=$(echo "$line" | sed 's/[\/&]/\\&/g')
    run_cmd sed -i "/${escaped_line}/d" "$_EXT_DB_FILE"
}

# ============================================================ #
#                  ВСТРОЕННЫЕ (ПРЕДУСТАНОВЛЕННЫЕ) СКРИПТЫ      #
# ============================================================ #
# Эти скрипты добавляются ТОЛЬКО при первом запуске (создании БД).
# Если ты хочешь сбросить к дефолтам — удали файл $_EXT_DB_FILE.

_ext_seed_defaults() {
    _ext_save_entry "🌐 Проверка IP на блокировки (Check.Place)" \
        "bash <(curl -Ls IP.Check.Place) -l en"

    _ext_save_entry "📸 Проверка блокировки аудио в Instagram" \
        "bash <(curl -L -s https://bench.openode.xyz/checker_inst.sh)"

    _ext_save_entry "⚡ YABS (Диск + Сеть + GeekBench)" \
        "curl -sL yabs.sh | bash -s -- -4"

    _ext_save_entry "🗺️  IP Region — регион по IP (v1)" \
        "bash <(wget -qO - https://github.com/vernette/ipregion/raw/master/ipregion.sh)"

    _ext_save_entry "🗺️  IP Region — регион по IP (v2 улучшенный)" \
        "bash <(wget -qO- https://ipregion.xyz)"

    _ext_save_entry "🔒 CensorCheck — проверка блокировки по DPI (RU)" \
        "bash <(wget -qO- https://github.com/vernette/censorcheck/raw/master/censorcheck.sh) --mode dpi"

    _ext_save_entry "🖥️  SysBench — нагрузочный тест CPU (1 поток)" \
        "sysbench cpu run --threads=1"
}

# ============================================================ #
#                       МЕНЮ: ЗАПУСК СКРИПТА                   #
# ============================================================ #

_ext_run_script() {
    local idx="$1"
    local entry
    entry=$(_ext_get_by_index "$idx")
    local name; name=$(echo "$entry" | cut -d'|' -f2)
    local cmd;  cmd=$(echo "$entry"  | cut -d'|' -f3-)

    clear
    menu_header "🚀 Запуск: ${name}"
    echo ""
    printf_info "Команда: ${C_CYAN}${cmd}${C_RESET}"
    echo ""
    printf_warning "Скрипт запускается от имени root. Убедись, что доверяешь источнику."
    echo ""

    if ! ask_yes_no "Запустить? (y/n): " "y"; then
        return
    fi

    echo ""
    print_separator "=" 60
    eval "$cmd"
    print_separator "=" 60
    echo ""
    wait_for_enter
}

# ============================================================ #
#                       МЕНЮ: ДОБАВЛЕНИЕ                       #
# ============================================================ #

_ext_add_script() {
    clear
    menu_header "➕ Добавить сторонний скрипт"
    echo ""
    printf_info "Введи название и команду для запуска нового скрипта."
    printf_description "Название будет отображаться в меню."
    echo ""

    local name
    name=$(ask_non_empty "  Название скрипта" "") || return

    echo ""
    printf_info "Примеры команд:"
    echo -e "    ${C_GRAY}bash <(curl -sL https://example.com/script.sh)"
    echo -e "    wget -qO- https://bench.sh | bash"
    echo -e "    sysbench cpu run --threads=4${C_RESET}"
    echo ""

    local cmd
    cmd=$(ask_non_empty "  Команда для запуска" "") || return

    _ext_save_entry "$name" "$cmd"
    printf_ok "Скрипт '${name}' успешно добавлен!"
    sleep 1
}

# ============================================================ #
#                       МЕНЮ: РЕДАКТИРОВАНИЕ                   #
# ============================================================ #

_ext_edit_script() {
    local idx="$1"
    local entry
    entry=$(_ext_get_by_index "$idx")
    local order; order=$(echo "$entry" | cut -d'|' -f1)
    local name;  name=$(echo "$entry"  | cut -d'|' -f2)
    local cmd;   cmd=$(echo "$entry"   | cut -d'|' -f3-)

    clear
    menu_header "✏️  Редактирование: ${name}"
    echo ""
    printf_info "Текущее название: ${C_WHITE}${name}${C_RESET}"
    printf_info "Текущая команда: ${C_WHITE}${cmd}${C_RESET}"
    echo ""

    local new_name
    new_name=$(safe_read "  Новое название (Enter = без изменений)" "$name") || return
    [[ -z "$new_name" ]] && new_name="$name"

    local new_cmd
    new_cmd=$(safe_read "  Новая команда (Enter = без изменений)" "$cmd") || return
    [[ -z "$new_cmd" ]] && new_cmd="$cmd"

    # Удаляем старую запись и создаём новую с тем же ORDER
    _ext_delete_by_index "$idx"
    echo "${order}|${new_name}|${new_cmd}" | run_cmd tee -a "$_EXT_DB_FILE" > /dev/null

    printf_ok "Скрипт успешно обновлён."
    sleep 1
}

# ============================================================ #
#                       МЕНЮ: УДАЛЕНИЕ                         #
# ============================================================ #

_ext_delete_script() {
    local idx="$1"
    local entry
    entry=$(_ext_get_by_index "$idx")
    local name; name=$(echo "$entry" | cut -d'|' -f2)

    echo ""
    printf_warning "Ты собираешься удалить: ${C_RED}${name}${C_RESET}"
    if ask_yes_no "  Точно удалить? (y/n): " "n"; then
        _ext_delete_by_index "$idx"
        printf_ok "Скрипт '${name}' удалён."
    else
        info "Отмена."
    fi
    sleep 1
}

# ============================================================ #
#                       МЕНЮ: СОРТИРОВКА                       #
# ============================================================ #

_ext_sort_menu() {
    enable_graceful_ctrlc
    while true; do
        clear
        menu_header "🔀 Сортировка скриптов"
        printf_description "Измени порядок скриптов. Числа ORDER — их приоритет (меньше = выше)."
        echo ""

        local count; count=$(_ext_count)
        if [[ "$count" -eq 0 ]]; then
            printf_warning "Список пуст. Нечего сортировать."
            wait_for_enter
            break
        fi

        local i=1
        while IFS='|' read -r order name _; do
            printf "   ${C_GRAY}[%d]${C_RESET} ${C_WHITE}%-40s${C_RESET} ${C_GRAY}(порядок: %d)${C_RESET}\n" "$i" "$name" "$order"
            ((i++))
        done < <(_ext_get_sorted)

        echo ""
        printf_info "Введи: ${C_CYAN}ПЕРЕМЕЩАЕМЫЙ_НОМЕР НОВЫЙ_ПОРЯДОК${C_RESET} или [b] для выхода"
        printf_description "Например: '3 5' — скрипт #3 получит порядок 5, список перестроится."
        echo ""

        local input
        input=$(safe_read "Твой выбор" "") || break
        [[ "$input" == "b" || "$input" == "B" ]] && break

        local move_idx new_order
        move_idx=$(echo "$input" | awk '{print $1}')
        new_order=$(echo "$input" | awk '{print $2}')

        if [[ ! "$move_idx" =~ ^[0-9]+$ ]] || [[ ! "$new_order" =~ ^[0-9]+$ ]]; then
            err "Введи два числа через пробел."; sleep 1; continue
        fi

        if [[ "$move_idx" -lt 1 || "$move_idx" -gt "$count" ]]; then
            err "Номер скрипта вне диапазона (1-${count})."; sleep 1; continue
        fi

        local entry
        entry=$(_ext_get_by_index "$move_idx")
        local name; name=$(echo "$entry" | cut -d'|' -f2)
        local cmd;  cmd=$(echo "$entry"  | cut -d'|' -f3-)

        _ext_delete_by_index "$move_idx"
        echo "${new_order}|${name}|${cmd}" | run_cmd tee -a "$_EXT_DB_FILE" > /dev/null
        printf_ok "Порядок скрипта '${name}' изменён на ${new_order}."
        sleep 1
    done
    disable_graceful_ctrlc
}

# ============================================================ #
#                     ГЛАВНОЕ МЕНЮ МОДУЛЯ                      #
# ============================================================ #

show_ext_services_menu() {
    _ext_init
    enable_graceful_ctrlc

    while true; do
        clear
        menu_header "🧩 Сторонние сервисы и скрипты"
        printf_description "Коллекция внешних утилит. Запускай в одно нажатие."
        echo ""

        local count; count=$(_ext_count)

        if [[ "$count" -eq 0 ]]; then
            printf_warning "Список скриптов пуст. Добавь первый с помощью [+]."
            echo ""
        else
            # Вывод пронумерованного меню из БД
            local i=1
            while IFS='|' read -r _ name _; do
                printf_menu_option "$i" "$name"
                ((i++))
            done < <(_ext_get_sorted)
            echo ""
        fi

        print_separator "-" 60
        printf_menu_option "+" "✅ Добавить новый скрипт"
        if [[ "$count" -gt 0 ]]; then
            printf_menu_option "e" "✏️  Редактировать скрипт"
            printf_menu_option "d" "🗑️  Удалить скрипт"
            printf_menu_option "s" "🔀 Сортировка / Изменить порядок"
        fi
        echo ""
        printf_menu_option "b" "🔙 Назад"
        print_separator "-" 60
        echo ""

        local choice
        choice=$(safe_read "Твой выбор" "") || break

        case "$choice" in
            +)
                _ext_add_script ;;
            e)
                if [[ "$count" -eq 0 ]]; then err "Список пуст."; sleep 1; continue; fi
                local idx
                idx=$(ask_number_in_range "  Номер скрипта для редактирования" 1 "$count" "") || continue
                _ext_edit_script "$idx" ;;
            d)
                if [[ "$count" -eq 0 ]]; then err "Список пуст."; sleep 1; continue; fi
                local idx
                idx=$(ask_number_in_range "  Номер скрипта для удаления" 1 "$count" "") || continue
                _ext_delete_script "$idx" ;;
            s)
                if [[ "$count" -eq 0 ]]; then err "Список пуст."; sleep 1; continue; fi
                _ext_sort_menu ;;
            [bB])
                break ;;
            *)
                if [[ "$choice" =~ ^[0-9]+$ ]] && [[ "$choice" -ge 1 ]] && [[ "$choice" -le "$count" ]]; then
                    _ext_run_script "$choice"
                else
                    err "Неверный выбор."; sleep 1
                fi ;;
        esac
    done
    disable_graceful_ctrlc
}
