#!/bin/bash
# ============================================================ #
# ==                МОДУЛЬ ОЧИСТКИ СИСТЕМЫ                  == #
# ============================================================ #
#
# Отвечает за удаление мусора: старых Docker-образов, висячих
# томов, сетей, а также чистку APT-кэша и сломанных репозиториев.
#
#  ( РОДИТЕЛЬ | КЛАВИША | НАЗВАНИЕ | ФУНКЦИЯ | ПОРЯДОК | ГРУППА | ОПИСАНИЕ )
# @menu.manifest
#
#  ( РОДИТЕЛЬ | КЛАВИША | НАЗВАНИЕ | ФУНКЦИЯ | ПОРЯДОК | ГРУППА | ОПИСАНИЕ )
# @menu.manifest
#
# @item( main | 6 | 🧹 Очистка системы ${C_YELLOW}(Мусорка)${C_RESET} | show_cleaner_menu | 40 | 2 | Глубокая очистка Docker, APT, логов и анализатор диска. )
#

[[ "${BASH_SOURCE[0]}" == "${0}" ]] && exit 1 # Защита от прямого запуска

# --- Конфигурация ---
CLEANER_CONF="/etc/reshala/cleaner"
LIMITS_FILE="${CLEANER_CONF}/limits.txt"
[[ ! -d "$CLEANER_CONF" ]] && mkdir -p "$CLEANER_CONF"
[[ ! -f "$LIMITS_FILE" ]] && echo "50M 3" > "$LIMITS_FILE"

# ============================================================ #
#                  ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ                     #
# ============================================================ #

_get_free_space() { df -k / | awk 'NR==2 {print $4}'; }

_human_readable() {
    local size=$1
    if (( size > 1048576 )); then echo "$(awk "BEGIN {printf \"%.2f\", $size/1048576}") ГБ"
    elif (( size > 1024 )); then echo "$(awk "BEGIN {printf \"%.2f\", $size/1024}") МБ"
    else echo "$size КБ"; fi
}

_run_with_diff() {
    local task_name=$1; shift; local space_before; space_before=$(_get_free_space)
    print_separator "-" 60
    printf_info "Запуск: $task_name"
    print_separator "-" 60
    "$@"
    local space_after; space_after=$(_get_free_space); local diff=$(( space_after - space_before ))
    echo ""
    if (( diff > 0 )); then printf_ok "Успешно! Освобождено: $(_human_readable $diff)"
    elif (( diff < 0 )); then printf_warning "Свободного места убавилось (система пишет логи)"
    else printf_info "Мусора не найдено."; fi
    wait_for_enter
}

# --- Операции очистки ---

_clean_docker() {
    if ! command -v docker &>/dev/null; then printf_warning "Docker не установлен."; return; fi
    printf_info "Очистка Docker (system prune)..."
    docker system prune -a --volumes -f
}

_clean_apt() {
    printf_info "Очистка кэша APT..."
    apt-get autoremove -y
    apt-get clean -y
    apt-get autoclean -y
    # Решение проблемы с репозиторием Ookla Speedtest
    local ookla_list="/etc/apt/sources.list.d/ookla_speedtest-cli.list"
    if [ -f "$ookla_list" ]; then
        printf_info "Удаление битого репозитория Ookla..."
        rm -f "$ookla_list" "$ookla_list.save"
    fi
}

_clean_journal() {
    printf_info "Очистка журналов (journalctl)..."
    journalctl --vacuum-time=3d
    journalctl --vacuum-size=100M
}

_clean_tmp() {
    printf_info "Очистка временных файлов (/tmp)..."
    rm -rf /tmp/* /var/tmp/* ~/.cache/* 2>/dev/null || true
}

_clean_snap() {
    if ! command -v snap &>/dev/null; then printf_warning "Snap не установлен."; return; fi
    printf_info "Очистка старых Snap-пакетов..."
    snap set system refresh.retain=2 2>/dev/null || true
    while read -r snapname revision; do
        [[ -n "$snapname" ]] && snap remove "$snapname" --revision="$revision"
    done < <(snap list all 2>/dev/null | awk '/disabled/{print $1, $3}')
}

_clean_all_funcs() {
    _clean_journal
    _clean_apt
    _clean_docker
    _clean_tmp
    _clean_snap
}

# ============================================================ #
#                АНАЛИЗАТОР ДИСКА (ИНТЕРАКТИВ)                 #
# ============================================================ #

_file_interaction() {
    local file=$1; local mode=$2
    while true; do
        clear
        menu_header "📄 Работа с файлом"
        printf_info "Файл: ${C_WHITE}$file${C_RESET}"
        printf_info "Размер: ${C_YELLOW}$(du -sh "$file" | awk '{print $1}')${C_RESET}"
        echo ""
        printf_menu_option "1" "👀 Посмотреть последние 50 строк"
        if [[ "$mode" == "truncate" ]]; then printf_menu_option "2" "${C_RED}🧹 Очистить файл (0 байт)${C_RESET}";
        elif [[ "$mode" == "rm" ]]; then printf_menu_option "2" "${C_RED}🗑️ Удалить навсегда${C_RESET}"; fi
        echo ""
        printf_menu_option "0" "🔙 Назад"
        
        local choice; choice=$(safe_read ">>") || return
        case $choice in
            1) clear; printf_info "Последние 50 строк $file:"; echo ""; if file "$file" | grep -qiE "text|empty"; then tail -n 50 "$file"; else printf_error "Это бинарный файл."; fi; wait_for_enter ;;
            2) if [[ "$mode" == "truncate" ]]; then > "$file"; printf_ok "Файл очищен."; sleep 1; return;
               elif [[ "$mode" == "rm" ]]; then rm -f "$file"; printf_ok "Файл удален."; sleep 1; return; fi ;;
            0) return ;;
        esac
    done
}

_inspect_directory() {
    local dir=$1; local mode=$2
    while true; do
        clear
        menu_header "📁 Анализ папки"
        printf_info "Путь: ${C_WHITE}$dir${C_RESET}"
        echo ""
        du -sh "$dir"/* 2>/dev/null | sort -hr | head -10 > /tmp/reshala_du.txt
        if [ ! -s /tmp/reshala_du.txt ]; then printf_warning "Пусто или нет доступа."; declare -a paths=(); else
            local i=1; declare -a paths; declare -a types
            while read -r line; do
                local size; size=$(echo "$line" | awk '{print $1}'); local fpath; fpath=$(echo "$line" | cut -f2-); local fname; fname=$(basename "$fpath")
                if [ -d "$fpath" ]; then printf "  ${C_YELLOW}[$i]${C_RESET} 📁 ${C_CYAN}%-8s${C_RESET} %s/\n" "$size" "$fname"; types[$i]="dir";
                else printf "  ${C_YELLOW}[$i]${C_RESET} 📄 ${C_GREEN}%-8s${C_RESET} %s\n" "$size" "$fname"; types[$i]="file"; fi
                paths[$i]="$fpath"; ((i++))
            done < /tmp/reshala_du.txt; rm -f /tmp/reshala_du.txt
        fi
        echo ""
        [[ "$mode" == "block" ]] && printf_warning "${C_RED}Только просмотр! Удаление может сломать систему.${C_RESET}"
        printf_info "Введите ${C_YELLOW}НОМЕР${C_RESET} или ${C_CYAN}0${C_RESET} для выхода."
        
        local choice; choice=$(safe_read ">>") || return
        [[ "$choice" == "0" || -z "$choice" ]] && return
        if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -lt "$i" ] && [ "$choice" -gt 0 ]; then
            local target="${paths[$choice]}"; local type="${types[$choice]}"
            [[ "$type" == "dir" ]] && _inspect_directory "$target" "$mode" || _file_interaction "$target" "$mode"
        else printf_error "Неверный ввод."; fi
    done
}

_analyze_disk() {
    while true; do
        clear
        menu_header "🔍 Анализатор диска"
        echo ""
        printf_menu_option "1" "📚 /var/log                 ${C_GRAY}(Логи - очистка)${C_RESET}"
        printf_menu_option "2" "🐳 /var/lib/docker          ${C_GRAY}(Docker - только просмотр)${C_RESET}"
        printf_menu_option "3" "📦 /var/cache/apt           ${C_GRAY}(APT - удаление)${C_RESET}"
        printf_menu_option "4" "🗑️  /tmp                     ${C_GRAY}(Временные - удаление)${C_RESET}"
        printf_menu_option "5" "🌐 /opt/remnawave/logs      ${C_GRAY}(Логи панели)${C_RESET}"
        echo ""
        printf_menu_option "0" "🔙 Назад"
        
        local choice; choice=$(safe_read ">>") || return
        case $choice in
            1) _inspect_directory "/var/log" "truncate" ;;
            2) _inspect_directory "/var/lib/docker" "block" ;;
            3) _inspect_directory "/var/cache/apt" "rm" ;;
            4) _inspect_directory "/tmp" "rm" ;;
            5) _inspect_directory "/opt/remnawave/nginx_logs" "truncate" ;;
            0) return ;;
        esac
    done
}

# ============================================================ #
#                РОТАЦИЯ ЛОГОВ (LOGROTATE)                     #
# ============================================================ #

_lr_create_rule() {
    local target=$1; local size=$2; local count=$3
    local name; name=$(echo "$target" | sed -e 's/\//_/g' -e 's/^_//' -e 's/\*//g' -e 's/\.log//g')
    local file="/etc/logrotate.d/reshala_${name}"

    cat << EOF > "$file"
${target} {
    size ${size}
    rotate ${count}
    missingok
    compress
    delaycompress
    notifempty
    copytruncate
}
EOF
    printf_ok "Правило для $target создано."
}

_lr_auto_scan() {
    local limits; limits=$(cat "$LIMITS_FILE")
    local def_size; def_size=$(echo "$limits" | awk '{print $1}')
    local def_count; def_count=$(echo "$limits" | awk '{print $2}')

    clear
    menu_header "📡 Радар 'диких' логов"
    printf_info "Поиск .log файлов в /opt, /var/log, /root..."
    echo ""

    mapfile -t log_dirs < <(
        find /opt /var/log /root -type f -name "*.log" 2>/dev/null | \
        grep -vE "/var/log/(journal|apt|installer|unattended-upgrades|private)" | \
        xargs -r dirname | sort -u
    )

    if [ ${#log_dirs[@]} -eq 0 ]; then printf_ok "Диких логов не найдено."; wait_for_enter; return; fi

    local i=1; declare -a dirs_arr
    for dir in "${log_dirs[@]}"; do
        local status; if grep -qr "$dir" /etc/logrotate.d/ 2>/dev/null; then status="${C_GREEN}[OK]${C_RESET}"; else status="${C_RED}[ДИКИЙ]${C_RESET}"; fi
        local size; size=$(du -sh "$dir" 2>/dev/null | awk '{print $1}')
        
        # Фиксированное выравнивание для путей (до 45 символов)
        local pad=$((45 - ${#dir}))
        [[ $pad -lt 1 ]] && pad=1
        
        printf "  ${C_YELLOW}[%2s]${C_RESET} %-45s %-8s %b\n" "$i" "$dir" "$size" "$status"
        dirs_arr[$i]=$dir; ((i++))
    done

    echo ""
    printf_info "Введите ${C_YELLOW}НОМЕР${C_RESET}, ${C_YELLOW}all${C_RESET} или ${C_CYAN}0${C_RESET}."
    local choice; choice=$(safe_read ">>") || return
    [[ "$choice" == "0" || -z "$choice" ]] && return

    if [[ "$choice" == "all" ]]; then
        for dir in "${dirs_arr[@]}"; do
            if ! grep -qr "$dir" /etc/logrotate.d/ 2>/dev/null; then _lr_create_rule "${dir}/*.log" "$def_size" "$def_count"; fi
        done
        wait_for_enter; return
    fi

    if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -lt "$i" ]; then
        local target_dir="${dirs_arr[$choice]}"
        _lr_create_rule "${target_dir}/*.log" "$def_size" "$def_count"
        wait_for_enter
    fi
}

_manage_logrotate() {
    while true; do
        local limits; limits=$(cat "$LIMITS_FILE")
        local d_size; d_size=$(echo "$limits" | awk '{print $1}')
        local d_count; d_count=$(echo "$limits" | awk '{print $2}')
        
        clear
        menu_header "🔄 Умная ротация логов"
        printf_description "Авто-архивация тяжелых логов."
        echo ""
        printf_menu_option "1" "🔍 Сканировать на 'дикие' логи"
        printf_menu_option "2" "➕ Добавить путь вручную"
        printf_menu_option "3" "📋 Управление правилами"
        printf_menu_option "4" "⚙️ Лимиты (сейчас: $d_size / $d_count шт.)"
        echo ""
        printf_menu_option "0" "🔙 Назад"

        local choice; choice=$(safe_read ">>") || return
        case $choice in
            1) _lr_auto_scan ;;
            2) local p; p=$(safe_read "Путь (с /*.log)"); [[ -n "$p" ]] && _lr_create_rule "$p" "$d_size" "$d_count"; wait_for_enter ;;
            3) clear; menu_header "Активные правила"; ls /etc/logrotate.d/reshala_* 2>/dev/null; wait_for_enter ;;
            4) 
               local s_num; s_num=$(safe_read "Новый размер в МБ (только число)")
               if [[ ! "$s_num" =~ ^[0-9]+$ ]]; then
                   printf_error "Ошибка: введите целое число!"
                   wait_for_enter; continue
               fi
               
               local c_num; c_num=$(safe_read "Кол-во хранимых копий")
               if [[ ! "$c_num" =~ ^[0-9]+$ ]]; then
                   printf_error "Ошибка: введите целое число!"
                   wait_for_enter; continue
               fi
               
               echo "${s_num}M ${c_num}" > "$LIMITS_FILE"
               printf_ok "Лимиты обновлены: ${s_num}M / ${c_num} шт."
               wait_for_enter
               ;;
            0) return ;;
        esac
    done
}

# ============================================================ #
#                    ГЛАВНОЕ МЕНЮ                              #
# ============================================================ #

show_cleaner_menu() {
    enable_graceful_ctrlc
    while true; do
        clear
        menu_header "🧹 Очистка системы (Мусорка)"
        printf_info "Свободно: ${C_GREEN}$(_human_readable $(_get_free_space))${C_RESET}"
        echo ""
        printf_menu_option "1" "✨ Полная уборка (Все сразу)"
        printf_menu_option "2" "📦 Очистить APT и кэш пакетов"
        printf_menu_option "3" "📚 Очистить системные логи (Journal)"
        printf_menu_option "4" "🐳 Очистить мусор Docker (Prune)"
        printf_menu_option "5" "🗑️  Очистить /tmp и кэш пользователя"
        printf_menu_option "6" "🧩 Очистить старые Snap-пакеты"
        print_separator "-" 60
        printf_menu_option "7" "🔍 Интерактивный Анализатор Диска"
        printf_menu_option "8" "🔄 Умная ротация логов (Logrotate)"
        echo ""
        printf_menu_option "b" "🔙 Назад"
        
        local choice; choice=$(safe_read "Твой выбор") || break
        case "$choice" in
            1) _run_with_diff "ПОЛНАЯ УБОРКА" _clean_all_funcs ;;
            2) _run_with_diff "ОЧИСТКА APT" _clean_apt ;;
            3) _run_with_diff "ОЧИСТКА ЖУРНАЛА" _clean_journal ;;
            4) _run_with_diff "ОЧИСТКА DOCKER" _clean_docker ;;
            5) _run_with_diff "ОЧИСТКА /TMP" _clean_tmp ;;
            6) _run_with_diff "ОЧИСТКА SNAP" _clean_snap ;;
            7) _analyze_disk ;;
            8) _manage_logrotate ;;
            [bB]) break ;;
            *) printf_error "Нет такого пункта." ;;
        esac
    done
    disable_graceful_ctrlc
}

