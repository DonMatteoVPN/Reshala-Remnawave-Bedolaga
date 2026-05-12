#!/bin/bash
# Подключаем генератор меню, чтобы иметь доступ к его функциям и кэшу
source "${SCRIPT_DIR}/modules/core/menu_generator.sh"

# ============================================================ #
# ==             МОДУЛЬ ИНФОРМАЦИОННОЙ ПАНЕЛИ               == #
# ============================================================ #
#
# Этот модуль — твои глаза. Он собирает всю инфу о системе
# и красиво её отрисовывает. Теперь с поддержкой виджетов!
#
[[ "${BASH_SOURCE[0]}" == "${0}" ]] && exit 1 # Защита от прямого запуска

# ============================================================ #
#          БЛОК СБОРА ИНФОРМАЦИИ О СИСТЕМЕ И ЖЕЛЕЗЕ           #
# ============================================================ #
# Здесь собраны все функции, которые выдёргивают сырые данные
# о системе и железе для дашборда. Не трогаем поведение без
# серьёзной причины: на них завязаны почти все экраны.

_get_os_ver() { grep -oP 'PRETTY_NAME="\K[^\"]+' /etc/os-release 2>/dev/null || echo "Linux"; }
_get_kernel() { uname -r | cut -d'-' -f1; }
_get_uptime() { uptime -p | sed 's/up //;s/ hours\?,/ч/;s/ minutes\?/мин/;s/ days\?,/д/;s/ weeks\?,/нед/'; }
_get_virt_type() {
    local virt_output; virt_output=$(systemd-detect-virt 2>/dev/null || echo "unknown")
    local virt_type_clean; virt_type_clean=$(echo "$virt_output" | head -n1 | tr -d '\n' | xargs)
    local result=""

    case "$virt_type_clean" in
        kvm|qemu) result="KVM (Честное железо)" ;;
        lxc|openvz) result="Container (${virt_type_clean^}) - ⚠️ Хуйня в контейнере (Беги отсюда)" ;; 
        none) result="Физический сервер (Дед)" ;;
        *) result="${virt_type_clean^}" ;;
    esac
    echo "$result" | tr -d '\n' | xargs # Ensure final output is single line
}
_get_public_ip() { curl -s --connect-timeout 4 -4 ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}'; }
_get_location() {
    local out
    out=$(curl -s --connect-timeout 2 ipinfo.io/country 2>/dev/null || true)
    # ipinfo в случае ошибки может вернуть JSON с Rate limit. Нас это не интересует.
    if [[ "$out" =~ ^[A-Z]{2}$ ]]; then
        echo "$out"
    else
        echo "??"
    fi
}
_get_hoster_info() {
    local out
    out=$(curl -s --connect-timeout 5 ipinfo.io/org 2>/dev/null || true)
    # Если пришёл JSON/ошибка (Rate limit и т.п.) — не светим мусор, просто "Не определён".
    if [[ "$out" == "" ]] || [[ "$out" == \{* ]]; then
        echo "Не определён"
    else
        echo "$out"
    fi
}
_get_active_users() { who | cut -d' ' -f1 | sort -u | wc -l; }
_get_ping_google() {
    local p; p=$(ping -c 1 -W 1 8.8.8.8 2>/dev/null | grep 'time=' | awk -F'time=' '{print $2}' | cut -d' ' -f1)
    [[ -z "$p" ]] && echo "OFFLINE ❌" || echo "${p} ms ⚡"
}

_get_cpu_info_clean() {
    local model; model=$(grep -m1 "model name" /proc/cpuinfo | cut -d: -f2 | sed 's/(R)//g; s/(TM)//g; s/ @.*//g; s/CPU//g' | xargs)
    [[ -z "$model" ]] && model=$(lscpu | grep "Model name" | sed -r 's/.*:\s+//' | sed 's/ @.*//')
    echo "$model" | cut -c 1-35 # Обрезаем, чтобы не ломать вёрстку
}

_draw_bar() {
    local perc=$1; local size=10
    local bar_perc=$perc; [[ "$bar_perc" -gt 100 ]] && bar_perc=100
    local color="${C_GREEN}"; [[ "$perc" -ge 70 ]] && color="${C_YELLOW}"; [[ "$perc" -ge 90 ]] && color="${C_RED}"
    # Use the new helper to get the bar string
    get_progress_bar_string "$bar_perc" "$size" "$color" "${C_GRAY}"
}

_get_cpu_load_visual() {
    # Для локального запуска считаем по /proc/stat, для SKYNET-агента — по loadavg, чтобы не мешать панели.
    local cores; cores=$(nproc 2>/dev/null || echo 1)

    # В режиме SKYNET_MODE=1 (агент на удалённом сервере) берём 1-минутный loadavg
    # и приводим его к процентам относительно числа vCore.
    if [ "${SKYNET_MODE:-0}" -eq 1 ]; then
        local load1
        load1=$(awk '{print $1}' /proc/loadavg 2>/dev/null || echo 0)
        local perc
        perc=$(awk -v l="$load1" -v c="$cores" 'BEGIN {
            if (c <= 0) c = 1;
            p = (l / c) * 100;
            if (p < 0) p = 0;
            if (p > 100) p = 100;
            printf "%.0f", p;
        }')
        local bar; bar=$(_draw_bar "$perc")
        echo "$bar (${perc}% / ${cores} vCore)"
        return
    fi

    # Локальный режим: более честная оценка загрузки CPU через /proc/stat
    local cpu_line1 cpu_line2
    cpu_line1=$(grep '^cpu ' /proc/stat 2>/dev/null)
    sleep 0.2
    cpu_line2=$(grep '^cpu ' /proc/stat 2>/dev/null)

    if [[ -z "$cpu_line1" || -z "$cpu_line2" ]]; then
        echo "N/A"
        return
    fi

    local _ user1 nice1 system1 idle1 iowait1 irq1 softirq1 steal1 guest1 guest_nice1
    local user2 nice2 system2 idle2 iowait2 irq2 softirq2 steal2 guest2 guest_nice2

    read -r _ user1 nice1 system1 idle1 iowait1 irq1 softirq1 steal1 guest1 guest_nice1 <<<"$cpu_line1"
    read -r _ user2 nice2 system2 idle2 iowait2 irq2 softirq2 steal2 guest2 guest_nice2 <<<"$cpu_line2"

    local idle_all1 idle_all2 non_idle1 non_idle2 total1 total2 total_delta idle_delta
    idle_all1=$((idle1 + iowait1))
    idle_all2=$((idle2 + iowait2))
    non_idle1=$((user1 + nice1 + system1 + irq1 + softirq1 + steal1))
    non_idle2=$((user2 + nice2 + system2 + irq2 + softirq2 + steal2))
    total1=$((idle_all1 + non_idle1))
    total2=$((idle_all2 + non_idle2))

    total_delta=$((total2 - total1))
    idle_delta=$((idle_all2 - idle_all1))

    local perc=0
    if (( total_delta > 0 )); then
        perc=$(awk "BEGIN {printf \"%.0f\", (1 - $idle_delta / $total_delta) * 100}")
    fi

    if [[ "$perc" -lt 0 ]]; then perc=0; fi
    if [[ "$perc" -gt 100 ]]; then perc=100; fi

    local bar; bar=$(_draw_bar "$perc")
    echo "$bar (${perc}% / ${cores} vCore)"
}

_get_ram_visual() {
    local ram_info; ram_info=$(free -m | grep Mem)
    local ram_used; ram_used=$(echo "$ram_info" | awk '{print $3}')
    local ram_total; ram_total=$(echo "$ram_info" | awk '{print $2}')
    if [ "$ram_total" -eq 0 ]; then echo "N/A"; return; fi
    local perc=$(( 100 * ram_used / ram_total ))
    local bar; bar=$(_draw_bar "$perc")
    local used_str; local total_str
    if [ "$ram_total" -gt 1024 ]; then
        used_str=$(awk "BEGIN {printf \"%.1fG\", $ram_used/1024}")
        total_str=$(awk "BEGIN {printf \"%.1fG\", $ram_total/1024}")
    else
        used_str="${ram_used}M"; total_str="${ram_total}M"
    fi
    echo "$bar ($used_str / $total_str)"
}

_get_disk_visual() {
    local main_disk; main_disk=$(df / | awk 'NR==2 {print $1}' | sed 's|/dev/||' | sed 's/[0-9]*$//' | sed 's/p[0-9]*$//')
    local disk_type="HDD"
    if [ -f "/sys/block/$main_disk/queue/rotational" ] && [ "$(cat "/sys/block/$main_disk/queue/rotational")" -eq 0 ]; then
        disk_type="SSD"; elif [[ "$main_disk" == *"nvme"* ]]; then disk_type="SSD"; fi
    local usage_stats; usage_stats=$(df -h / | awk 'NR==2 {print $3 "/" $2}')
    local perc_str; perc_str=$(df / | awk 'NR==2 {print $5}' | tr -d '%')
    local bar; bar=$(_draw_bar "$perc_str")
    echo "$disk_type|$bar ($usage_stats)"
}

_get_port_speed() {
    local iface; iface=$(ip route | grep default | head -n1 | awk '{print $5}')
    local speed=""

    if [ -n "$iface" ] && [ -f "/sys/class/net/$iface/speed" ]; then
        local raw; raw=$(cat "/sys/class/net/$iface/speed" 2>/dev/null)
        if [[ "$raw" =~ ^[0-9]+$ ]] && [ "$raw" -gt 0 ]; then
            speed="${raw}Mbps"
        fi
    fi

    if [ -z "$speed" ] && command -v ethtool &>/dev/null && [ -n "$iface" ]; then
        speed=$(ethtool "$iface" 2>/dev/null | grep "Speed:" | awk '{print $2}')
    fi

    if [[ -z "$speed" ]] || [[ "$speed" == "Unknown!" ]]; then
        return
    fi

    if [ "$speed" == "1000Mbps" ];  then speed="1 Gbps";  fi
    if [ "$speed" == "10000Mbps" ]; then speed="10 Gbps"; fi
    if [ "$speed" == "2500Mbps" ];  then speed="2.5 Gbps"; fi

    echo "$speed"
}


_get_traffic_limiter_status_string() {
    local config_dir="/etc/reshala/traffic_limiter"
    if ! ls -A "${config_dir}"/*.conf >/dev/null 2>&1; then
        echo ""
        return
    fi
    local status_string=""
    while IFS= read -r file; do
        if [[ -f "$file" ]]; then
            local port; port=$(grep '^PORT=' "$file" | cut -d'=' -f2 | tr -d '"')
            local down; down=$(grep '^DOWN_LIMIT=' "$file" | cut -d'=' -f2 | tr -d '"' | sed 's/mbit//')
            local up; up=$(grep '^UP_LIMIT=' "$file" | cut -d'=' -f2 | tr -d '"' | sed 's/mbit//')
            if [[ -n "$port" && -n "$down" && -n "$up" ]]; then
                status_string+="${port} (${down}/${up}); "
            fi
        fi
    done < <(find "${config_dir}" -name "port-*.conf")
    echo "${status_string%; }"
}

# Кэш для сетевой информации, чтобы не долбить внешние сервисы на каждый кадр
DASHBOARD_NET_CACHE_INITIALIZED=0
DASHBOARD_IP_ADDR=""
DASHBOARD_LOCATION=""
DASHBOARD_HOSTER_INFO=""

# Общий кэш метрик дашборда (легкий TTL, чтобы не дёргать систему при быстрых переходах)
DASHBOARD_CACHE_TS=0

# Профиль нагрузки дашборда: normal / light / ultra_light
# Хранится в конфиге через set_config_var "DASHBOARD_LOAD_PROFILE".
# Если не указан, используем normal.
DASHBOARD_LOAD_PROFILE=$(get_config_var "DASHBOARD_LOAD_PROFILE")
if [[ -z "$DASHBOARD_LOAD_PROFILE" ]]; then
    DASHBOARD_LOAD_PROFILE="normal"
fi

# Базовые TTL берём из конфига (readonly-константы), если они есть
local_base_cache_ttl=${DASHBOARD_CACHE_TTL:-25}
local_base_widget_ttl=${DASHBOARD_WIDGET_CACHE_TTL:-60}

# Множители в зависимости от профиля
case "$DASHBOARD_LOAD_PROFILE" in
    light)
        local_factor=2
        ;;
    ultra_light)
        local_factor=4
        ;;
    *)
        DASHBOARD_LOAD_PROFILE="normal"
        local_factor=1
        ;;
esac

local DASHBOARD_CACHE_TTL_ADJ=$(( local_base_cache_ttl * local_factor ))
local DASHBOARD_WIDGET_CACHE_TTL_ADJ=$(( local_base_widget_ttl * local_factor ))

DASHBOARD_CACHE_OS=""
DASHBOARD_CACHE_KERNEL=""
DASHBOARD_CACHE_UPTIME=""
DASHBOARD_CACHE_USERS=""
DASHBOARD_CACHE_VIRT=""
DASHBOARD_CACHE_CPUINFO=""
DASHBOARD_CACHE_CPULOAD=""
DASHBOARD_CACHE_RAMVIZ=""
DASHBOARD_CACHE_DISKRAW=""

# Кэш для вывода виджетов (через файлы, чтобы не мудрить с eval)
WIDGET_CACHE_DIR="/tmp/reshala_widgets_cache"

# ============================================================ #
#                  ГЛАВНАЯ ФУНКЦИЯ ОТРИСОВКИ                   #
# ============================================================ #
show() {
    clear
    mkdir -p "$WIDGET_CACHE_DIR" 2>/dev/null || true

    # Минимальная ширина колонки для лейблов виджетов.
    # Фактическая ширина будет = max(минимум, максимальный лейбл среди активных виджетов).
    local min_label_width="${DASHBOARD_LABEL_WIDTH:-16}"
    # Оставляем только цифры в начале, остальное отбрасываем
    min_label_width="${min_label_width%%[^0-9]*}"
    if [[ -z "$min_label_width" ]]; then
        min_label_width=16
    fi

    # Обновляем картину мира Remnawave/бота перед отрисовкой панели
    # (модуль state_scanner портирован из старого монолита)
    if command -v run_module &>/dev/null; then
        run_module core/state_scanner scan_remnawave_state
    fi

    # --- Сбор данных ---
    local now_ts; now_ts=$(date +%s)

    # Если кэш протух или ещё не заполнялся — обновляем метрики
    if (( now_ts - ${DASHBOARD_CACHE_TS:-0} >= ${DASHBOARD_CACHE_TTL_ADJ:-3} )); then
        DASHBOARD_CACHE_OS=$(_get_os_ver)
        DASHBOARD_CACHE_KERNEL=$(_get_kernel)
        DASHBOARD_CACHE_UPTIME=$(_get_uptime)
        DASHBOARD_CACHE_USERS=$(_get_active_users)
        DASHBOARD_CACHE_VIRT=$(_get_virt_type)
        DASHBOARD_CACHE_CPUINFO=$(_get_cpu_info_clean)
        DASHBOARD_CACHE_CPULOAD=$(_get_cpu_load_visual)
        DASHBOARD_CACHE_RAMVIZ=$(_get_ram_visual)
        DASHBOARD_CACHE_DISKRAW=$(_get_disk_visual)
        DASHBOARD_CACHE_TS=$now_ts
    fi

    local os_ver="$DASHBOARD_CACHE_OS"; local kernel="$DASHBOARD_CACHE_KERNEL"
    local uptime="$DASHBOARD_CACHE_UPTIME"; local users_online="$DASHBOARD_CACHE_USERS"
    local virt="$DASHBOARD_CACHE_VIRT"

    # Сетевую инфу и данные от внешних сервисов кэшируем, чтобы не грузить систему и не ловить rate limit
    if [[ ${DASHBOARD_NET_CACHE_INITIALIZED:-0} -eq 0 ]]; then
        DASHBOARD_IP_ADDR=$(_get_public_ip)
        DASHBOARD_LOCATION=$(_get_location)
        DASHBOARD_HOSTER_INFO=$(_get_hoster_info)
        DASHBOARD_NET_CACHE_INITIALIZED=1
    fi
    local ip_addr="$DASHBOARD_IP_ADDR"; local location="$DASHBOARD_LOCATION"; local ping=$(_get_ping_google)
    local hoster_info="$DASHBOARD_HOSTER_INFO"

    local cpu_info="$DASHBOARD_CACHE_CPUINFO"
    local cpu_load_viz="$DASHBOARD_CACHE_CPULOAD"
    local ram_viz="$DASHBOARD_CACHE_RAMVIZ"
    local disk_raw="$DASHBOARD_CACHE_DISKRAW"; local disk_type=$(echo "$disk_raw" | cut -d'|' -f1); local disk_viz=$(echo "$disk_raw" | cut -d'|' -f2)
    local port_speed; port_speed=$(_get_port_speed)

    # --- Заголовок ---
    if [ "${SKYNET_MODE:-0}" -eq 1 ]; then
        menu_header "👁️  ПОДКЛЮЧЕН ЧЕРЕЗ SKYNET (УДАЛЕННОЕ УПРАВЛЕНИЕ) 👁️" 64 "${C_RED}"
        print_vertical_line
        print_key_value "Агент Решалы" "${VERSION}" "$min_label_width"
        print_vertical_line
    else
        menu_header "🧠 ИНСТРУМЕНТ «РЕШАЛА» ${VERSION}" 62 "${C_CYAN}"
        print_vertical_line
    fi

    # --- Секция "Система" (жёсткое выравнивание, как в Primer/install_reshala.sh) ---
    print_section_title "СИСТЕМА"
    print_key_value "ОС / Ядро" "$os_ver ($kernel)" "$min_label_width"
    print_key_value "Аптайм" "$uptime (Юзеров: $users_online)" "$min_label_width"
    print_key_value "Виртуалка" "${C_CYAN}$virt${C_RESET}" "$min_label_width"
    print_key_value "IP Адрес" "${C_YELLOW}$ip_addr${C_RESET} ($ping) [${C_CYAN}$location${C_RESET}]" "$min_label_width"
    print_key_value "Хостер" "${C_CYAN}$hoster_info${C_RESET}" "$min_label_width"
    
    print_vertical_line

    # --- Секция "ЖЕЛЕЗО" ---
    print_section_title "ЖЕЛЕЗО"
    print_key_value "CPU Модель" "$cpu_info" "$min_label_width"
    print_key_value "Загрузка CPU" "$cpu_load_viz" "$min_label_width"
    print_key_value "Память (RAM)" "$ram_viz" "$min_label_width"
    print_key_value "Диск ($disk_type)" "$disk_viz" "$min_label_width"
 
    print_vertical_line
    
    # --- Секция "Статус" ---
    print_section_title "STATUS"
 
    # Нормализуем отображение версий, чтобы не было "vlatest(... )" и прочего трэша
    local panel_ver_pretty="" node_ver_pretty="" bot_ver_pretty=""
    if [[ -n "$PANEL_VERSION" ]]; then
        if [[ "$PANEL_VERSION" == latest* ]]; then
            panel_ver_pretty="$PANEL_VERSION"
        else
            panel_ver_pretty="v${PANEL_VERSION}"
        fi
    fi
    if [[ -n "$NODE_VERSION" ]]; then
        if [[ "$NODE_VERSION" == latest* ]]; then
            node_ver_pretty="$NODE_VERSION"
        else
            node_ver_pretty="v${NODE_VERSION}"
        fi
    fi
    if [[ -n "$BOT_VERSION" ]]; then
        if [[ "$BOT_VERSION" == latest* ]]; then
            bot_ver_pretty="$BOT_VERSION"
        else
            bot_ver_pretty="v${BOT_VERSION}"
        fi
    fi
    local sub_ver_pretty=""
    if [[ -n "${SUBPAGE_VERSION:-}" ]]; then
        if [[ "$SUBPAGE_VERSION" == latest* ]]; then
            sub_ver_pretty="$SUBPAGE_VERSION"
        else
            sub_ver_pretty="v${SUBPAGE_VERSION}"
        fi
    fi

    # Remnawave / Нода / Бот (данные даёт state_scanner)
    case "$SERVER_TYPE" in
        "Панель и Нода")
            print_key_value "Remnawave" "${C_GREEN}🔥 COMBO (Панель + Нода)${C_RESET}" "$min_label_width"
            print_key_value "Версии" "P: ${panel_ver_pretty:-?} | N: ${node_ver_pretty:-?}" "$min_label_width"
            ;;
        "Панель, Нода и Sub-page")
            print_key_value "Версии" "P: ${panel_ver_pretty:-?} | N: ${node_ver_pretty:-?} | S: ${sub_ver_pretty:-?}" "$min_label_width"
            ;;
        "Панель + Sub-page")
            print_key_value "Remnawave" "${C_GREEN}Панель (${panel_ver_pretty:-?}) + Sub-page (${sub_ver_pretty:-?})${C_RESET}" "$min_label_width"
            ;;
        "Панель")
            print_key_value "Remnawave" "${C_GREEN}Панель управления${C_RESET} (${panel_ver_pretty:-unknown})" "$min_label_width"
            ;;
        "Нода")
            print_key_value "Remnawave" "${C_GREEN}Боевая Нода${C_RESET} (${node_ver_pretty:-unknown})" "$min_label_width"
            ;;
        "Sub-page и Нода")
            print_key_value "Remnawave" "${C_CYAN}Sub-page (${sub_ver_pretty:-?}) + Нода (${node_ver_pretty:-?})${C_RESET}" "$min_label_width"
            ;;
        "Sub-page подписки")
            print_key_value "Remnawave" "${C_CYAN}Страница подписки (Sub-page)${C_RESET} (${sub_ver_pretty:-unknown})" "$min_label_width"
            ;;
        "Сервак не целка")
            print_key_value "Remnawave" "${C_RED}НЕ НАЙДЕНО / СТОРОННИЙ СОФТ${C_RESET}" "$min_label_width"
            ;;
        *)
            print_key_value "Remnawave" "Не установлена" "$min_label_width"
            ;;
    esac

    if [ "${BOT_DETECTED:-0}" -eq 1 ]; then
        print_key_value "Bedolaga" "${C_CYAN}АКТИВЕН${C_RESET} (${bot_ver_pretty:-unknown})" "$min_label_width"
    fi

    if [[ "$WEB_SERVER" != "Не определён" ]]; then
        print_key_value "Web-Server" "${C_CYAN}$WEB_SERVER${C_RESET}" "$min_label_width"
    fi

    if [[ -n "$port_speed" ]]; then
        print_key_value "Канал (Link)" "${C_BOLD}$port_speed${C_RESET}" "$min_label_width"
    fi

    # === ИЗМЕНЕНИЕ: Порядок отображения изменен ===
    local capacity_display; capacity_display=$(get_config_var "LAST_VPN_CAPACITY")
    if [[ -n "$capacity_display" ]]; then
        print_key_value "Вместимость юзеров" "${C_GREEN}$capacity_display${C_RESET}" "$min_label_width"
    else
        local maintenance_key; maintenance_key=$(get_key_for_menu_action "show_maintenance_menu" "main")
        print_key_value "Вместимость юзеров" "${C_YELLOW}Газуй в спидтест (меню [${maintenance_key}])${C_RESET}" "$min_label_width"
    fi

    local shaper_status; shaper_status=$(_get_traffic_limiter_status_string)
    if [[ -n "$shaper_status" ]]; then
        print_key_value "Шейпер трафика" "${C_GREEN}$shaper_status${C_RESET}" "$min_label_width"
    fi
    # === КОНЕЦ ИЗМЕНЕНИЯ ===

    print_vertical_line

    # ======================================================= #
    # === НОВЫЙ БЛОК: ДИНАМИЧЕСКИЕ ВИДЖЕТЫ С ПЕРЕКЛЮЧАТЕЛЕМ = #
    # ======================================================= #
    local WIDGETS_DIR="${SCRIPT_DIR}/plugins/dashboard_widgets"
    # Получаем список ВКЛЮЧЕННЫХ виджетов из конфига
    local enabled_widgets; enabled_widgets=$(get_config_var "ENABLED_WIDGETS")

    if [ -d "$WIDGETS_DIR" ] && [ -n "$enabled_widgets" ]; then
        local has_visible_widgets=0

        # Сначала собираем все строки виджетов, чтобы вычислить максимальную ширину лейбла
        local -a widget_labels=()
        local -a widget_values=()
        local max_label_len=0
        
        # Проходим по всем файлам в папке виджетов (не требуем +x, запускаем через bash)
        for widget_file in "$WIDGETS_DIR"/*.sh; do
            if [ -f "$widget_file" ]; then
                local widget_name; widget_name=$(basename "$widget_file")
                
                # Проверяем, есть ли имя этого виджета в списке включенных
                if [[ ",$enabled_widgets," == *",$widget_name,"* ]]; then
                    has_visible_widgets=1

                    # Человеко-читаемый заголовок виджета из # TITLE
                    local widget_title
                    widget_title=$(grep -m1 '^# TITLE:' "$widget_file" 2>/dev/null | sed 's/^# TITLE:[[:space:]]*//')
                    if [[ -z "$widget_title" ]]; then
                        widget_title="$widget_name"
                    fi

                    local widget_output=""
                    local cache_file="$WIDGET_CACHE_DIR/${widget_name}.cache"
                    local building_flag="$WIDGET_CACHE_DIR/${widget_name}.building"

                    if [ -f "$cache_file" ]; then
                        # Всегда читаем хоть что-то из кеша, чтобы не было пустоты
                        widget_output=$(cat "$cache_file" 2>/dev/null || true)

                        # Если кеш протух и в фоне ещё не идёт пересборка — запустим её асинхронно
                        local mtime; mtime=$(stat -c %Y "$cache_file" 2>/dev/null || echo 0)
                        if (( now_ts - mtime >= DASHBOARD_WIDGET_CACHE_TTL_ADJ )) && [ ! -f "$building_flag" ]; then
                            (
                                touch "$building_flag" 2>/dev/null || true
                                bash "$widget_file" >"${cache_file}.tmp" 2>/dev/null || true
                                mv -f "${cache_file}.tmp" "$cache_file" 2>/dev/null || true
                                rm -f "$building_flag" 2>/dev/null || true
                            ) &
                        fi
                    else
                        # Кеша ещё нет: запускаем сборку в фоне и выводим аккуратную заглушку
                        widget_output="$widget_title: загрузка..."
                        if [ ! -f "$building_flag" ]; then
                            (
                                touch "$building_flag" 2>/dev/null || true
                                bash "$widget_file" >"${cache_file}.tmp" 2>/dev/null || true
                                mv -f "${cache_file}.tmp" "$cache_file" 2>/dev/null || true
                                rm -f "$building_flag" 2>/dev/null || true
                            ) &
                        fi
                    fi

                    # Разбираем вывод и накапливаем строки для дальнейшей отрисовки
                    while IFS= read -r line; do
                        # Убираем возможные символы CR (\r), чтобы не было артефактов вида "rn" при копипасте
                        line=${line%$'\r'}

                        # Пропускаем полностью пустые строки, чтобы не плодить "║                    :"
                        if [[ -z "$line" ]]; then
                            continue
                        fi

                        local label value
                        if [[ "$line" == *:* ]]; then
                            label=$(echo "$line" | cut -d':' -f1 | xargs)
                            value=$(echo "$line" | cut -d':' -f2- | xargs)
                        else
                            # Если двоеточий нет — считаем, что label = заголовок, value = вся строка
                            label="$widget_title"
                            value="$line"
                        fi

                        if [[ -z "$label" && -z "$value" ]]; then
                            continue
                        fi

                        widget_labels+=("$label")
                        widget_values+=("$value")

                        if (( ${#label} > max_label_len )); then
                            max_label_len=${#label}
                        fi
                    done <<< "$widget_output"
                fi
            fi
        done

        # Если есть хоть один виджет/строка — отрисовываем блок с автоподбором ширины
        if [ $has_visible_widgets -eq 1 ] && [ ${#widget_labels[@]} -gt 0 ]; then
print_vertical_line
            print_section_title "WIDGETS"

            local effective_width=$max_label_len
            if (( effective_width < min_label_width )); then
                effective_width=$min_label_width
            fi

            local idx
            for idx in "${!widget_labels[@]}"; do
                local label="${widget_labels[$idx]}"
                local value="${widget_values[$idx]}"

                print_key_value "$label" "${C_CYAN}$value${C_RESET}" "$effective_width"
            done
        fi
    fi
    # ======================================================= #
    # === КОНЕЦ БЛОКА ВИДЖЕТОВ ================================ #
    # ======================================================= #

    menu_footer 64 "${C_CYAN}"
}
