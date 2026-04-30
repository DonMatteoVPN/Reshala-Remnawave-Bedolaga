#!/bin/bash
# ============================================================ #
# ==             MODULE: TRAFFIC LIMITER v4.0.1             == #
# ==          ENGINE: eBPF + EDT (Earliest Departure)       == #
# ==          SUPPORT: Kernel 5.4+                          == #
# ============================================================ #
#
# Отвечает за современное ограничение скорости с использованием
# eBPF + EDT (Earliest Departure Time). 
# Обеспечивает 0% коллизий, поддержку IPv6 и раздельный лимит DL/UL.
#
# ВЕРСИОНИРОВАНИЕ:
#   v4.0.1 (08.04.2026) - Добавлена поддержка 5.15+, улучшена диагностика,
#                         поиск bpftool и поддержка libbpf strict mode.
#   v4.0.0 (07.04.2026) - Переход на eBPF/EDT, отказ от ifb0/tc-u32.
#
#  ( РОДИТЕЛЬ | КЛАВИША | НАЗВАНИЕ | ФУНКЦИЯ | ПОРЯДОК | ГРУППА | ОПИСАНИЕ )
# @menu.manifest
#
# @item( main | 2 | 🚦 Шейпер трафика ${C_GREEN}(eBPF + EDT)${C_RESET} | show_traffic_limiter_menu | 2 | 0 | Умное ограничение скорости на базе eBPF. )
#

[[ "${BASH_SOURCE[0]}" == "${0}" ]] && exit 1 # Защита от прямого запуска

# Подключаем ядро и зависимости
source "$SCRIPT_DIR/modules/core/common.sh"
source "$SCRIPT_DIR/modules/core/dependencies.sh"
source "$SCRIPT_DIR/modules/security/whitelist_manager.sh"

# ============================================================ #
# ==                  ГЛОБАЛЬНАЯ КОНФИГУРАЦИЯ               == #
# ============================================================ #

readonly TL_MODULE_VERSION="3.2 (HighLoad)"
readonly TL_CONFIG_DIR="/etc/reshala/traffic_limiter"
readonly TL_BPF_SRC_PATH="${SCRIPT_DIR}/modules/local/shaper.bpf.c"
readonly TL_BPF_OBJ_PATH="${TL_CONFIG_DIR}/shaper.bpf.o"
readonly TL_CTRL_PY_PATH="${SCRIPT_DIR}/modules/local/reshala_ctrl.py"
readonly TL_SERVICE_NAME="reshala-traffic-limiter.service"
readonly TL_SERVICE_PATH="/etc/systemd/system/${TL_SERVICE_NAME}"
readonly TL_OLD_APPLY_SCRIPT="/usr/local/bin/reshala-traffic-limiter-apply.sh"
readonly TL_BPF_PIN_DIR="/sys/fs/bpf/reshala"

# Глобальные переменные
IFACE=""

# ============================================================ #
# ==                      ГЛАВНОЕ МЕНЮ                      == #
# ============================================================ #

show_traffic_limiter_menu() {
    local k_major; k_major=$(uname -r | cut -d. -f1)
    local k_minor; k_minor=$(uname -r | cut -d. -f2)
    local kernel_ver=$(uname -r | cut -d- -f1)

    # Правильное сравнение версий: (Major < 5) ИЛИ (Major == 5 И Minor < 4)
    if [[ "$k_major" -lt 5 ]] || [[ "$k_major" -eq 5 && "$k_minor" -lt 4 ]]; then
        clear; menu_header "🚦 Шейпер трафика (eBPF)"
        printf_critical_warning "ОШИБКА: Твое ядро ($kernel_ver) слишком старое для eBPF шейпера (нужно 5.4+)."
        echo
        echo -e "  ${C_CYAN}══════════════════════════════════════════════════════════════${C_RESET}"
        echo -e "  ${C_YELLOW}📋 ТЕХНИЧЕСКИЙ ОТЧЕТ ДЛЯ ПОДДЕРЖКИ:${C_RESET}"
        echo -e "  ${C_CYAN}──────────────────────────────────────────────────────────────${C_RESET}"
        echo -e "  1. Ядро:         $(uname -a)"
        echo -e "  2. Дистрибутив:  $(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)"
        echo -e "  3. Статус BTF:   $(ls -l /sys/kernel/btf/vmlinux 2>/dev/null | awk '{print $1, $9}' || echo 'не найден')"
        echo -e "  4. Конфиг BPF:   $((zgrep CONFIG_BPF /proc/config.gz 2>/dev/null || grep CONFIG_BPF /boot/config-$(uname -r) 2>/dev/null) | grep -E 'CONFIG_BPF_SYSCALL|CONFIG_NET_CLS_BPF' | xargs echo || echo 'недоступен')"
        echo -e "  5. Сетевой стек: $(ip -br link | head -n 3 | xargs echo)..."
        echo -e "  ${C_CYAN}══════════════════════════════════════════════════════════════${C_RESET}"
        echo
        echo -e "  ${C_GREEN}💡 ЧТО ДЕЛАТЬ?${C_RESET}"
        echo -e "  • Твоему серверу нужно обновить ядро до актуальной версии."
        echo -e "  • На Ubuntu/Debian: ${C_WHITE}apt update && apt upgrade -y && reboot${C_RESET}"
        echo -e "  • После перезагрузки ядро должно стать 5.15 или выше."
        echo
        wait_for_enter; return
    fi

    enable_graceful_ctrlc
    while true; do
        clear; menu_header "🚦 Шейпер трафика (eBPF + EDT) v${TL_MODULE_VERSION}"
        local is_active="false"; if systemctl is-active --quiet ${TL_SERVICE_NAME}; then is_active="true"; fi
        local status_icon="${C_GRAY}[∅ Не настроен]${C_RESET}"
        if [[ "$is_active" == "true" ]]; then status_icon="${C_GREEN}[✓ Работает: eBPF активен]${C_RESET}"; fi

        local wl_count=0
        if [[ -f "${TL_CONFIG_DIR}/whitelist.txt" ]]; then
            wl_count=$(grep -v '^\s*#' "${TL_CONFIG_DIR}/whitelist.txt" | grep -v '^\s*$' | wc -l)
        fi
        local wl_status="${C_GRAY}[0]${C_RESET}"
        if [[ "$wl_count" -gt 0 ]]; then wl_status="${C_GREEN}[✓ IP: ${wl_count}]${C_RESET}"; fi

        printf_menu_option "1" "📋 Активные правила ${status_icon}"
        printf_menu_option "2" "📊 Статистика (топ IP по правилам)"
        printf_menu_option "3" "➕ Добавить / изменить правило"
        printf_menu_option "4" "🗑  Удалить правило"
        printf_menu_option "5" "🧹 Полная очистка системы"
        printf_menu_option "6" "📜 Посмотреть лог сервиса"
        printf_menu_option "7" "🔄 Перезапустить движок"
        printf_menu_option "8" "📈 Мониторинг (iftop)"
        printf_menu_option "9" "🛡️  Белый список (Whitelist) ${wl_status}"
        echo; printf_menu_option "b" "🔙 Назад"; print_separator "-" 60

        local choice; choice=$(safe_read "Твой выбор") || break
        if [[ "$choice" == "b" || "$choice" == "B" ]]; then break; fi
        case "$choice" in
            1) _tl_list_rules ;;
            2) _tl_show_status ;;
            3) _tl_apply_limit_ebpf_wizard ;;
            4) _tl_delete_rule_wizard ;;
            5) _tl_complete_cleanup_wizard ;;
            6) _tl_view_service_log ;;
            7) _tl_restart_ebpf_engine ;;
            8) _tl_monitor_traffic ;;
            9) _tl_edit_whitelist ;;
            *) warn "Нет такого пункта." ;;
        esac
        wait_for_enter
    done
    disable_graceful_ctrlc
}

# ============================================================ #
# ==                  ЛОГИКА И ПОДМЕНЮ                      == #
# ============================================================ #

_tl_ensure_ebpf_deps() {
    info "Проверка зависимостей для eBPF..."
    # Добавляем bpftool в основной список
    ensure_dependencies "clang" "llvm" "libbpf-dev" "python3" "bc" "kmod" "bpftool"
    
    # Дополнительная проверка на случай, если bpftool не в PATH или в linux-tools
    if ! which bpftool &>/dev/null; then
        info "Авто-Хирург: Ищу bpftool в специфичных путях..."
        if [[ -f /etc/debian_version ]]; then
            # Пытаемся поставить пакет bpftool (для новых ядер) или linux-tools (для старых)
            apt-get update
            apt-get install -y bpftool || apt-get install -y linux-tools-common linux-tools-generic "linux-tools-$(uname -r)" || true
        fi
        
        # Поиск по известным путям linux-tools
        local p
        local k_ver; k_ver=$(uname -r)
        local possible_bins=(
            "/usr/lib/linux-tools/${k_ver}/bpftool"
            "/usr/lib/linux-tools-$(echo ${k_ver} | cut -d'-' -f1-2)/bpftool"
            "/usr/lib/linux-tools-generic/bpftool"
            "/usr/local/sbin/bpftool"
            "/usr/sbin/bpftool"
        )
        
        for p in "${possible_bins[@]}"; do
            if [[ -x "$p" ]]; then
                info "Нашел bpftool: $p. Создаю симлинк..."
                ln -sf "$p" /usr/local/bin/bpftool 2>/dev/null || true
                break
            fi
        done
    fi

    local kheaders="linux-headers-$(uname -r)"
    local kheaders_meta="linux-headers-$(dpkg --print-architecture 2>/dev/null || echo amd64)"
    
    if ! dpkg -s "$kheaders" &>/dev/null && ! dpkg -s "$kheaders_meta" &>/dev/null; then
        info "Устанавливаю заголовки ядра $kheaders..."
        apt-get update
        apt-get install -y "$kheaders" || apt-get install -y "$kheaders_meta" || true
    fi
    sysctl -w kernel.unprivileged_bpf_disabled=0 &>/dev/null || true
}

_tl_compile_bpf() {
    info "Компиляция eBPF программы..."
    mkdir -p "${TL_CONFIG_DIR}"
    
    # Автоматический поиск путей для asm/types.h
    local arch_include=""
    local possible_paths=(
        "/usr/include/$(uname -m)-linux-gnu"
        "/usr/include/aarch64-linux-gnu"
        "/usr/include/x86_64-linux-gnu"
        "/usr/include/arm-linux-gnueabihf"
    )
    
    for path in "${possible_paths[@]}"; do
        if [[ -d "$path/asm" ]]; then
            arch_include="-I$path"
            break
        fi
    done

    if ! clang -O2 -g -target bpf ${arch_include} -c "${TL_BPF_SRC_PATH}" -o "${TL_BPF_OBJ_PATH}"; then
        err "Ошибка компиляции eBPF! Проверь наличие заголовков ядра."
        return 1
    fi
    ok "Компиляция завершена успешно."
    return 0
}

_tl_cleanup_old_system() {
    info "🧹 Очистка старых правил..."
    systemctl stop "${TL_SERVICE_NAME}" &>/dev/null || true
    systemctl disable "${TL_SERVICE_NAME}" &>/dev/null || true
    rm -f "${TL_SERVICE_PATH}" "${TL_OLD_APPLY_SCRIPT}"
    systemctl daemon-reload
    # Очищаем tc на всех интерфейсах
    ip -o link show | awk -F': ' '{print $2}' | grep -v '^lo$' | while read -r iface; do
        tc qdisc del dev "$iface" root &>/dev/null || true
        tc qdisc del dev "$iface" clsact &>/dev/null || true
        tc qdisc del dev "$iface" ingress &>/dev/null || true
    done
    
    # Удаляем BPF-карты (иначе "several maps match this handle")
    rm -rf "${TL_BPF_PIN_DIR}" &>/dev/null || true
    ok "Очистка завершена."
}

_tl_get_shaper_rule_info_for_port() {
    local target_port="$1"
    local rules_file="${TL_CONFIG_DIR}/rules.json"
    [ ! -f "$rules_file" ] && return 1

    # Ищем правило, где в списке портов (через запятую) есть наш порт
    # Используем map(gsub(" "; "")) для очистки пробелов в JSON
    local rule_data
    rule_data=$(jq -r --arg p "$target_port" '
        to_entries[] | 
        select(
            (.value.ports | tostring) == "0" or 
            (.value.ports | tostring | split(",") | map(gsub(" "; "")) | contains([$p]))
        ) | 
        "\(.key)|\(.value.mode)|\(.value.down_mbs)|\(.value.up_mbs)"
    ' "$rules_file" 2>/dev/null | head -n1)

    if [[ -n "$rule_data" ]]; then
        local rid; rid=$(echo "$rule_data" | cut -d'|' -f1)
        local mode; mode=$(echo "$rule_data" | cut -d'|' -f2)
        local down; down=$(echo "$rule_data" | cut -d'|' -f3)
        local up; up=$(echo "$rule_data" | cut -d'|' -f4)
        
        local mode_text="Статика"
        [[ "$mode" == "2" ]] && mode_text="Динамика"
        [[ "$mode" == "3" ]] && mode_text="Общее"
        
        echo -e " ${C_GREEN}[✓ Правило #$rid | $mode_text | $down/$up МБ/с]${C_RESET}"
        return 0
    fi
    return 1
}

_tl_show_listening_ports_smart() {
    echo -e "  ${C_CYAN}[i] Подсказка: Эта таблица показывает запущенные на сервере сервисы.${C_RESET}"
    echo -e "  ${C_GRAY}    • Если вы видите${C_RESET} xray ${C_GRAY}или${C_RESET} v2ray ${C_GRAY}— это порт вашего VPN, его нужно шейпить.${C_RESET}"
    echo -e "  ${C_GRAY}    • Если вы видите${C_RESET} sshd ${C_GRAY}— это порт консоли сервера. Лучше его не трогать.${C_RESET}"
    echo

    # 1. Проверяем UFW
    if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then
        echo -e "  ${C_GREEN}[✓] UFW активен.${C_RESET}"
        local ufw_out; ufw_out=$(ufw status verbose)
        local in_policy; in_policy=$(echo "$ufw_out" | grep "Default:" | awk '{print $2}')
        local out_policy; out_policy=$(echo "$ufw_out" | grep "Default:" | awk '{print $4}' | tr -d ',')
        
        echo -e "  ${C_CYAN}[i] Политика по умолчанию:${C_RESET}"
        local in_text="Разрешены"; [[ "$in_policy" == "deny" ]] && in_text="Блокируются (рекомендуется)"
        local out_text="Разрешены (стандарт)"; [[ "$out_policy" == "deny" ]] && out_text="Блокируются"
        echo -e "          ${C_GRAY}↳   Входящие: $in_text${C_RESET}"
        echo -e "          ${C_GRAY}↳   Исходящие: $out_text${C_RESET}"
        
        echo -e "  ${C_CYAN}[i] Активные правила:${C_RESET}"
        # Парсим правила UFW (берем только ALLOW)
        ufw status | grep "ALLOW" | grep -v "(v6)" | while read -r line; do
            local port_raw; port_raw=$(echo "$line" | awk '{print $1}')
            local port; port=$(echo "$port_raw" | cut -d'/' -f1)
            # Пропускаем, если не число
            [[ ! "$port" =~ ^[0-9]+$ ]] && continue
            
            local comment; comment=$(echo "$line" | grep -o '#.*' | sed 's/# //')
            [ -z "$comment" ] && comment="Открыт для всех"
            
            local rule_info; rule_info=$(_tl_get_shaper_rule_info_for_port "$port")
            echo -e "          ${C_GRAY}↳   ${C_YELLOW}● Порт $port${C_RESET} ($comment)$rule_info"
        done
        echo
    fi

    echo -e "  ${C_CYAN}Активные процессы (слушают порты):${C_RESET}"
    echo "  ------------------------------------------------------------"
    # Надежный парсинг вывода ss -tulnp
    ss -tulnp | grep LISTEN | while read -r line; do
        local_add_port=$(echo "$line" | awk '{print $5}')
        proc_info=$(echo "$line" | awk '{print $NF}')
        port="${local_add_port##*:}"
        proc_name=$(echo "$proc_info" | grep -o '("[^"]*"' | head -n1 | tr -d '"(')
        [ -z "$proc_name" ] && proc_name="Системный/Неизвестен"
        
        local rule_info; rule_info=$(_tl_get_shaper_rule_info_for_port "$port")
        echo -e "    • Порт: ${C_YELLOW}${port}${C_RESET}  —>  слушает ${C_GREEN}${proc_name}${C_RESET}$rule_info"
    done | sort -u -t: -k2 -n
    echo "  ------------------------------------------------------------"
}

_tl_show_speed_reference() {
    echo
    printf "  ${C_CYAN}╔══════════════════════════════════════════════════════════╗${C_RESET}\n"
    printf "  ${C_CYAN}║${C_RESET}  📡 Справка по скоростям (лимит на 1 пользователя)     ${C_CYAN}║${C_RESET}\n"
    printf "  ${C_CYAN}╠══════════════════════════════════════════════════════════╣${C_RESET}\n"
    printf "  ${C_CYAN}║${C_RESET}  ${C_GRAY}Применение              Мин.   Комфорт   Идеал${C_RESET}        ${C_CYAN}║${C_RESET}\n"
    printf "  ${C_CYAN}╠══════════════════════════════════════════════════════════╣${C_RESET}\n"
    printf "  ${C_CYAN}║${C_RESET}  📞 Звонки / VoIP        0.1    0.5 МБ/с  1 МБ/с       ${C_CYAN}║${C_RESET}\n"
    printf "  ${C_CYAN}║${C_RESET}  🎵 Музыка / Telegram    0.1    0.3 МБ/с  0.5 МБ/с     ${C_CYAN}║${C_RESET}\n"
    printf "  ${C_CYAN}║${C_RESET}  📺 YouTube 720p         0.5    1.0 МБ/с  1.5 МБ/с     ${C_CYAN}║${C_RESET}\n"
    printf "  ${C_CYAN}║${C_RESET}  📺 YouTube 1080p        1.0    2.0 МБ/с  3.0 МБ/с     ${C_CYAN}║${C_RESET}\n"
    printf "  ${C_CYAN}║${C_RESET}  🎬 YouTube 4K / Netflix  3.0   6.0 МБ/с  12.0 МБ/с    ${C_CYAN}║${C_RESET}\n"
    printf "  ${C_CYAN}╠══════════════════════════════════════════════════════════╣${C_RESET}\n"
    printf "  ${C_CYAN}║${C_RESET}  ${C_GREEN}Рекомендуем: 3-5 МБ/с = комфорт для большинства${C_RESET}      ${C_CYAN}║${C_RESET}\n"
    printf "  ${C_CYAN}╠══════════════════════════════════════════════════════════╣${C_RESET}\n"
    printf "  ${C_CYAN}║${C_RESET}  👥 Кол-во пользователей при лимите 3 МБ/с:            ${C_CYAN}║${C_RESET}\n"
    printf "  ${C_CYAN}║${C_RESET}     Канал 1 Гбит/с  → ~${C_YELLOW}40 пользователей${C_RESET}             ${C_CYAN}║${C_RESET}\n"
    printf "  ${C_CYAN}║${C_RESET}     Канал 10 Гбит/с → ~${C_YELLOW}416 пользователей${C_RESET}            ${C_CYAN}║${C_RESET}\n"
    printf "  ${C_CYAN}║${C_RESET}  👥 При лимите 5 МБ/с:                                 ${C_CYAN}║${C_RESET}\n"
    printf "  ${C_CYAN}║${C_RESET}     Канал 1 Гбит/с  → ~${C_YELLOW}25 пользователей${C_RESET}             ${C_CYAN}║${C_RESET}\n"
    printf "  ${C_CYAN}║${C_RESET}     Канал 10 Гбит/с → ~${C_YELLOW}250 пользователей${C_RESET}            ${C_CYAN}║${C_RESET}\n"
    printf "  ${C_CYAN}╚══════════════════════════════════════════════════════════╝${C_RESET}\n"
    echo
}

_tl_show_shaper_intro() {
    echo -e "  ${C_CYAN}╔══════════════════════════════════════════════════════════╗${C_RESET}"
    echo -e "  ${C_CYAN}║${C_RESET}  ${C_YELLOW}⚡ Reshala eBPF Traffic Shaper v3.2 (HighLoad)${C_RESET}"
    echo -e "  ${C_CYAN}╠══════════════════════════════════════════════════════════╣${C_RESET}"
    echo -e "  ${C_CYAN}║${C_RESET}  ${C_GRAY}Что это?${C_RESET}"
    echo -e "  ${C_CYAN}║${C_RESET}  Ограничитель скорости на базе ${C_YELLOW}eBPF + EDT${C_RESET} (Linux ядро)"
    echo -e "  ${C_CYAN}║${C_RESET}  Работает на уровне ${C_YELLOW}L3/L4${C_RESET} (IP + TCP/UDP)"
    echo -e "  ${C_CYAN}║${C_RESET}  ${C_GREEN}✔${C_RESET} Лимит отдельно по каждому IP-адресу"
    echo -e "  ${C_CYAN}║${C_RESET}  ${C_GREEN}✔${C_RESET} Раздельные лимиты Download и Upload"
    echo -e "  ${C_CYAN}║${C_RESET}  ${C_GREEN}✔${C_RESET} Полная поддержка IPv4 и IPv6"
    echo -e "  ${C_CYAN}║${C_RESET}  ${C_GREEN}✔${C_RESET} 0%% коллизий (eBPF Hash Map по IP)"
    echo -e "  ${C_CYAN}║${C_RESET}  ${C_GREEN}✔${C_RESET} До 32 портов одновременно"
    echo -e "  ${C_CYAN}║${C_RESET}  ${C_GRAY}Как работает (HighLoad версия 10 Gbit/s)?${C_RESET}"
    echo -e "  ${C_CYAN}║${C_RESET}  ${C_YELLOW}Download${C_RESET}: Сервер → ${C_GREEN}eBPF (EDT)${C_RESET} → fq qdisc → Пользователь"
    echo -e "  ${C_CYAN}║${C_RESET}  ${C_YELLOW}Upload${C_RESET}  : Пользователь → ${C_GREEN}eBPF (Token Bucket Hard Drop)${C_RESET}"
    echo -e "  ${C_CYAN}║${C_RESET}  * EDT = Плавная задержка отправки для идеального стриминга"
    echo -e "  ${C_CYAN}║${C_RESET}  * Token Bucket = Сброс лишних upload-пакетов (TCP сам снизит скорость)"
    echo -e "  ${C_CYAN}╠══════════════════════════════════════════════════════════╣${C_RESET}"
    echo -e "  ${C_CYAN}║${C_RESET}  ${C_GRAY}Режимы работы${C_RESET}"
    echo -e "  ${C_CYAN}║${C_RESET}  ${C_GREEN}[1] Статический${C_RESET}: жёсткий лимит скорости на каждого пользователя"
    echo -e "  ${C_CYAN}║${C_RESET}  ${C_YELLOW}[2] Динамический${C_RESET}: burst → квота → штраф → нормальная (на каждого)"
    echo -e "  ${C_CYAN}║${C_RESET}  ${C_CYAN}[3] Общее ограничение${C_RESET}: единый канал скорости на весь порт (Shared)"
    echo -e "  ${C_CYAN}╠══════════════════════════════════════════════════════════╣${C_RESET}"
    echo -e "  ${C_CYAN}║${C_RESET}  ${C_GRAY}🥇 Приоритетная маршрутизация и порт 0${C_RESET}"
    echo -e "  ${C_CYAN}║${C_RESET}  Точные порты (например, 443) имеют абсолютный приоритет."
    echo -e "  ${C_CYAN}║${C_RESET}  Добавив правило на порт ${C_YELLOW}0${C_RESET} (ВСЕ ПОРТЫ), вы создаёте"
    echo -e "  ${C_CYAN}║${C_RESET}  «запасной аэродром» для любого неучтенного трафика."
    echo -e "  ${C_CYAN}║${C_RESET}  ${C_GRAY}Пример: выдайте VIP-порту 443 лимит 5 МБ/с, а на порт 0${C_RESET}"
    echo -e "  ${C_CYAN}║${C_RESET}  ${C_GRAY}повесьте 1 МБ/с. Так вы разделите тарифы без конфликтов.${C_RESET}"
    echo -e "  ${C_CYAN}╠══════════════════════════════════════════════════════════╣${C_RESET}"
    echo -e "  ${C_CYAN}║${C_RESET}  ${C_GRAY}Ограничения${C_RESET}"
    echo -e "  ${C_CYAN}║${C_RESET}  ${C_RED}⚠${C_RESET}  Ядро Linux >= 5.4 (bpf_ktime, EDT, clsact)"
    echo -e "  ${C_CYAN}║${C_RESET}  ${C_RED}⚠${C_RESET}  Требует: clang, bpftool, libbpf-dev, iproute2"
    echo -e "  ${C_CYAN}║${C_RESET}  ${C_RED}⚠${C_RESET}  Не анализирует содержимое пакетов (работает на уровне IP)"
    echo -e "  ${C_CYAN}║${C_RESET}  ${C_RED}⚠${C_RESET}  Макс. отслеживаемых IP: 65536 на направление (DL/UL)"
    echo -e "  ${C_CYAN}║${C_RESET}  ${C_RED}⚠${C_RESET}  Макс. портов в одном правиле: 32"
    echo -e "  ${C_CYAN}╚══════════════════════════════════════════════════════════╝${C_RESET}"
    echo
}

_tl_list_rules() {
    clear; menu_header "📋 Активные правила шейпера"
    python3 "${TL_CTRL_PY_PATH}" \
        --pin-dir "${TL_BPF_PIN_DIR}/maps" \
        --rules-file "${TL_CONFIG_DIR}/rules.json" \
        rules
}

_tl_delete_rule_wizard() {
    clear; menu_header "🗑  Удалить правило"
    python3 "${TL_CTRL_PY_PATH}" \
        --pin-dir "${TL_BPF_PIN_DIR}/maps" \
        --rules-file "${TL_CONFIG_DIR}/rules.json" \
        rules
    echo
    local rule_id; rule_id=$(safe_read "Номер правила для удаления") || return
    if ! [[ "$rule_id" =~ ^[0-9]+$ ]]; then
        warn "Некорректный ID"; return
    fi
    if ask_yes_no "Удалить правило #${rule_id}?" "n"; then
        python3 "${TL_CTRL_PY_PATH}" \
            --pin-dir "${TL_BPF_PIN_DIR}/maps" \
            --rules-file "${TL_CONFIG_DIR}/rules.json" \
            delete --rule-id "${rule_id}"
    fi
}

_tl_ensure_engine_ready() {
    # 1. Проверяем, запущен ли сервис и есть ли карты
    if ! systemctl is-active --quiet "${TL_SERVICE_NAME}" || [ ! -d "${TL_BPF_PIN_DIR}/maps" ]; then
        echo -e "\n  ${C_RED}╔════════════════════════════════════════════════════════════╗${C_RESET}"
        echo -e "  ${C_RED}║ 🔥 ОБНАРУЖЕН СТАРЫЙ ДВИЖОК ИЛИ СБОЙ ИНИЦИАЛИЗАЦИИ!       ║${C_RESET}"
        echo -e "  ${C_RED}╠════════════════════════════════════════════════════════════╣${C_RESET}"
        echo -e "  ${C_WHITE}║ Старые правила шейпинга будут удалены.                     ║${C_RESET}"
        echo -e "  ${C_WHITE}║ Выполняю миграцию на новый eBPF движок...                  ║${C_RESET}"
        echo -e "  ${C_RED}╚════════════════════════════════════════════════════════════╝${C_RESET}\n"
        
        sleep 2
        
        # 2. Очистка старья
        _tl_cleanup_old_system
        
        # 3. Подготовка и запуск
        _tl_ensure_ebpf_deps || return 1
        _tl_compile_bpf || return 1
        
        _tl_generate_ebpf_service_file > "${TL_SERVICE_PATH}"
        systemctl daemon-reload
        systemctl enable --now "${TL_SERVICE_NAME}"
        
        # Ожидание инициализации карт
        local timeout=10
        while [ ! -d "${TL_BPF_PIN_DIR}/maps" ] && [ $timeout -gt 0 ]; do
            sleep 1; ((timeout--))
        done

        if [ ! -d "${TL_BPF_PIN_DIR}/maps" ]; then
             err "❌ Ошибка: eBPF движок не запустился. Проверь 'journalctl -u ${TL_SERVICE_NAME}'"
             return 1
        fi
        ok "Миграция завершена! Новый движок активен."
    fi
    return 0
}

_tl_apply_limit_ebpf_wizard() {
    _tl_ensure_ebpf_deps || return
    clear; menu_header "eBPF Шейпер — Информация"
    _tl_show_shaper_intro
    wait_for_enter

    # ── Шаг 0: какой rule_id ──
    clear; menu_header "eBPF Шейпер: Шаг 0 (ID правила)"
    echo -e "  ${C_YELLOW}💡 Текущие правила:${C_RESET}"
    python3 "${TL_CTRL_PY_PATH}" \
        --pin-dir "${TL_BPF_PIN_DIR}/maps" \
        --rules-file "${TL_CONFIG_DIR}/rules.json" \
        rules 2>/dev/null || true
    echo
    echo -e "  ${C_GRAY}─────────────────────────────────────────────────────${C_RESET}"
    echo -e "  ${C_CYAN}ID 0..31. Новое правило — свободный номер.${C_RESET}"
    echo -e "  ${C_CYAN}Изменить существующее — введи его ID.${C_RESET}"
    local rule_id; rule_id=$(ask_number_in_range "Номер правила (rule_id)" 0 31 0) || return

    # Подгружаем интерфейс из конфига
    if [ -f "${TL_CONFIG_DIR}/ebpf_config.conf" ]; then
        # shellcheck source=/dev/null
        source "${TL_CONFIG_DIR}/ebpf_config.conf"
    fi
    
    # Авто-детект интерфейса, если он пуст
    if [[ -z "$IFACE" ]]; then
        IFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
        [[ -z "$IFACE" ]] && IFACE=$(ip -br link | grep -v "lo" | awk '{print $1}' | head -n1)
    fi

    # ── Шаг 1: интерфейс (только если движок ещё не запущен) ──
    local is_active="false"
    if systemctl is-active --quiet "${TL_SERVICE_NAME}"; then is_active="true"; fi
    local iface=""
    if [[ "$is_active" == "false" ]]; then
        clear; menu_header "eBPF Шейпер: Шаг 1 (Интерфейс)"
        echo -e "  ${C_YELLOW}💡 Как выбрать интерфейс?${C_RESET}"
        echo -e "  ${C_GRAY}─────────────────────────────────────────────────────${C_RESET}"
        echo -e "  ${C_GREEN}✔${C_RESET} Выбирай основной сетевой интерфейс (${C_YELLOW}ens3${C_RESET}, ${C_YELLOW}eth0${C_RESET}, ${C_YELLOW}enp3s0${C_RESET})"
        echo -e "  ${C_GREEN}✔${C_RESET} Через него идёт трафик пользователей"
        echo -e "  ${C_RED}✗${C_RESET} НЕ выбирай ${C_GRAY}docker0${C_RESET}, ${C_GRAY}br-*${C_RESET}, ${C_GRAY}veth*${C_RESET} — мосты Docker"
        echo -e "  ${C_RED}✗${C_RESET} НЕ выбирай ${C_GRAY}lo${C_RESET} — loopback"
        echo -e "  ${C_GRAY}─────────────────────────────────────────────────────${C_RESET}"
        echo
        iface=$(_tl_select_interface) || return
    else
        iface=$(grep 'IFACE=' "${TL_CONFIG_DIR}/ebpf_config.conf" 2>/dev/null | cut -d'"' -f2)
        info "Движок уже запущен на интерфейсе ${C_YELLOW}${iface}${C_RESET}, пропускаем выбор."
    fi

    # ── Шаг 2: режим ──
    clear; menu_header "eBPF Шейпер: Шаг 2 (Режим)"
    echo -e "  ${C_YELLOW}💡 Выбери режим шейпинга:${C_RESET}"
    echo -e "  ${C_GRAY}─────────────────────────────────────────────────────${C_RESET}"
    echo -e ""
    echo -e "  ${C_GREEN}[1] Статический${C_RESET} — жёсткий лимит скорости на каждого пользователя"
    echo -e "      ${C_GRAY}Каждый IP получает ровно N МБ/с. Просто и предсказуемо.${C_RESET}"
    echo -e "      ${C_CYAN}→ Подходит: VPN, игровые серверы, стабильное качество${C_RESET}"
    echo -e ""
    echo -e "  ${C_YELLOW}[2] Динамический${C_RESET} — burst → квота → штраф → восстановление"
    echo -e "      ${C_GRAY}Быстро до квоты, затем штрафная скорость, потом восстановление.${C_RESET}"
    echo -e "      ${C_CYAN}→ Подходит: ограничение «качальщиков», справедливое распределение${C_RESET}"
    echo -e ""
    echo -e "  ${C_CYAN}[3] Общее ограничение${C_RESET} — единая труба на всех (Shared Pool)"
    echo -e "      ${C_GRAY}Скорость делится между всеми IP без остатка. Если трубку в 100 МБ/с"
    echo -e "      занимает 1 человек — он качает 100. Если 10 — качают по 10 МБ/с.${C_RESET}"
    echo -e "      ${C_CYAN}→ Подходит: защита сервера от пропускного коллапса (DDoS)${C_RESET}"
    echo -e ""
    echo -e "  ${C_GRAY}─────────────────────────────────────────────────────${C_RESET}"
    local mode; mode=$(ask_number_in_range "Выбери режим" 1 3 1) || return

    # ── Шаг 3: порты ──
    clear; menu_header "eBPF Шейпер: Шаг 3 (Порты)"
    _tl_show_listening_ports_smart
    echo
    info "Можно указать несколько портов через запятую: ${C_YELLOW}443,80,8080${C_RESET} — или ${C_YELLOW}0${C_RESET} для всех"
    local ports_input; ports_input=$(safe_read "Порты (через запятую, 0 = все порты)" "0") || return
    ports_input=$(echo "$ports_input" | tr -d ' ')

    # ── Шаг 4: скорости ──
    clear; menu_header "eBPF Шейпер: Шаг 4 (Скорости)"
    
    local dflt_speed=5
    if [[ "$mode" == "3" ]]; then
        dflt_speed=100
        echo -e "  ${C_CYAN}╔══════════════════════════════════════════════════════════╗${C_RESET}"
        echo -e "  ${C_CYAN}║${C_RESET}  ${C_YELLOW}🌍 Справка по скоростям ОБЩЕГО ОГРАНИЧЕНИЯ (Shared)${C_RESET}"
        echo -e "  ${C_CYAN}╠══════════════════════════════════════════════════════════╣${C_RESET}"
        echo -e "  ${C_CYAN}║${C_RESET}  ${C_GRAY}Внимание: эта скорость делится на ВСЕХ пользователей порта.${C_RESET}"
        echo -e "  ${C_CYAN}║${C_RESET}  ${C_GRAY}Рекомендуется указывать суммарную емкость канала.${C_RESET}"
        echo -e "  ${C_CYAN}║${C_RESET}  50 МБ/с   = ~400 Мбит/с  (хватит на ~10-20 юзеров)"
        echo -e "  ${C_CYAN}║${C_RESET}  100 МБ/с  = ~800 Мбит/с  (хватит на ~20-50 юзеров)"
        echo -e "  ${C_CYAN}║${C_RESET}  500 МБ/с  = ~4 Гбит/с    (серьёзный узел)"
        echo -e "  ${C_CYAN}╚══════════════════════════════════════════════════════════╝${C_RESET}"
        echo
    else
        _tl_show_speed_reference
    fi
    
    local down_speed; down_speed=$(ask_float_in_range "Скачивание (DL) МБ/с" 0.1 50000 $dflt_speed) || return
    local up_speed;   up_speed=$(ask_float_in_range   "Загрузка   (UL) МБ/с" 0.1 50000 $dflt_speed) || return

    local pspeed=0.1; local burst=100; local win=10; local pen=60
    if [[ "$mode" == "2" ]]; then
        echo
        echo -e "  ${C_CYAN}╔══════════════════════════════════════════════════════════╗${C_RESET}"
        echo -e "  ${C_CYAN}║${C_RESET}  ${C_YELLOW}⚡ Как работает система Burst + Штраф?${C_RESET}"
        echo -e "  ${C_CYAN}╠══════════════════════════════════════════════════════════╣${C_RESET}"
        echo -e "  ${C_CYAN}║${C_RESET}  ${C_GREEN}1. Burst (квота):${C_RESET}"
        echo -e "  ${C_CYAN}║${C_RESET}     Пользователь качает на полной скорости (DL/UL)."
        echo -e "  ${C_CYAN}║${C_RESET}     Шейпер считает трафик в окне X секунд."
        echo -e "  ${C_CYAN}║${C_RESET}     Как только скачано > КВОТЫ за окно — штраф."
        echo -e "  ${C_CYAN}╠══════════════════════════════════════════════════════════╣${C_RESET}"
        echo -e "  ${C_CYAN}║${C_RESET}  ${C_YELLOW}2. Штраф:${C_RESET}"
        echo -e "  ${C_CYAN}║${C_RESET}     Скорость резко падает до штрафной (например 0.5 МБ/с)."
        echo -e "  ${C_CYAN}║${C_RESET}     Штраф длится N секунд, потом скорость восстанавливается."
        echo -e "  ${C_CYAN}║${C_RESET}     Штраф 0 МБ/с = полная блокировка на время штрафа."
        echo -e "  ${C_CYAN}╠══════════════════════════════════════════════════════════╣${C_RESET}"
        echo -e "  ${C_CYAN}║${C_RESET}  ${C_GRAY}Пример: квота 100 МБ в окне 10с, штраф 0.5 МБ/с на 60с."
        echo -e "  ${C_CYAN}║${C_RESET}  ${C_GRAY}Качальщик скачал 100 МБ за 10с → 60с сидит на 0.5 МБ/с."
        echo -e "  ${C_CYAN}║${C_RESET}  ${C_GRAY}Обычный пользователь (соцсети, VoIP) — не замечает.${C_RESET}"
        echo -e "  ${C_CYAN}╚══════════════════════════════════════════════════════════╝${C_RESET}"
        echo
        pspeed=$(ask_float_in_range "Штрафная скорость (МБ/с, 0=блок)"  0 1000 0.5) || return
        burst=$(ask_number_in_range  "Квота на Burst (МБайт)"            1 50000 100) || return
        win=$(ask_number_in_range    "Окно проверки (секунд)"             1 3600 10)   || return
        pen=$(ask_number_in_range    "Длительность штрафа (секунд)"       0 86400 60)  || return
    fi

    # ── Шаг 5: Белый список ──
    local use_gwl="false"
    if global_whitelist_offer "Traffic Limiter"; then
        use_gwl="true"
    fi

    # ── Финальная проверка ──
    local dl_mbit; dl_mbit=$(echo "$down_speed * 8" | bc -l | xargs printf "%.1f")
    local ul_mbit; ul_mbit=$(echo "$up_speed   * 8" | bc -l | xargs printf "%.1f")
    clear; menu_header "Финальная проверка"
    print_key_value "Правило #" "$rule_id" 25
    print_key_value "Интерфейс" "$iface" 25
    local mode_print="Неизвестно"
    if [[ "$mode" == "1" ]]; then mode_print="Статика (на 1 юзера)"; fi
    if [[ "$mode" == "2" ]]; then mode_print="Динамика (на 1 юзера)"; fi
    if [[ "$mode" == "3" ]]; then mode_print="Общая труба (на всех)"; fi

    print_key_value "Режим"     "$mode_print" 25
    print_key_value "Порты"     "$( [[ "$ports_input" == "0" ]] && echo "ВСЕ ПОРТЫ" || echo "$ports_input" )" 25
    print_key_value "Download"  "${down_speed} МБ/с  (${dl_mbit} Мбит/с)" 25
    print_key_value "Upload"    "${up_speed} МБ/с  (${ul_mbit} Мбит/с)" 25
    if [[ "$mode" == "2" ]]; then
        print_key_value "Burst"   "${burst} МБ в окне ${win}с" 25
        print_key_value "Штраф"   "${pspeed} МБ/с на ${pen}с" 25
    fi
    print_key_value "Белый список" "$( [[ "$use_gwl" == "true" ]] && echo "ГЛОБАЛЬНЫЙ (Активен)" || echo "Нет" )" 25
    echo
    if ! ask_yes_no "Применить?"; then return; fi

    # ── ПРОВЕРКА И ИНИЦИАЛИЗАЦИЯ ДВИЖКА (АВТОНОМНО) ──
    if ! systemctl is-active --quiet "${TL_SERVICE_NAME}" || [ ! -d "${TL_BPF_PIN_DIR}/maps" ]; then
        echo -e "\n  ${C_RED}╔════════════════════════════════════════════════════════════╗${C_RESET}"
        echo -e "  ${C_RED}║ 🔥 ВНИМАНИЕ: МИГРАЦИЯ НА НОВЫЙ eBPF ДВИЖОК               ║${C_RESET}"
        echo -e "  ${C_RED}╠════════════════════════════════════════════════════════════╣${C_RESET}"
        echo -e "  ${C_WHITE}║ Старые правила (U32/Legacy) будут полностью удалены.       ║${C_RESET}"
        echo -e "  ${C_WHITE}║ Настройки переносятся в новый формат.                      ║${C_RESET}"
        echo -e "  ${C_RED}╚════════════════════════════════════════════════════════════╝${C_RESET}\n"
        
        sleep 2
        
        # Полная зачистка старого шейпера
        _tl_cleanup_old_system
        
        # Компиляция и подготовка
        _tl_compile_bpf || return
        mkdir -p "${TL_CONFIG_DIR}"
        
        # Сохранение конфига интерфейса
        cat <<EOF > "${TL_CONFIG_DIR}/ebpf_config.conf"
IFACE="${iface}"
EOF
        # Снимаем маскировку, если сервис был заблокирован системой
        systemctl unmask "${TL_SERVICE_NAME}" &>/dev/null || true
        
        # Генерация и установка сервиса
        _tl_generate_ebpf_service_file > "${TL_SERVICE_PATH}"
        
        systemctl daemon-reload
        systemctl enable "${TL_SERVICE_NAME}"
        
        info "Запуск eBPF движка..."
        systemctl restart "${TL_SERVICE_NAME}"
        
        # Ожидание инициализации (проверка появления карт)
        local timeout=10
        while [ ! -d "${TL_BPF_PIN_DIR}/maps" ] && [ $timeout -gt 0 ]; do
            sleep 1; ((timeout--))
        done

        if [ ! -d "${TL_BPF_PIN_DIR}/maps" ]; then
             err "❌ Критическая ошибка: Движок не запустился. Проверь логи: journalctl -u ${TL_SERVICE_NAME}"
             return 1
        fi
        ok "Движок успешно развернут!"
    fi

    # Применяем правило (движок уже работает)
    info "Применяю правило #${rule_id}..."
    python3 "${TL_CTRL_PY_PATH}" \
        --pin-dir "${TL_BPF_PIN_DIR}/maps" \
        --rules-file "${TL_CONFIG_DIR}/rules.json" \
        set \
        --rule-id "${rule_id}" \
        --mode    "${mode}" \
        --ports   "${ports_input}" \
        --down    "${down_speed}" \
        --up      "${up_speed}" \
        --pen     "${pspeed}" \
        --burst   "${burst}" \
        --win     "${win}" \
        --pen-sec "${pen}"

    # Синхронизируем whitelist если выбрано
    if [[ "$use_gwl" == "true" ]]; then
        global_whitelist_sync_all
    fi
}

_tl_generate_ebpf_service_file() {
    source "${TL_CONFIG_DIR}/ebpf_config.conf"
    local PIN_PROGS="${TL_BPF_PIN_DIR}/progs"
    local PIN_MAPS="${TL_BPF_PIN_DIR}/maps"

    # 1. Поиск bpftool
    local bpftool_path; bpftool_path=$(which bpftool 2>/dev/null)
    
    if [[ -z "$bpftool_path" ]]; then
        local k_ver; k_ver=$(uname -r)
        local possible_paths=(
            "/usr/local/bin/bpftool"
            "/usr/local/sbin/bpftool"
            "/usr/sbin/bpftool"
            "/usr/bin/bpftool"
            "/usr/lib/linux-tools/${k_ver}/bpftool"
            "/usr/lib/linux-tools-$(echo ${k_ver} | cut -d'-' -f1-2)/bpftool"
            "/usr/lib/linux-tools-generic/bpftool"
        )
        for p in "${possible_paths[@]}"; do
            [[ -x "$p" ]] && { bpftool_path="$p"; break; }
        done
        
        if [[ -z "$bpftool_path" ]]; then
            bpftool_path=$(find /usr/sbin /usr/bin /sbin /bin /usr/lib -name bpftool -type f -executable 2>/dev/null | head -n 1)
        fi
    fi

    if [[ -z "$bpftool_path" ]]; then
        printf "%b" "${C_RED}╔════════════════════════════════════════════════════════════╗${C_RESET}\n" >&2
        printf "%b" "${C_RED}║ 🔥 ЯДЕРНОЕ ПРЕДУПРЕЖДЕНИЕ: BPFTOOL НЕ НАЙДЕН!             ║${C_RESET}\n" >&2
        printf "%b" "${C_RED}╠════════════════════════════════════════════════════════════╣${C_RESET}\n" >&2
        printf "%b" "${C_WHITE}║ Твое ядро или репозиторий блокируют установку BPF-пакетов. ║${C_RESET}\n" >&2
        printf "%b" "${C_CYAN}║ ЧТО ТЕБЕ НУЖНО СДЕЛАТЬ СЕЙЧАС (ВРУЧНУЮ):                   ║${C_RESET}\n" >&2
        printf "%b" "${C_YELLOW}║ 1. apt update && apt install -y bpftool                    ║${C_RESET}\n" >&2
        printf "%b" "${C_RED}╚════════════════════════════════════════════════════════════╝${C_RESET}\n" >&2
        return 1
    fi

    local tc_path;     tc_path=$(which tc 2>/dev/null || echo "/sbin/tc")
    local sysctl_path; sysctl_path=$(which sysctl 2>/dev/null || echo "/sbin/sysctl")
    local rm_path;     rm_path=$(which rm 2>/dev/null || echo "/bin/rm")
    local mkdir_path;  mkdir_path=$(which mkdir 2>/dev/null || echo "/bin/mkdir")
    local python_path; python_path=$(which python3 2>/dev/null || echo "/usr/bin/python3")
    local ls_path;     ls_path=$(which ls 2>/dev/null || echo "/bin/ls")

    cat <<EOF
[Unit]
Description=Reshala eBPF Traffic Limiter (Multi-Rule)
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes

# === ПОДГОТОВКА ===
ExecStartPre=-${sysctl_path} -w kernel.unprivileged_bpf_disabled=0
ExecStartPre=-${tc_path} qdisc del dev ${IFACE} root
ExecStartPre=-${tc_path} qdisc del dev ${IFACE} clsact
# Глубокая очистка для предотвращения "File exists"
ExecStartPre=-/bin/bash -c "${rm_path} -rf ${TL_BPF_PIN_DIR}/*"
ExecStartPre=-${rm_path} -rf ${TL_BPF_PIN_DIR}
ExecStartPre=${mkdir_path} -p ${PIN_PROGS} ${PIN_MAPS}

# === ЗАГРУЗКА И ДИАГНОСТИКА ===
# Убрали --legacy (не везде поддерживается), оставили type classifier (универсально)
ExecStartPre=${bpftool_path} --debug prog loadall ${TL_BPF_OBJ_PATH} ${PIN_PROGS} type classifier pinmaps ${PIN_MAPS}
# Выводим список созданных файлов для отладки
ExecStartPre=-${ls_path} -l ${PIN_PROGS}

# === ПОДКЛЮЧЕНИЕ ШЕЙПЕРА (Автоматический поиск имен файлов) ===
ExecStartPre=${tc_path} qdisc add dev ${IFACE} root fq
ExecStartPre=${tc_path} qdisc add dev ${IFACE} clsact
# Ищем файл для Egress (Download): ищем 'down' в названии
ExecStartPre=/bin/bash -c '\
    PROG_DOWN=\$(ls ${PIN_PROGS} | grep "down" | head -n 1); \
    if [ -n "\$PROG_DOWN" ]; then \
        ${tc_path} filter add dev ${IFACE} egress bpf direct-action pinned ${PIN_PROGS}/\$PROG_DOWN; \
    else \
        echo "ERROR: Download BPF program not found in ${PIN_PROGS}" >&2; exit 1; \
    fi'
# Ищем файл для Ingress (Upload): ищем 'up' в названии
ExecStartPre=/bin/bash -c '\
    PROG_UP=\$(ls ${PIN_PROGS} | grep "up" | head -n 1); \
    if [ -n "\$PROG_UP" ]; then \
        ${tc_path} filter add dev ${IFACE} ingress bpf direct-action pinned ${PIN_PROGS}/\$PROG_UP; \
    else \
        echo "ERROR: Upload BPF program not found in ${PIN_PROGS}" >&2; exit 1; \
    fi'

# === ВОССТАНОВЛЕНИЕ ПРАВИЛ И БЕЛОГО СПИСКА ===
ExecStart=${python_path} ${TL_CTRL_PY_PATH} --pin-dir ${PIN_MAPS} --rules-file ${TL_CONFIG_DIR}/rules.json restore
ExecStartPost=-${python_path} ${TL_CTRL_PY_PATH} --pin-dir ${PIN_MAPS} whitelist-sync --file ${TL_CONFIG_DIR}/whitelist.txt

# === ОСТАНОВКА ===
ExecStop=-/bin/bash -c "${rm_path} -rf ${TL_BPF_PIN_DIR}/*"
ExecStop=${rm_path} -rf ${TL_BPF_PIN_DIR}
ExecStop=-${tc_path} qdisc del dev ${IFACE} root
ExecStop=-${tc_path} qdisc del dev ${IFACE} clsact

[Install]
WantedBy=multi-user.target
EOF
}

_tl_show_status() {
    while true; do
        clear
        menu_header "📊 Статистика eBPF шейпера"

        if ! systemctl is-active --quiet "${TL_SERVICE_NAME}"; then
            printf_warning "Шейпер не запущен. Статистика недоступна."
            echo ""
            printf_menu_option "r" "🔄 Запустить шейпер"
            printf_menu_option "b" "🔙 Назад"
            print_separator "-" 60
            local c; c=$(safe_read "Выбор") || return
            case "$c" in
                r|R) systemctl start "${TL_SERVICE_NAME}" && ok "Запущен." ;;
                b|B|q|Q) return ;;
            esac
            continue
        fi

        echo ""
        python3 "${TL_CTRL_PY_PATH}" --pin-dir "${TL_BPF_PIN_DIR}/maps" status
        echo ""

        print_separator "-" 60
        printf_menu_option "1" "🔄 Обновить статистику (топ-10)"
        printf_menu_option "2" "📋 Показать полный список всех IP"
        printf_menu_option "3" "🧹 Сбросить счётчики (перезапуск)"
        printf_menu_option "4" "🔙 Назад"
        print_separator "-" 60

        local choice; choice=$(safe_read "Выбор [1-4]") || return
        case "$choice" in
            1) continue ;;
            2)
                clear; menu_header "📋 Все IP — полный список"
                python3 "${TL_CTRL_PY_PATH}" --pin-dir "${TL_BPF_PIN_DIR}/maps" status --full
                wait_for_enter ;;
            3)
                if ask_yes_no "Перезапустить шейпер (сбросит счётчики)?" "n"; then
                    _tl_restart_ebpf_engine
                    sleep 1
                fi ;;
            4|b|B|q|Q) return ;;
        esac
    done
}

_tl_restart_ebpf_engine() {
    info "Перезагрузка..."; _tl_compile_bpf || return
    
    # Принудительно загружаем модули ядра
    modprobe cls_bpf 2>/dev/null || true
    modprobe sch_fq 2>/dev/null || true
    
    systemctl unmask "${TL_SERVICE_NAME}" &>/dev/null || true
    systemctl restart "${TL_SERVICE_NAME}" && ok "Перезапущено."
}

_tl_edit_whitelist() {
    clear; menu_header "🛡️ Белый список (Whitelist)"

    # Предлагаем Глобальный Белый Список, если он доступен
    if command -v global_whitelist_offer &>/dev/null; then
        if global_whitelist_offer "Шейпер"; then
            local whitelist_file="${TL_CONFIG_DIR}/whitelist.txt"
            mkdir -p "${TL_CONFIG_DIR}"
            info "Копирую IP из Глобального Белого Списка в шейпер..."
            # Копируем глобальный список в файл шейпера
            cp -f "/etc/reshala/global-whitelist.txt" "$whitelist_file" 2>/dev/null || true
            # Синхронизируем BPF-карту
            local sync_out
            sync_out=$(python3 "${TL_CTRL_PY_PATH}" --pin-dir "${TL_BPF_PIN_DIR}/maps" whitelist-sync --file "$whitelist_file" 2>&1)
            echo "$sync_out"
            if echo "$sync_out" | grep -q "whitelist_map не найден"; then
                echo ""
                echo -e "  ${C_RED}██████████████████████████████████████████████████████████████${C_RESET}"
                echo -e "  ${C_RED}█${C_RESET}  ${C_YELLOW}ВНИМАНИЕ! Нажми ${C_GREEN}[7] 🔄 Перезапустить движок${C_YELLOW} для применения.${C_RESET}  ${C_RED}█${C_RESET}"
                echo -e "  ${C_RED}██████████████████████████████████████████████████████████████${C_RESET}"
            else
                ok "Глобальный Белый Список синхронизирован с шейпером."
            fi
            wait_for_enter
            return
        fi
    fi
    
    echo -e "  ${C_CYAN}╔══════════════════════════════════════════════════════════╗${C_RESET}"
    echo -e "  ${C_CYAN}║${C_RESET}  ${C_YELLOW}💡 Что такое Белый список?${C_RESET}"
    echo -e "  ${C_CYAN}╠══════════════════════════════════════════════════════════╣${C_RESET}"
    echo -e "  ${C_CYAN}║${C_RESET}  IP-адреса, добавленные в этот список, будут полностью"
    echo -e "  ${C_CYAN}║${C_RESET}  ${C_GREEN}игнорировать все ограничения скорости${C_RESET} (скачивание"
    echo -e "  ${C_CYAN}║${C_RESET}  и отдача на максимальной пропускной способности канала)."
    echo -e "  ${C_CYAN}╠══════════════════════════════════════════════════════════╣${C_RESET}"
    echo -e "  ${C_CYAN}║${C_RESET}  ${C_GRAY}Формат записи:${C_RESET}"
    echo -e "  ${C_CYAN}║${C_RESET}  ${C_WHITE}192.168.1.100 # Комментарий (имя пользователя)${C_RESET}"
    echo -e "  ${C_CYAN}║${C_RESET}  ${C_WHITE}2001:db8::1   # IPv6 тоже поддерживается${C_RESET}"
    echo -e "  ${C_CYAN}╠══════════════════════════════════════════════════════════╣${C_RESET}"
    echo -e "  ${C_CYAN}║${C_RESET}  ${C_GRAY}После закрытия редактора список применится мгновенно,${C_RESET}"
    echo -e "  ${C_CYAN}║${C_RESET}  ${C_GRAY}без перезапуска всего шейпера!${C_RESET}"
    echo -e "  ${C_CYAN}╚══════════════════════════════════════════════════════════╝${C_RESET}"
    echo
    
    if ! ask_yes_no "Открыть редактор белого списка?" "y"; then return; fi

    local whitelist_file="${TL_CONFIG_DIR}/whitelist.txt"
    mkdir -p "${TL_CONFIG_DIR}"
    
    # Создаем шаблон, если файла нет
    if [ ! -f "$whitelist_file" ]; then
        cat <<EOF > "$whitelist_file"
# Белый список IP-адресов (Whitelist)
# Указанные здесь IP будут полностью игнорировать шейпер.
# Формат: IP-адрес # Комментарий (имя)
# Пример:
# 192.168.1.100 # Мой сервер
# 2001:db8::1   # Мой IPv6
EOF
    fi

    # Открываем в nano (или vi)
    local editor="${EDITOR:-nano}"
    if ! command -v "$editor" &>/dev/null; then editor="vi"; fi
    
    $editor "$whitelist_file"
    
    # Применяем белый список через Python-скрипт
    echo
    info "Применяю изменения..."
    local sync_out
    sync_out=$(python3 "${TL_CTRL_PY_PATH}" --pin-dir "${TL_BPF_PIN_DIR}/maps" whitelist-sync --file "$whitelist_file" 2>&1)
    echo "$sync_out"
    
    if echo "$sync_out" | grep -q "whitelist_map не найден"; then
        echo
        echo -e "  ${C_RED}██████████████████████████████████████████████████████████████${C_RESET}"
        echo -e "  ${C_RED}█${C_RESET}                                                            ${C_RED}█${C_RESET}"
        echo -e "  ${C_RED}█${C_RESET}  ${C_YELLOW}ВНИМАНИЕ! Шейпер ещё не знает про Белый список!${C_RESET}           ${C_RED}█${C_RESET}"
        echo -e "  ${C_RED}█${C_RESET}  ${C_WHITE}Тебе нужно нажать ${C_GREEN}[7] 🔄 Перезапустить движок${C_WHITE} в меню,${C_RESET}       ${C_RED}█${C_RESET}"
        echo -e "  ${C_RED}█${C_RESET}  ${C_WHITE}чтобы новая версия загрузилась в ядро системы.${C_RESET}            ${C_RED}█${C_RESET}"
        echo -e "  ${C_RED}█${C_RESET}                                                            ${C_RED}█${C_RESET}"
        echo -e "  ${C_RED}██████████████████████████████████████████████████████████████${C_RESET}"
    fi
    echo
}

_tl_complete_cleanup_wizard() {
    if ask_yes_no "Полностью удалить шейпер?"; then
        _tl_cleanup_old_system; rm -rf "${TL_CONFIG_DIR}"; ok "Всё удалено.";
    fi
}

_tl_view_service_log() {
    clear; menu_header "Логи"; journalctl -u "${TL_SERVICE_NAME}" -n 50 --no-pager
}

_tl_monitor_traffic() {
    ensure_package "iftop"
    local iface; iface=$(_tl_select_interface) || return

    # Определяем текущий лимит из конфига для заголовка
    local limit_str="не настроен"
    local cfg_file; cfg_file=$(python3 "${TL_CTRL_PY_PATH}" --pin-dir "${TL_BPF_PIN_DIR}/maps" status 2>/dev/null | grep 'Лимит DL' | awk '{print $NF}' || true)
    [[ -n "$cfg_file" ]] && limit_str="${cfg_file}"

    clear
    echo -e "${C_CYAN}╔══════════════════════════════════════════════════════════╗${C_RESET}"
    echo -e "${C_CYAN}║${C_RESET}  ${C_YELLOW}📈 Мониторинг трафика${C_RESET}  •  Интерфейс: ${C_GREEN}${iface}${C_RESET}"
    echo -e "${C_CYAN}║${C_RESET}  Единицы: ${C_WHITE}МБ/с (байты)${C_RESET}  •  Лимит шейпера: ${C_YELLOW}${limit_str}${C_RESET}"
    echo -e "${C_CYAN}║${C_RESET}  ${C_GRAY}Управление: [P] пауза  [J/K] скролл  [Q] выход${C_RESET}"
    echo -e "${C_CYAN}╚══════════════════════════════════════════════════════════╝${C_RESET}"
    echo
    sleep 1

    # -B = байты (МБ/с вместо Мбит/с), -n = без DNS, -N = без имён портов
    iftop -B -n -N -i "$iface"
}

_tl_select_interface() {
    local ifaces=($(ip -o link show | awk -F': ' '{print $2}' | grep -v 'lo'))
    if [[ ${#ifaces[@]} -eq 0 ]]; then return 1; fi
    if [[ ${#ifaces[@]} -eq 1 ]]; then echo "${ifaces[0]}"; return 0; fi
    local choice; choice=$(ask_selection "Выбери интерфейс:" "${ifaces[@]}") || return 1
    echo "${ifaces[$((choice-1))]}"
}
