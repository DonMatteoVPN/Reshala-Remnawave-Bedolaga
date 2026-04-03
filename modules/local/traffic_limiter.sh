#!/bin/bash
# ============================================================ #
# ==                 МОДУЛЬ ШЕЙПЕРА ТРАФИКА                 == #
# ==                      VERSION 3.1 (eBPF)                 == #
# ============================================================ #
#
# Отвечает за современное ограничение скорости с использованием
# eBPF + EDT (Earliest Departure Time). 
# Обеспечивает 0% коллизий, поддержку IPv6 и раздельный лимит DL/UL.
#
# ВЕРСИОНИРОВАНИЕ:
#   v3.1 (29.03.2025) - Исправлены ошибки компиляции, добавлен раздельный DL/UL
#   v3.0 (29.03.2025) - Переход на eBPF + EDT (0% коллизий, IPv6)
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

# ============================================================ #
# ==                  ГЛОБАЛЬНАЯ КОНФИГУРАЦИЯ               == #
# ============================================================ #

readonly TL_MODULE_VERSION="3.1 (eBPF)"
readonly TL_CONFIG_DIR="/etc/reshala/traffic_limiter"
readonly TL_BPF_SRC_PATH="${SCRIPT_DIR}/modules/local/shaper.bpf.c"
readonly TL_BPF_OBJ_PATH="${TL_CONFIG_DIR}/shaper.bpf.o"
readonly TL_CTRL_PY_PATH="${SCRIPT_DIR}/modules/local/reshala_ctrl.py"
readonly TL_SERVICE_NAME="reshala-traffic-limiter.service"
readonly TL_SERVICE_PATH="/etc/systemd/system/${TL_SERVICE_NAME}"
readonly TL_OLD_APPLY_SCRIPT="/usr/local/bin/reshala-traffic-limiter-apply.sh"
readonly TL_BPF_PIN_DIR="/sys/fs/bpf/reshala"

# ============================================================ #
# ==                      ГЛАВНОЕ МЕНЮ                      == #
# ============================================================ #

show_traffic_limiter_menu() {
    local kernel_ver; kernel_ver=$(uname -r | cut -d. -f1,2)
    if (( $(echo "$kernel_ver < 5.4" | bc -l) )); then
        clear; menu_header "🚦 Шейпер трафика (eBPF)"
        printf_critical_warning "ОШИБКА: Твое ядро ($kernel_ver) слишком старое для eBPF шейпера (нужно 5.4+)."
        wait_for_enter; return
    fi

    enable_graceful_ctrlc
    while true; do
        clear; menu_header "🚦 Шейпер трафика (eBPF + EDT) v${TL_MODULE_VERSION}"
        local is_active="false"; if systemctl is-active --quiet ${TL_SERVICE_NAME}; then is_active="true"; fi
        local status_icon="${C_GRAY}[∅ Не настроен]${C_RESET}"
        if [[ "$is_active" == "true" ]]; then status_icon="${C_GREEN}[✓ Работает: eBPF активен]${C_RESET}"; fi

        printf_menu_option "1" "📋 Активные правила ${status_icon}"
        printf_menu_option "2" "📊 Статистика (топ IP по правилам)"
        printf_menu_option "3" "➕ Добавить / изменить правило"
        printf_menu_option "4" "🗑  Удалить правило"
        printf_menu_option "5" "🧹 Полная очистка системы"
        printf_menu_option "6" "📜 Посмотреть лог сервиса"
        printf_menu_option "7" "🔄 Перезапустить движок"
        printf_menu_option "8" "📈 Мониторинг (iftop)"
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
    ensure_dependencies "clang" "llvm" "libbpf-dev" "bpftool" "python3" "bc" "kmod"
    local kheaders="linux-headers-$(uname -r)"
    if ! dpkg -s "$kheaders" &>/dev/null; then
        info "Устанавливаю заголовки ядра $kheaders..."
        apt-get update && apt-get install -y "$kheaders"
    fi
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
    # Удаляем IFB интерфейс полностью (иначе "File exists" при следующем запуске)
    ip link set dev ifb0 down &>/dev/null || true
    ip link del dev ifb0 &>/dev/null || true
    # Удаляем пинингованные BPF-карты (иначе "several maps match this handle")
    rm -rf "${TL_BPF_PIN_DIR}" &>/dev/null || true
    ok "Очистка завершена."
}

_tl_show_listening_ports_smart() {
    info "Активные порты прямо сейчас:"
    echo "------------------------------------------------------------"
    ss -tulnp | grep LISTEN | awk '{print $5, $7}' | sed 's/::://g; s/0.0.0.0://g' | awk -F'[: ]' '{print "  • Порт:", $2, "->", $3}' | sort -u
    echo "------------------------------------------------------------"
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
    echo -e "  ${C_CYAN}║${C_RESET}  ${C_YELLOW}⚡ Reshala eBPF Traffic Shaper v3.1${C_RESET}"
    echo -e "  ${C_CYAN}╠══════════════════════════════════════════════════════════╣${C_RESET}"
    echo -e "  ${C_CYAN}║${C_RESET}  ${C_GRAY}Что это?${C_RESET}"
    echo -e "  ${C_CYAN}║${C_RESET}  Ограничитель скорости на базе ${C_YELLOW}eBPF + EDT${C_RESET} (Linux ядро)"
    echo -e "  ${C_CYAN}║${C_RESET}  Работает на уровне ${C_YELLOW}L3/L4${C_RESET} (IP + TCP/UDP)"
    echo -e "  ${C_CYAN}║${C_RESET}  ${C_GREEN}✔${C_RESET} Лимит отдельно по каждому IP-адресу"
    echo -e "  ${C_CYAN}║${C_RESET}  ${C_GREEN}✔${C_RESET} Раздельные лимиты Download и Upload"
    echo -e "  ${C_CYAN}║${C_RESET}  ${C_GREEN}✔${C_RESET} Полная поддержка IPv4 и IPv6"
    echo -e "  ${C_CYAN}║${C_RESET}  ${C_GREEN}✔${C_RESET} 0%% коллизий (eBPF Hash Map по IP)"
    echo -e "  ${C_CYAN}║${C_RESET}  ${C_GREEN}✔${C_RESET} До 32 портов одновременно"
    echo -e "  ${C_CYAN}╠══════════════════════════════════════════════════════════╣${C_RESET}"
    echo -e "  ${C_CYAN}║${C_RESET}  ${C_GRAY}Как работает?${C_RESET}"
    echo -e "  ${C_CYAN}║${C_RESET}  ${C_YELLOW}Download${C_RESET}: ens3 → ${C_GREEN}eBPF (EDT)${C_RESET} → fq qdisc → Пользователь"
    echo -e "  ${C_CYAN}║${C_RESET}  ${C_YELLOW}Upload${C_RESET}  : Пользователь → IFB0 → ${C_GREEN}eBPF (EDT)${C_RESET} → fq qdisc"
    echo -e "  ${C_CYAN}║${C_RESET}  EDT = Earliest Departure Time (точное время отправки пакета)"
    echo -e "  ${C_CYAN}╠══════════════════════════════════════════════════════════╣${C_RESET}"
    echo -e "  ${C_CYAN}║${C_RESET}  ${C_GRAY}Режимы работы${C_RESET}"
    echo -e "  ${C_CYAN}║${C_RESET}  ${C_GREEN}[1] Статический${C_RESET}: жёсткий лимит скорости всегда"
    echo -e "  ${C_CYAN}║${C_RESET}  ${C_YELLOW}[2] Динамический${C_RESET}: burst → квота → штраф → нормальная скорость"
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
    local max_id=$(( MAX_RULES - 1 )) 2>/dev/null || local max_id=31
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
    echo -e "  ${C_GREEN}[1] Статический${C_RESET} — жёсткий лимит скорости всегда"
    echo -e "      ${C_GRAY}Каждый пользователь получает ровно N МБ/с. Просто и предсказуемо.${C_RESET}"
    echo -e "      ${C_CYAN}→ Подходит: VPN, игровые серверы, стабильное качество${C_RESET}"
    echo -e ""
    echo -e "  ${C_YELLOW}[2] Динамический${C_RESET} — burst → квота → штраф → восстановление"
    echo -e "      ${C_GRAY}Быстро до квоты, затем штрафная скорость, потом восстановление.${C_RESET}"
    echo -e "      ${C_CYAN}→ Подходит: ограничение «качальщиков», справедливое распределение${C_RESET}"
    echo -e ""
    echo -e "  ${C_GRAY}─────────────────────────────────────────────────────${C_RESET}"
    local mode; mode=$(ask_number_in_range "Выбери режим" 1 2 1) || return

    # ── Шаг 3: порты ──
    clear; menu_header "eBPF Шейпер: Шаг 3 (Порты)"
    _tl_show_listening_ports_smart
    echo
    info "Можно указать несколько портов через запятую: ${C_YELLOW}443,80,8080${C_RESET} — или ${C_YELLOW}0${C_RESET} для всех"
    local ports_input; ports_input=$(safe_read "Порты (через запятую, 0 = все порты)" "0") || return
    ports_input=$(echo "$ports_input" | tr -d ' ')

    # ── Шаг 4: скорости ──
    clear; menu_header "eBPF Шейпер: Шаг 4 (Скорости)"
    _tl_show_speed_reference
    local down_speed; down_speed=$(ask_number_in_range "Скачивание (DL) МБ/с" 1 5000 5) || return
    local up_speed;   up_speed=$(ask_number_in_range   "Загрузка   (UL) МБ/с" 1 5000 5) || return

    local pspeed=0.1; local burst=100; local win=10; local pen=60
    if [[ "$mode" == "2" ]]; then
        pspeed=$(ask_number_in_range "Скорость при ШТРАФЕ (МБ/с)"   1 1000 1)  || return
        burst=$(ask_number_in_range  "Квота на Burst (МБайт)"        1 50000 100) || return
        win=$(ask_number_in_range    "Окно проверки (секунд)"         1 3600 10)  || return
        pen=$(ask_number_in_range    "Длительность штрафа (секунд)"   1 3600 60)  || return
    fi

    # ── Финальная проверка ──
    clear; menu_header "Финальная проверка"
    print_key_value "Правило #" "$rule_id" 25
    print_key_value "Интерфейс" "$iface" 25
    print_key_value "Режим"     "$( [[ "$mode" == "1" ]] && echo "Статика" || echo "Динамика" )" 25
    print_key_value "Порты"     "$( [[ "$ports_input" == "0" ]] && echo "ВСЕ ПОРТЫ" || echo "$ports_input" )" 25
    print_key_value "Download"  "$down_speed МБ/с  ($(( down_speed * 8 )) Мбит/с)" 25
    print_key_value "Upload"    "$up_speed МБ/с  ($(( up_speed * 8 )) Мбит/с)" 25
    echo
    if ! ask_yes_no "Применить?"; then return; fi

    # ── Применяем ──
    if [[ "$is_active" == "false" ]]; then
        # Первый запуск — полная установка движка
        _tl_cleanup_old_system
        _tl_compile_bpf || return
        mkdir -p "${TL_CONFIG_DIR}"
        cat <<EOF > "${TL_CONFIG_DIR}/ebpf_config.conf"
IFACE="${iface}"
EOF
        _tl_generate_ebpf_service_file > "${TL_SERVICE_PATH}"
        systemctl daemon-reload && systemctl enable "${TL_SERVICE_NAME}"
        if ! systemctl restart "${TL_SERVICE_NAME}"; then
            err "Ошибка запуска движка!"; return
        fi
        ok "Движок запущен!"
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
}

_tl_generate_ebpf_service_file() {
    source "${TL_CONFIG_DIR}/ebpf_config.conf"
    local PIN_PROGS="${TL_BPF_PIN_DIR}/progs"
    local PIN_MAPS="${TL_BPF_PIN_DIR}/maps"
    cat <<EOF
[Unit]
Description=Reshala eBPF Traffic Limiter (Multi-Rule)
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes

# === ПОДГОТОВКА IFB (Upload shaping) ===
ExecStartPre=/sbin/modprobe ifb numifbs=1
ExecStartPre=-/sbin/ip link add ifb0 type ifb
ExecStartPre=/sbin/ip link set dev ifb0 up

# === ОЧИСТКА ===
ExecStartPre=-/sbin/tc qdisc del dev ${IFACE} root
ExecStartPre=-/sbin/tc qdisc del dev ${IFACE} clsact
ExecStartPre=-/sbin/tc qdisc del dev ifb0 root
ExecStartPre=-/sbin/tc qdisc del dev ifb0 clsact
ExecStartPre=/bin/rm -rf ${TL_BPF_PIN_DIR}
ExecStartPre=/bin/mkdir -p ${PIN_PROGS} ${PIN_MAPS}

# === ЗАГРУЗКА BPF-ПРОГРАММ ===
ExecStartPre=/sbin/bpftool prog loadall ${TL_BPF_OBJ_PATH} ${PIN_PROGS} pinmaps ${PIN_MAPS}

# === ИНТЕРФЕЙС ${IFACE} ===
ExecStartPre=/sbin/tc qdisc add dev ${IFACE} root fq
ExecStartPre=/sbin/tc qdisc add dev ${IFACE} clsact
ExecStartPre=/sbin/tc filter add dev ${IFACE} egress bpf direct-action pinned ${PIN_PROGS}/handle_down
ExecStartPre=/sbin/tc filter add dev ${IFACE} ingress protocol all prio 1 u32 match u32 0 0 action mirred egress redirect dev ifb0

# === IFB (Upload path) ===
ExecStartPre=/sbin/tc qdisc add dev ifb0 root fq
ExecStartPre=/sbin/tc qdisc add dev ifb0 clsact
ExecStartPre=/sbin/tc filter add dev ifb0 egress bpf direct-action pinned ${PIN_PROGS}/handle_up

# === ВОССТАНОВЛЕНИЕ ВСЕХ ПРАВИЛ ИЗ rules.json ===
ExecStart=/usr/bin/python3 ${TL_CTRL_PY_PATH} --pin-dir ${PIN_MAPS} --rules-file ${TL_CONFIG_DIR}/rules.json restore

# === ОСТАНОВКА ===
ExecStop=/bin/rm -rf ${TL_BPF_PIN_DIR}
ExecStop=-/sbin/tc qdisc del dev ${IFACE} root
ExecStop=-/sbin/tc qdisc del dev ${IFACE} clsact
ExecStop=-/sbin/tc qdisc del dev ifb0 root
ExecStop=-/sbin/tc qdisc del dev ifb0 clsact
ExecStop=-/sbin/ip link set dev ifb0 down
ExecStop=-/sbin/ip link del dev ifb0

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
    systemctl restart "${TL_SERVICE_NAME}" && ok "Перезапущено."
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
