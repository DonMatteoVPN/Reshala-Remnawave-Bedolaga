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

        printf_menu_option "1" "📊 Текущий статус (Топ-IP) ${status_icon}"
        printf_menu_option "2" "➕ Настроить лимиты (eBPF)"
        printf_menu_option "3" "🧹 Полная очистка системы"
        printf_menu_option "4" "📜 Посмотреть лог сервиса"
        printf_menu_option "5" "🔄 Перезапустить движок"
        printf_menu_option "6" "📈 Мониторинг (iftop)"
        echo; printf_menu_option "b" "🔙 Назад"; print_separator "-" 60

        local choice; choice=$(safe_read "Твой выбор") || break
        if [[ "$choice" == "b" || "$choice" == "B" ]]; then break; fi
        case "$choice" in
            1) _tl_show_status ;; 
            2) _tl_apply_limit_ebpf_wizard ;; 
            3) _tl_complete_cleanup_wizard ;; 
            4) _tl_view_service_log ;; 
            5) _tl_restart_ebpf_engine ;;
            6) _tl_monitor_traffic ;;
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
    ip -o link show up | awk -F': ' '{print $2}' | grep -v '^lo$' | while read -r iface; do
        tc qdisc del dev "$iface" root &>/dev/null || true
        tc qdisc del dev "$iface" clsact &>/dev/null || true
        tc qdisc del dev "$iface" ingress &>/dev/null || true
    done
    modprobe -r ifb &>/dev/null || true
    ok "Очистка завершена."
}

_tl_show_listening_ports_smart() {
    info "Активные порты прямо сейчас:"
    echo "------------------------------------------------------------"
    ss -tulnp | grep LISTEN | awk '{print $5, $7}' | sed 's/::://g; s/0.0.0.0://g' | awk -F'[: ]' '{print "  • Порт:", $2, "->", $3}' | sort -u
    echo "------------------------------------------------------------"
}

_tl_apply_limit_ebpf_wizard() {
    _tl_ensure_ebpf_deps || return
    clear; menu_header "eBPF Шейпер: Шаг 1 (Интерфейс)"
    local iface; iface=$(_tl_select_interface) || return

    clear; menu_header "eBPF Шейпер: Шаг 2 (Режим)"
    printf_menu_option "1" "Статический (Простой лимит)"
    printf_menu_option "2" "Динамический (Квоты + Штраф)"
    local mode; mode=$(ask_number_in_range "Выбери режим" 1 2 1) || return

    clear; menu_header "eBPF Шейпер: Шаг 3 (Порт)"
    _tl_show_listening_ports_smart
    local port; port=$(safe_read "Целевой порт (0 = ВСЕ ПОРТЫ)" "0") || return

    clear; menu_header "eBPF Шейпер: Шаг 4 (Скорости)"
    local down_speed; down_speed=$(ask_number_in_range "Скачивание (DL) Мбит/с" 1 10000 50) || return
    local up_speed; up_speed=$(ask_number_in_range "Загрузка (UL) Мбит/с" 1 10000 50) || return
    
    local pspeed=10; local burst=100; local win=10; local pen=60
    if [[ "$mode" == "2" ]]; then
        pspeed=$(ask_number_in_range "Скорость при ШТРАФЕ (Мбит/с)" 1 1000 10) || return
        burst=$(ask_number_in_range "Квота на Burst (Мбайт)" 1 50000 100) || return
        win=$(ask_number_in_range "Окно проверки (секунд)" 1 3600 10) || return
        pen=$(ask_number_in_range "Длительность штрафа (секунд)" 1 3600 60) || return
    fi

    clear; menu_header "Финальная проверка"
    print_key_value "Интерфейс" "$iface" 25
    print_key_value "Режим" "$( [[ "$mode" == "1" ]] && echo "Статика" || echo "Динамика" )" 25
    print_key_value "Порт" "$port" 25
    print_key_value "Download" "$down_speed Мбит/с" 25
    print_key_value "Upload" "$up_speed Мбит/с" 25
    echo
    if ! ask_yes_no "Применить?"; then return; fi

    _tl_cleanup_old_system
    _tl_compile_bpf || return
    mkdir -p "${TL_CONFIG_DIR}"
    cat << EOF > "${TL_CONFIG_DIR}/ebpf_config.conf"
IFACE="${iface}"
MODE="${mode}"
PORT="${port}"
DOWN="${down_speed}"
UP="${up_speed}"
BURST="${burst}"
WIN="${win}"
PEN="${pen}"
EOF

    _tl_generate_ebpf_service_file > "${TL_SERVICE_PATH}"
    systemctl daemon-reload && systemctl enable "${TL_SERVICE_NAME}"
    if systemctl restart "${TL_SERVICE_NAME}"; then ok "Движок запущен!"; else err "Ошибка запуска!"; fi
}

_tl_generate_ebpf_service_file() {
    source "${TL_CONFIG_DIR}/ebpf_config.conf"
    cat << EOF
[Unit]
Description=Reshala eBPF Traffic Limiter (DL/UL)
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=-/sbin/modprobe ifb numifbs=1
ExecStartPre=-/sbin/ip link set dev ifb0 up
ExecStartPre=-/sbin/tc qdisc del dev ${IFACE} root
ExecStartPre=-/sbin/tc qdisc del dev ${IFACE} clsact
ExecStartPre=/sbin/tc qdisc add dev ${IFACE} root fq
ExecStartPre=/sbin/tc qdisc add dev ${IFACE} clsact
ExecStartPre=/sbin/tc filter add dev ${IFACE} egress bpf direct-action obj ${TL_BPF_OBJ_PATH} sec classifier/down
ExecStartPre=/sbin/tc filter add dev ${IFACE} ingress bpf direct-action obj ${TL_BPF_OBJ_PATH} sec classifier/down
ExecStartPre=/sbin/tc filter add dev ${IFACE} ingress protocol all prio 1 u32 match u32 0 0 action mirred egress redirect dev ifb0
ExecStartPre=-/sbin/tc qdisc del dev ifb0 root
ExecStartPre=/sbin/tc qdisc add dev ifb0 root fq
ExecStartPre=/sbin/tc filter add dev ifb0 egress bpf direct-action obj ${TL_BPF_OBJ_PATH} sec classifier/up
ExecStart=/usr/bin/python3 ${TL_CTRL_PY_PATH} set --mode ${MODE} --port ${PORT} --down ${DOWN} --up ${UP} --burst ${BURST} --win ${WIN} --pen ${PEN}
ExecStop=/sbin/tc qdisc del dev ${IFACE} root
ExecStop=/sbin/tc qdisc del dev ${IFACE} clsact
ExecStop=/sbin/ip link set dev ifb0 down

[Install]
WantedBy=multi-user.target
EOF
}

_tl_show_status() {
    if ! systemctl is-active --quiet "${TL_SERVICE_NAME}"; then warn "Не запущен."; return; fi
    clear; menu_header "Статистика eBPF шейпера"
    python3 "${TL_CTRL_PY_PATH}" status
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
    iftop -n -i "$iface"
}

_tl_select_interface() {
    local ifaces=($(ip -o link show | awk -F': ' '{print $2}' | grep -v 'lo'))
    if [[ ${#ifaces[@]} -eq 0 ]]; then return 1; fi
    if [[ ${#ifaces[@]} -eq 1 ]]; then echo "${ifaces[0]}"; return 0; fi
    local choice; choice=$(ask_selection "Выбери интерфейс:" "${ifaces[@]}") || return 1
    echo "${ifaces[$((choice-1))]}"
}
