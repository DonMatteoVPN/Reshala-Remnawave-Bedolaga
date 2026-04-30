#!/bin/bash
#   ( РОДИТЕЛЬ | КЛАВИША | НАЗВАНИЕ | ФУНКЦИЯ | ПОРЯДОК | ГРУППА | ОПИСАНИЕ )
# @menu.manifest
# @item( security | 1 | 🔥 Firewall (UFW) | show_firewall_menu | 10 | 10 | Настройка правил и портов. )
#
# firewall.sh - Управление Firewall (UFW)
#

# Вызывается из /modules/security/menu.sh

_firewall_check_status() {
    print_separator
    info "Статус Firewall (UFW)"
    if ! command -v ufw &> /dev/null; then
        warn "UFW не установлен."
    elif run_cmd ufw status | grep -q "inactive"; then
        printf_description "Состояние: ${C_RED}Не активен (НЕТ ЗАЩИТЫ!)${C_RESET}"
    else
        printf_description "Состояние: ${C_GREEN}Активен${C_RESET}"
    fi
    print_separator
}

show_firewall_menu() {
    while true; do
        clear
        enable_graceful_ctrlc
        menu_header "🔥 Firewall (UFW)"
        printf_description "Управление правилами межсетевого экрана"

        _firewall_check_status
        
        echo ""
        if ! command -v ufw &> /dev/null; then
            printf_menu_option "i" "УСТАНОВИТЬ UFW FIREWALL" "${C_YELLOW}"
        else
            printf_menu_option "1" "Показать текущие правила"
            printf_menu_option "2" "Перенастроить firewall (мастер)"
            printf_menu_option "3" "Добавить правило"
            printf_menu_option "4" "Удалить правило"
            echo ""
            printf_menu_option "5" "⚙️ Anti-DDoS лимиты (CONN/RATE)"
            printf_menu_option "6" "📊 Логи и Аналитика (Кто атакует?)"
            echo ""
            printf_menu_option "s" "Показать статус UFW (systemd)"
            printf_menu_option "e" "Включить UFW"
            printf_menu_option "d" "Выключить UFW"
            printf_menu_option "r" "Сбросить все правила ${C_RED}(ОПАСНО)${C_RESET}"
        fi
        echo ""
        printf_menu_option "b" "Назад"
        echo ""

        local choice
        choice=$(safe_read "Выберите действие" "") || { break; }
        
        case "$choice" in
            i|I)
                if ! command -v ufw &> /dev/null; then
                    _firewall_install_ufw
                    wait_for_enter
                fi
                ;;
            1)
                _firewall_show_rules
                wait_for_enter
                ;;
            2)
                _firewall_reconfigure_wizard
                wait_for_enter
                ;;
            3)
                _firewall_add_rule
                wait_for_enter
                ;;
            4)
                _firewall_delete_rule
                wait_for_enter
                ;;
            5)
                _firewall_antiddos_menu
                ;;
            6)
                _firewall_logs_analytics
                wait_for_enter
                ;;
            s|S)
                if ! command -v ufw &> /dev/null; then err "UFW не установлен."; else run_cmd systemctl status ufw; fi
                wait_for_enter
                ;;
            e|E)
                if ! command -v ufw &> /dev/null; then err "UFW не установлен."; else info "Включаю UFW..."; echo "y" | run_cmd ufw enable; fi
                ;;
            d|D)
                if ! command -v ufw &> /dev/null; then err "UFW не установлен."; elif ask_yes_no "Вы уверены, что хотите отключить firewall?"; then
                    warn "Отключаю UFW..."
                    echo "y" | run_cmd ufw disable
                fi
                ;;
            r|R)
                if ! command -v ufw &> /dev/null; then
                    err "UFW не установлен."
                else
                    printf "%b" "${C_RED}Сбросить ВСE правила UFW? Это действие необратимо.${C_RESET}"
                    if ask_yes_no " "; then
                        warn "Сбрасываю UFW..."
                        echo "y" | run_cmd ufw --force reset
                    fi
                fi
                ;;

            b | B) 
                break
                ;;
            *)
                warn "Неверный выбор"
                ;;
        esac
        disable_graceful_ctrlc
    done
}

_firewall_show_rules() {
    print_separator
    info "Текущие правила Firewall (UFW)"
    print_separator

    if ! command -v ufw &> /dev/null; then
        err "UFW не установлен. Установите его: apt install ufw"
        return 1
    fi
    
    if run_cmd ufw status | grep -q "inactive"; then
        warn "UFW не активен. Все порты открыты!"
        return 1
    fi
    
    ok "UFW активен."
    
    info "Политика по умолчанию:"
    local default_in
    default_in=$(run_cmd ufw status verbose | grep "Default:")
    if echo "$default_in" | grep -q "deny (incoming)"; then
        printf_description "  Входящие: ${C_GREEN}Блокируются${C_RESET} (рекомендуется)"
    else
        printf_description "  Входящие: ${C_RED}Разрешены${C_RESET} (опасно!)"
    fi
     if echo "$default_in" | grep -q "allow (outgoing)"; then
        printf_description "  Исходящие: ${C_GREEN}Разрешены${C_RESET} (стандарт)"
    else
        printf_description "  Исходящие: ${C_RED}Блокируются${C_RESET} (нестандартно)"
    fi

    info "Активные правила:"
    
    local rules_output
    rules_output=$(run_cmd ufw status)
    
    if ! echo "$rules_output" | grep -q "ALLOW"; then
        warn "Не найдено разрешающих правил."
        return
    fi
    
    # Получаем текущий SSH порт
    local ssh_port
    ssh_port=$(grep "^Port " /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    ssh_port=${ssh_port:-22}
    
    echo "$rules_output" | while IFS= read -r line; do
        if ! echo "$line" | grep -q "ALLOW"; then continue; fi
        if echo "$line" | grep -qE "\(v6\)"; then continue; fi # Skip IPv6 for brevity

        local target action source
        # Use awk to handle potentially inconsistent spacing
        target=$(echo "$line" | awk '{print $1}')
        action=$(echo "$line" | awk '{print $2}')
        source=$(echo "$line" | awk '{print $3}')
        
        if [[ "$action" != "ALLOW" ]]; then continue; fi
        
        local port_num
        port_num=$(echo "$target" | cut -d'/' -f1)
        
        if ! [[ "$port_num" =~ ^[0-9]+$ ]]; then
             if [[ "$target" == "Anywhere" ]]; then
                printf_description "  ${C_GREEN}● Полный доступ${C_RESET} ← от ${C_CYAN}${source}${C_RESET}"
             fi
             continue
        fi

        local desc=""
        if [[ "$port_num" == "$ssh_port" ]]; then
            desc="SSH"
        else
            case "$port_num" in
                22) desc="SSH (стандартный)" ;;
                80) desc="HTTP" ;;
                443) desc="HTTPS/VPN" ;;
                2222) desc="Панель/Нода" ;;
                3306) desc="MySQL" ;;
            esac
        fi
        
        local source_display="для всех"
        if [[ "$source" != "Anywhere" ]]; then
            source_display="только с ${C_CYAN}${source}${C_RESET}"
        fi
        
        printf_description "  ${C_YELLOW}● Порт ${C_CYAN}${target}${C_RESET} открыт ${source_display} ${C_WHITE}${desc:+($desc)}${C_RESET}"
    done
}

_firewall_reconfigure_wizard() {
    if ! command -v ufw &> /dev/null; then
        err "UFW не установлен. Действие отменено."
        return 1
    fi

    print_separator
    info "Мастер перенастройки Firewall"
    print_separator
    
    if ! ask_yes_no "Мастер сбросит все текущие правила и создаст новые. Продолжить?"; then
        info "Отмена."
        return
    fi

    echo ""
    info "Шаг 1: Роль сервера"
    local role_choice
    role_choice=$(ask_selection "" "Это главный сервер (Панель управления)" "Это управляемый узел (Нода Skynet)") || return

    echo ""
    info "Шаг 2: Настройка доступа"
    
    local ssh_port
    ssh_port=$(get_config_var "SSH_PORT")
    ssh_port=${ssh_port:-22}
    ssh_port=$(safe_read "SSH порт" "$ssh_port") || return

    local admin_ip
    admin_ip=$(safe_read "IP администратора (оставьте пустым для доступа отовсюду)" "") || return
    if [[ -n "$admin_ip" ]] && ! validate_ip "$admin_ip"; then
        err "Некорректный IP администратора."
        return
    fi

    local panel_ip=""
    if [[ "$role_choice" == "2" ]]; then # Если это Нода
        panel_ip=$(ask_non_empty "IP адрес Панели управления (для полного доступа)") || return
        if ! validate_ip "$panel_ip"; then
            err "Некорректный IP панели."
            return
        fi
    fi
    
    # Отключаем IPv6 в UFW
    if [[ -f "/etc/default/ufw" ]] && grep -q "^IPV6=yes" "/etc/default/ufw"; then
        run_cmd sed -i 's/^IPV6=yes/IPV6=no/' "/etc/default/ufw"
    fi

    info "Применяю новые правила..."
    run_cmd ufw --force reset
    run_cmd ufw default deny incoming
    run_cmd ufw default allow outgoing

    # SSH
    if [[ -n "$admin_ip" ]]; then
        run_cmd ufw allow from "$admin_ip" to any port "$ssh_port" proto tcp comment 'Admin SSH'
        ok "SSH (порт $ssh_port) разрешен для $admin_ip"
    else
        run_cmd ufw allow "$ssh_port"/tcp comment 'SSH'
        warn "SSH (порт $ssh_port) разрешен для всех IP!"
    fi

    if [[ "$role_choice" == "1" ]]; then # Панель
        run_cmd ufw allow 80/tcp comment 'HTTP'
        run_cmd ufw allow 443/tcp comment 'HTTPS'
        ok "Открыты порты 80 (HTTP) и 443 (HTTPS)."
    else # Нода
        if [[ -n "$panel_ip" ]]; then
            run_cmd ufw allow from "$panel_ip" comment 'Panel Full Access'
            ok "Предоставлен полный доступ для Панели ($panel_ip)."
        fi
        run_cmd ufw allow 443/tcp comment 'VPN/HTTPS'
        ok "Открыт порт 443 (VPN/HTTPS)."
        
        if ask_yes_no "Открыть доп. порты для VPN на ноде?"; then
            local extra_ports
            extra_ports=$(safe_read "Введите порты через пробел (напр. 8443 9443)" "")
            for port in $extra_ports; do
                if validate_port "$port"; then
                    run_cmd ufw allow "$port" comment 'Custom VPN'
                    ok "Открыт дополнительный порт $port"
                else
                    warn "Пропущен некорректный порт: $port"
                fi
            done
        fi
    fi
    
    echo ""
    if ask_yes_no "Все правила добавлены. Включить firewall?"; then
        echo "y" | run_cmd ufw enable
        ok "Firewall включен и работает."
    fi
}

_firewall_add_rule() {
    if ! command -v ufw &> /dev/null; then
        err "UFW не установлен. Действие отменено."
        return 1
    fi

    print_separator
    info "Добавление нового правила UFW"
    print_separator

    printf_menu_option "1" "Открыть порт"
    printf_menu_option "2" "Добавить IP в whitelist (полный доступ)"
    printf_menu_option "b" "Назад"
    echo ""
    
    local choice
    choice=$(safe_read "Выберите тип правила" "") || return

    case "$choice" in
        1)
            local port
            port=$(ask_non_empty "Какой порт открыть?") || return
            if ! validate_port "$port"; then
                err "Некорректный номер порта."
                return
            fi

            local ip
            ip=$(safe_read "Разрешить только для одного IP? (оставьте пустым для всех)" "") || return
            if [[ -n "$ip" ]] && ! validate_ip "$ip"; then
                err "Некорректный IP адрес."
                return
            fi

            if [[ -n "$ip" ]]; then
                if ask_yes_no "Открыть порт ${port} только для IP ${ip}?"; then
                    run_cmd ufw allow from "$ip" to any port "$port" comment "Manual Rule"
                    ok "Правило добавлено."
                fi
            else
                if ask_yes_no "Открыть порт ${port} для всех?"; then
                    run_cmd ufw allow "$port" comment "Manual Rule"
                    ok "Правило добавлено."
                fi
            fi
            ;;
        2)
            local ip
            ip=$(ask_non_empty "Какой IP добавить в whitelist?") || return
            if ! validate_ip "$ip"; then
                err "Некорректный IP адрес."
                return
            fi

            if ask_yes_no "Дать полный доступ IP ${ip}?"; then
                run_cmd ufw allow from "$ip" comment "Manual Whitelist"
                ok "IP ${ip} добавлен в whitelist."
            fi
            ;;
        b|B)
            return
            ;;
        *)
            warn "Неверный выбор"
            ;;
    esac
}

_firewall_delete_rule() {
    if ! command -v ufw &> /dev/null; then
        err "UFW не установлен. Действие отменено."
        return 1
    fi

    print_separator
    info "Удаление правила UFW"
    print_separator

    if ! run_cmd ufw status numbered | grep -q "\["; then
        warn "Нет правил для удаления."
        return
    fi
    
    run_cmd ufw status numbered
    echo ""

    local rule_num
    rule_num=$(ask_non_empty "Введите номер правила для удаления") || return

    if ! [[ "$rule_num" =~ ^[0-9]+$ ]]; then
        err "Нужно ввести число."
        return
    fi

    # Check if rule exists
    if ! run_cmd ufw status numbered | grep -q "\[\s*${rule_num}\s*\]"; then
        err "Правила с номером ${rule_num} не существует."
        return
    fi

    if ask_yes_no "Вы уверены, что хотите удалить правило номер ${rule_num}?"; then
        echo "y" | run_cmd ufw delete "$rule_num"
        ok "Правило ${rule_num} удалено."
    fi
}

# ============================================================ #
#            ANTI-DDOS ЛИМИТЫ (CONN/RATE в before.rules)       #
# ============================================================ #

ANTIDDOS_MARKER_START="# --- НАЧАЛО: Reshala Anti-DDoS ---"
ANTIDDOS_MARKER_END="# --- КОНЕЦ: Reshala Anti-DDoS ---"

_firewall_antiddos_menu() {
    while true; do
        clear
        enable_graceful_ctrlc
        menu_header "⚙️ Anti-DDoS лимиты"
        printf_description "Управление CONN/RATE лимитами в UFW before.rules."

        # Показываем текущие лимиты
        local before_rules="/etc/ufw/before.rules"
        if [[ -f "$before_rules" ]] && grep -q "$ANTIDDOS_MARKER_START" "$before_rules"; then
            local conn_limit rate_limit
            conn_limit=$(grep "connlimit-above" "$before_rules" | head -1 | grep -oP '\d+' | tail -1)
            rate_limit=$(grep "hashlimit-above" "$before_rules" | head -1 | grep -oP '[0-9]+/sec' | head -1)
            info "Текущие лимиты:"
            printf_description "  CONN: ${C_CYAN}${conn_limit:-не задан}${C_RESET} одновременных подключений"
            printf_description "  RATE: ${C_CYAN}${rate_limit:-не задан}${C_RESET}"
        else
            warn "Anti-DDoS лимиты не настроены."
        fi

        print_separator
        echo ""
        printf_menu_option "1" "🔧 Настроить лимиты"
        printf_menu_option "2" "🗑️  Удалить все лимиты"
        printf_menu_option "3" "📋 Показать блок в before.rules"
        echo ""
        printf_menu_option "b" "Назад"
        echo ""

        local choice
        choice=$(safe_read "Выберите действие" "") || { break; }

        case "$choice" in
            1) _antiddos_setup_limits; wait_for_enter;;
            2)
                if ask_yes_no "Удалить все Anti-DDoS лимиты?"; then
                    _antiddos_remove_block
                    run_cmd ufw reload 2>/dev/null || true
                    ok "Anti-DDoS лимиты удалены."
                fi
                wait_for_enter
                ;;
            3)
                if [[ -f "$before_rules" ]]; then
                    sed -n "/${ANTIDDOS_MARKER_START}/,/${ANTIDDOS_MARKER_END}/p" "$before_rules"
                else
                    warn "Файл before.rules не найден."
                fi
                wait_for_enter
                ;;
            b|B) break;;
            *) warn "Неверный выбор";;
        esac
        disable_graceful_ctrlc
    done
}

_antiddos_setup_limits() {
    print_separator
    info "Настройка Anti-DDoS лимитов"
    print_separator

    local conn_limit rate_limit
    conn_limit=$(ask_number_in_range "Лимит подключений (CONN, рекомендуется 50-150)" 10 1000 "100") || return
    rate_limit=$(ask_number_in_range "Лимит пакетов/сек (RATE, рекомендуется 25-100)" 5 500 "50") || return

    info "Применяю: CONN=${conn_limit}, RATE=${rate_limit}/sec..."

    # Удаляем старый блок
    _antiddos_remove_block

    local before_rules="/etc/ufw/before.rules"
    [[ ! -f "$before_rules" ]] && { err "Файл before.rules не найден!"; return; }

    # Собираем whitelist IP
    local wl_rules=""
    if command -v global_whitelist_get_ips &>/dev/null; then
        local ips
        mapfile -t ips < <(global_whitelist_get_ips)
        for ip in "${ips[@]}"; do
            wl_rules+="# Whitelist: ${ip}\n-A ufw-before-input -s ${ip} -j ACCEPT\n"
        done
    fi

    # Вставляем через Python (безопасная точечная вставка)
    python3 - "$before_rules" "$conn_limit" "$rate_limit" "$wl_rules" <<'PYEOF'
import sys, re
rules_file = sys.argv[1]
conn = sys.argv[2]
rate = sys.argv[3]
wl = sys.argv[4] if len(sys.argv) > 4 else ""

with open(rules_file, 'r') as f:
    content = f.read()

block = f"""
{wl}# --- НАЧАЛО: Reshala Anti-DDoS ---
# CONN limit: max {conn} connections per IP
-A ufw-before-input -p tcp --syn -m connlimit --connlimit-above {conn} --connlimit-mask 32 -j DROP
# RATE limit: max {rate} packets/sec per IP
-A ufw-before-input -p tcp -m hashlimit --hashlimit-above {rate}/sec --hashlimit-burst {int(int(rate)*2)} --hashlimit-mode srcip --hashlimit-name reshala_rate -j DROP
# ICMP flood protection
-A ufw-before-input -p icmp --icmp-type echo-request -m limit --limit 1/s --limit-burst 4 -j ACCEPT
-A ufw-before-input -p icmp --icmp-type echo-request -j DROP
# --- КОНЕЦ: Reshala Anti-DDoS ---
"""

target = ':ufw-before-input - [0:0]'
if target in content:
    content = content.replace(target, target + block, 1)
    with open(rules_file, 'w') as f:
        f.write(content)
    print("OK")
else:
    print("ERROR: target not found")
    sys.exit(1)
PYEOF

    if [[ $? -eq 0 ]]; then
        run_cmd ufw reload 2>/dev/null || true
        ok "Anti-DDoS лимиты применены: CONN=${conn_limit}, RATE=${rate_limit}/sec"
    else
        err "Не удалось применить лимиты."
    fi
}

_antiddos_remove_block() {
    local before_rules="/etc/ufw/before.rules"
    [[ ! -f "$before_rules" ]] && return

    python3 - <<'PYEOF'
import re
with open('/etc/ufw/before.rules', 'r') as f:
    content = f.read()
content = re.sub(r'\n# --- НАЧАЛО: Reshala Anti-DDoS ---.*?# --- КОНЕЦ: Reshala Anti-DDoS ---\n', '', content, flags=re.DOTALL)
# Also remove whitelist entries above it
content = re.sub(r'\n# Whitelist: [^\n]+\n-A ufw-before-input -s [^\n]+ -j ACCEPT\n', '', content)
with open('/etc/ufw/before.rules', 'w') as f:
    f.write(content)
PYEOF
}

# ============================================================ #
#                   ЛОГИ И АНАЛИТИКА                           #
# ============================================================ #

_firewall_logs_analytics() {
    print_separator
    menu_header "📊 Логи и Аналитика UFW"
    print_separator

    if ! command -v ufw &>/dev/null; then
        err "UFW не установлен."
        return
    fi

    local log_file; log_file=$(find_log_file "ufw")
    if [[ ! -f "$log_file" ]]; then
        warn "Файлы логов UFW не найдены."
        return
    fi

    # ТОП-10 атакующих IP
    info "ТОП-10 IP, заблокированных UFW:"
    print_separator "-" 50
    grep "\[UFW BLOCK\]" "$log_file" 2>/dev/null | \
        grep -oP 'SRC=\K[0-9.]+' | \
        sort | uniq -c | sort -rn | head -10 | \
        while read count ip; do
            printf "  ${C_RED}%-8s${C_RESET} ${C_CYAN}%s${C_RESET}\n" "${count} блок." "$ip"
        done

    echo ""

    # ТОП-10 портов
    info "ТОП-10 атакуемых портов:"
    print_separator "-" 50
    grep "\[UFW BLOCK\]" "$log_file" 2>/dev/null | \
        grep -oP 'DPT=\K[0-9]+' | \
        sort | uniq -c | sort -rn | head -10 | \
        while read count port; do
            printf "  ${C_YELLOW}%-8s${C_RESET} Порт ${C_CYAN}%s${C_RESET}\n" "${count} блок." "$port"
        done

    echo ""

    # Общая статистика
    local total_blocks
    total_blocks=$(grep -c "\[UFW BLOCK\]" "$log_file" 2>/dev/null || echo "0")
    ok "Всего блокировок в логе: ${C_RED}${total_blocks}${C_RESET}"

    echo ""
    if ask_yes_no "Показать живой мониторинг блокировок? (Ctrl+C для выхода)" "n"; then
        enable_graceful_ctrlc
        tail -f "$log_file" | grep --line-buffered "\[UFW BLOCK\]"
        disable_graceful_ctrlc
    fi
}

_firewall_install_ufw() {
    print_separator
    info "Установка UFW Firewall..."
    
    if run_cmd apt update && run_cmd apt install -y ufw; then
        ok "UFW успешно установлен."
        
        # Сразу предлагаем базовую настройку, чтобы юзер не закрыл себе доступ
        info "Настройка базовых правил (SSH разрешен)..."
        run_cmd ufw allow ssh
        run_cmd ufw default deny incoming
        run_cmd ufw default allow outgoing
        
        if ask_yes_no "Включить Firewall сейчас?"; then
            echo "y" | run_cmd ufw enable
        fi
    else
        err "Не удалось установить UFW. Проверьте интернет-соединение или репозитории."
    fi
}
