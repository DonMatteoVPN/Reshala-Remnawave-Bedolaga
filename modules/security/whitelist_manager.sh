#!/bin/bash
#   ( РОДИТЕЛЬ | КЛАВИША | НАЗВАНИЕ | ФУНКЦИЯ | ПОРЯДОК | ГРУППА | ОПИСАНИЕ )
# @menu.manifest
# @item( security | w | 🌍 Глобальный Белый Список | show_global_whitelist_menu | 5 | 5 | Единый whitelist для всех модулей защиты. )
#
# whitelist_manager.sh - Глобальный Белый Список (Unified Whitelist)
#
# Центральный менеджер IP-адресов, которым доверяют ВСЕ модули:
#   - eBPF Шейпер (whitelist_map)
#   - Fail2Ban (ignoreip)
#   - UFW before.rules (обход Anti-DDoS лимитов)
#   - Geo-block ipset (обход блокировки стран)
#
# API для других модулей:
#   global_whitelist_get_ips  — Получить массив IP из глобального списка
#   global_whitelist_add_ip   — Добавить IP и синхронизировать
#   global_whitelist_remove_ip — Удалить IP и синхронизировать
#   global_whitelist_sync_all — Принудительная полная синхронизация
#   global_whitelist_offer    — Предложить использовать глобальный список (вызывается из модулей)
#

[[ "${BASH_SOURCE[0]}" == "${0}" ]] && exit 1

# --- Конфигурация ---
GLOBAL_WHITELIST_DIR="/etc/reshala"
GLOBAL_WHITELIST_FILE="${GLOBAL_WHITELIST_DIR}/global-whitelist.txt"

# ============================================================ #
#                         ПУБЛИЧНЫЙ API                        #
# ============================================================ #

# Инициализирует директорию и файл белого списка
_gwl_ensure_file() {
    if [[ ! -d "$GLOBAL_WHITELIST_DIR" ]]; then
        run_cmd mkdir -p "$GLOBAL_WHITELIST_DIR"
    fi
    if [[ ! -f "$GLOBAL_WHITELIST_FILE" ]]; then
        run_cmd touch "$GLOBAL_WHITELIST_FILE"
        run_cmd chmod 644 "$GLOBAL_WHITELIST_FILE"
        # Создаем шаблон
        cat <<'TEMPLATE' | run_cmd tee "$GLOBAL_WHITELIST_FILE" > /dev/null
# ══════════════════════════════════════════════════════════
# Глобальный Белый Список IP (Reshala Unified Whitelist)
# ══════════════════════════════════════════════════════════
# Все IP из этого файла автоматически получают обход:
#   ✓ eBPF Шейпер      — без ограничений скорости
#   ✓ Fail2Ban         — игнорирование банов
#   ✓ UFW Anti-DDoS    — обход CONN/RATE лимитов
#   ✓ Geo-Block        — обход блокировки стран
#
# Формат: IP # Комментарий
# Пример:
# 185.100.200.50 # Панель управления
# 91.200.100.25  # Мой домашний IP
# 2001:db8::1   # Мой IPv6 адрес
#
TEMPLATE
    fi
}

# Возвращает список IP (без комментариев и пустых строк)
# Использование: mapfile -t ips < <(global_whitelist_get_ips)
global_whitelist_get_ips() {
    _gwl_ensure_file
    grep -v '^\s*#' "$GLOBAL_WHITELIST_FILE" | grep -v '^\s*$' | awk '{print $1}' | grep -E '^[0-9a-fA-F]'
}

# Возвращает количество IP в списке
global_whitelist_count() {
    local count
    count=$(global_whitelist_get_ips | wc -l)
    echo "${count:-0}"
}

# Добавить IP в глобальный список и синхронизировать
# Использование: global_whitelist_add_ip "1.2.3.4" "Комментарий"
global_whitelist_add_ip() {
    local ip="$1"
    local comment="${2:-Manual}"
    _gwl_ensure_file

    # Допускаем IP или CIDR-подсеть (10.0.0.0/8)
    if ! validate_ip_or_cidr "$ip"; then
        err "Некорректный IP адрес или CIDR: $ip"
        return 1
    fi

    # Проверяем дубликаты
    if grep -q "^${ip}" "$GLOBAL_WHITELIST_FILE" 2>/dev/null; then
        warn "IP ${ip} уже в Глобальном Белом Списке."
        return 0
    fi

    echo "${ip} # ${comment}" | run_cmd tee -a "$GLOBAL_WHITELIST_FILE" > /dev/null
    ok "IP ${C_CYAN}${ip}${C_RESET} добавлен в Глобальный Белый Список."
    global_whitelist_sync_all
    return 0
}

# Удалить IP из глобального списка и синхронизировать
global_whitelist_remove_ip() {
    local ip="$1"
    _gwl_ensure_file

    if ! grep -q "^${ip}" "$GLOBAL_WHITELIST_FILE" 2>/dev/null; then
        err "IP ${ip} не найден в Глобальном Белом Списке."
        return 1
    fi

    run_cmd sed -i "/^${ip}/d" "$GLOBAL_WHITELIST_FILE"
    ok "IP ${C_CYAN}${ip}${C_RESET} удален из Глобального Белого Списка."
    global_whitelist_sync_all
    return 0
}

# Автоматически добавляет системные IP в НАЧАЛО файла (IN не стирая существующие)
global_whitelist_prepend_system_ips() {
    _gwl_ensure_file

    # Собираем системные IP с описаниями
    local -A system_ips_map  # ip -> comment
    system_ips_map["127.0.0.1"]="Локальный хост — без этого IP сервер блокирует сам себя"
    system_ips_map["::1"]="Локальный хост IPv6 — обязательно для корректной работы"
    system_ips_map["172.16.0.0/12"]="Сеть Docker-контейнеров — без этого блокируется весь Docker"
    system_ips_map["10.0.0.0/8"]="Внутренние сети — типичная сеть для VPS/облака"
    system_ips_map["192.168.0.0/16"]="Локальная сеть Docker и bridge-интерфейсы"

    # IP самого сервера (Внутренний)
    local server_ip
    server_ip=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' | head -1)
    if [[ -n "$server_ip" ]] && validate_ip "$server_ip" 2>/dev/null; then
        system_ips_map["${server_ip}"]="Внутренний IP сервера — защита от самобана"
    fi

    # IP самого сервера (Публичный)
    local public_ip
    public_ip=$(curl -s --max-time 3 https://api.ipify.org 2>/dev/null)
    if [[ -n "$public_ip" && "$public_ip" != "$server_ip" ]] && validate_ip "$public_ip" 2>/dev/null; then
        system_ips_map["${public_ip}"]="Публичный IP сервера — защита от самобана"
    fi

    # Читаем текущее содержимое файла
    local current_content
    current_content=$(cat "$GLOBAL_WHITELIST_FILE" 2>/dev/null || echo "")

    # Строим блок для вставки (только новые IP, которых ещё нет в файле)
    local new_block=""
    local added_any=0

    # Фиксированный порядок добавления (сначала IPv4, потом сети, потом IPv6)
    local ordered_keys=("127.0.0.1" "::1" "${server_ip}" "${public_ip}" "10.0.0.0/8" "172.16.0.0/12" "192.168.0.0/16")

    local first_entry=1
    for ip_key in "${ordered_keys[@]}"; do
        [[ -z "$ip_key" ]] && continue
        local comment="${system_ips_map[$ip_key]:-Системный IP}"

        # Пропускаем, если уже есть
        if echo "$current_content" | grep -q "^${ip_key}\b"; then
            continue
        fi

        if [[ "$first_entry" -eq 1 ]]; then
            if ! echo "$current_content" | grep -q "СИСТЕМНЫЕ IP — НЕ УДАЛЯТЬ"; then
                new_block+="# ─────────────────────────────────────────────────────────────────
# ⚠️  СИСТЕМНЫЕ IP — НЕ УДАЛЯТЬ! Добавлено автоматически Reshala.
# Если удалить эти IP — система начнёт блокировать саму себя и свои рабочие процессы.
# ─────────────────────────────────────────────────────────────────
"
            fi
            first_entry=0
        fi
        new_block+="${ip_key} # ${comment}
"
        ((added_any++))
    done

    if [[ "$added_any" -gt 0 ]]; then
        # Вставляем новый блок ПОСЛЕ шапки (первые строки с #)
        python3 - "$GLOBAL_WHITELIST_FILE" "$new_block" <<'PYEOF'
import sys
fpath = sys.argv[1]
new_block = sys.argv[2]
with open(fpath, 'r') as f:
    lines = f.readlines()

# Находим первую не-комментную строку для вставки перед ней
insert_at = len(lines)  # по умолчанию — в конец
for i, line in enumerate(lines):
    stripped = line.strip()
    if stripped and not stripped.startswith('#'):
        insert_at = i
        break

new_lines = lines[:insert_at] + [new_block] + lines[insert_at:]
with open(fpath, 'w') as f:
    f.writelines(new_lines)
PYEOF

        debug_log "GWL_PREPEND: Добавлено ${added_any} системных IP в начало белого списка."
    else
        debug_log "GWL_PREPEND: Новых системных IP нет, пропуск добавления."
    fi

    # Очистка возможных дублей шапки (авто-фикс для существующих файлов)
    python3 - "$GLOBAL_WHITELIST_FILE" <<'PYEOF'
import sys
fpath = sys.argv[1]
with open(fpath, 'r') as f:
    lines = f.readlines()
out = []
seen = False
skip = 0
for i, line in enumerate(lines):
    if skip > 0:
        skip -= 1
        continue
    if 'СИСТЕМНЫЕ IP — НЕ УДАЛЯТЬ' in line:
        if seen:
            if len(out) > 0 and '──────' in out[-1]:
                out.pop()
            skip = 2
            continue
        seen = True
    out.append(line)
with open(fpath, 'w') as f:
    f.writelines(out)
PYEOF

    debug_log "GWL_PREPEND: Добавлено ${added_any} системных IP в начало белого списка."
}

# Полная синхронизация всех подсистем
global_whitelist_sync_all() {
    _gwl_ensure_file
    info "Синхронизация Глобального Белого Списка..."

    # Сначала добавляем системные IP (чтобы сами себя не блокировали)
    global_whitelist_prepend_system_ips

    local ips
    mapfile -t ips < <(global_whitelist_get_ips)
    local count=${#ips[@]}

    # --- 1. Fail2Ban ignoreip ---
    _gwl_sync_fail2ban "${ips[@]}"

    # --- 2. eBPF Шейпер ---
    _gwl_sync_shaper

    # --- 3. Geo-block ipset ---
    _gwl_sync_geoblock "${ips[@]}"

    # --- 4. UFW Anti-DDoS before.rules ---
    _gwl_sync_ufw "${ips[@]}"

    ok "Синхронизация завершена. Подключено IP: ${C_CYAN}${count}${C_RESET}"
}

# Предложить использовать глобальный список (для модулей)
# Использование: global_whitelist_offer "shaper"
# Возвращает: 0 = использовать глобальный, 1 = оставить свой
global_whitelist_offer() {
    local module_name="$1"
    _gwl_ensure_file

    local count
    count=$(global_whitelist_count)

    if [[ "$count" -eq 0 ]]; then
        return 1 # Нет глобального списка
    fi

    echo ""
    echo -e "  ${C_CYAN}╔══════════════════════════════════════════════════════════╗${C_RESET}"
    echo -e "  ${C_CYAN}║${C_RESET}  ${C_YELLOW}🌍 Обнаружен Глобальный Белый Список (${count} IP)${C_RESET}"
    echo -e "  ${C_CYAN}╠══════════════════════════════════════════════════════════╣${C_RESET}"
    echo -e "  ${C_CYAN}║${C_RESET}  Этот единый список автоматически применяется ко всем"
    echo -e "  ${C_CYAN}║${C_RESET}  модулям защиты (Шейпер, Fail2Ban, UFW, Geo-Block)."
    echo -e "  ${C_CYAN}╠══════════════════════════════════════════════════════════╣${C_RESET}"
    echo -e "  ${C_CYAN}║${C_RESET}  ${C_WHITE}Текущие IP:${C_RESET}"

    local ips
    mapfile -t ips < <(global_whitelist_get_ips)
    for ip in "${ips[@]}"; do
        echo -e "  ${C_CYAN}║${C_RESET}    ${C_GREEN}●${C_RESET} ${ip}"
    done

    echo -e "  ${C_CYAN}╚══════════════════════════════════════════════════════════╝${C_RESET}"
    echo ""

    if ask_yes_no "Использовать Глобальный Белый Список для модуля '${module_name}'?" "y"; then
        return 0
    fi
    return 1
}

# ============================================================ #
#                    СИНХРОНИЗАЦИЯ ПОДСИСТЕМ                    #
# ============================================================ #

# Синхронизация с Fail2Ban
_gwl_sync_fail2ban() {
    local ips=("$@")
    if [[ ! -f "/etc/fail2ban/jail.local" ]]; then
        debug_log "GWL_SYNC: Fail2Ban jail.local не найден, пропуск."
        return
    fi

    # Автоматически синхронизируем локальный файл Fail2Ban с глобальным белым списком
    run_cmd cp -f "$GLOBAL_WHITELIST_FILE" "/etc/reshala/fail2ban-whitelist.txt" 2>/dev/null || true

    local ignoreip="127.0.0.1/8 ::1"
    for ip in "${ips[@]}"; do
        ignoreip="$ignoreip $ip"
    done

    # Сверхнадежное обновление ignoreip с помощью Python
    python3 - "$ignoreip" <<'PYEOF'
import sys
import re

fpath = "/etc/fail2ban/jail.local"
ignoreip_val = sys.argv[1]

try:
    with open(fpath, "r") as f:
        content = f.read()

    # Ищем ignoreip (любые отступы, опциональный комментарий #)
    pattern = re.compile(r"^[ \t]*#?[ \t]*ignoreip[ \t]*=[ \t]*.*$", re.MULTILINE | re.IGNORECASE)

    if pattern.search(content):
        content = pattern.sub(f"ignoreip = {ignoreip_val}", content)
    else:
        # Если нет, ищем [DEFAULT]
        default_pattern = re.compile(r"^\[DEFAULT\]", re.MULTILINE | re.IGNORECASE)
        if default_pattern.search(content):
            content = default_pattern.sub(f"[DEFAULT]\nignoreip = {ignoreip_val}", content, 1)
        else:
            content = f"[DEFAULT]\nignoreip = {ignoreip_val}\n\n" + content

    with open(fpath, "w") as f:
        f.write(content)
except Exception as e:
    sys.stderr.write(f"Error updating jail.local: {e}\n")
    sys.exit(1)
PYEOF

    # Перезапускаем или перезагружаем Fail2Ban в зависимости от статуса
    if systemctl is-active --quiet fail2ban; then
        run_cmd systemctl reload fail2ban 2>/dev/null || run_cmd systemctl restart fail2ban 2>/dev/null || true
    else
        run_cmd systemctl start fail2ban 2>/dev/null || true
    fi
    debug_log "GWL_SYNC: Fail2Ban ignoreip обновлен."
}

# Синхронизация с eBPF Шейпером
_gwl_sync_shaper() {
    # Ищем конфиг шейпера
    local shaper_config_dir="/etc/reshala/traffic_limiter"
    local shaper_whitelist="${shaper_config_dir}/global-whitelist.txt"
    local ctrl_py="${SCRIPT_DIR}/modules/local/reshala_ctrl.py"
    local pin_dir="/sys/fs/bpf/reshala/maps"

    if [[ ! -f "$ctrl_py" ]]; then
        debug_log "GWL_SYNC: reshala_ctrl.py не найден, пропуск шейпера."
        return
    fi

    # Копируем глобальный список в файл шейпера (для истории)
    if [[ -d "$shaper_config_dir" ]]; then
        run_cmd cp -f "$GLOBAL_WHITELIST_FILE" "$shaper_whitelist" 2>/dev/null || true
    fi

    # Синхронизируем BPF-карту, если движок активен
    if [[ -d "$pin_dir" ]]; then
        python3 "$ctrl_py" --pin-dir "$pin_dir" whitelist-sync --file "${shaper_config_dir}/whitelist.txt" "$GLOBAL_WHITELIST_FILE" 2>/dev/null || true
        debug_log "GWL_SYNC: eBPF whitelist_map обновлена."
    else
        debug_log "GWL_SYNC: eBPF pin_dir не существует (движок не запущен), пропуск."
    fi
}

# Синхронизация с Geo-block ipset
_gwl_sync_geoblock() {
    local ips=("$@")

    if ! command -v ipset &>/dev/null; then
        debug_log "GWL_SYNC: ipset не установлен, пропуск Geo-block."
        return
    fi

    # Нам нужно два сета, так как ipset не смешивает v4 и v6
    for family in "inet" "inet6"; do
        local set_name="reshala_geo_whitelist"
        [[ "$family" == "inet6" ]] && set_name="reshala_geo_whitelist6"

        if ! ipset list "$set_name" -terse &>/dev/null; then
            run_cmd ipset create "$set_name" hash:net family "$family" hashsize 256 maxelem 1024 2>/dev/null || true
        fi
        run_cmd ipset flush "$set_name" 2>/dev/null || true
    done

    # Распределяем IP по сетам
    for ip in "${ips[@]}"; do
        if [[ "$ip" == *":"* ]]; then
            run_cmd ipset add reshala_geo_whitelist6 "$ip" 2>/dev/null || true
        else
            run_cmd ipset add reshala_geo_whitelist "$ip" 2>/dev/null || true
        fi
    done

    debug_log "GWL_SYNC: Geo-block whitelist (v4/v6) обновлен."
}

# Синхронизация с UFW Anti-DDoS (before.rules)
# Добавляет whitelist IP в блок Reshala Anti-DDoS если он уже настроен
_gwl_sync_ufw() {
    local ips=("$@")
    local before_rules="/etc/ufw/before.rules"
    local antiddos_start="# --- НАЧАЛО: Reshala Anti-DDoS ---"

    if [[ ! -f "$before_rules" ]]; then
        debug_log "GWL_SYNC: UFW before.rules не найден, пропуск."
        return
    fi

    if ! grep -q "$antiddos_start" "$before_rules" 2>/dev/null; then
        debug_log "GWL_SYNC: Anti-DDoS блок в UFW не настроен, пропуск."
        return
    fi

    # Удаляем старые whitelist-записи
    python3 - <<'PYEOF'
import re
with open('/etc/ufw/before.rules', 'r') as f:
    content = f.read()
content = re.sub(r'# Whitelist: [^\n]+\n-A ufw-before-input -s [^\n]+ -j ACCEPT\n', '', content)
with open('/etc/ufw/before.rules', 'w') as f:
    f.write(content)
PYEOF

    # Добавляем актуальные whitelist-записи перед блоком Anti-DDoS
    local wl_lines=""
    for ip in "${ips[@]}"; do
        wl_lines="${wl_lines}# Whitelist: ${ip}\n-A ufw-before-input -s ${ip} -j ACCEPT\n"
    done

    if [[ -n "$wl_lines" ]]; then
        python3 - "$wl_lines" <<'PYEOF'
import sys
wl = sys.argv[1]
with open('/etc/ufw/before.rules', 'r') as f:
    content = f.read()
target = '# --- НАЧАЛО: Reshala Anti-DDoS ---'
if target in content:
    content = content.replace(target, wl.replace('\\n', '\n') + target, 1)
    with open('/etc/ufw/before.rules', 'w') as f:
        f.write(content)
PYEOF
    fi

    run_cmd ufw reload 2>/dev/null || true
    debug_log "GWL_SYNC: UFW before.rules whitelist обновлен (${#ips[@]} IP)."
}

# ============================================================ #
#                           МЕНЮ                               #
# ============================================================ #

show_global_whitelist_menu() {
    _gwl_ensure_file
    global_whitelist_prepend_system_ips

    while true; do
        clear
        enable_graceful_ctrlc
        menu_header "🌍 Глобальный Белый Список"
        
        echo -e "  ${C_CYAN}╔══════════════════════════════════════════════════════════╗${C_RESET}"
        echo -e "  ${C_CYAN}║${C_RESET}  ${C_YELLOW}🌍 Глобальный Белый Список${C_RESET}"
        echo -e "  ${C_CYAN}╠══════════════════════════════════════════════════════════╣${C_RESET}"
        echo -e "  ${C_CYAN}║${C_RESET}  ${C_WHITE}Что это:${C_RESET} Единый список доверенных IP-адресов."
        echo -e "  ${C_CYAN}║${C_RESET}  ${C_WHITE}Как работает:${C_RESET} IP добавляются в исключения (bypass) для"
        echo -e "  ${C_CYAN}║${C_RESET}  всех подсистем защиты: eBPF Шейпера, Fail2Ban, Anti-DDoS,"
        echo -e "  ${C_CYAN}║${C_RESET}  UFW и Geo-Block."
        echo -e "  ${C_CYAN}╚══════════════════════════════════════════════════════════╝${C_RESET}"
        echo ""

        print_separator
        info "Файл: ${C_CYAN}${GLOBAL_WHITELIST_FILE}${C_RESET}"

        # Показываем текущий список
        local ips
        mapfile -t ips < <(global_whitelist_get_ips)
        local count=${#ips[@]}

        if [[ "$count" -gt 0 ]]; then
            info "Доверенные IP (${C_CYAN}${count}${C_RESET}):"
            local i=1
            local sys_count=0
            while IFS= read -r line; do
                [[ -z "$line" ]] && continue
                [[ "$line" =~ ^[[:space:]]*# ]] && continue
                local ip comment
                ip=$(echo "$line" | awk '{print $1}')
                comment=$(echo "$line" | sed 's/^[^ ]* *# *//' | sed 's/^[^ ]*$//')
                
                # Проверяем, является ли это системным IP (на основе комментария)
                # Публичный IP специально не включен, чтобы он отображался как обычный добавленный IP
                if [[ "$comment" != *"(Публичный)"* ]] && [[ "$comment" == *"Локальный хост"* || "$comment" == *"Внутренний IP сервера"* || "$comment" == *"Внутренние сети"* || "$comment" == *"Сеть Docker"* || "$comment" == *"Локальная сеть"* || "$comment" == *"Системный IP"* || "$comment" == *"IP этого сервера"* ]]; then
                    ((sys_count++))
                    continue
                fi
                
                printf_description "${C_WHITE}${i})${C_RESET} ${C_CYAN}${ip}${C_RESET}${comment:+  ${C_GRAY}(${comment})${C_RESET}}"
                ((i++))
            done < <(grep -v '^\s*#' "$GLOBAL_WHITELIST_FILE" | grep -v '^\s*$')
            
            if [[ "$sys_count" -gt 0 ]]; then
                printf_description "${C_WHITE}*)${C_RESET} ${C_CYAN}СИСТЕМНЫЕ IP${C_RESET}  ${C_GRAY}(Локальные и Docker адреса, защита от самобана. Скрыто: ${sys_count})${C_RESET}"
            fi
        else
            warn "Список пуст. Добавьте IP для защиты от блокировок."
        fi

        # Показываем статус синхронизации
        echo ""
        info "Статус синхронизации:"
        # Fail2Ban
        if [[ -f "/etc/fail2ban/jail.local" ]]; then
            printf_description "  ${C_GREEN}✓${C_RESET} Fail2Ban (ignoreip)"
        else
            printf_description "  ${C_GRAY}○${C_RESET} Fail2Ban (не установлен)"
        fi
        # Шейпер
        if [[ -d "/sys/fs/bpf/reshala/maps" ]]; then
            printf_description "  ${C_GREEN}✓${C_RESET} eBPF Шейпер (whitelist_map)"
        else
            printf_description "  ${C_GRAY}○${C_RESET} eBPF Шейпер (движок не запущен)"
        fi
        # Geo-block
        if command -v ipset &>/dev/null && ipset list reshala_geo_whitelist -terse &>/dev/null; then
            printf_description "  ${C_GREEN}✓${C_RESET} Geo-Block (ipset)"
        else
            printf_description "  ${C_GRAY}○${C_RESET} Geo-Block (не активен)"
        fi

        print_separator

        echo ""
        printf_menu_option "1" "➕ Добавить IP"
        printf_menu_option "2" "➖ Удалить IP"
        printf_menu_option "3" "🔄 Принудительная синхронизация"
        printf_menu_option "4" "📋 Авто-определить мой IP"
        printf_menu_option "5" "📝 Ручное редактирование (Editor)"
        echo ""
        printf_menu_option "b" "Назад"
        echo ""

        local choice
        choice=$(safe_read "Выберите действие" "") || { break; }

        case "$choice" in
            1)
                local new_ip new_comment
                while true; do
                    new_ip=$(ask_non_empty "Введите IP адрес (или 'q' для отмены)") || break
                    [[ "$new_ip" == "q" ]] && break
                    
                    if validate_ip "$new_ip"; then
                        new_comment=$(safe_read "Комментарий (имя/описание)" "Manual") || break
                        global_whitelist_add_ip "$new_ip" "$new_comment"
                        break
                    else
                        warn "Некорректный IP: $new_ip. Попробуй еще раз (пример: 1.2.3.4)"
                    fi
                done
                wait_for_enter
                ;;
            2)
                if [[ "$count" -eq 0 ]]; then
                    warn "Список пуст, нечего удалять."
                    wait_for_enter
                    continue
                fi
                local del_ip
                del_ip=$(ask_non_empty "Введите IP для удаления") || continue
                global_whitelist_remove_ip "$del_ip"
                wait_for_enter
                ;;
            3)
                global_whitelist_sync_all
                wait_for_enter
                ;;
            4)
                _gwl_autodetect_ip
                wait_for_enter
                ;;
            5)
                info "Открываю список в редакторе..."
                sleep 1
                nano "$GLOBAL_WHITELIST_FILE"
                ok "Изменения сохранены. Запускаю синхронизацию..."
                global_whitelist_sync_all
                wait_for_enter
                ;;
            b|B)
                break
                ;;
            *)
                warn "Неверный выбор"
                ;;
        esac
        disable_graceful_ctrlc
    done
}

# Авто-определение IP текущей сессии
_gwl_autodetect_ip() {
    print_separator
    info "Авто-определение IP"
    print_separator

    local my_ip
    # Способ 1: из SSH-сессии
    my_ip=$(who -m 2>/dev/null | awk '{print $5}' | tr -d '()')
    
    # Способ 2: через внешний сервис
    if [[ -z "$my_ip" ]] || ! validate_ip "$my_ip"; then
        info "Определяю внешний IP..."
        my_ip=$(curl -s --max-time 5 ifconfig.me 2>/dev/null)
    fi

    if [[ -n "$my_ip" ]] && validate_ip "$my_ip"; then
        ok "Ваш текущий IP: ${C_CYAN}${my_ip}${C_RESET}"

        if grep -q "^${my_ip}" "$GLOBAL_WHITELIST_FILE" 2>/dev/null; then
            info "Этот IP уже есть в Глобальном Белом Списке."
            return
        fi

        if ask_yes_no "Добавить ${my_ip} в Глобальный Белый Список?" "y"; then
            global_whitelist_add_ip "$my_ip" "Auto-detected ($(date +%Y-%m-%d))"
        fi
    else
        err "Не удалось определить IP. Добавьте его вручную."
    fi
}
