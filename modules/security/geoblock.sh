#!/bin/bash
#   ( РОДИТЕЛЬ | КЛАВИША | НАЗВАНИЕ | ФУНКЦИЯ | ПОРЯДОК | ГРУППА | ОПИСАНИЕ )
# @menu.manifest
# @item( security | 8 | 🌐 Geo-Block (Блокировка стран) | show_geoblock_menu | 80 | 10 | Блокировка трафика по странам через ipset. )
#
# geoblock.sh - Geo-Block Manager
#
# Блокирует входящий трафик по странам через ipset + iptables/UFW.
# Интегрирован с Глобальным Белым Списком для обхода блокировки.
#

[[ "${BASH_SOURCE[0]}" == "${0}" ]] && exit 1

GEO_CONFIG_DIR="/etc/reshala/geoblock"
GEO_COUNTRIES_FILE="${GEO_CONFIG_DIR}/countries.txt"
GEO_IPSET_NAME="reshala_geoblock"
GEO_SERVICE_FILE="/etc/systemd/system/reshala-geoblock.service"
GEO_RESTORE_SCRIPT="/usr/local/bin/reshala-geoblock-restore.sh"

# Полный список стран ISO 3166-1 alpha-2
declare -A GEO_ALL_COUNTRIES=(
    [AF]="Афганистан" [AL]="Албания" [DZ]="Алжир" [AO]="Ангола" [AR]="Аргентина"
    [AM]="Армения" [AZ]="Азербайджан" [BD]="Бангладеш" [BY]="Беларусь" [BJ]="Бенин"
    [BO]="Боливия" [BR]="Бразилия" [BG]="Болгария" [BF]="Буркина-Фасо" [BI]="Бурунди"
    [KH]="Камбоджа" [CM]="Камерун" [CF]="ЦАР" [TD]="Чад" [CN]="Китай"
    [CO]="Колумбия" [CG]="Конго" [CD]="ДР Конго" [CI]="Кот-д'Ивуар" [CU]="Куба"
    [DJ]="Джибути" [EC]="Эквадор" [EG]="Египет" [ER]="Эритрея" [ET]="Эфиопия"
    [GA]="Габон" [GH]="Гана" [GN]="Гвинея" [GW]="Гвинея-Бисау" [GY]="Гайана"
    [HT]="Гаити" [HN]="Гондурас" [IN]="Индия" [ID]="Индонезия" [IR]="Иран"
    [IQ]="Ирак" [KZ]="Казахстан" [KE]="Кения" [KG]="Кыргызстан" [KP]="КНДР"
    [LA]="Лаос" [LB]="Ливан" [LR]="Либерия" [LY]="Ливия" [MG]="Мадагаскар"
    [MW]="Малави" [ML]="Мали" [MR]="Мавритания" [MX]="Мексика" [MN]="Монголия"
    [MZ]="Мозамбик" [MM]="Мьянма" [NP]="Непал" [NI]="Никарагуа" [NE]="Нигер"
    [NG]="Нигерия" [PK]="Пакистан" [PS]="Палестина" [PY]="Парагвай" [PE]="Перу"
    [PH]="Филиппины" [RW]="Руанда" [SN]="Сенегал" [SL]="Сьерра-Леоне" [SO]="Сомали"
    [SS]="Южный Судан" [SD]="Судан" [SY]="Сирия" [TJ]="Таджикистан" [TZ]="Танзания"
    [TH]="Таиланд" [TG]="Того" [TN]="Тунис" [TM]="Туркменистан" [UG]="Уганда"
    [UA]="Украина" [UZ]="Узбекистан" [VE]="Венесуэла" [VN]="Вьетнам" [YE]="Йемен"
    [ZM]="Замбия" [ZW]="Зимбабве"
    # Дополнительные страны (Европа, СНГ, прочие)
    [RU]="Россия" [DE]="Германия" [FR]="Франция" [GB]="Великобритания" [IT]="Италия"
    [ES]="Испания" [PL]="Польша" [NL]="Нидерланды" [TR]="Турция" [US]="США"
    [CA]="Канада" [AU]="Австралия" [JP]="Япония" [KR]="Южная Корея" [IL]="Израиль"
    [GE]="Грузия" [MD]="Молдова" [LV]="Латвия" [LT]="Литва" [EE]="Эстония"
)

# Пресеты
GEO_PRESET_RECOMMENDED="CN,IN,BD,VN,ID,PH,NG,BR,EG,PK,TH,MM,KH,LA,ET,UZ,TN,VE,EC,KE,TZ"
GEO_PRESET_ASIA="CN,IN,BD,VN,ID,PH,TH,MM,KH,LA,KP,PK,NP,MN,KG,TJ,TM,UZ,KZ,AF"
GEO_PRESET_AFRICA="NG,EG,KE,TZ,ET,GH,CM,SN,CI,MZ,MG,MW,ZM,ZW,UG,TG,BF,ML,NE,SO,SD,SS"
GEO_PRESET_LATAM="BR,VE,EC,CO,PE,BO,PY,MX,CU,HN,NI,GY,HT"

show_geoblock_menu() {
    while true; do
        clear
        enable_graceful_ctrlc
        menu_header "🌐 Geo-Block (Блокировка стран)"
        printf_description "Блокировка входящего трафика по странам."

        _geo_show_status

        echo ""
        printf_menu_option "1" "🟢 Включить / Обновить Geo-Block"
        printf_menu_option "2" "🔴 Выключить Geo-Block"
        printf_menu_option "3" "📋 Управление списком стран"
        printf_menu_option "4" "📊 Статистика блокировок"
        echo ""
        printf_menu_option "b" "Назад"
        echo ""

        local choice
        choice=$(safe_read "Выберите действие" "") || { break; }

        case "$choice" in
            1) _geo_activate; wait_for_enter;;
            2) _geo_deactivate; wait_for_enter;;
            3) _geo_manage_countries;;
            4) _geo_show_stats; wait_for_enter;;
            b|B) break;;
            *) warn "Неверный выбор";;
        esac
        disable_graceful_ctrlc
    done
}

_geo_show_status() {
    print_separator
    info "Статус Geo-Block"

    if ipset list "$GEO_IPSET_NAME" &>/dev/null 2>&1; then
        local ip_count
        ip_count=$(ipset list "$GEO_IPSET_NAME" 2>/dev/null | grep -c "^[0-9]" || echo "0")
        printf_description "Состояние: ${C_GREEN}Активен${C_RESET}"
        printf_description "Заблокировано подсетей: ${C_CYAN}${ip_count}${C_RESET}"

        if [[ -f "$GEO_COUNTRIES_FILE" ]]; then
            local countries
            countries=$(cat "$GEO_COUNTRIES_FILE" | tr '\n' ',' | sed 's/,$//')
            printf_description "Страны: ${C_YELLOW}${countries}${C_RESET}"
        fi
    else
        printf_description "Состояние: ${C_RED}Не активен${C_RESET}"
    fi

    # Автозагрузка
    if systemctl is-enabled reshala-geoblock &>/dev/null 2>&1; then
        printf_description "Автозагрузка: ${C_GREEN}Включена${C_RESET}"
    else
        printf_description "Автозагрузка: ${C_GRAY}Выключена${C_RESET}"
    fi

    print_separator
}

_geo_manage_countries() {
    while true; do
        clear
        enable_graceful_ctrlc
        menu_header "📋 Управление списком стран"

        run_cmd mkdir -p "$GEO_CONFIG_DIR"

        # Показываем текущие
        if [[ -f "$GEO_COUNTRIES_FILE" ]] && [[ -s "$GEO_COUNTRIES_FILE" ]]; then
            info "Текущий список стран для блокировки:"
            local col=0
            local col_width=25
            while IFS= read -r code; do
                [[ -z "$code" ]] && continue
                local name="${GEO_ALL_COUNTRIES[$code]:-Неизвестно}"
                local pad=$((col_width - ${#name}))
                [[ $pad -lt 1 ]] && pad=1
                
                printf "  ${C_RED}✗${C_RESET} ${C_CYAN}%-3s${C_RESET} %s%*s" "$code" "$name" "$pad" ""
                
                ((col++))
                if [[ $((col % 2)) -eq 0 ]]; then echo ""; fi
            done < "$GEO_COUNTRIES_FILE"
            echo ""
        else
            warn "Список стран пуст."
        fi

        print_separator
        echo ""
        printf_menu_option "1" "🎯 Использовать пресет"
        printf_menu_option "2" "➕ Добавить страну вручную (код ISO)"
        printf_menu_option "3" "➖ Удалить страну"
        printf_menu_option "4" "📖 Показать все доступные страны"
        printf_menu_option "5" "🗑️  Очистить весь список"
        echo ""
        printf_menu_option "b" "Назад"
        echo ""

        local choice
        choice=$(safe_read "Выберите действие" "") || { break; }

        case "$choice" in
            1) _geo_select_preset; wait_for_enter;;
            2) _geo_add_country; wait_for_enter;;
            3) _geo_remove_country; wait_for_enter;;
            4) _geo_show_all_countries; wait_for_enter;;
            5)
                if ask_yes_no "Очистить весь список стран?"; then
                    > "$GEO_COUNTRIES_FILE"
                    ok "Список стран очищен."
                fi
                wait_for_enter
                ;;
            b|B) break;;
            *) warn "Неверный выбор";;
        esac
        disable_graceful_ctrlc
    done
}

_geo_select_preset() {
    print_separator
    info "Выберите пресет стран для блокировки"
    print_separator

    echo ""
    printf_menu_option "1" "🌍 Рекомендуемый (21 страна) — ${C_GRAY}Основные источники атак${C_RESET}"
    printf_menu_option "2" "🌏 Азия (20 стран)"
    printf_menu_option "3" "🌍 Африка (22 страны)"
    printf_menu_option "4" "🌎 Латинская Америка (13 стран)"
    printf_menu_option "5" "🔥 ВСЕ СТРАНЫ из базы (Глобальный блок)"
    printf_menu_option "6" "✍️  Вручную (ввести коды через запятую)"
    echo ""

    local choice
    choice=$(safe_read "Выберите пресет" "") || return

    local preset=""
    case "$choice" in
        1) preset="$GEO_PRESET_RECOMMENDED"; info "Выбран: Рекомендуемый";;
        2) preset="$GEO_PRESET_ASIA"; info "Выбран: Азия";;
        3) preset="$GEO_PRESET_AFRICA"; info "Выбран: Африка";;
        4) preset="$GEO_PRESET_LATAM"; info "Выбран: Латинская Америка";;
        5)
            preset=$(printf '%s,' "${!GEO_ALL_COUNTRIES[@]}" | sed 's/,$//')
            warn "Выбран: ВСЕ СТРАНЫ (${#GEO_ALL_COUNTRIES[@]} шт.)"
            ;;
        6)
            local custom
            custom=$(ask_non_empty "Введите коды стран через запятую (напр: CN,VN,IN)") || return
            preset="$custom"
            ;;
        *) warn "Неверный выбор"; return;;
    esac

    if [[ -z "$preset" ]]; then return; fi

    local mode="replace"
    if [[ -f "$GEO_COUNTRIES_FILE" ]] && [[ -s "$GEO_COUNTRIES_FILE" ]]; then
        if ask_yes_no "Заменить текущий список? (n = добавить к существующему)" "y"; then
            mode="replace"
        else
            mode="append"
        fi
    fi

    run_cmd mkdir -p "$GEO_CONFIG_DIR"
    if [[ "$mode" == "replace" ]]; then
        > "$GEO_COUNTRIES_FILE"
    fi

    local count=0
    IFS=',' read -ra codes <<< "$preset"
    for code in "${codes[@]}"; do
        code=$(echo "$code" | tr '[:lower:]' '[:upper:]' | xargs)
        [[ -z "$code" ]] && continue
        if ! grep -qx "$code" "$GEO_COUNTRIES_FILE" 2>/dev/null; then
            echo "$code" >> "$GEO_COUNTRIES_FILE"
            ((count++))
        fi
    done

    ok "Добавлено стран: ${count}. Общее количество: $(wc -l < "$GEO_COUNTRIES_FILE")"
    warn "Не забудьте активировать Geo-Block (пункт 1 в меню)."
}

_geo_add_country() {
    local code
    code=$(ask_non_empty "Введите код страны (ISO 3166-1, напр: CN)") || return
    code=$(echo "$code" | tr '[:lower:]' '[:upper:]' | xargs)

    if [[ -z "${GEO_ALL_COUNTRIES[$code]+exists}" ]]; then
        warn "Код '${code}' не найден в базе. Добавить всё равно?"
        if ! ask_yes_no "Добавить?"; then return; fi
    fi

    run_cmd mkdir -p "$GEO_CONFIG_DIR"
    if grep -qx "$code" "$GEO_COUNTRIES_FILE" 2>/dev/null; then
        warn "Страна ${code} уже в списке."
        return
    fi
    echo "$code" >> "$GEO_COUNTRIES_FILE"
    ok "Страна ${code} (${GEO_ALL_COUNTRIES[$code]:-?}) добавлена."
}

_geo_remove_country() {
    if [[ ! -f "$GEO_COUNTRIES_FILE" ]] || [[ ! -s "$GEO_COUNTRIES_FILE" ]]; then
        warn "Список стран пуст."; return
    fi
    local code
    code=$(ask_non_empty "Введите код страны для удаления") || return
    code=$(echo "$code" | tr '[:lower:]' '[:upper:]' | xargs)

    if grep -qx "$code" "$GEO_COUNTRIES_FILE"; then
        run_cmd sed -i "/^${code}$/d" "$GEO_COUNTRIES_FILE"
        ok "Страна ${code} удалена."
    else
        err "Страна ${code} не найдена в списке."
    fi
}

_geo_show_all_countries() {
    print_separator
    info "Все доступные страны (${#GEO_ALL_COUNTRIES[@]} шт.)"
    print_separator

    local sorted_codes
    mapfile -t sorted_codes < <(printf '%s\n' "${!GEO_ALL_COUNTRIES[@]}" | sort)

    local col=0
    local col_width=24 # Фиксированная ширина колонки (в символах)
    for code in "${sorted_codes[@]}"; do
        local name="${GEO_ALL_COUNTRIES[$code]}"
        local pad=$((col_width - ${#name}))
        [[ $pad -lt 1 ]] && pad=1
        
        printf "  ${C_CYAN}%-3s${C_RESET} %s%*s" "$code" "$name" "$pad" ""
        
        ((col++))
        if [[ $((col % 3)) -eq 0 ]]; then echo ""; fi
    done
    echo ""
}

_geo_activate() {
    print_separator
    info "Активация Geo-Block"
    print_separator

    if [[ ! -f "$GEO_COUNTRIES_FILE" ]] || [[ ! -s "$GEO_COUNTRIES_FILE" ]]; then
        err "Список стран пуст! Сначала настройте список (пункт 3)."
        return
    fi

    if ! ensure_package "ipset"; then return 1; fi
    if ! ensure_package "curl"; then return 1; fi

    if ! ask_yes_no "Активировать Geo-Block? Будут загружены зоны и настроены правила."; then
        return
    fi

    # Создаем ipset
    info "Создаю ipset ${GEO_IPSET_NAME}..."
    run_cmd ipset destroy "$GEO_IPSET_NAME" 2>/dev/null || true
    run_cmd ipset create "$GEO_IPSET_NAME" hash:net hashsize 65536 maxelem 500000

    # Загружаем зоны стран
    local total=0
    while IFS= read -r country; do
        [[ -z "$country" ]] && continue
        country=$(echo "$country" | xargs)
        info "Загружаю зону: ${country} (${GEO_ALL_COUNTRIES[$country]:-?})..."

        local zone_url="https://www.ipdeny.com/ipblocks/data/aggregated/${country,,}-aggregated.zone"
        local zone_data
        zone_data=$(curl -s --max-time 15 "$zone_url" 2>/dev/null)

        if [[ -z "$zone_data" ]]; then
            warn "Не удалось загрузить зону для ${country}. Пропуск."
            continue
        fi

        local count=0
        while IFS= read -r subnet; do
            [[ -z "$subnet" ]] && continue
            run_cmd ipset add "$GEO_IPSET_NAME" "$subnet" 2>/dev/null || true
            ((count++))
        done <<< "$zone_data"
        total=$((total + count))
        ok "  ${country}: ${count} подсетей"
    done < "$GEO_COUNTRIES_FILE"

    ok "Загружено подсетей: ${total}"

    # Добавляем whitelist из Глобального Белого Списка
    info "Добавляю IP из Глобального Белого Списка в обход..."
    if command -v global_whitelist_get_ips &>/dev/null; then
        local wl_ips
        mapfile -t wl_ips < <(global_whitelist_get_ips)
        # Создаем whitelist ipset
        run_cmd ipset destroy reshala_geo_whitelist 2>/dev/null || true
        run_cmd ipset create reshala_geo_whitelist hash:ip hashsize 256 maxelem 1024 2>/dev/null || true
        for ip in "${wl_ips[@]}"; do
            run_cmd ipset add reshala_geo_whitelist "$ip" 2>/dev/null || true
        done
        ok "Whitelist: ${#wl_ips[@]} IP добавлены в обход."
    fi

    # Вставляем правило в UFW before.rules
    _geo_insert_ufw_rule

    # Создаем systemd-сервис для автозагрузки
    _geo_create_autostart

    # Перезагружаем UFW
    if command -v ufw &>/dev/null; then
        run_cmd ufw reload 2>/dev/null || true
    fi

    ok "Geo-Block активирован! Заблокировано стран: $(wc -l < "$GEO_COUNTRIES_FILE"), подсетей: ${total}"
}

_geo_deactivate() {
    print_separator
    info "Деактивация Geo-Block"
    print_separator

    if ! ask_yes_no "Выключить Geo-Block? Все блокировки будут сняты."; then
        return
    fi

    # Удаляем ipset
    run_cmd ipset destroy "$GEO_IPSET_NAME" 2>/dev/null || true
    run_cmd ipset destroy reshala_geo_whitelist 2>/dev/null || true

    # Удаляем правило из before.rules
    _geo_remove_ufw_rule

    # Удаляем автозагрузку
    run_cmd systemctl disable reshala-geoblock 2>/dev/null || true
    run_cmd rm -f "$GEO_SERVICE_FILE" "$GEO_RESTORE_SCRIPT" 2>/dev/null || true
    run_cmd systemctl daemon-reload 2>/dev/null || true

    if command -v ufw &>/dev/null; then
        run_cmd ufw reload 2>/dev/null || true
    fi

    ok "Geo-Block деактивирован."
}

_geo_insert_ufw_rule() {
    local before_rules="/etc/ufw/before.rules"
    [[ ! -f "$before_rules" ]] && return

    # Удаляем старый блок если есть
    _geo_remove_ufw_rule

    # Вставляем новый блок после :ufw-before-input
    python3 - <<PYEOF
import re

with open('$before_rules', 'r') as f:
    content = f.read()

geo_block = """
# --- НАЧАЛО: Reshala Geo-Block ---
# Белый список (обход Geo-Block)
-A ufw-before-input -m set --match-set reshala_geo_whitelist src -j ACCEPT
# Блокировка по странам
-A ufw-before-input -m set --match-set ${GEO_IPSET_NAME} src -j DROP
# --- КОНЕЦ: Reshala Geo-Block ---
"""

target = ':ufw-before-input - [0:0]'
if target in content:
    content = content.replace(target, target + geo_block, 1)
    with open('$before_rules', 'w') as f:
        f.write(content)

PYEOF
}

_geo_remove_ufw_rule() {
    local before_rules="/etc/ufw/before.rules"
    [[ ! -f "$before_rules" ]] && return

    python3 - <<'PYEOF'
import re
with open('/etc/ufw/before.rules', 'r') as f:
    content = f.read()
content = re.sub(r'\n# --- НАЧАЛО: Reshala Geo-Block ---.*?# --- КОНЕЦ: Reshala Geo-Block ---\n', '', content, flags=re.DOTALL)
with open('/etc/ufw/before.rules', 'w') as f:
    f.write(content)
PYEOF
}

_geo_create_autostart() {
    # Скрипт восстановления ipset после ребута
    cat <<SCRIPT | run_cmd tee "$GEO_RESTORE_SCRIPT" > /dev/null
#!/bin/bash
# Reshala Geo-Block: Восстановление ipset после ребута
ipset destroy ${GEO_IPSET_NAME} 2>/dev/null || true
ipset create ${GEO_IPSET_NAME} hash:net hashsize 65536 maxelem 500000

COUNTRIES_FILE="${GEO_COUNTRIES_FILE}"
[[ ! -f "\$COUNTRIES_FILE" ]] && exit 0

while IFS= read -r country; do
    [[ -z "\$country" ]] && continue
    country=\$(echo "\$country" | xargs | tr '[:upper:]' '[:lower:]')
    curl -s --max-time 15 "https://www.ipdeny.com/ipblocks/data/aggregated/\${country}-aggregated.zone" | while read -r subnet; do
        [[ -n "\$subnet" ]] && ipset add ${GEO_IPSET_NAME} "\$subnet" 2>/dev/null || true
    done
done < "\$COUNTRIES_FILE"

# Whitelist
ipset destroy reshala_geo_whitelist 2>/dev/null || true
ipset create reshala_geo_whitelist hash:ip hashsize 256 maxelem 1024 2>/dev/null || true
if [[ -f "${GLOBAL_WHITELIST_FILE}" ]]; then
    grep -v '^\s*#' "${GLOBAL_WHITELIST_FILE}" | grep -v '^\s*$' | awk '{print \$1}' | while read -r ip; do
        ipset add reshala_geo_whitelist "\$ip" 2>/dev/null || true
    done
fi
SCRIPT
    run_cmd chmod +x "$GEO_RESTORE_SCRIPT"

    cat <<SERVICE | run_cmd tee "$GEO_SERVICE_FILE" > /dev/null
[Unit]
Description=Reshala Geo-Block Restore
After=network-online.target ufw.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${GEO_RESTORE_SCRIPT}
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
SERVICE
    run_cmd systemctl daemon-reload
    run_cmd systemctl enable reshala-geoblock 2>/dev/null || true
    ok "Автозагрузка Geo-Block настроена."
}

_geo_show_stats() {
    print_separator
    info "Статистика Geo-Block"
    print_separator

    if ! ipset list "$GEO_IPSET_NAME" &>/dev/null 2>&1; then
        warn "Geo-Block не активен."
        return
    fi

    local total
    total=$(ipset list "$GEO_IPSET_NAME" 2>/dev/null | grep -c "^[0-9]" || echo "0")
    ok "Заблокировано подсетей: ${C_CYAN}${total}${C_RESET}"

    if [[ -f "$GEO_COUNTRIES_FILE" ]]; then
        ok "Стран в блоке: ${C_CYAN}$(wc -l < "$GEO_COUNTRIES_FILE")${C_RESET}"
    fi

    # Показываем iptables статистику
    if iptables -L ufw-before-input -v -n 2>/dev/null | grep -q "$GEO_IPSET_NAME"; then
        local dropped
        dropped=$(iptables -L ufw-before-input -v -n 2>/dev/null | grep "$GEO_IPSET_NAME" | awk '{print $1}')
        ok "Заблокировано пакетов: ${C_RED}${dropped:-0}${C_RESET}"
    fi
}
