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
GLOBAL_WHITELIST_FILE="/etc/reshala/global-whitelist.txt"

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
        
        echo -e "  ${C_CYAN}╔══════════════════════════════════════════════════════════╗${C_RESET}"
        _geo_print_card_header "🌐 Geo-Block (Блокировка стран)"
        echo -e "  ${C_CYAN}╠══════════════════════════════════════════════════════════╣${C_RESET}"
        _geo_print_card_row "Что это:" "Блокировщик входящего трафика"
        _geo_print_card_row "Как работает:" "Скачивает IP-диапазоны стран"
        _geo_print_card_row "Технологии:" "Блокировка через ipset + UFW"
        _geo_print_card_row "Назначение:" "Отсекает нежелательный трафик"
        echo -e "  ${C_CYAN}╚══════════════════════════════════════════════════════════╝${C_RESET}"
        echo ""

        _geo_show_status

        echo ""
        printf_menu_option "1" "🟢 Включить / Обновить Geo-Block"
        printf_menu_option "2" "🔴 Выключить Geo-Block"
        printf_menu_option "3" "📋 Управление списком стран"
        printf_menu_option "4" "📊 Статистика блокировок"
        printf_menu_option "5" "🔍 Проверить IP-адрес (разрешен ли?)"
        printf_menu_option "6" "🔄 Автообновление базы (Cron-задача)"
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
            5) _geo_test_ip; wait_for_enter;;
            6) _geo_toggle_auto_update; wait_for_enter;;
            b|B) break;;
            *) warn "Неверный выбор";;
        esac
        disable_graceful_ctrlc
    done
}

_geo_get_ipset_count() {
    local set_name="$1"
    if ! ipset list "$set_name" -terse &>/dev/null; then
        echo "0"
        return
    fi
    ipset list "$set_name" -terse 2>/dev/null | grep -Fi "Number of entries:" | awk '{print $4}' || echo "0"
}

_geo_print_card_row() {
    local label="$1"
    local value="$2"
    local width=56 # Внутренняя ширина без рамок (внешняя 60)
    
    local vis_label
    vis_label=$(_get_visible_length "$label")
    local vis_value
    vis_value=$(_get_visible_length "$value")
    
    local content_width=$((width - 4))
    local spaces_needed=$((content_width - vis_label - vis_value))
    if ((spaces_needed < 0)); then spaces_needed=1; fi
    
    local spaces=""
    if ((spaces_needed > 0)); then
        spaces=$(printf '%*s' "$spaces_needed" "")
    fi
    
    echo -e "  ${C_CYAN}║${C_RESET}  ${C_WHITE}${label}${C_RESET}${spaces}${value}  ${C_CYAN}║${C_RESET}"
}

_geo_print_card_header() {
    local title="$1"
    local width=56
    local vis_title
    vis_title=$(_get_visible_length "$title")
    
    local content_width=$((width - 4))
    local left_spaces=$(( (content_width - vis_title) / 2 ))
    local right_spaces=$(( content_width - vis_title - left_spaces ))
    
    local left_pad=""
    if ((left_spaces > 0)); then left_pad=$(printf '%*s' "$left_spaces" ""); fi
    local right_pad=""
    if ((right_spaces > 0)); then right_pad=$(printf '%*s' "$right_spaces" ""); fi
    
    echo -e "  ${C_CYAN}║${C_RESET}  ${left_pad}${C_WHITE}${title}${C_RESET}${right_pad}  ${C_CYAN}║${C_RESET}"
}

_geo_show_status() {
    print_separator
    info "Статус Geo-Block"

    local active=0
    local ip_count=0
    local countries_count=0
    local names_str=""
    
    if ipset list "$GEO_IPSET_NAME" -terse &>/dev/null 2>&1; then
        active=1
        ip_count=$(_geo_get_ipset_count "$GEO_IPSET_NAME")
        
        if [[ -f "$GEO_COUNTRIES_FILE" ]]; then
            countries_count=$(grep -c "^[A-Z]" "$GEO_COUNTRIES_FILE" || echo "0")
            
            local names=()
            while IFS= read -r code || [[ -n "$code" ]]; do
                code="${code//[$'\r\n\t ']/}"
                code="${code^^}"
                if [[ "$code" =~ ^[A-Z]{2}$ ]]; then
                    local name=""
                    if [[ -v GEO_ALL_COUNTRIES[$code] ]]; then
                        name="${GEO_ALL_COUNTRIES[$code]}"
                    fi
                    names+=("${name:-$code}")
                fi
            done < "$GEO_COUNTRIES_FILE"

            if [[ "$countries_count" -gt 5 ]]; then
                local head_names=""
                for ((i=0; i<4; i++)); do
                    if [[ -n "${names[$i]:-}" ]]; then
                        head_names="${head_names}${names[$i]}, "
                    fi
                done
                head_names="${head_names%, }"
                local remain=$((countries_count - 4))
                names_str="${head_names} и еще ${remain} шт."
            else
                local all_names=""
                for name in "${names[@]}"; do
                    all_names="${all_names}${name}, "
                done
                all_names="${all_names%, }"
                names_str="$all_names"
            fi
        fi
    fi

    local autostart="${C_GRAY}Выключена${C_RESET}"
    if systemctl is-enabled reshala-geoblock &>/dev/null 2>&1; then
        autostart="${C_GREEN}Включена${C_RESET}"
    fi

    local autoupdate="${C_GRAY}Выключено${C_RESET}"
    if [[ -f "/etc/cron.d/reshala-geoblock-update" ]]; then
        autoupdate="${C_GREEN}Включено (еженедельно)${C_RESET}"
    fi

    echo -e "  ${C_CYAN}╔══════════════════════════════════════════════════════════╗${C_RESET}"
    if [[ $active -eq 1 ]]; then
        _geo_print_card_row "Состояние:" "${C_GREEN}● АКТИВЕН${C_RESET}"
        _geo_print_card_row "Заблокировано подсетей:" "${C_CYAN}${ip_count}${C_RESET}"
        if [[ $countries_count -gt 0 ]]; then
            local max_len=26
            local truncated_names="${names_str}"
            if [[ ${#truncated_names} -gt $max_len ]]; then
                truncated_names="${truncated_names:0:$((max_len-3))}..."
            fi
            _geo_print_card_row "Заблокировано стран:" "${C_YELLOW}${truncated_names} (${countries_count} шт.)${C_RESET}"
        fi
    else
        _geo_print_card_row "Состояние:" "${C_RED}○ НЕ АКТИВЕН${C_RESET}"
    fi
    _geo_print_card_row "Автозагрузка при загрузке ОС:" "$autostart"
    _geo_print_card_row "Автообновление базы:" "$autoupdate"
    echo -e "  ${C_CYAN}╚══════════════════════════════════════════════════════════╝${C_RESET}"
    print_separator
}


_geo_manage_countries() {
    local sorted_codes=()
    local temp_sorted
    mapfile -t temp_sorted < <(
        for code in "${!GEO_ALL_COUNTRIES[@]}"; do
            if [[ -n "$code" ]]; then
                echo "${GEO_ALL_COUNTRIES[$code]:-?}|$code"
            fi
        done | sort -f
    )
    for entry in "${temp_sorted[@]}"; do
        sorted_codes+=("${entry#*|}")
    done

    local -A selected_countries
    if [[ -f "$GEO_COUNTRIES_FILE" ]]; then
        while IFS= read -r line || [[ -n "$line" ]]; do
            line="${line//[$'\r\n\t ']/}"
            line="${line^^}"
            if [[ -n "$line" ]]; then
                selected_countries[$line]=1
            fi
        done < "$GEO_COUNTRIES_FILE"
    fi

    local search_query=""
    local page_size=15
    local current_page=0

    while true; do
        clear
        enable_graceful_ctrlc
        menu_header "📋 Управление списком стран"

        # Build filtered list
        local filtered_codes=()
        for code in "${sorted_codes[@]}"; do
            local name=""
            if [[ "$code" =~ ^[A-Z]{2}$ && -v GEO_ALL_COUNTRIES[$code] ]]; then
                name="${GEO_ALL_COUNTRIES[$code]}"
            else
                name="?"
            fi
            if [[ -z "$search_query" ]]; then
                filtered_codes+=("$code")
            else
                local q_lower="${search_query,,}"
                local name_lower="${name,,}"
                local code_lower="${code,,}"
                if [[ "$name_lower" == *"$q_lower"* || "$code_lower" == *"$q_lower"* ]]; then
                    filtered_codes+=("$code")
                fi
            fi
        done

        local total_items=${#filtered_codes[@]}
        local total_pages=$(( (total_items + page_size - 1) / page_size ))
        [[ $total_pages -lt 1 ]] && total_pages=1

        if [[ $current_page -ge $total_pages ]]; then
            current_page=$((total_pages - 1))
        fi
        [[ $current_page -lt 0 ]] && current_page=0

        # Display countries on this page
        local page_start=$((current_page * page_size))
        local page_end=$((page_start + page_size - 1))
        [[ $page_end -ge $total_items ]] && page_end=$((total_items - 1))

        echo -e "  ${C_CYAN}╔══════════════════════════════════════════════════════════╗${C_RESET}"
        _geo_print_card_header "📋 УПРАВЛЕНИЕ СПИСКОМ СТРАН"
        _geo_print_card_header "Показано $((page_start+1))-$((page_end+1)) из $total_items"
        echo -e "  ${C_CYAN}╠══════════════════════════════════════════════════════════╣${C_RESET}"
        if [[ $total_items -gt 0 ]]; then
            local display_idx=1
            for ((i=page_start; i<=page_end; i++)); do
                local code="${filtered_codes[$i]}"
                local name=""
                if [[ "$code" =~ ^[A-Z]{2}$ && -v GEO_ALL_COUNTRIES[$code] ]]; then
                    name="${GEO_ALL_COUNTRIES[$code]}"
                else
                    name="?"
                fi
                local chk="[ ]"
                if [[ -n "${selected_countries[$code]:-}" ]]; then
                    chk="[${C_GREEN}✓${C_RESET}]"
                fi
                _geo_print_card_row "  ${chk}  ${C_WHITE}${display_idx})${C_RESET} ${C_CYAN}${code}${C_RESET}" "${C_WHITE}${name}${C_RESET}"
                ((display_idx++))
            done
        else
            _geo_print_card_row "  ${C_RED}Страны по вашему запросу не найдены.${C_RESET}" ""
        fi
        echo -e "  ${C_CYAN}╚══════════════════════════════════════════════════════════╝${C_RESET}"

        print_separator
        local total_selected=${#selected_countries[@]}
        printf_description "Выбрано стран: ${C_YELLOW}${total_selected}${C_RESET} | Страница: ${C_CYAN}$((current_page+1))${C_RESET} из ${C_CYAN}${total_pages}${C_RESET} (Всего найдено: ${C_YELLOW}${total_items}${C_RESET})"
        if [[ -n "$search_query" ]]; then
            printf_description "Активный фильтр: ${C_GREEN}${search_query}${C_RESET} (введите ${C_YELLOW}c${C_RESET} для сброса)"
        fi
        print_separator
        echo ""
        
        printf_menu_option "1-15 (или 1 3 5)" "Переключить страну(ы) на странице"
        printf_menu_option "RU, CN (или RU CN)" "Переключить страну(ы) напрямую по ISO-коду"
        printf_menu_option "n / p" "Следующая / Предыдущая страница"
        printf_menu_option "s" "Поиск по названию или коду"
        printf_menu_option "a" "Выбрать/снять все на этой странице"
        printf_menu_option "r" "Наложить рекомендуемый пресет (merge)"
        printf_menu_option "asia / africa / latam" "Наложить континентальные пресеты (merge)"
        printf_menu_option "all" "Выбрать ВСЕ страны (Глобальный блок)"
        printf_menu_option "clear" "Сбросить выбор полностью"
        echo ""
        printf_menu_option "ok" "Сохранить изменения и выйти (Enter)"
        printf_menu_option "b" "Назад без сохранения"
        echo ""

        local choice
        choice=$(safe_read "Введите действие" "ok") || { break; }

        local choice_clean="${choice//,/ }"
        # Trim leading and trailing spaces using native Bash constructs
        choice_clean="${choice_clean#"${choice_clean%%[![:space:]]*}"}"
        choice_clean="${choice_clean%"${choice_clean##*[![:space:]]}"}"

        if [[ -z "$choice_clean" ]]; then
            choice_clean="ok"
        fi

        local tokens=()
        read -ra tokens <<< "$choice_clean"

        local handled_command=0
        if [[ ${#tokens[@]} -eq 1 ]]; then
            local token="${tokens[0]}"
            case "$token" in
                b|B)
                    if ask_yes_no "Выйти без сохранения изменений?"; then
                        break
                    fi
                    handled_command=1
                    ;;
                ok|OK)
                    # Save selected countries back to file
                    run_cmd mkdir -p "$GEO_CONFIG_DIR"
                    > "$GEO_COUNTRIES_FILE"
                    for code in "${!selected_countries[@]}"; do
                        if [[ -n "$code" ]]; then
                            echo "$code" >> "$GEO_COUNTRIES_FILE"
                        fi
                    done
                    ok "Список стран успешно сохранен!"
                    wait_for_enter
                    break
                    ;;
                n|N)
                    if [[ $((current_page + 1)) -lt $total_pages ]]; then
                        ((current_page++))
                    else
                        current_page=0
                    fi
                    handled_command=1
                    ;;
                p|P)
                    if [[ $current_page -gt 0 ]]; then
                        ((current_page--))
                    else
                        current_page=$((total_pages - 1))
                    fi
                    handled_command=1
                    ;;
                s|S)
                    local q
                    q=$(safe_read "Введите поисковый запрос" "")
                    # Trim spaces using native constructs
                    search_query="${q#"${q%%[![:space:]]*}"}"
                    search_query="${search_query%"${search_query##*[![:space:]]}"}"
                    current_page=0
                    handled_command=1
                    ;;
                c|C)
                    search_query=""
                    current_page=0
                    handled_command=1
                    ;;
                clear)
                    if ask_yes_no "Сбросить текущий выбор полностью?"; then
                        selected_countries=()
                        ok "Выбор полностью сброшен."
                        sleep 0.5
                    fi
                    handled_command=1
                    ;;
                all)
                    if ask_yes_no "Выбрать ВСЕ страны из базы для глобальной блокировки?"; then
                        for code in "${sorted_codes[@]}"; do
                            if [[ -n "$code" ]]; then
                                selected_countries[$code]=1
                            fi
                        done
                        ok "Выбраны все страны из базы."
                        sleep 0.5
                    fi
                    handled_command=1
                    ;;
                a|A)
                    if [[ $total_items -gt 0 ]]; then
                        local all_selected=1
                        for ((i=page_start; i<=page_end; i++)); do
                            local code="${filtered_codes[$i]}"
                            if [[ -z "${selected_countries[$code]:-}" ]]; then
                                all_selected=0
                                break
                            fi
                        done

                        for ((i=page_start; i<=page_end; i++)); do
                            local code="${filtered_codes[$i]}"
                            if [[ $all_selected -eq 1 ]]; then
                                unset "selected_countries[$code]"
                            else
                                selected_countries[$code]=1
                            fi
                        done
                        ok "Состояние элементов на странице изменено."
                        sleep 0.5
                    fi
                    handled_command=1
                    ;;
                r|R)
                    IFS=',' read -ra codes <<< "$GEO_PRESET_RECOMMENDED"
                    for code in "${codes[@]}"; do
                        if [[ -n "$code" ]]; then
                            selected_countries[$code]=1
                        fi
                    done
                    ok "Рекомендуемые страны добавлены."
                    sleep 0.5
                    handled_command=1
                    ;;
                asia)
                    IFS=',' read -ra codes <<< "$GEO_PRESET_ASIA"
                    for code in "${codes[@]}"; do
                        if [[ -n "$code" ]]; then
                            selected_countries[$code]=1
                        fi
                    done
                    ok "Страны Азии добавлены."
                    sleep 0.5
                    handled_command=1
                    ;;
                africa)
                    IFS=',' read -ra codes <<< "$GEO_PRESET_AFRICA"
                    for code in "${codes[@]}"; do
                        if [[ -n "$code" ]]; then
                            selected_countries[$code]=1
                        fi
                    done
                    ok "Страны Африки добавлены."
                    sleep 0.5
                    handled_command=1
                    ;;
                latam)
                    IFS=',' read -ra codes <<< "$GEO_PRESET_LATAM"
                    for code in "${codes[@]}"; do
                        if [[ -n "$code" ]]; then
                            selected_countries[$code]=1
                        fi
                    done
                    ok "Страны Латинской Америки добавлены."
                    sleep 0.5
                    handled_command=1
                    ;;
            esac
        fi

        if [[ $handled_command -eq 0 ]]; then
            local toggled_any=0
            for token in "${tokens[@]}"; do
                if [[ "$token" =~ ^[0-9]+$ ]]; then
                    local idx="$token"
                    local target_idx=$((page_start + idx - 1))
                    if [[ "$idx" -ge 1 && "$target_idx" -le $page_end ]]; then
                        local code="${filtered_codes[$target_idx]}"
                        local country_name=""
                        if [[ "$code" =~ ^[A-Z]{2}$ && -v GEO_ALL_COUNTRIES[$code] ]]; then
                            country_name="${GEO_ALL_COUNTRIES[$code]}"
                        else
                            country_name="?"
                        fi
                        if [[ -n "${selected_countries[$code]:-}" ]]; then
                            unset "selected_countries[$code]"
                            ok "Убрано: $code (${country_name})"
                        else
                            selected_countries[$code]=1
                            ok "Добавлено: $code (${country_name})"
                        fi
                        toggled_any=1
                    else
                        err "Неверный номер на странице: $idx"
                    fi
                elif [[ "$token" =~ ^[a-zA-Z]{2}$ ]]; then
                    local code="${token^^}"
                    if [[ "$code" =~ ^[A-Z]{2}$ && -v GEO_ALL_COUNTRIES[$code] ]]; then
                        local country_name="${GEO_ALL_COUNTRIES[$code]}"
                        if [[ -n "${selected_countries[$code]:-}" ]]; then
                            unset "selected_countries[$code]"
                            ok "Убрано: $code (${country_name})"
                        else
                            selected_countries[$code]=1
                            ok "Добавлено: $code (${country_name})"
                        fi
                        toggled_any=1
                    else
                        err "Код страны не найден в базе: $code"
                    fi
                else
                    err "Неизвестное действие или код: $token"
                fi
            done
            if [[ $toggled_any -eq 1 ]]; then
                sleep 0.5
            else
                sleep 1
            fi
        fi
        disable_graceful_ctrlc
    done
}

_geo_draw_progress_bar() {
    local current="$1"
    local total="$2"
    local country_name="$3"
    local subnets="$4"
    
    local width=20
    local percentage=$(( current * 100 / total ))
    local filled=$(( current * width / total ))
    local empty=$(( width - filled ))
    
    local bar=""
    for ((i=0; i<filled; i++)); do bar="${bar}█"; done
    for ((i=0; i<empty; i++)); do bar="${bar}░"; done
    
    printf "\r  ${C_CYAN}[%s]${C_RESET} %3d%% (%d/%d) | Текущая: ${C_YELLOW}%-15.15s${C_RESET} | Подсети: ${C_GREEN}%d${C_RESET}\e[K" \
        "$bar" "$percentage" "$current" "$total" "$country_name" "$subnets"
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

    # Инициализируем перехват Ctrl+C
    enable_graceful_ctrlc
    _LAST_CTRLC_SIGNALED=0

    # Читаем страны во временный массив, очищая пустые строки и carriage returns
    local countries=()
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line//[$'\r\n\t ']/}"
        line="${line^^}"
        [[ -n "$line" ]] && countries+=("$line")
    done < "$GEO_COUNTRIES_FILE"

    local total_countries=${#countries[@]}
    if [[ "$total_countries" -eq 0 ]]; then
        err "Список стран пуст или поврежден!"
        disable_graceful_ctrlc
        return 1
    fi

    local temp_ipset="${GEO_IPSET_NAME}_temp"
    local temp_wl_ipset="reshala_geo_whitelist_temp"

    # Вспомогательная функция для быстрой проверки отмены
    _check_ctrlc() {
        if [[ "${_LAST_CTRLC_SIGNALED:-0}" -eq 1 ]]; then
            echo ""
            warn "Активация прервана пользователем!"
            if [[ ${#pids[@]} -gt 0 ]]; then
                for pid in "${pids[@]}"; do
                    kill "$pid" 2>/dev/null || true
                done
            fi
            if [[ -n "${temp_dir:-}" && -d "$temp_dir" ]]; then
                rm -rf "$temp_dir"
            fi
            run_cmd ipset destroy "$temp_ipset" 2>/dev/null || true
            run_cmd ipset destroy "$temp_wl_ipset" 2>/dev/null || true
            disable_graceful_ctrlc
            return 1
        fi
        return 0
    }

    # Создаем временный ipset
    info "Создаю временный ipset..."
    run_cmd ipset destroy "$temp_ipset" 2>/dev/null || true
    run_cmd ipset create "$temp_ipset" hash:net hashsize 65536 maxelem 500000

    _check_ctrlc || return 130

    local temp_dir
    temp_dir=$(mktemp -d)

    _check_ctrlc || return 130

    local max_parallel=16
    local pids=()
    local -A country_map
    local completed=0
    local subnets_total=0
    local skipped_countries=()

    # Загружаем зоны стран параллельно
    local idx=0
    while [[ $idx -lt $total_countries || ${#pids[@]} -gt 0 ]]; do
        _check_ctrlc || return 130

        # Добавляем новые задачи в очередь
        while [[ ${#pids[@]} -lt $max_parallel && $idx -lt $total_countries ]]; do
            _check_ctrlc || return 130
            
            local country="${countries[$idx]}"
            local zone_url="https://www.ipdeny.com/ipblocks/data/aggregated/${country,,}-aggregated.zone"
            
            (
                curl -s --max-time 15 "$zone_url" > "$temp_dir/$country.zone"
            ) &
            local new_pid=$!
            pids+=("$new_pid")
            country_map[$new_pid]="$country"
            ((idx++))
        done

        sleep 0.1
        _check_ctrlc || return 130

        # Опрашиваем процессы
        local active_pids=()
        for pid in "${pids[@]}"; do
            if kill -0 "$pid" 2>/dev/null; then
                active_pids+=("$pid")
            else
                local country="${country_map[$pid]}"
                local country_name="?"
                if [[ "$country" =~ ^[A-Z]{2}$ && -v GEO_ALL_COUNTRIES[$country] ]]; then
                    country_name="${GEO_ALL_COUNTRIES[$country]}"
                else
                    country_name="$country"
                fi
                local zone_file="$temp_dir/$country.zone"
                
                local count=0
                if [[ -f "$zone_file" ]]; then
                    count=$(grep -c "^[0-9]" "$zone_file" || echo "0")
                    if [[ "$count" -gt 0 ]]; then
                        awk -v set_name="$temp_ipset" '/^[0-9]/ {print "add " set_name " " $1 " -exist"}' "$zone_file" >> "$temp_dir/restore.txt"
                        subnets_total=$((subnets_total + count))
                    else
                        skipped_countries+=("$country")
                    fi
                else
                    skipped_countries+=("$country")
                fi
                
                ((completed++))
                _geo_draw_progress_bar "$completed" "$total_countries" "$country_name" "$subnets_total"
            fi
        done
        pids=("${active_pids[@]}")
    done

    echo "" # Завершаем прогресс-бар

    _check_ctrlc || return 130

    if [[ ${#skipped_countries[@]} -gt 0 ]]; then
        warn "Не удалось загрузить зоны для стран: ${skipped_countries[*]} (пропущено)"
    fi

    if [[ "$subnets_total" -gt 0 ]]; then
        info "Применяю правила блокировки для ${subnets_total} подсетей (пакетный режим через ipset restore)..."
        _check_ctrlc || return 130

        if run_cmd ipset restore < "$temp_dir/restore.txt"; then
            # Производим бесшовную замену (swap) основного ipset
            if ! ipset list "$GEO_IPSET_NAME" &>/dev/null; then
                run_cmd ipset create "$GEO_IPSET_NAME" hash:net hashsize 65536 maxelem 500000
            fi
            run_cmd ipset swap "$GEO_IPSET_NAME" "$temp_ipset"
            run_cmd ipset destroy "$temp_ipset" 2>/dev/null || true
            ok "Загружено подсетей: ${subnets_total}"
        else
            if [[ "${_LAST_CTRLC_SIGNALED:-0}" -eq 1 ]]; then
                run_cmd ipset destroy "$temp_ipset" 2>/dev/null || true
                rm -rf "$temp_dir"
                _check_ctrlc
                return 130
            fi
            err "Ошибка при восстановлении ipset!"
            run_cmd ipset destroy "$temp_ipset" 2>/dev/null || true
            rm -rf "$temp_dir"
            disable_graceful_ctrlc
            return 1
        fi
    else
        err "Ни одна зона не была загружена! Проверьте интернет-соединение."
        rm -rf "$temp_dir"
        run_cmd ipset destroy "$temp_ipset" 2>/dev/null || true
        disable_graceful_ctrlc
        return 1
    fi
    rm -rf "$temp_dir"

    _check_ctrlc || return 130

    # Добавляем whitelist из Глобального Белого Списка
    info "Добавляю IP из Глобального Белого Списка в обход..."
    _check_ctrlc || return 130

    local found_wl_manager=0
    if ! command -v global_whitelist_prepend_system_ips &>/dev/null; then
        if [[ -f "${SCRIPT_DIR:-/opt/reshala}/modules/security/whitelist_manager.sh" ]]; then
            source "${SCRIPT_DIR:-/opt/reshala}/modules/security/whitelist_manager.sh" && found_wl_manager=1
        elif [[ -f "modules/security/whitelist_manager.sh" ]]; then
            source "modules/security/whitelist_manager.sh" && found_wl_manager=1
        fi
    else
        found_wl_manager=1
    fi

    if [[ $found_wl_manager -eq 1 ]]; then
        global_whitelist_prepend_system_ips || true
    fi

    run_cmd ipset destroy "$temp_wl_ipset" 2>/dev/null || true
    run_cmd ipset create "$temp_wl_ipset" hash:net hashsize 256 maxelem 1024 2>/dev/null || true

    _check_ctrlc || return 130

    local wl_ips=()
    # Автоматически добавляем локальные диапазоны
    wl_ips+=("127.0.0.1")
    wl_ips+=("10.0.0.0/8")
    wl_ips+=("172.16.0.0/12")
    wl_ips+=("192.168.0.0/16")

    # Получаем локальный внутренний IP сервера
    local srv_ip
    srv_ip=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' | head -1)
    if [[ -n "$srv_ip" ]]; then
        wl_ips+=("$srv_ip")
    fi

    # Получаем публичный IP сервера с фолбеком
    local pub_ip
    pub_ip=$(curl -s --max-time 3 https://api.ipify.org 2>/dev/null)
    if [[ -z "$pub_ip" ]]; then
        pub_ip=$(curl -s --max-time 3 https://ifconfig.me 2>/dev/null)
    fi
    if [[ -n "$pub_ip" && "$pub_ip" != "$srv_ip" ]]; then
        wl_ips+=("$pub_ip")
    fi

    # Считываем пользовательские настройки
    local custom_ips=()
    if command -v global_whitelist_get_ips &>/dev/null; then
        mapfile -t custom_ips < <(global_whitelist_get_ips)
    elif [[ -f "$GLOBAL_WHITELIST_FILE" ]]; then
        while IFS= read -r line || [[ -n "$line" ]]; do
            line="${line%%#*}"
            line="${line//[$'\r\n\t ']/}"
            if [[ -n "$line" ]]; then
                custom_ips+=("$line")
            fi
        done < "$GLOBAL_WHITELIST_FILE"
    fi

    # Объединяем все адреса
    for ip in "${custom_ips[@]}"; do
        wl_ips+=("$ip")
    done

    _check_ctrlc || { run_cmd ipset destroy "$temp_wl_ipset" 2>/dev/null || true; return 130; }

    # Удаляем дубликаты и валидируем форматы (поддерживается только IPv4 в hash:net)
    local -A seen_wl_ips
    local unique_wl_ips=()
    for ip in "${wl_ips[@]}"; do
        ip="${ip//[$'\r\n\t ']/}"
        [[ -z "$ip" ]] && continue
        if [[ "$ip" == *:* ]]; then
            continue
        fi
        if [[ -z "${seen_wl_ips[$ip]:-}" ]]; then
            seen_wl_ips[$ip]=1
            unique_wl_ips+=("$ip")
        fi
    done

    local added_count=0
    if [[ ${#unique_wl_ips[@]} -gt 0 ]]; then
        local temp_wl_restore
        temp_wl_restore=$(mktemp)
        for ip in "${unique_wl_ips[@]}"; do
            echo "add $temp_wl_ipset $ip -exist" >> "$temp_wl_restore"
            ((added_count++))
        done
        
        _check_ctrlc || { rm -f "$temp_wl_restore"; run_cmd ipset destroy "$temp_wl_ipset" 2>/dev/null || true; return 130; }

        if [[ $added_count -gt 0 ]]; then
            if ! run_cmd ipset restore < "$temp_wl_restore"; then
                if [[ "${_LAST_CTRLC_SIGNALED:-0}" -eq 1 ]]; then
                    rm -f "$temp_wl_restore"
                    run_cmd ipset destroy "$temp_wl_ipset" 2>/dev/null || true
                    _check_ctrlc
                    return 130
                else
                    err "Ошибка при импорте белого списка в ipset!"
                    run_cmd ipset destroy "$temp_wl_ipset" 2>/dev/null || true
                    rm -f "$temp_wl_restore"
                    disable_graceful_ctrlc
                    return 1
                fi
            fi
        fi
        rm -f "$temp_wl_restore"
    fi

    # Swap whitelist
    if ! ipset list reshala_geo_whitelist &>/dev/null; then
        run_cmd ipset create reshala_geo_whitelist hash:net hashsize 256 maxelem 1024 2>/dev/null || true
    fi
    run_cmd ipset swap reshala_geo_whitelist "$temp_wl_ipset"
    run_cmd ipset destroy "$temp_wl_ipset" 2>/dev/null || true

    ok "Whitelist: ${added_count} IPv4 адрес(ов) добавлены в обход."

    _check_ctrlc || return 130

    # Вставляем правило в UFW before.rules
    _geo_insert_ufw_rule

    _check_ctrlc || return 130

    # Создаем кэш на диске
    info "Сохраняю правила в локальный кэш..."
    run_cmd mkdir -p "$GEO_CONFIG_DIR"
    run_cmd ipset save "$GEO_IPSET_NAME" > "$GEO_CONFIG_DIR/${GEO_IPSET_NAME}.ipset"
    run_cmd ipset save reshala_geo_whitelist > "$GEO_CONFIG_DIR/reshala_geo_whitelist.ipset"
    ok "Локальный кэш успешно обновлен."

    _check_ctrlc || return 130

    # Создаем systemd-сервис для автозагрузки
    _geo_create_autostart

    _check_ctrlc || return 130

    # Перезагружаем UFW
    if command -v ufw &>/dev/null; then
        run_cmd ufw reload 2>/dev/null || true
    fi

    disable_graceful_ctrlc
    ok "Geo-Block активирован! Заблокировано стран: ${total_countries}, подсетей: ${subnets_total}"
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
# Блокировка по странам (новые соединения, исключая loopback и белый список)
-A ufw-before-input ! -i lo -m set --match-set ${GEO_IPSET_NAME} src -m set ! --match-set reshala_geo_whitelist src -m conntrack --ctstate NEW -j DROP
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
    # Скрипт восстановления ipset после ребута из кэша с фолбеком на загрузку
    cat <<'SCRIPT' | run_cmd tee "$GEO_RESTORE_SCRIPT" > /dev/null
#!/bin/bash
# Reshala Geo-Block: Быстрое оффлайн-восстановление ipset после ребута

GEO_CONFIG_DIR="/etc/reshala/geoblock"
GEO_IPSET_NAME="reshala_geoblock"
GEO_COUNTRIES_FILE="${GEO_CONFIG_DIR}/countries.txt"
GLOBAL_WHITELIST_FILE="/etc/reshala/global-whitelist.txt"

# Разрушаем существующие
ipset destroy ${GEO_IPSET_NAME} 2>/dev/null || true
ipset destroy reshala_geo_whitelist 2>/dev/null || true

# 1. Проверяем локальный кэш
if [[ -f "${GEO_CONFIG_DIR}/${GEO_IPSET_NAME}.ipset" && -f "${GEO_CONFIG_DIR}/reshala_geo_whitelist.ipset" ]]; then
    echo "[i] Восстановление Geo-Block из локального кэша..."
    if ipset restore < "${GEO_CONFIG_DIR}/${GEO_IPSET_NAME}.ipset" && \
       ipset restore < "${GEO_CONFIG_DIR}/reshala_geo_whitelist.ipset"; then
        echo "[✓] Успешно восстановлено из кэша!"
        exit 0
    fi
    echo "[!] Сбой восстановления из кэша, пробуем пересобрать..."
fi

# 2. Фолбек: если кэша нет или сбой, скачиваем зоны
echo "[!] Кэш не найден или поврежден. Пересобираю базы..."
ipset create ${GEO_IPSET_NAME} hash:net hashsize 65536 maxelem 500000
ipset create reshala_geo_whitelist hash:net hashsize 256 maxelem 1024 2>/dev/null || true

[[ ! -f "$GEO_COUNTRIES_FILE" ]] && exit 0

TEMP_RESTORE=$(mktemp)

while IFS= read -r country || [[ -n "$country" ]]; do
    country="${country//[$'\r\n\t ']/}"
    country="${country,,}"
    [[ -z "$country" ]] && continue
    
    ZONE_DATA=$(curl -s --max-time 15 "https://www.ipdeny.com/ipblocks/data/aggregated/${country}-aggregated.zone" 2>/dev/null)
    if [[ -n "$ZONE_DATA" ]]; then
        echo "$ZONE_DATA" | awk -v set_name="${GEO_IPSET_NAME}" '/^[0-9]/ {print "add " set_name " " $1 " -exist"}' >> "$TEMP_RESTORE"
    fi
done < "$GEO_COUNTRIES_FILE"

if [[ -s "$TEMP_RESTORE" ]]; then
    ipset restore < "$TEMP_RESTORE"
fi
rm -f "$TEMP_RESTORE"

# Whitelist
if [[ -f "${GLOBAL_WHITELIST_FILE}" ]]; then
    TEMP_WL_RESTORE=$(mktemp)
    grep -v '^\s*#' "${GLOBAL_WHITELIST_FILE}" | grep -v '^\s*$' | awk '{print $1}' | while read -r ip; do
        ip="${ip//[$'\r\n\t ']/}"
        if [[ -n "$ip" && "$ip" != *:* ]]; then
            echo "add reshala_geo_whitelist $ip -exist" >> "$TEMP_WL_RESTORE"
        fi
    done
    if [[ -s "$TEMP_WL_RESTORE" ]]; then
        ipset restore < "$TEMP_WL_RESTORE"
    fi
    rm -f "$TEMP_WL_RESTORE"
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

    if ! ipset list "$GEO_IPSET_NAME" -terse &>/dev/null 2>&1; then
        warn "Geo-Block не активен."
        return
    fi

    local total
    total=$(_geo_get_ipset_count "$GEO_IPSET_NAME")
    
    local countries_count="0"
    if [[ -f "$GEO_COUNTRIES_FILE" ]]; then
        countries_count=$(grep -c "^[A-Z]" "$GEO_COUNTRIES_FILE" || echo "0")
    fi

    local dropped="0"
    if iptables -L ufw-before-input -v -n 2>/dev/null | grep -q "$GEO_IPSET_NAME"; then
        dropped=$(iptables -L ufw-before-input -v -n 2>/dev/null | grep "$GEO_IPSET_NAME" | awk '{print $1}')
    fi

    echo -e "  ${C_CYAN}╔══════════════════════════════════════════════════════════╗${C_RESET}"
    _geo_print_card_header "📊 ТЕКУЩИЕ ПОКАЗАТЕЛИ БЛОКИРОВКИ"
    echo -e "  ${C_CYAN}╠══════════════════════════════════════════════════════════╣${C_RESET}"
    _geo_print_card_row "Активная база подсетей (ipset):" "${C_CYAN}${total}${C_RESET}"
    _geo_print_card_row "Заблокировано целевых стран:" "${C_YELLOW}${countries_count}${C_RESET}"
    _geo_print_card_row "Отсечено пакетов (iptables/UFW):" "${C_RED}${dropped:-0}${C_RESET}"
    echo -e "  ${C_CYAN}╚══════════════════════════════════════════════════════════╝${C_RESET}"
    echo ""
}

_geo_test_ip() {
    print_separator
    info "Проверка IP-адреса"
    print_separator

    local ip
    ip=$(safe_read "Введите IP-адрес для проверки" "") || return
    ip="${ip//[$'\r\n\t ']/}"
    
    if [[ -z "$ip" ]]; then
        err "IP-адрес не может быть пустым."
        return
    fi

    # Валидация формата IPv4
    if [[ ! "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        err "Некорректный формат IPv4-адреса."
        return
    fi

    # Проверяем октеты
    local IFS='.'
    local octets
    read -ra octets <<< "$ip"
    for octet in "${octets[@]}"; do
        if ((octet < 0 || octet > 255)); then
            err "Каждый октет IPv4 должен быть от 0 до 255."
            return
        fi
    done

    info "Диагностика адреса $ip..."

    # Проверка страны через онлайн API (сверхбыстрый тайм-аут)
    local country_code=""
    country_code=$(curl -s --max-time 2 "https://ipinfo.io/${ip}/country" 2>/dev/null)
    country_code="${country_code//[$'\r\n\t ']/}"
    country_code="${country_code^^}"

    local country_name="Неизвестно"
    if [[ -n "$country_code" ]]; then
        if [[ -v GEO_ALL_COUNTRIES[$country_code] ]]; then
            country_name="${GEO_ALL_COUNTRIES[$country_code]}"
        else
            country_name="Код $country_code"
        fi
    fi

    # Проверка в ipset
    local is_active=0
    local in_whitelist="⚪ Нет"
    local in_geoblock="⚪ Нет"
    local status="${C_GREEN}🟢 РАЗРЕШЕН (Geo-Block не активен)${C_RESET}"

    if ipset list reshala_geo_whitelist &>/dev/null; then
        is_active=1
        if ipset test reshala_geo_whitelist "$ip" &>/dev/null; then
            in_whitelist="${C_GREEN}🟢 Да (В белом списке)${C_RESET}"
        fi
    fi

    if ipset list "$GEO_IPSET_NAME" &>/dev/null; then
        is_active=1
        if ipset test "$GEO_IPSET_NAME" "$ip" &>/dev/null; then
            in_geoblock="${C_RED}🔴 Да (В черном списке)${C_RESET}"
        fi
    fi

    if [[ $is_active -eq 1 ]]; then
        if [[ "$in_whitelist" == *"Да"* ]]; then
            status="${C_GREEN}🟢 РАЗРЕШЕН (Белый список обходит блокировки)${C_RESET}"
        elif [[ "$in_geoblock" == *"Да"* ]]; then
            status="${C_RED}🔴 ЗАБЛОКИРОВАН (Страна входит в Geo-Block)${C_RESET}"
        else
            status="${C_GREEN}🟢 РАЗРЕШЕН (Страна не заблокирована)${C_RESET}"
        fi
    fi

    echo -e "  ${C_CYAN}╔══════════════════════════════════════════════════════════╗${C_RESET}"
    _geo_print_card_header "🔬 РЕЗУЛЬТАТ ДИАГНОСТИКИ IP"
    echo -e "  ${C_CYAN}╠══════════════════════════════════════════════════════════╣${C_RESET}"
    _geo_print_card_row "IP-адрес:" "${C_WHITE}${ip}${C_RESET}"
    _geo_print_card_row "Определенная страна:" "${C_YELLOW}${country_name} (${country_code:-?})${C_RESET}"
    _geo_print_card_row "В белом списке:" "$in_whitelist"
    _geo_print_card_row "В базе блокировок:" "$in_geoblock"
    _geo_print_card_row "Итоговый статус:" "$status"
    echo -e "  ${C_CYAN}╚══════════════════════════════════════════════════════════╝${C_RESET}"
    echo ""
}

_geo_toggle_auto_update() {
    print_separator
    info "Управление автоматическим обновлением"
    print_separator

    local cron_file="/etc/cron.d/reshala-geoblock-update"
    local updater_script="/usr/local/bin/reshala-geoblock-update.sh"

    local active=0
    if [[ -f "$cron_file" ]]; then
        active=1
    fi

    if [[ $active -eq 1 ]]; then
        printf_description "Текущий статус: ${C_GREEN}ВКЛЮЧЕНО (еженедельно)${C_RESET}"
        if ask_yes_no "Выключить автоматическое обновление?"; then
            run_cmd rm -f "$cron_file" "$updater_script" 2>/dev/null || true
            ok "Автоматическое обновление выключено."
        fi
    else
        printf_description "Текущий статус: ${C_RED}ВЫКЛЮЧЕНО${C_RESET}"
        if ask_yes_no "Включить еженедельное обновление по понедельникам в 03:00?"; then
            # Создаем скрипт тихого обновления
            cat <<'UPDATE_SCRIPT' | run_cmd tee "$updater_script" > /dev/null
#!/bin/bash
# Reshala Geo-Block: Тихое фоновое автообновление правил
export SCRIPT_DIR="/opt/reshala"
source "${SCRIPT_DIR}/modules/core/common.sh" 2>/dev/null || true
source "${SCRIPT_DIR}/modules/security/geoblock.sh" 2>/dev/null || true

# Временный лог
exec 1>>/var/log/reshala-geoblock-update.log 2>&1

echo "[$(date '+%Y-%m-%d %H:%M:%S')] Запуск автообновления..."

if [[ ! -f "/etc/reshala/geoblock/countries.txt" ]] || [[ ! -s "/etc/reshala/geoblock/countries.txt" ]]; then
    echo "[!] Список стран пуст. Обновление невозможно."
    exit 1
fi

# Имитируем тихую активацию
# Считываем страны
countries=()
while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line//[$'\r\n\t ']/}"
    line="${line^^}"
    [[ -n "$line" ]] && countries+=("$line")
done < "/etc/reshala/geoblock/countries.txt"

total_countries=${#countries[@]}
temp_dir=$(mktemp -d)
temp_ipset="reshala_geoblock_temp"

ipset destroy "$temp_ipset" 2>/dev/null || true
ipset create "$temp_ipset" hash:net hashsize 65536 maxelem 500000

subnets_total=0
for country in "${countries[@]}"; do
    zone_url="https://www.ipdeny.com/ipblocks/data/aggregated/${country,,}-aggregated.zone"
    curl -s --max-time 15 "$zone_url" > "$temp_dir/$country.zone"
    if [[ -f "$temp_dir/$country.zone" ]]; then
        count=$(grep -c "^[0-9]" "$temp_dir/$country.zone" || echo "0")
        if [[ "$count" -gt 0 ]]; then
            awk -v set_name="$temp_ipset" '/^[0-9]/ {print "add " set_name " " $1 " -exist"}' "$temp_dir/$country.zone" >> "$temp_dir/restore.txt"
            subnets_total=$((subnets_total + count))
        fi
    fi
done

if [[ "$subnets_total" -gt 0 && -f "$temp_dir/restore.txt" ]]; then
    if ipset restore < "$temp_dir/restore.txt"; then
        # Swap
        if ! ipset list reshala_geoblock &>/dev/null; then
            ipset create reshala_geoblock hash:net hashsize 65536 maxelem 500000
        fi
        ipset swap reshala_geoblock "$temp_ipset"
        ipset destroy "$temp_ipset" 2>/dev/null || true
        
        # Сохраняем в кэш
        mkdir -p "/etc/reshala/geoblock"
        ipset save reshala_geoblock > "/etc/reshala/geoblock/reshala_geoblock.ipset"
        echo "[✓] База успешно обновлена! Загружено подсетей: $subnets_total"
    else
        echo "[✗] Ошибка при восстановлении ipset во время обновления."
        ipset destroy "$temp_ipset" 2>/dev/null || true
        rm -rf "$temp_dir"
        exit 1
    fi
else
    echo "[✗] Не удалось загрузить ни одну зону."
    ipset destroy "$temp_ipset" 2>/dev/null || true
    rm -rf "$temp_dir"
    exit 1
fi

rm -rf "$temp_dir"
exit 0
UPDATE_SCRIPT
            run_cmd chmod +x "$updater_script"

            # Создаем задачу в cron
            echo "0 3 * * 1 root $updater_script" | run_cmd tee "$cron_file" > /dev/null
            ok "Автоматическое обновление успешно настроено (каждый понедельник в 03:00)."
        fi
    fi
}

