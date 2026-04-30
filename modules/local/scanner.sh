#!/bin/bash
# ============================================================ #
# ==           МОДУЛЬ REALITY TLS SCANNER PRO               == #
# ============================================================ #
#
# Мощный радар для поиска идеальных доменов маскировки Reality.
#
#  ( РОДИТЕЛЬ | КЛАВИША | НАЗВАНИЕ | ФУНКЦИЯ | ПОРЯДОК | ГРУППА | ОПИСАНИЕ )
# @menu.manifest
#
# @item( main | 3 | 🔍 TLS Reality Scanner ${C_MAGENTA}(PRO)${C_RESET} | menu_scanner | 10 | 2 | Поиск идеальных SNI для обхода блокировок. )
#

[[ "${BASH_SOURCE[0]}" == "${0}" ]] && exit 1 # Защита от прямого запуска
SCANNER_DIR="/opt/RealiTLScanner"
SCANNER_BIN="$SCANNER_DIR/RealiTLScanner"
GEO_DB="$SCANNER_DIR/Country.mmdb"
INPUT_FILE="$SCANNER_DIR/in.txt"
RECON_DIR="$SCANNER_DIR/recon"

# --- 1. УСТАНОВКА И СБОРКА ---
check_scanner_install() {
    export PATH=/usr/local/go/bin:$PATH
    mkdir -p "$RECON_DIR" 2>/dev/null
    
    # Очистка от старого мусора (убиваем дефолтный out.csv)
    rm -f "$SCANNER_DIR/out.csv" 2>/dev/null

if [[ ! -f "$SCANNER_BIN" ]]; then
        echo -e "${YELLOW}[*] Сканер не найден. Начинаю установку (Go 1.22+)...${NC}"
        
        # ⚡ ЕДИНЫЙ СТАНДАРТ: Установка пакетов
        ensure_package "git"
        ensure_package "curl"
        ensure_package "wget"
        
        # ⚡ ЕДИНЫЙ СТАНДАРТ: Умное скачивание Go
        echo -e "${C_GRAY}--> Скачивание Golang...${C_RESET}"
        run_cmd curl -sL --connect-timeout 120 -o "/tmp/go.tar.gz" "https://go.dev/dl/go1.22.1.linux-amd64.tar.gz" || return 1
        
        rm -rf /usr/local/go
        tar -C /usr/local -xzf /tmp/go.tar.gz
        rm /tmp/go.tar.gz
        export PATH=/usr/local/go/bin:$PATH

        rm -rf "$SCANNER_DIR/RealiTLScanner_src"
        
        # ⚡ ЕДИНЫЙ СТАНДАРТ: Умный Git Clone с зеркалами
        run_cmd git clone "https://github.com/xtls/RealiTLScanner.git" "$SCANNER_DIR/RealiTLScanner_src" || return 1
        
        cd "$SCANNER_DIR/RealiTLScanner_src" || return
        echo -e "${CYAN}[*] Компиляция бинарника...${NC}"
        go build -o "$SCANNER_BIN"
        
        if [[ -f "$SCANNER_BIN" ]]; then 
            chmod +x "$SCANNER_BIN"
            rm -rf "$SCANNER_DIR/RealiTLScanner_src"
        else 
            echo -e "${RED}[!] ОШИБКА сборки.${NC}"; pause; return 1
        fi
    fi

    if [[ ! -f "$GEO_DB" ]]; then
        echo -e "${C_YELLOW}[*] Загрузка MaxMind GeoLite2 (Country.mmdb)...${C_RESET}"
        run_cmd curl -sL --connect-timeout 30 -o "$GEO_DB" "https://github.com/Loyalsoldier/geoip/releases/latest/download/Country.mmdb" || return 1
    fi
}

show_geo_help() {
    echo -e "\n${CYAN}📋 СПРАВОЧНИК ПОПУЛЯРНЫХ КОДОВ СТРАН (ISO 3166-1 alpha-2):${NC}"
    echo -e "${GRAY}FI - Финляндия | NL - Нидерланды | DE - Германия | FR - Франция${NC}"
    echo -e "${GRAY}US - США       | GB - Великобрит.| RU - Россия   | PL - Польша${NC}"
    echo -e "${GRAY}SE - Швеция    | CH - Швейцария  | ES - Испания  | TR - Турция${NC}\n"
}

# --- 2. РЕЖИМ "РЕНТГЕН" И ПРОБИВ ПРОВАЙДЕРА (ОДНА ЦЕЛЬ) ---
run_single_scan() {
    clear
    echo -e "${MAGENTA}======================================================${NC}"
    echo -e "${BOLD} 🔬 РЕЖИМ: СТРОГИЙ СКАН И ПРОБИВ ЦЕЛИ (OSINT)${NC}"
    echo -e "${MAGENTA}======================================================${NC}"
    echo -e "${CYAN}Для чего это нужно?${NC}"
    echo -e "${GRAY}Скрипт проверяет конкретный сервер, выдает его полное TLS-досье и ищет${NC}"
    echo -e "${GRAY}сайт хостинг-провайдера (чтобы вы могли арендовать сервер там же).${NC}\n"

    read -p ">> Введите цель (IP или Домен): " target
    [[ -z "$target" ]] && return

    if [[ "$target" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then 
        local safe_target=$target
        target="${target}/32"
    else
        local safe_target=$target
    fi

    echo -e "\n${BLUE}--- ⚙️ ТОНКАЯ НАСТРОЙКА ---${NC}"
    echo -e "${YELLOW}1. Целевые порты (-port)${NC}"
    echo -e "${GRAY}Обычно маскировка Reality работает на HTTPS порту 443.${NC}"
    echo -e "${GRAY}Но можно указать несколько (напр: 443, 8443). Скрипт проверит их по очереди.${NC}"
    read -p ">> Порт(ы) через запятую (Enter = 443): " s_port
    s_port=${s_port:-443}
    IFS=',' read -ra PORT_ARRAY <<< "${s_port// /}"

    echo -e "\n${GREEN}[*] ЗАПУСК СКАНИРОВАНИЯ И СБОР ДАННЫХ (OSINT)...${NC}"
    echo -e "${RED}⚠️ ВАЖНО: Вы можете прервать процесс, нажав [Ctrl+C] в любой момент!${NC}"
    echo -e "${GRAY}Скрипт НЕ закроется. Он просто досрочно остановит проверку портов,${NC}"
    echo -e "${GRAY}сохранит всё, что успел найти, и покажет вам готовое досье.${NC}\n"
    
    local REPORT_OUTPUT=""
    local nl=$'\n'

    local ip_to_check=$safe_target
    if [[ ! "$ip_to_check" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        ip_to_check=$(getent hosts "$safe_target" | awk '{ print $1 }' | head -n 1)
    fi

    REPORT_OUTPUT+="======================================================${nl}"
    REPORT_OUTPUT+=" 📄 ПОЛНОЕ ДОСЬЕ НА ЦЕЛЬ: ${safe_target}${nl}"
    REPORT_OUTPUT+="======================================================${nl}"

    if [[ -n "$ip_to_check" ]]; then
        ensure_package "jq" >/dev/null 2>&1
        local provider=$(curl -sL "https://ipinfo.io/${ip_to_check}/json" | jq -r '.org // "Неизвестно"' 2>/dev/null || echo "Неизвестно")
        local country=$(curl -sL "https://ipinfo.io/${ip_to_check}/json" | jq -r '.country // "??"' 2>/dev/null || echo "??")
        local city=$(curl -sL "https://ipinfo.io/${ip_to_check}/json" | jq -r '.city // "Неизвестно"' 2>/dev/null || echo "Неизвестно")
        local host_name=$(curl -sL "https://ipinfo.io/${ip_to_check}/json" | jq -r '.hostname // ""' 2>/dev/null || echo "")
        
        REPORT_OUTPUT+=" 📡 ИНФОРМАЦИЯ О ПРОВАЙДЕРЕ (OSINT)${nl}"
        REPORT_OUTPUT+="   └─ Провайдер (ASN): ${provider}${nl}"
        REPORT_OUTPUT+="   └─ Город:           ${city} (${country})${nl}"
        
        if [[ -n "$host_name" && "$host_name" != "null" ]]; then
            local base_domain=$(echo "$host_name" | awk -F. '{if (NF>1) print $(NF-1)"."$NF; else print $0}')
            REPORT_OUTPUT+="   └─ Сайт хостинга:   https://${base_domain} (из PTR: $host_name)${nl}"
        fi
        
        if [[ -n "$provider" ]]; then
            local search_query=$(echo "buy vps $provider" | sed 's/ /+/g')
            REPORT_OUTPUT+="   └─ Резервный поиск: https://www.google.com/search?q=${search_query}${nl}"
        fi
        REPORT_OUTPUT+="------------------------------------------------------${nl}"
    fi
    
    cd "$SCANNER_DIR" || return
    export PATH=/usr/local/go/bin:$PATH
    
    trap 'echo -e "\n${YELLOW}🛑 Процесс прерван пользователем. Формируем досье...${NC}"; break' INT

    for current_port in "${PORT_ARRAY[@]}"; do
        REPORT_OUTPUT+=" >>> СКАНИРОВАНИЕ ПОРТА: ${current_port} <<<${nl}"
        
        local tmp_ghost="tmp_ghost_${current_port}.csv"
        local scan_log=$(./RealiTLScanner -addr "$target" -port "$current_port" -timeout 5 -v -out "$tmp_ghost" 2>&1)
        rm -f "$tmp_ghost" 2>/dev/null # Уничтожаем призрачный файл
        
        local found_info=false
        
        while read -r line; do
            if [[ "$line" == *"Connected to target"* ]]; then
                found_info=true
                local feas=$(echo "$line" | grep -oP 'feasible=\K[^ ]+')
                local ip=$(echo "$line" | grep -oP 'ip=\K[^ ]+')
                local tls=$(echo "$line" | grep -oP 'tls=\K([^ ]+|"[^"]+")' | tr -d '"')
                local alpn=$(echo "$line" | grep -oP 'alpn=\K([^ ]+|"[^"]+")' | tr -d '"')
                local dom=$(echo "$line" | grep -oP 'cert-domain=\K([^ ]+|"[^"]+")' | tr -d '"')
                local iss=$(echo "$line" | grep -oP 'cert-issuer=\K([^ ]+|"[^"]+")' | tr -d '"')
                local geo=$(echo "$line" | grep -oP 'geo=\K[^ ]+')

                REPORT_OUTPUT+="${nl} 🌐 IP-адрес:  ${ip:-Неизвестно}${nl}"
                if [[ "$feas" == "true" ]]; then REPORT_OUTPUT+=" ✅ Статус:    ПОДХОДИТ ДЛЯ REALITY${nl}"
                else REPORT_OUTPUT+=" ❌ Статус:    НЕ ПОДХОДИТ (См. параметры ниже)${nl}"; fi
                REPORT_OUTPUT+=" 🔒 TLS Версия: ${tls:-Отсутствует}${nl}"
                REPORT_OUTPUT+=" ⚡ ALPN:       ${alpn:-Отсутствует}${nl}"
                REPORT_OUTPUT+=" 📍 Домен (SNI): ${dom:-Отсутствует}${nl}"
                REPORT_OUTPUT+=" 🏢 Издатель:  ${iss:-Отсутствует}${nl}"
                REPORT_OUTPUT+=" 🌍 Локация:   ${geo:-N/A}${nl}"
                REPORT_OUTPUT+="------------------------------------------------------${nl}"
            
            elif [[ "$line" == *"TLS handshake failed"* ]]; then
                found_info=true
                local tip=$(echo "$line" | grep -oP 'target=\K[^ ]+')
                REPORT_OUTPUT+=" ❌ [$tip] ОШИБКА: Сервер не поддерживает нужный HTTPS/TLS${nl}"
            elif [[ "$line" == *"Cannot dial"* ]]; then
                found_info=true
                local tip=$(echo "$line" | grep -oP 'target=\K[^ ]+')
                REPORT_OUTPUT+=" ❌ [$tip] ОШИБКА: Сервер мертв или порт закрыт${nl}"
            elif [[ "$line" == *"Failed to get IP"* || "$line" == *"no IP found"* ]]; then
                found_info=true
                REPORT_OUTPUT+=" ❌ ОШИБКА: Домен не существует (Невозможно получить IP)${nl}"
            fi
        done <<< "$scan_log"

        if [[ "$found_info" == false ]]; then
            REPORT_OUTPUT+=" ❌ Нет ответа. Возможно, цель блокирует сканирование.${nl}"
        fi
    done
    trap - INT
    
    clear
    echo "$REPORT_OUTPUT" | sed -e "s/ПОДХОДИТ ДЛЯ REALITY/$(printf '\033[1;32m')&$(printf '\033[0m')/" \
                                -e "s/НЕ ПОДХОДИТ.*/$(printf '\033[1;31m')&$(printf '\033[0m')/" \
                                -e "s/ОШИБКА.*/$(printf '\033[1;31m')&$(printf '\033[0m')/" \
                                -e "s/ИНФОРМАЦИЯ О ПРОВАЙДЕРЕ/$(printf '\033[1;36m')&$(printf '\033[0m')/"

    echo -e "\n${BLUE}======================================================${NC}"
    read -p ">> Сохранить это досье в Менеджере Отчетов? (Y/n): " keep_recon
    if [[ "$keep_recon" =~ ^[nNтТ] ]]; then
        echo -e "${YELLOW}Досье не сохранено.${NC}"
    else
        local safe_name=$(echo "$safe_target" | sed 's/[^a-zA-Z0-9А-Яа-яЁё]/_/g')
        local recon_file="$RECON_DIR/recon_${safe_name}_$(date +%s).txt"
        echo "$REPORT_OUTPUT" > "$recon_file"
        echo -e "${GREEN}Досье успешно сохранено! (Менеджер Отчетов -> 2)${NC}"
    fi
    pause
}

# --- 2.1 МАССОВЫЙ ПРОБИВ OSINT (ДЛЯ IN.TXT) ---
run_mass_recon() {
    if [[ ! -s "$INPUT_FILE" ]]; then echo -e "${RED}Файл $INPUT_FILE пуст!${NC}"; sleep 2; return; fi

    clear
    echo -e "${MAGENTA}======================================================${NC}"
    echo -e "${BOLD} 🕵️ РЕЖИМ: МАССОВЫЙ ПРОБИВ ЦЕЛЕЙ ПО СПИСКУ (OSINT)${NC}"
    echo -e "${MAGENTA}======================================================${NC}"
    echo -e "${GRAY}Скрипт поочередно пробьет каждый IP/Домен из вашего файла in.txt,${NC}"
    echo -e "${GRAY}найдет сайты хостеров и сохранит в единое гигантское досье.${NC}\n"

    echo -e "${BLUE}--- ⚙️ ТОНКАЯ НАСТРОЙКА ---${NC}"
    echo -e "${YELLOW}1. Целевые порты (-port)${NC}"
    echo -e "${GRAY}Обычно маскировка Reality работает на HTTPS порту 443.${NC}"
    echo -e "${GRAY}Но можно указать несколько (напр: 443, 8443). Скрипт проверит их по очереди.${NC}"
    read -p ">> Порт(ы) через запятую (Enter = 443): " s_port
    s_port=${s_port:-443}
    IFS=',' read -ra PORT_ARRAY <<< "${s_port// /}"

    echo -e "\n${GREEN}[*] ЗАПУСК СКАНИРОВАНИЯ И СБОР ДАННЫХ ПО СПИСКУ...${NC}"
    echo -e "${RED}⚠️ ВАЖНО: Вы можете прервать процесс, нажав [Ctrl+C] в любой момент!${NC}"
    echo -e "${GRAY}Скрипт НЕ закроется. Он просто досрочно остановит перебор списка,${NC}"
    echo -e "${GRAY}сохранит всё, что успел пробить, и покажет вам готовое Мега-Досье.${NC}\n"
    
    local FULL_REPORT=""
    local nl=$'\n'

    cd "$SCANNER_DIR" || return
    export PATH=/usr/local/go/bin:$PATH

    trap 'echo -e "\n${YELLOW}🛑 Процесс прерван пользователем. Сохраняем собранные данные...${NC}"; break' INT

    while IFS= read -r raw_target; do
        [[ -z "$raw_target" ]] && continue
        
        local target=$raw_target
        local safe_target=$target
        if [[ "$target" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then target="${target}/32"; fi

        local ip_to_check=$safe_target
        if [[ ! "$ip_to_check" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            ip_to_check=$(getent hosts "$safe_target" | awk '{ print $1 }' | head -n 1)
        fi

        FULL_REPORT+="======================================================${nl}"
        FULL_REPORT+=" 📄 ДОСЬЕ НА ЦЕЛЬ: ${safe_target}${nl}"
        FULL_REPORT+="======================================================${nl}"

        if [[ -n "$ip_to_check" ]]; then
            ensure_package "jq" >/dev/null 2>&1
            local org_info=$(curl -sL "https://ipinfo.io/${ip_to_check}/json" | jq -r '.org // "Неизвестно"' 2>/dev/null || echo "Неизвестно")
            local city_info=$(curl -sL "https://ipinfo.io/${ip_to_check}/json" | jq -r '.city // "Неизвестно"' 2>/dev/null || echo "Неизвестно")
            local country_info=$(curl -sL "https://ipinfo.io/${ip_to_check}/json" | jq -r '.country // "??"' 2>/dev/null || echo "??")
            local host_name=$(curl -sL "https://ipinfo.io/${ip_to_check}/json" | jq -r '.hostname // ""' 2>/dev/null || echo "")
            
            FULL_REPORT+=" 📡 ИНФОРМАЦИЯ О ПРОВАЙДЕРЕ (OSINT)${nl}"
            FULL_REPORT+="   └─ Провайдер (ASN): ${org_info:-Неизвестно}${nl}"
            FULL_REPORT+="   └─ Город:           ${city_info:-Неизвестно} (${country_info:-N/A})${nl}"
            
            if [[ -n "$host_name" && "$host_name" != "null" ]]; then
                local base_domain=$(echo "$host_name" | awk -F. '{if (NF>1) print $(NF-1)"."$NF; else print $0}')
                FULL_REPORT+="   └─ Сайт хостинга:   https://${base_domain} (из PTR: $host_name)${nl}"
            fi
            
            if [[ -n "$org_info" ]]; then
                local search_query=$(echo "buy vps $org_info" | sed 's/ /+/g')
                FULL_REPORT+="   └─ Резервный поиск: https://www.google.com/search?q=${search_query}${nl}"
            fi
            FULL_REPORT+="------------------------------------------------------${nl}"
        fi

        for current_port in "${PORT_ARRAY[@]}"; do
            FULL_REPORT+=" >>> СКАНИРОВАНИЕ ПОРТА: ${current_port} <<<${nl}"
            echo -ne "\r\033[K${CYAN}⏳ Пробив: ${YELLOW}${safe_target}${NC} (Порт: ${current_port})...${NC}"
            
            local tmp_ghost="tmp_ghost_${current_port}.csv"
            local scan_log=$(./RealiTLScanner -addr "$target" -port "$current_port" -timeout 5 -v -out "$tmp_ghost" 2>&1)
            rm -f "$tmp_ghost" 2>/dev/null

            local found_info=false
            
            while read -r line; do
                if [[ "$line" == *"Connected to target"* ]]; then
                    found_info=true
                    local feas=$(echo "$line" | grep -oP 'feasible=\K[^ ]+')
                    local ip=$(echo "$line" | grep -oP 'ip=\K[^ ]+')
                    local tls=$(echo "$line" | grep -oP 'tls=\K([^ ]+|"[^"]+")' | tr -d '"')
                    local alpn=$(echo "$line" | grep -oP 'alpn=\K([^ ]+|"[^"]+")' | tr -d '"')
                    local dom=$(echo "$line" | grep -oP 'cert-domain=\K([^ ]+|"[^"]+")' | tr -d '"')
                    local iss=$(echo "$line" | grep -oP 'cert-issuer=\K([^ ]+|"[^"]+")' | tr -d '"')
                    local geo=$(echo "$line" | grep -oP 'geo=\K[^ ]+')

                    FULL_REPORT+="${nl} 🌐 IP-адрес:  ${ip:-Неизвестно}${nl}"
                    if [[ "$feas" == "true" ]]; then FULL_REPORT+=" ✅ Статус:    ПОДХОДИТ ДЛЯ REALITY${nl}"
                    else FULL_REPORT+=" ❌ Статус:    НЕ ПОДХОДИТ (См. параметры ниже)${nl}"; fi
                    FULL_REPORT+=" 🔒 TLS Версия: ${tls:-Отсутствует}${nl}"
                    FULL_REPORT+=" ⚡ ALPN:       ${alpn:-Отсутствует}${nl}"
                    FULL_REPORT+=" 📍 Домен (SNI): ${dom:-Отсутствует}${nl}"
                    FULL_REPORT+=" 🏢 Издатель:  ${iss:-Отсутствует}${nl}"
                    FULL_REPORT+=" 🌍 Локация:   ${geo:-N/A}${nl}"
                    FULL_REPORT+="------------------------------------------------------${nl}"
                elif [[ "$line" == *"TLS handshake failed"* ]]; then
                    found_info=true
                    local tip=$(echo "$line" | grep -oP 'target=\K[^ ]+')
                    FULL_REPORT+=" ❌ [$tip] ОШИБКА: Сервер не поддерживает нужный HTTPS/TLS${nl}"
                elif [[ "$line" == *"Cannot dial"* ]]; then
                    found_info=true
                    local tip=$(echo "$line" | grep -oP 'target=\K[^ ]+')
                    FULL_REPORT+=" ❌ [$tip] ОШИБКА: Сервер мертв или порт закрыт${nl}"
                fi
            done <<< "$scan_log"

            if [[ "$found_info" == false ]]; then
                FULL_REPORT+=" ❌ Нет ответа. Возможно, цель блокирует сканирование.${nl}"
            fi
        done
        FULL_REPORT+="${nl}"
    done < "$INPUT_FILE"
    trap - INT

    clear
    echo "$FULL_REPORT" | sed -e "s/ПОДХОДИТ ДЛЯ REALITY/$(printf '\033[1;32m')&$(printf '\033[0m')/" \
                                -e "s/НЕ ПОДХОДИТ.*/$(printf '\033[1;31m')&$(printf '\033[0m')/" \
                                -e "s/ОШИБКА.*/$(printf '\033[1;31m')&$(printf '\033[0m')/" \
                                -e "s/ИНФОРМАЦИЯ О ПРОВАЙДЕРЕ/$(printf '\033[1;36m')&$(printf '\033[0m')/"

    echo -e "\n${BLUE}======================================================${NC}"
    read -p ">> Сохранить этот массовый отчет OSINT? (Y/n): " keep_recon
    if [[ "$keep_recon" =~ ^[nNтТ] ]]; then
        echo -e "${YELLOW}Массовое досье не сохранено.${NC}"
    else
        local recon_file="$RECON_DIR/mass_recon_$(date +%s).txt"
        echo "$FULL_REPORT" > "$recon_file"
        echo -e "${GREEN}Мега-досье успешно сохранено! (Менеджер Отчетов -> 2)${NC}"
    fi
    pause
}

# --- 3. УМНЫЙ АНАЛИЗАТОР ---
analyze_results_auto() {
    local file=$1
    local total_lines=$(wc -l < "$file" 2>/dev/null)
    if [[ "$total_lines" -le 1 ]]; then echo -e "${RED}[!] Для этой цели ничего не найдено.${NC}"; return; fi

    local sorted_data=$(awk -F, '
    NR>1 {
        issuer = tolower($4); weight = 5;
        if (issuer ~ /google|apple|microsoft/) weight = 1;
        else if (issuer ~ /digicert|globalsign|sectigo/) weight = 2;
        else if (issuer ~ /cloudflare/) weight = 3;
        else if (issuer ~ /let'\''s encrypt|zerossl/) weight = 4;
        if (weight < 5) {
            port = $6 ? $6 : "443";
            print weight "|" $3 "|" $1 "|" port "|" $5 "|" $4;
        }
    }' "$file" | sort -t'|' -k1,1n | uniq)

    local best=$(echo "$sorted_data" | head -n 5)
    if [[ -z "$best" ]]; then echo -e "${YELLOW}Надежных SNI кандидатов не найдено.${NC}"
    else
        echo -e "${GREEN}🏆 ТОП-5 ЛУЧШИХ SNI:${NC}"
        echo "$best" | while IFS='|' read -r weight domain ip port geo issuer; do
            if [[ "$weight" == "1" ]]; then echo -e "💎 \033[1;36m$domain\033[0m"
            elif [[ "$weight" == "2" || "$weight" == "3" ]]; then echo -e "📍 \033[1;32m$domain\033[0m"
            else echo -e "🔸 \033[0;32m$domain\033[0m"; fi
            echo -e "   └─ IP: $ip (Порт: \033[1;36m$port\033[0m) | ГЕО: \033[1;33m$geo\033[0m | Издатель: $issuer"
        done
    fi
}

analyze_results() {
    local file=$1
    [[ ! -f "$file" ]] && { echo -e "${RED}[!] Файл $file не найден.${NC}"; return; }

    local total_lines=$(wc -l < "$file" 2>/dev/null)
    if [[ "$total_lines" -le 1 ]]; then echo -e "\n${RED}[!] В отчете пусто. Сканер ничего не нашел.${NC}"; return; fi

    clear
    echo -e "${MAGENTA}======================================================${NC}"
    echo -e "${BOLD}🤖 АНАЛИЗАТОР: ОТБОР ИДЕАЛЬНЫХ SNI КАНДИДАТОВ${NC}"
    echo -e "${MAGENTA}======================================================${NC}"
    
    local my_ip=$(curl -sL "https://ipinfo.io/json" | jq -r '.ip // "127.0.0.1"' 2>/dev/null || echo "127.0.0.1")
    local my_geo=$(curl -sL "https://ipinfo.io/json" | jq -r '.country // "??"' 2>/dev/null || echo "??")
    
    echo -e "${CYAN}[*] Ваш текущий сервер:${NC} $my_ip ${YELLOW}($my_geo)${NC}"
    show_geo_help
    read -p ">> Фильтр по Стране (Enter = Искать в $my_geo, 'n' = Искать везде): " user_geo
    
    local target_geo=""
    if [[ -z "$user_geo" ]]; then target_geo="$my_geo"
    elif [[ "$user_geo" =~ ^[nNтТ] ]]; then target_geo=""
    else target_geo=$(echo "$user_geo" | tr '[:lower:]' '[:upper:]')
    fi

    echo -e "\n${CYAN}Анализ и сортировка файла: $(basename "$file")...${NC}"
    
    local sorted_data=$(awk -F, -v target_geo="$target_geo" '
    NR>1 {
        issuer = tolower($4); weight = 5;
        if (issuer ~ /google|apple|microsoft/) weight = 1;
        else if (issuer ~ /digicert|globalsign|sectigo/) weight = 2;
        else if (issuer ~ /cloudflare/) weight = 3;
        else if (issuer ~ /let'\''s encrypt|zerossl/) weight = 4;
        
        if (target_geo != "" && $5 != target_geo) next;
        
        if (weight < 5) {
            port = $6 ? $6 : "443";
            print weight "|" $3 "|" $1 "|" port "|" $5 "|" $4;
        }
    }' "$file" | sort -t'|' -k1,1n | uniq)

    local best=$(echo "$sorted_data" | head -n 15)

    if [[ -z "$best" ]]; then echo -e "${YELLOW}Идеальных целей (с нужным ГЕО и надежным сертификатом) не найдено.${NC}"
    else
        echo -e "\n${GREEN}🏆 ТОП-15 ИДЕАЛЬНЫХ SNI КАНДИДАТОВ:${NC}"
        echo -e "${BLUE}------------------------------------------------------${NC}"
        echo "$best" | while IFS='|' read -r weight domain ip port geo issuer; do
            if [[ "$weight" == "1" ]]; then echo -e "💎 \033[1;36m$domain\033[0m"
            elif [[ "$weight" == "2" || "$weight" == "3" ]]; then echo -e "📍 \033[1;32m$domain\033[0m"
            else echo -e "🔸 \033[0;32m$domain\033[0m"; fi
            echo -e "   └─ IP: $ip (Порт: \033[1;36m$port\033[0m) | ГЕО: \033[1;33m$geo\033[0m | Издатель: $issuer\n"
        done
    fi
}

# --- 4. МАССОВЫЙ СКАНЕР (ДЛЯ ПУНКТОВ 2, 3, 5) ---
run_scanner() {
    local mode=$1
    local target=$2
    local title=$3
    local description=$4

    clear
    echo -e "${MAGENTA}======================================================${NC}"
    echo -e "${BOLD} $title${NC}"
    echo -e "${MAGENTA}======================================================${NC}"
    echo -e "${CYAN}💡 Для чего это нужно?${NC}"
    echo -e "${GRAY}$description${NC}\n"

    if [[ -z "$target" ]]; then
        read -p ">> Введите цель: " target
        [[ -z "$target" ]] && return
    fi

    if [[ "$mode" == "addr" && "$target" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then target="${target}/32"; fi

    local safe_target=$(echo "$target" | sed 's/[^a-zA-Z0-9]/_/g' | cut -c 1-15)
    local out_file="scan_${mode}_${safe_target}_$(date +%s).csv"

    echo -e "${BLUE}--- ⚙️ ТОНКАЯ НАСТРОЙКА СКАНИРОВАНИЯ ---${NC}"
    echo -e "${CYAN}Цель:${NC} $target (Режим: -$mode)\n"

    echo -e "${YELLOW}1. Целевые порты (-port)${NC}"
    echo -e "${GRAY}Обычно маскировка Reality работает на HTTPS порту 443.${NC}"
    echo -e "${GRAY}Но можно указать несколько (напр: 443, 8443). Скрипт проверит их по очереди.${NC}"
    read -p ">> Порт(ы) через запятую (Enter = 443): " s_port; s_port=${s_port:-443}
    IFS=',' read -ra PORT_ARRAY <<< "${s_port// /}"

    echo -e "\n${YELLOW}2. Количество потоков (-thread)${NC}"
    echo -e "${GRAY}Сколько IP проверять одновременно. Больше = быстрее, но может нагрузить сервер.${NC}"
    read -p ">> Потоков (Enter = 10, макс 50): " s_thread; s_thread=${s_thread:-10}

    echo -e "\n${YELLOW}3. Таймаут ответа (-timeout)${NC}"
    echo -e "${GRAY}Сколько секунд ждать ответа от сервера. 5 секунд оптимально для хороших сетей.${NC}"
    read -p ">> Таймаут в сек (Enter = 5): " s_timeout; s_timeout=${s_timeout:-5}
    
    echo -e "\n${YELLOW}4. Лимит поиска (Стоп-кран)${NC}"
    echo -e "${GRAY}Скрипт остановится автоматически, когда найдет нужное количество рабочих SNI.${NC}"
    read -p ">> Сколько успешных SNI найти? (Enter = 0, искать до конца списка): " s_limit; s_limit=${s_limit:-0}

    echo -e "\n${YELLOW}5. Имя файла (Тег)${NC}"
    echo -e "${GRAY}Добавьте понятную метку (напр. Hetzner), чтобы потом легко найти этот отчет.${NC}"
    read -p ">> Метка для файла [Enter = пропустить]: " s_tag
    
    local safe_tag=$(echo "$s_tag" | sed 's/[^a-zA-Z0-9А-Яа-яЁё]/_/g')
    if [[ -n "$safe_tag" ]]; then out_file="scan_${safe_tag}_${safe_target}_$(date +%s).csv"; fi

    echo -e "\n${GREEN}[*] ЗАПУСК СКАНИРОВАНИЯ...${NC}"
    echo -e "${RED}⚠️ ВАЖНО: Вы можете прервать процесс, нажав [Ctrl+C] в любой момент!${NC}"
    echo -e "${GRAY}Скрипт НЕ закроется. Он просто досрочно остановит текущий поиск,${NC}"
    echo -e "${GRAY}сохранит всё, что успел найти, и плавно перейдет к Умному Анализу.${NC}\n"
    
    cd "$SCANNER_DIR" || return
    export PATH=/usr/local/go/bin:$PATH
    
    echo "IP,ORIGIN,CERT_DOMAIN,CERT_ISSUER,GEO_CODE,PORT" > "$SCANNER_DIR/$out_file"

    for current_port in "${PORT_ARRAY[@]}"; do
        echo -e "${MAGENTA}>>> СКАНИРОВАНИЕ ПОРТА: ${current_port} <<<${NC}"
        local tmp_csv="tmp_scan_${current_port}.csv"
        
        ./RealiTLScanner -"$mode" "$target" -port "$current_port" -thread "$s_thread" -timeout "$s_timeout" -out "$tmp_csv" >/dev/null 2>&1 &
        local SCAN_PID=$!
        
        trap 'kill $SCAN_PID 2>/dev/null; echo -e "\n\n${YELLOW}🛑 Сканирование прервано пользователем. Переход к анализу...${NC}"; break' INT

        while kill -0 $SCAN_PID 2>/dev/null; do
            if [[ -f "$tmp_csv" ]]; then
                local current_count=$(cat "$tmp_csv" 2>/dev/null | wc -l)
                local actual_count=$((current_count > 0 ? current_count - 1 : 0))
                local last_sni=$(tail -n 1 "$tmp_csv" 2>/dev/null | awk -F, '{print $3}')
                
                if [[ -n "$last_sni" && "$last_sni" != "CERT_DOMAIN" ]]; then
                    echo -ne "\r\033[K${CYAN}⏳ Сканирование... Найдено SNI: ${GREEN}${actual_count}${NC} | Последний: ${YELLOW}${last_sni}${NC}"
                else
                    echo -ne "\r\033[K${CYAN}⏳ Сканирование... Найдено SNI: ${GREEN}${actual_count}${NC}"
                fi
                
                if [[ "$s_limit" -gt 0 && "$actual_count" -ge "$s_limit" ]]; then
                    echo -e "\n\n${GREEN}[+] Лимит ($s_limit) достигнут! Останавливаем сканер...${NC}"
                    kill $SCAN_PID 2>/dev/null; break
                fi
            else
                echo -ne "\r\033[K${CYAN}⏳ Запуск потоков и ожидание первых результатов...${NC}"
            fi
            sleep 1
        done
        echo -e ""
        trap - INT

        if [[ -f "$tmp_csv" ]]; then
            tail -n +2 "$tmp_csv" | awk -v p="$current_port" -F',' '{print $0","p}' >> "$SCANNER_DIR/$out_file"
            rm -f "$tmp_csv"
        fi
    done

    # АВТО-ОЧИСТКА: Если в файле только заголовок (ничего не найдено) - удаляем его!
    local check_lines=$(wc -l < "$SCANNER_DIR/$out_file" 2>/dev/null)
    if [[ "$check_lines" -le 1 ]]; then
        echo -e "${RED}[!] Сканер ничего не нашел. Пустой отчет удален.${NC}"
        rm -f "$SCANNER_DIR/$out_file" 2>/dev/null
        pause
        return
    fi

    echo -e "${GREEN}[+] Сканирование завершено!${NC}"
    analyze_results "$SCANNER_DIR/$out_file"

    echo -e "\n${BLUE}======================================================${NC}"
    read -p ">> Сохранить этот отчет в Менеджере Отчетов? (Y/n): " keep_report
    if [[ "$keep_report" =~ ^[nNтТ] ]]; then
        rm -f "$SCANNER_DIR/$out_file" 2>/dev/null
        echo -e "${YELLOW}Отчет удален.${NC}"
    else
        echo -e "${GREEN}Отчет успешно сохранен!${NC} (Имя: $out_file)"
    fi
    pause
}

# --- 4.1 МАССОВЫЙ СКАН ПОДСЕТЕЙ ПО СПИСКУ (ДЛЯ IN.TXT) ---
run_mass_subnet_scan() {
    if [[ ! -s "$INPUT_FILE" ]]; then echo -e "${RED}Файл $INPUT_FILE пуст!${NC}"; sleep 2; return; fi

    clear
    echo -e "${MAGENTA}======================================================${NC}"
    echo -e "${BOLD} 🔍 РЕЖИМ: МАССОВЫЙ СКАН ПОДСЕТЕЙ ПО СПИСКУ${NC}"
    echo -e "${MAGENTA}======================================================${NC}"
    echo -e "${CYAN}💡 Для чего это нужно?${NC}"
    echo -e "${GRAY}Скрипт берет каждый IP из вашего списка, автоматически превращает его${NC}"
    echo -e "${GRAY}в подсеть (/24) и ищет 'соседей' с хорошими SNI-доменами.${NC}"
    echo -e "${GRAY}Для каждой подсети будет выведен свой личный ТОП кандидатов!${NC}\n"

    echo -e "${BLUE}--- ⚙️ ТОНКАЯ НАСТРОЙКА СКАНИРОВАНИЯ ---${NC}"
    echo -e "${YELLOW}1. Целевые порты (-port)${NC}"
    echo -e "${GRAY}Обычно маскировка Reality работает на HTTPS порту 443.${NC}"
    echo -e "${GRAY}Но можно указать несколько (напр: 443, 8443). Скрипт проверит их по очереди.${NC}"
    read -p ">> Порт(ы) через запятую (Enter = 443): " s_port; s_port=${s_port:-443}
    IFS=',' read -ra PORT_ARRAY <<< "${s_port// /}"

    echo -e "\n${YELLOW}2. Количество потоков (-thread)${NC}"
    echo -e "${GRAY}Сколько IP проверять одновременно. Больше = быстрее, но может нагрузить сервер.${NC}"
    read -p ">> Потоков (Enter = 10, макс 50): " s_thread; s_thread=${s_thread:-10}

    echo -e "\n${YELLOW}3. Таймаут ответа (-timeout)${NC}"
    echo -e "${GRAY}Сколько секунд ждать ответа от сервера. 5 секунд оптимально для хороших сетей.${NC}"
    read -p ">> Таймаут в сек (Enter = 5): " s_timeout; s_timeout=${s_timeout:-5}

    echo -e "\n${YELLOW}4. Лимит поиска (Стоп-кран) для КАЖДОЙ подсети${NC}"
    echo -e "${GRAY}Сколько успешных SNI найти для одного IP, прежде чем перейти к следующему.${NC}"
    read -p ">> Сколько найти? (Enter = 0, до конца): " s_limit; s_limit=${s_limit:-0}
    
    echo -e "\n${GREEN}[*] ЗАПУСК СКАНИРОВАНИЯ СПИСКА...${NC}"
    echo -e "${RED}⚠️ ВАЖНО: Вы можете прервать процесс, нажав [Ctrl+C] в любой момент!${NC}"
    echo -e "${GRAY}Это досрочно прервет скан ТЕКУЩЕЙ подсети, сохранит её результат${NC}"
    echo -e "${GRAY}и плавно перейдет к следующему IP-адресу из вашего списка in.txt.${NC}\n"
    
    cd "$SCANNER_DIR" || return
    export PATH=/usr/local/go/bin:$PATH

    while IFS= read -r raw_target; do
        [[ -z "$raw_target" ]] && continue
        
        local target=$raw_target
        if [[ "$target" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            target=$(echo "$target" | awk -F. '{print $1"."$2"."$3".0/24"}')
        fi

        local safe_target=$(echo "$target" | sed 's/[^a-zA-Z0-9]/_/g' | cut -c 1-15)
        local out_file="scan_list_${safe_target}_$(date +%s).csv"

        echo -e "${BLUE}======================================================${NC}"
        echo -e "${CYAN}🎯 СКАНИРОВАНИЕ ПОДСЕТИ: ${YELLOW}$target${NC}"
        echo -e "${BLUE}======================================================${NC}"

        echo "IP,ORIGIN,CERT_DOMAIN,CERT_ISSUER,GEO_CODE,PORT" > "$SCANNER_DIR/$out_file"

        for current_port in "${PORT_ARRAY[@]}"; do
            local tmp_csv="tmp_scan_${current_port}.csv"
            
            ./RealiTLScanner -addr "$target" -port "$current_port" -thread "$s_thread" -timeout "$s_timeout" -out "$tmp_csv" >/dev/null 2>&1 &
            local SCAN_PID=$!
            
            trap 'kill $SCAN_PID 2>/dev/null; echo -e "\n${YELLOW}🛑 Пропуск текущей подсети. Переход к следующей...${NC}"; break' INT

            while kill -0 $SCAN_PID 2>/dev/null; do
                if [[ -f "$tmp_csv" ]]; then
                    local current_count=$(cat "$tmp_csv" 2>/dev/null | wc -l)
                    local actual_count=$((current_count > 0 ? current_count - 1 : 0))
                    local last_sni=$(tail -n 1 "$tmp_csv" 2>/dev/null | awk -F, '{print $3}')
                    
                    if [[ -n "$last_sni" && "$last_sni" != "CERT_DOMAIN" ]]; then
                        echo -ne "\r\033[K${CYAN}⏳ Порт $current_port | Найдено SNI: ${GREEN}${actual_count}${NC} | Последний: ${YELLOW}${last_sni}${NC}"
                    else
                        echo -ne "\r\033[K${CYAN}⏳ Порт $current_port | Найдено SNI: ${GREEN}${actual_count}${NC}"
                    fi
                    
                    if [[ "$s_limit" -gt 0 && "$actual_count" -ge "$s_limit" ]]; then
                        echo -e "\n${GREEN}[+] Лимит ($s_limit) достигнут!${NC}"
                        kill $SCAN_PID 2>/dev/null; break
                    fi
                else
                    echo -ne "\r\033[K${CYAN}⏳ Порт $current_port | Запуск потоков...${NC}"
                fi
                sleep 1
            done
            echo -e ""
            trap - INT

            if [[ -f "$tmp_csv" ]]; then
                tail -n +2 "$tmp_csv" | awk -v p="$current_port" -F',' '{print $0","p}' >> "$SCANNER_DIR/$out_file"
                rm -f "$tmp_csv"
            fi
        done

        # АВТО-ОЧИСТКА ПУСТЫХ ПОДСЕТЕЙ
        local check_lines=$(wc -l < "$SCANNER_DIR/$out_file" 2>/dev/null)
        if [[ "$check_lines" -le 1 ]]; then
            rm -f "$SCANNER_DIR/$out_file" 2>/dev/null
            echo -e "\n${YELLOW}[!] В этой подсети ничего не найдено. Пустой файл удален.${NC}\n"
        else
            analyze_results_auto "$SCANNER_DIR/$out_file"
            echo -e "\n${GRAY}Файл сохранен: $out_file${NC}\n"
        fi

    done < "$INPUT_FILE"

    echo -e "${GREEN}======================================================${NC}"
    echo -e "${BOLD}✅ ВСЕ ЦЕЛИ ИЗ СПИСКА ОБРАБОТАНЫ!${NC}"
    echo -e "${GREEN}======================================================${NC}"
    echo -e "${GRAY}Все успешные CSV файлы (не пустые) сохранены в Менеджере Отчетов.${NC}"
    pause
}

# --- 5. РАЗДЕЛЕННЫЙ МЕНЕДЖЕР ОТЧЕТОВ ---
manage_csv_reports() {
    while true; do
        clear
        echo -e "${MAGENTA}=== 📊 ОТЧЕТЫ МАССОВОГО СКАНИРОВАНИЯ (CSV) ===${NC}"
        mapfile -t CSV_FILES < <(ls -1t "$SCANNER_DIR"/*.csv 2>/dev/null)
        if [[ ${#CSV_FILES[@]} -eq 0 ]]; then echo -e "${YELLOW}Отчетов CSV пока нет.${NC}"; pause; return; fi

        for i in "${!CSV_FILES[@]}"; do
            local f_size=$(du -sh "${CSV_FILES[$i]}" | awk '{print $1}')
            local f_name=$(basename "${CSV_FILES[$i]}")
            echo -e " ${YELLOW}$((i+1)).${NC} ${CYAN}$f_name${NC} ${GRAY}($f_size)${NC}"
        done

        echo -e "\n${BLUE}------------------------------------------------------${NC}"
        echo -e " 👉 ${YELLOW}НОМЕР${NC} - Посмотреть таблицу. | 👉 ${GREEN}aНОМЕР${NC} - Запустить Умный Анализ."
        echo -e " 👉 ${RED}dНОМЕР${NC} - Удалить отчет.    | 👉 ${RED}D${NC} - Удалить ВСЕ отчеты разом."
        echo -e " ${CYAN}0.${NC} Назад"
        read -p ">> " r_choice
        
        [[ "$r_choice" == "0" ]] && return
        if [[ "$r_choice" =~ ^[dDвВ]$ ]]; then
            read -p "Удалить ВСЕ CSV отчеты? (y/N): " confirm_del
            [[ "$confirm_del" =~ ^[yYнН] ]] && rm -f "$SCANNER_DIR"/*.csv 2>/dev/null && echo -e "${GREEN}Очищено!${NC}" && sleep 1
        elif [[ "$r_choice" =~ ^[dDвВ]([0-9]+)$ ]]; then
            local idx=$((${BASH_REMATCH[1]}-1))
            [[ -n "${CSV_FILES[$idx]}" ]] && rm -f "${CSV_FILES[$idx]}" && echo -e "${GREEN}Удалено!${NC}" && sleep 1
        elif [[ "$r_choice" =~ ^[aAфФ]([0-9]+)$ ]]; then
            local idx=$((${BASH_REMATCH[1]}-1))
            [[ -n "${CSV_FILES[$idx]}" ]] && analyze_results "${CSV_FILES[$idx]}" && pause
        elif [[ "$r_choice" =~ ^[0-9]+$ ]]; then
            local idx=$((r_choice-1))
            [[ -n "${CSV_FILES[$idx]}" ]] && column -t -s ',' "${CSV_FILES[$idx]}" | less -S
        else echo -e "${RED}Неверный ввод.${NC}"; sleep 1; fi
    done
}

manage_recon_reports() {
    while true; do
        clear
        echo -e "${MAGENTA}=== 📄 ДОСЬЕ НА КОНКРЕТНЫЕ ЦЕЛИ (TXT) ===${NC}"
        mapfile -t TXT_FILES < <(ls -1t "$RECON_DIR"/*.txt 2>/dev/null)
        if [[ ${#TXT_FILES[@]} -eq 0 ]]; then echo -e "${YELLOW}Сохраненных досье пока нет.${NC}"; pause; return; fi

        for i in "${!TXT_FILES[@]}"; do
            local f_size=$(du -sh "${TXT_FILES[$i]}" | awk '{print $1}')
            local f_name=$(basename "${TXT_FILES[$i]}")
            echo -e " ${YELLOW}$((i+1)).${NC} ${CYAN}$f_name${NC} ${GRAY}($f_size)${NC}"
        done

        echo -e "\n${BLUE}------------------------------------------------------${NC}"
        echo -e " 👉 ${YELLOW}НОМЕР${NC} - Открыть досье. | 👉 ${RED}dНОМЕР${NC} - Удалить досье."
        echo -e " 👉 ${RED}D${NC} - Удалить ВСЕ досье разом."
        echo -e " ${CYAN}0.${NC} Назад"
        read -p ">> " r_choice
        
        [[ "$r_choice" == "0" ]] && return
        if [[ "$r_choice" =~ ^[dDвВ]$ ]]; then
            read -p "Удалить ВСЕ досье? (y/N): " confirm_del
            [[ "$confirm_del" =~ ^[yYнН] ]] && rm -f "$RECON_DIR"/*.txt 2>/dev/null && echo -e "${GREEN}Очищено!${NC}" && sleep 1
        elif [[ "$r_choice" =~ ^[dDвВ]([0-9]+)$ ]]; then
            local idx=$((${BASH_REMATCH[1]}-1))
            [[ -n "${TXT_FILES[$idx]}" ]] && rm -f "${TXT_FILES[$idx]}" && echo -e "${GREEN}Удалено!${NC}" && sleep 1
        elif [[ "$r_choice" =~ ^[0-9]+$ ]]; then
            local idx=$((r_choice-1))
            [[ -n "${TXT_FILES[$idx]}" ]] && less -r "${TXT_FILES[$idx]}"
        else echo -e "${RED}Неверный ввод.${NC}"; sleep 1; fi
    done
}

manage_reports_menu() {
    while true; do
        clear
        echo -e "${MAGENTA}======================================================${NC}"
        echo -e "${BOLD} 📂 МЕНЕДЖЕР ОТЧЕТОВ${NC}"
        echo -e "${MAGENTA}======================================================${NC}"
        echo -e " ${YELLOW}1.${NC} 📊 Отчеты массового сканирования (CSV)"
        echo -e " ${GRAY}   └─ Результаты работы по подсетям, файлам и URL.${NC}"
        echo -e " ${YELLOW}2.${NC} 📄 Досье на конкретные цели (TXT)"
        echo -e " ${GRAY}   └─ Сохраненные пробивы провайдеров и рентген серверов.${NC}"
        echo -e " ${CYAN}0.${NC} ↩️ Назад"
        read -p ">> " rm_choice
        case $rm_choice in
            1) manage_csv_reports ;;
            2) manage_recon_reports ;;
            0) return ;;
            *) echo -e "${RED}Неверный ввод.${NC}"; sleep 1 ;;
        esac
    done
}

manage_input_file() {
    while true; do
        clear
        echo -e "${MAGENTA}=== УПРАВЛЕНИЕ СПИСКОМ ЦЕЛЕЙ (in.txt) ===${NC}"
        if [[ ! -f "$INPUT_FILE" ]]; then touch "$INPUT_FILE"; fi
        echo -e " ${YELLOW}1.${NC} 📝 Редактировать список (nano)"
        echo -e " ${YELLOW}2.${NC} 🔍 Запустить массовый скан подсетей (Поиск SNI соседей)"
        echo -e " ${YELLOW}3.${NC} 🕵️  Запустить массовый ПРОБИВ (OSINT + Рентген)"
        echo -e " ${CYAN}0.${NC} ↩️  Назад"
        read -p ">> " in_choice
        case $in_choice in
            1) nano "$INPUT_FILE" ;;
            2) run_mass_subnet_scan ;;
            3) run_mass_recon ;;
            0) return ;;
        esac
    done
}

menu_scanner() {
    check_scanner_install || return
    local my_ip=$(curl -sL "https://ipinfo.io/json" | jq -r '.ip // "127.0.0.1"' 2>/dev/null || echo "127.0.0.1")
    local my_subnet=$(echo "$my_ip" | awk -F. '{print $1"."$2"."$3".0/24"}')

    while true; do
        clear
        echo -e "${BLUE}======================================================${NC}"
        echo -e "${BOLD}  🔍 REALITY - TLS - SCANNER${NC}"
        echo -e "  Мощный радар для поиска идеальных доменов маскировки."
        echo -e "${BLUE}======================================================${NC}"
        echo -e " ${YELLOW}1.${NC} Строгий скан одного IP / Домена"
        echo -e " ${GRAY}   └─ Пробив провайдера и полное досье (Рентген) на сервер.${NC}"
        echo -e " ${YELLOW}2.${NC} Массовый скан подсети (CIDR)"
        echo -e " ${GRAY}   └─ Главный режим! Ищет лучшие домены среди ваших 'соседей'.${NC}"
        echo -e " ${YELLOW}3.${NC} Бесконечный поиск ${BLUE}(Infinity Mode)${NC}"
        echo -e " ${GRAY}   └─ Ищет подходящие сервера во все стороны от стартового IP.${NC}"
        echo -e " ${YELLOW}4.${NC} 📂 Скан по списку из файла"
        echo -e " ${GRAY}   └─ Проверяет ваши заранее заготовленные списки.${NC}"
        echo -e " ${YELLOW}5.${NC} Сбор и скан доменов по ${BLUE}URL${NC}"
        echo -e " ${GRAY}   └─ Вытаскивает и проверяет домены с любой веб-страницы.${NC}"
        echo -e "${BLUE}------------------------------------------------------${NC}"
        echo -e " ${CYAN}8.${NC} 📂 Менеджер Отчетов ${BLUE}(Анализ / Просмотр / Удаление)${NC}"
        echo -e " ${RED}0.${NC} ↩️ Назад"
        
        read -p ">> " s_choice
        case $s_choice in
            1) run_single_scan "" ;;
            2) 
                echo -e "\n${CYAN}[*] Ваша подсеть: ${YELLOW}$my_subnet${NC}"
                read -p ">> Введите подсеть (CIDR) [Enter = $my_subnet]: " sub
                sub=${sub:-$my_subnet}
                if [[ "$sub" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                    sub=$(echo "$sub" | awk -F. '{print $1"."$2"."$3".0/24"}')
                    echo -e "${YELLOW}[!] Вы ввели IP вместо подсети. Исправлено на: $sub${NC}"; sleep 1
                fi
                run_scanner "addr" "$sub" "🌐 РЕЖИМ: МАССОВЫЙ СКАН ПОДСЕТИ (CIDR)" "Этот режим проверяет целый пул адресов (например, 256 штук в подсети /24).\nОбычно используется для поиска идеальных SNI-кандидатов среди 'соседей' вашего VPN сервера.\nЧем ближе сервер маскировки к вам физически, тем сложнее цензорам вас заблокировать!" ;;
            3)
                echo -e "\n${CYAN}[*] Ваш IP-адрес: ${YELLOW}$my_ip${NC}"
                read -p ">> Введите стартовый IP [Enter = $my_ip]: " s_ip
                run_scanner "addr" "${s_ip:-$my_ip}" "♾️ РЕЖИМ: БЕСКОНЕЧНЫЙ ПОИСК (INFINITY MODE)" "Скрипт берет стартовый IP и бесконечно проверяет соседние адреса (+1/-1),\nпока вы его не остановите (нажав Ctrl+C) или пока он не найдет нужное количество SNI." ;;
            4) manage_input_file ;;
            5)
                echo -e "\n${GRAY}Пример: https://launchpad.net/ubuntu/+archivemirrors${NC}"
                read -p ">> URL со списком: " s_url
                [[ -n "$s_url" ]] && run_scanner "url" "$s_url" "🕸️ РЕЖИМ: ВЕБ-КРАУЛЕР (СБОР ПО URL)" "Скрипт зайдет на указанную страницу, найдет там все доменные имена\n(например, список зеркал) и просканирует их на пригодность для Reality." ;;
            8) manage_reports_menu ;;
            0) return ;;
        esac
    done
}
