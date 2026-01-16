cat > /root/don_remna_up.sh << 'ENDOFFILE'
#!/bin/bash

# ==========================================
#  DON MATTEO SYSTEM UPGRADER
#  Code: LETHAL | Style: GANGSTA | Status: GOD MODE
#  Edition: ANTI-WINDOWS FIX (v1.6)
# ==========================================

# Цветовая палитра
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# Ссылка на RAW версию
UPDATE_URL="https://raw.githubusercontent.com/DonMatteoVPN/Reshala-Remnawave-Bedolaga/main/don_remna_up.sh"
# Жесткий путь установки
INSTALL_PATH="/root/don_remna_up.sh"
# Симлинк
LINK_PATH="/usr/local/bin/donup"

# ==================================================================================
# ⚙️  ЗОНА ДЛЯ РОВНЫХ ПАЦАНОВ (CONFIG ZONE)  ⚙️
# ==================================================================================

# 1. Где лежит ГЛАВНЫЙ МОЗГ (Ядро).
CORE_PATH="/opt/remnawave"

# 2. Список точек, куда мы сейчас нагрянем с проверкой.
SERVICES=(
    "/opt/remnawave"
    "/opt/remnawave/nginx"
    "/opt/certwarden"
    "/opt/certwardenclient"
    "/opt/remnawave/subscription"
    "/opt/remnawave/remnawave-telegram-sub-mini-app"
)

# ==================================================================================
# ⛔ ДАЛЬШЕ НЕ ЛЕЗЬ, ТАМ ТОК И БОЛЬ (СИСТЕМНАЯ ЛОГИКА) ⛔
# ==================================================================================

# ========== HELPER: ИЩЕЙКА КОНФИГА ==========
find_compose_file() {
    local dir="$1"
    local file=$(find "$dir" -maxdepth 1 -type f \( -name "*compose*.yml" -o -name "*compose*.yaml" \) | sort | head -n 1)
    echo "$file"
}

# ========== БЛОК: УСТАНОВКА И ПРОВЕРКА (INSTALL CHECK) ==========
CURRENT_EXEC=$(readlink -f "$0")

# 1. Если скрипт запущен НЕ из /root/don_remna_up.sh
if [ "$CURRENT_EXEC" != "$INSTALL_PATH" ]; then
    clear
    echo -e "${MAGENTA}🚀 Запуск 'на лету'. Скачиваю базу...${NC}"
    
    if command -v curl >/dev/null 2>&1; then
        curl -s -o "$INSTALL_PATH" "$UPDATE_URL"
    else
        wget -q -O "$INSTALL_PATH" "$UPDATE_URL"
    fi

    if [ ! -s "$INSTALL_PATH" ]; then
        echo -e "${RED}❌ Не смог скачать скрипт. Гитхаб лежит или инета нет.${NC}"
        if [ ! -f "$INSTALL_PATH" ]; then exit 1; fi
    else
        # === ЛЕЧЕНИЕ ОТ WINDOWS (CRLF) ===
        sed -i 's/\r$//' "$INSTALL_PATH"
        # ================================
        
        chmod +x "$INSTALL_PATH"
        ln -sf "$INSTALL_PATH" "$LINK_PATH"
        echo -e "${GREEN}✅ Установлено в $INSTALL_PATH${NC}"
        echo -e "${CYAN}🔄 Перезапускаюсь...${NC}"
        sleep 1
        exec bash "$INSTALL_PATH"
        exit 0
    fi
fi

# 2. Если скрипт УЖЕ в правильной папке, но симлинка donup НЕТ
CURRENT_LINK_TARGET=$(readlink -f "$LINK_PATH" 2>/dev/null)
if [ "$CURRENT_LINK_TARGET" != "$INSTALL_PATH" ]; then
    chmod +x "$INSTALL_PATH"
    ln -sf "$INSTALL_PATH" "$LINK_PATH"
    
    clear
    echo -e "${GREEN}######################################################${NC}"
    echo -e "${GREEN}#                                                    #${NC}"
    echo -e "${GREEN}#     ✅ КОРОЧЕ, Я ПРОПИСАЛСЯ В СИСТЕМЕ. ВСЁ. ✅     #${NC}"
    echo -e "${GREEN}#                                                    #${NC}"
    echo -e "${GREEN}######################################################${NC}"
    echo ""
    echo -e "${YELLOW}Слушай сюда. Теперь я тут главный по обновам.${NC}"
    echo -e "${YELLOW}В следующий раз не мучай wget, просто пиши:${NC}"
    echo ""
    echo -e "           👉  ${MAGENTA}donup${NC}  👈"
    echo ""
    echo -e "Жми ${GREEN}[ENTER]${NC}, погнали работать..."
    read
fi

# ========== РАЗВЕДКА БОЕМ (PRE-SCAN v3.0) ==========
DETECTED_COMPOSE=$(find_compose_file "$CORE_PATH")

SERVER_TYPE="UNKNOWN"
SERVER_LABEL="НЕПОНЯТНАЯ ДИЧЬ"
COMPOSE_NAME_FOR_SHOW="нет файла"

if [ -n "$DETECTED_COMPOSE" ]; then
    COMPOSE_NAME_FOR_SHOW=$(basename "$DETECTED_COMPOSE")
    
    # Ищем маркеры в файле
    if grep -q "image:.*backend" "$DETECTED_COMPOSE" || grep -q "image:.*remnawave/panel" "$DETECTED_COMPOSE"; then
        SERVER_TYPE="PANEL"
        SERVER_LABEL="👑 ПАХАН (PANEL)"
    elif grep -q "image:.*remnawave/node" "$DETECTED_COMPOSE"; then
        SERVER_TYPE="NODE"
        SERVER_LABEL="🚜 РАБОТЯГА (NODE)"
    elif grep -q "container_name:.*remnawave" "$DETECTED_COMPOSE"; then 
        SERVER_TYPE="PANEL"
        SERVER_LABEL="👑 ПАХАН (BY NAME)"
    elif grep -q "container_name:.*remnanode" "$DETECTED_COMPOSE"; then
        SERVER_TYPE="NODE"
        SERVER_LABEL="🚜 РАБОТЯГА (BY NAME)"
    else
        SERVER_LABEL="👽 МУТАНТ (CUSTOM)"
    fi
else
    SERVER_LABEL="👻 ПРИЗРАК (ФАЙЛ НЕ НАЙДЕН)"
fi

# ========== HELPER ФУНКЦИИ ==========

print_header() {
    clear
    echo -e "${MAGENTA}######################################################"
    echo -e "#                                                    #"
    echo -e "#          💣 DON MATTEO UPGRADER v1.6 💣            #"
    echo -e "#            Инструмент для четких админов           #"
    echo -e "#       Косяков не прощаем. Работаем по красоте.     #"
    echo -e "#                                                    #"
    echo -e "######################################################${NC}"
    echo ""
}

print_section() {
    local emoji="$1"
    local title="$2"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}${emoji} ${title}${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

print_action() {
    local emoji="$1"
    local text="$2"
    local path="$3"
    echo -ne "${emoji}  ${text} ${CYAN}${path}${NC} ... "
}

print_success() {
    echo -e "${GREEN}✓ ЧЁТКО${NC}"
}

print_error() {
    local code="$1"
    local dir="$2"
    echo -e "${RED}💀 КОСЯК [Код: $code]${NC}"
    echo -e "${YELLOW}🔍 Чекни лог, брат:${NC}"
    local cfile=$(find_compose_file "$dir")
    if [ -n "$cfile" ]; then
        local last_err=$(cd "$dir" && docker compose -f "$(basename "$cfile")" up -d 2>&1 | tail -n 2)
        echo -e "${RED}>>> ${last_err}${NC}"
    else
        echo -e "${RED}>>> Файл compose не найден в $dir${NC}"
    fi
    echo -e "------------------------------------------------------"
}

confirm_execution() {
    print_header
    echo -e "${YELLOW}📢 ВНИМАНИЕ! Сейчас будет суета. Разносим (обновляем) сервер.${NC}"
    echo -e "Вот список жертв:"
    echo ""
    
    local found=0
    for dir in "${SERVICES[@]}"; do
        if [ -d "$dir" ]; then
             if [ "$dir" == "$CORE_PATH" ]; then
                echo -e "   ⭐ ${CYAN}$dir${NC} ($SERVER_LABEL) [${YELLOW}$COMPOSE_NAME_FOR_SHOW${NC}]"
             else
                echo -e "   🎯 ${CYAN}$dir${NC}"
             fi
             ((found++))
        fi
    done

    if [ $found -eq 0 ]; then
        echo -e "${RED}❌ Слыш, а где файлы? Я ничё не нашел. Проверь CONFIG!${NC}"
        exit 1
    fi
    
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}💡 НЕ ВИДИШЬ СВОЮ ПАПКУ? РАЗУЙ ГЛАЗА!${NC}"
    echo -e "   Зайди в файл и поправь пути:"
    echo -e "   ${YELLOW}nano $INSTALL_PATH${NC}" 
    echo -e "   Секция ${MAGENTA}CONFIG ZONE${NC} вверху. Я ждал, пока ты спросишь."
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    echo ""
    echo -e "${MAGENTA}Ну чё, ты готов или как?${NC}"
    
    ROASTS=(
        "Эй, хакер, ты пальцы в узел завязал? 'y' или 'n'!"
        "Не та кнопка! Ты чё, первый день за компом?"
        "Соберись, тряпка! Мне нужно 'y' (давай) или 'n' (вали)."
        "Ты головой по клаве бьёшься? Попади по букве 'y'!"
        "Я щас сам за тебя нажму... Шучу. Давай рожай."
        "Не зли меня. 'y' или 'n'. Это просто."
        "Ты испытываешь моё терпение... Нажми 'y'!"
        "Ctrl+C — выход для трусов. Будь мужиком, жми 'y'."
    )

    echo -ne "${BLUE}Введи 'y' (погнали) или 'n' (я пас): ${NC}"

    local needs_cleanup=false
    while true; do
        read -n 1 -r -s REPLY
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            echo ""
            echo -e "${GREEN}Во, наш человек. Наводим суету! 🚀${NC}"
            echo ""
            break
        elif [[ $REPLY =~ ^[Nn]$ ]]; then
            echo ""
            echo -e "${RED}⛔ Ну и иди гуляй. Сервер целее будет.${NC}"
            exit 1
        else
            echo -ne "\r\033[K"
            if [ "$needs_cleanup" = true ]; then
                echo -ne "\033[1A\033[2K"
            fi
            RAND_IDX=$((RANDOM % ${#ROASTS[@]}))
            echo -e "${YELLOW}🙄 ${ROASTS[$RAND_IDX]}${NC}"
            echo -ne "${BLUE}Соберись и нажми нормально (y/n): ${NC}"
            needs_cleanup=true
        fi
    done
}

# ========== СТАРТ СКРИПТА ==========

confirm_execution

# --- ЭТАП 1: ГАСИМ СВЕТ ---
print_section "🛑" "ЭТАП 1: ГАСИМ СВЕТ (DOWN)"
for dir in "${SERVICES[@]}"; do
    if [ -d "$dir" ]; then
        cfile=$(find_compose_file "$dir")
        if [ -n "$cfile" ]; then
            fname=$(basename "$cfile")
            print_action "💤" "Вырубаем ($fname)" "$dir"
            (cd "$dir" && docker compose -f "$fname" down) &>/dev/null
            if [ $? -eq 0 ]; then 
                print_success
            else 
                print_error $? "$dir"
            fi
        else
            echo -e "${YELLOW}⚠️  В $dir нет compose-файла. Пропускаю.${NC}"
        fi
    fi
done

echo -ne "🧹 Выметаем мусор из сети Docker (prune)... "
docker network prune -f &>/dev/null
print_success
echo ""

# --- ЭТАП 2: ТЯНЕМ ---
print_section "🔄" "ЭТАП 2: ТЯНЕМ ОБНОВЫ С НЕБЕС (PULL)"
for dir in "${SERVICES[@]}"; do
    if [ -d "$dir" ]; then
        cfile=$(find_compose_file "$dir")
        if [ -n "$cfile" ]; then
            fname=$(basename "$cfile")
            print_action "📥" "Засасываем ($fname)" "$dir"
            (cd "$dir" && docker compose -f "$fname" pull) &>/dev/null
            if [ $? -eq 0 ]; then 
                print_success
            else 
                print_error $? "$dir"
            fi
        fi
    fi
done
echo ""

# --- ЭТАП 3: ЯДРО ---
print_section "💎" "ЭТАП 3: ЗАПУСК ДВИЖКА (CORE)"

if [ ! -d "$CORE_PATH" ]; then
    echo -e "${RED}🤬 АЛЛО! Папки ядра ($CORE_PATH) нет! Ты чё удалил, валенок?!${NC}"
    exit 1
fi

if [ -z "$DETECTED_COMPOSE" ]; then
    echo -e "${RED}❌ В папке ядра ($CORE_PATH) нет ни одного файла *compose*.yml!${NC}"
    echo -e "${RED}   Как я тебе это запущу? Силой мысли?${NC}"
    exit 1
fi

CORE_FILENAME=$(basename "$DETECTED_COMPOSE")
echo -e "${MAGENTA}🔍 Кто тут у нас:${NC} $SERVER_LABEL"
print_action "🚀" "Поднимаем ($CORE_FILENAME)" "$SERVER_LABEL"

(cd "$CORE_PATH" && docker compose -f "$CORE_FILENAME" up -d) &>/dev/null
RES=$?
if [ $RES -eq 0 ]; then 
    print_success
else 
    print_error $RES "$CORE_PATH"
    echo -e "${RED}Всё, приехали. Движок заглох. Чини давай.${NC}"
    exit 1
fi

echo -ne "⏳ Ждём ${YELLOW}40 секунд${NC}, пока база данных протрезвеет... "
sleep 40
print_success 
echo ""

# --- ЭТАП 4: ОБВЕС ---
print_section "🛠️" "ЭТАП 4: ПОДРУБАЕМ ОСТАЛЬНОЕ"
for dir in "${SERVICES[@]}"; do
    if [ "$dir" == "$CORE_PATH" ]; then continue; fi
    
    if [ -d "$dir" ]; then
        cfile=$(find_compose_file "$dir")
        if [ -n "$cfile" ]; then
            fname=$(basename "$cfile")
            print_action "🔌" "Врубаем ($fname)" "$dir"
            (cd "$dir" && docker compose -f "$fname" up -d) &>/dev/null
            RES=$?
            if [ $RES -eq 0 ]; then 
                print_success
            else 
                print_error $RES "$dir"
            fi
        fi
    fi
done
echo ""

# --- ЭТАП 5: ЛОГИ ---
print_section "📝" "ЭТАП 5: СМОТРИ В ГЛАЗА (LOGS)"

CORE_LOG_CMD="docker compose -f \"$CORE_FILENAME\" logs -f"

if [ "$SERVER_TYPE" == "PANEL" ]; then
    echo -e "${GREEN}📡 Это у нас:${NC} ${CYAN}МАСТЕР-СЕРВЕР${NC}"
    
    NGINX_PATH=""
    for dir in "${SERVICES[@]}"; do
        if [[ "$dir" == *"/nginx"* ]]; then
            NGINX_PATH="$dir"
            break
        fi
    done

    NGINX_COMPOSE=""
    if [ -n "$NGINX_PATH" ] && [ -d "$NGINX_PATH" ]; then
        NGINX_COMPOSE=$(find_compose_file "$NGINX_PATH")
    fi

    if [ -n "$NGINX_COMPOSE" ]; then
        echo -e "${GREEN}📄 Вывожу логи Nginx. Если там ошибки 500 — я не виноват.${NC}"
        echo ""
        cd "$NGINX_PATH" && docker compose -f "$(basename "$NGINX_COMPOSE")" logs -f
    else
        echo -e "${GREEN}📄 Вывожу логи Панели...${NC}"
        echo ""
        cd "$CORE_PATH" && eval $CORE_LOG_CMD
    fi

elif [ "$SERVER_TYPE" == "NODE" ]; then
    echo -e "${YELLOW}🤖 Это у нас:${NC} ${CYAN}НОДА${NC}"
    echo -e "${YELLOW}📄 Вывожу логи Узла. Надеюсь, коннект есть...${NC}"
    echo ""
    cd "$CORE_PATH" && eval $CORE_LOG_CMD

else
    echo -e "${RED}🤡 Это у нас:${NC} ${CYAN}ХЗ ЧТО ТАКОЕ${NC}"
    echo -e "Конфиг есть, но я не ванга. Смотри логи сам:"
    echo ""
    cd "$CORE_PATH" && eval $CORE_LOG_CMD
fi
ENDOFFILE
