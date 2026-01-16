cat > /root/don_remna_up.sh << 'ENDOFFILE'
#!/bin/bash

# ==========================================
#  DON MATTEO SYSTEM UPGRADER
#  Code: LETHAL | Style: GANGSTA | Status: GOD MODE
#  Edition: IDENTITY CRISIS FIX (v1.5)
# ==========================================

# Цветовая палитра
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# ==================================================================================
# 🕵️  ИЩЕЙКА (AUTO-DISCOVERY ZONE)  🕵️
# ==================================================================================
# Сюда не лезь. Скрипт сам найдет, куда ты спрятал файлы.

echo -e "${BLUE}🔍 Начинаю шмон по системе... Ищем твои контейнеры...${NC}"

# Функция поиска docker-compose
find_core_path() {
    # 1. Проверяем дефолт (для ленивых)
    if [ -f "/opt/remnawave/docker-compose.yml" ]; then
        echo "/opt/remnawave"
        return
    fi
    
    # 2. Если ты "творческая личность", ищем в /opt и /root (глубина 4)
    # Ищем файл, в котором упоминается образ remnawave (node или backend)
    local FOUND=$(find /opt /root -maxdepth 4 -name "docker-compose.y*ml" -print0 2>/dev/null | xargs -0 grep -lE "image:.*remnawave/(node|backend)" | head -n 1)
    
    if [ -n "$FOUND" ]; then
        dirname "$FOUND"
    else
        echo "NOT_FOUND"
    fi
}

CORE_PATH=$(find_core_path)

if [ "$CORE_PATH" == "NOT_FOUND" ]; then
    echo -e "${RED}🤬 Слыш, я перерыл /opt и /root, но не нашел ни Панели, ни Ноды!${NC}"
    echo -e "${YELLOW}Либо ты назвал папку как-то совсем криво, либо у тебя вообще ничего не стоит.${NC}"
    echo -e "Укажи путь руками в скрипте, если ты такой уникальный."
    exit 1
fi

echo -e "${GREEN}🎯 Опа, нашел логово тут: ${CYAN}$CORE_PATH${NC}"

# ==================================================================================
# ⚙️  ЗОНА КОНФИГА (ДИНАМИЧЕСКАЯ)  ⚙️
# ==================================================================================

# 2. Список точек обновляем динамически от найденного ядра
SERVICES=(
    "$CORE_PATH" # Тут сам ищет ноду или панель! если не найдет добавляй путь ниже!
    "/opt/remnawave/nginx"
    "/opt/certwarden"
    "/opt/certwardenclient"
    "/opt/remnawave/subscription"
    "/opt/remnawave/remnawave-telegram-sub-mini-app"
)

# ==================================================================================
# ⛔ ДАЛЬШЕ НЕ ЛЕЗЬ, ТАМ ТОК И БОЛЬ (СИСТЕМНАЯ ЛОГИКА) ⛔
# ==================================================================================

# ========== БЛОК: Я ТУТ ТЕПЕРЬ ЖИВУ (AUTO-INSTALL) ==========
REAL_PATH=$(readlink -f "$0")
LINK_PATH="/usr/local/bin/donup"
CURRENT_LINK_TARGET=$(readlink -f "$LINK_PATH" 2>/dev/null)

if [ "$REAL_PATH" != "$CURRENT_LINK_TARGET" ]; then
    chmod +x "$REAL_PATH"
    ln -sf "$REAL_PATH" "$LINK_PATH"
    
    # Удаляем старый файл с неправильным именем, если он есть
    if [ -f "/root/don_remna.sh" ]; then
        rm -f "/root/don_remna.sh"
    fi

    clear
    echo -e "${GREEN}######################################################${NC}"
    echo -e "${GREEN}#                                                    #${NC}"
    echo -e "${GREEN}#     ✅ КОРОЧЕ, Я ПРОПИСАЛСЯ В СИСТЕМЕ. ВСЁ. ✅     #${NC}"
    echo -e "${GREEN}#                                                    #${NC}"
    echo -e "${GREEN}######################################################${NC}"
    echo ""
    echo -e "${YELLOW}Слушай сюда. Теперь я тут главный по обновам.${NC}"
    echo -e "${YELLOW}Захочешь обновиться — просто свистни (введи команду):${NC}"
    echo ""
    echo -e "           👉  ${MAGENTA}donup${NC}  👈"
    echo ""
    echo -e "${CYAN}P.S. Старый файл я снес, чтобы ты не путался.${NC}"
    echo ""
    echo -e "Жми ${GREEN}[ENTER]${NC}, погнали работать, время — деньги..."
    read
fi

# ========== РАЗВЕДКА БОЕМ (SCAN & DETECT v2) ==========
COMPOSE_FILE="$CORE_PATH/docker-compose.yml"
# Если .yml не найден, пробуем .yaml
if [ ! -f "$COMPOSE_FILE" ]; then COMPOSE_FILE="$CORE_PATH/docker-compose.yaml"; fi

SERVER_TYPE="UNKNOWN"
SERVER_LABEL="НЕПОНЯТНАЯ ДИЧЬ"

if [ -f "$COMPOSE_FILE" ]; then
    # Теперь смотрим в корень: проверяем ОБРАЗЫ (IMAGES), это точнее имен контейнеров.
    
    # 1. Сначала проверяем на НОДУ (NODE), так как в её имени тоже есть 'remnawave' (в image)
    if grep -q "image:.*remnawave/node" "$COMPOSE_FILE"; then
        SERVER_TYPE="NODE"
        SERVER_LABEL="🚜 РАБОТЯГА (NODE)"
    
    # 2. Потом проверяем на ПАНЕЛЬ (BACKEND)
    elif grep -q "image:.*remnawave/backend" "$COMPOSE_FILE"; then
        SERVER_TYPE="PANEL"
        SERVER_LABEL="👑 ПАХАН (PANEL)"

    # 3. Фолбэк на имена контейнеров, если образы кастомные
    elif grep -q "container_name:.*remnanode" "$COMPOSE_FILE"; then
        SERVER_TYPE="NODE"
        SERVER_LABEL="🚜 РАБОТЯГА (NODE)"
    elif grep -q "container_name:.*remnawave" "$COMPOSE_FILE"; then
        SERVER_TYPE="PANEL"
        SERVER_LABEL="👑 ПАХАН (PANEL)"
    
    else
        SERVER_LABEL="👽 МУТАНТ (CUSTOM)"
    fi
else
    SERVER_LABEL="👻 ПРИЗРАК (НЕТ КОНФИГА)"
    echo -e "${RED}💀 Файла docker-compose.yml нет в $CORE_PATH!${NC}"
    exit 1
fi

# ========== HELPER ФУНКЦИИ ==========

print_header() {
    clear
    echo -e "${MAGENTA}######################################################"
    echo -e "#                                                    #"
    echo -e "#          💣 DON MATTEO UPGRADER v1.4 💣            #"
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
    echo -e "${YELLOW}🔍 Чё-то пошло не по плану. Чекни лог, брат:${NC}"
    local last_err=$(cd "$dir" && docker compose up -d 2>&1 | tail -n 2)
    echo -e "${RED}>>> ${last_err}${NC}"
    echo -e "------------------------------------------------------"
}

confirm_execution() {
    print_header
    echo -e "${YELLOW}📢 ВНИМАНИЕ! Сейчас будет суета. Разносим (обновляем) сервер.${NC}"
    echo -e "Тип сервера определен как: $SERVER_LABEL"
    echo -e "Вот список жертв, которых мы затронем:"
    echo ""
    
    local found=0
    for dir in "${SERVICES[@]}"; do
        if [ -d "$dir" ]; then
             if [ "$dir" == "$CORE_PATH" ]; then
                echo -e "   ⭐ ${CYAN}$dir${NC} ($SERVER_LABEL)"
             else
                echo -e "   🎯 ${CYAN}$dir${NC}"
             fi
             ((found++))
        fi
    done

    if [ $found -eq 0 ]; then
        echo -e "${RED}❌ Слыш, а где файлы? Я ничё не нашел. Проверь пути!${NC}"
        exit 1
    fi
    
    echo ""
    echo -e "${MAGENTA}Ну чё, ты готов или как? Бэкапы — для слабаков, но я предупредил.${NC}"
    
    ROASTS=(
        "Эй, хакер, ты пальцы в узел завязал? 'y' или 'n'!"
        "Не та кнопка! Ты чё, первый день за компом?"
        "Соберись, тряпка! Мне нужно 'y' (давай) или 'n' (вали)."
        "Ты головой по клаве бьёшься? Попади по букве 'y'!"
        "Я щас сам за тебя нажму... Шучу. Давай рожай."
        "Может тебе курсы компьютерной грамотности оплатить?"
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
        print_action "💤" "Вырубаем всё в" "$dir"
        (cd "$dir" && docker compose down) &>/dev/null
        if [ $? -eq 0 ]; then 
            print_success
        else 
            print_error $? "$dir"
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
        print_action "📥" "Засасываем свежак в" "$dir"
        (cd "$dir" && docker compose pull) &>/dev/null
        if [ $? -eq 0 ]; then 
            print_success
        else 
            print_error $? "$dir"
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

echo -e "${MAGENTA}🔍 Кто тут у нас:${NC} $SERVER_LABEL"
print_action "🚀" "Поднимаем эту махину" "$SERVER_LABEL"

(cd "$CORE_PATH" && docker compose up -d) &>/dev/null
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
        print_action "🔌" "Врубаем рубильник на" "$dir"
        (cd "$dir" && docker compose up -d) &>/dev/null
        RES=$?
        if [ $RES -eq 0 ]; then 
            print_success
        else 
            print_error $RES "$dir"
        fi
    fi
done
echo ""

# --- ЭТАП 5: ЛОГИ ---
print_section "📝" "ЭТАП 5: СМОТРИ В ГЛАЗА (LOGS)"

if [ "$SERVER_TYPE" == "PANEL" ]; then
    echo -e "${GREEN}📡 Это у нас:${NC} ${CYAN}МАСТЕР-СЕРВЕР${NC}"
    
    NGINX_PATH=""
    for dir in "${SERVICES[@]}"; do
        if [[ "$dir" == *"/nginx"* ]]; then
            NGINX_PATH="$dir"
            break
        fi
    done

    if [ -n "$NGINX_PATH" ] && [ -d "$NGINX_PATH" ]; then
        echo -e "${GREEN}📄 Вывожу логи Nginx. Если там ошибки 500 — я не виноват.${NC}"
        echo ""
        cd "$NGINX_PATH" && docker compose logs -f
    else
        echo -e "${GREEN}📄 Вывожу логи Панели...${NC}"
        echo ""
        cd "$CORE_PATH" && docker compose logs -f
    fi

elif [ "$SERVER_TYPE" == "NODE" ]; then
    echo -e "${YELLOW}🤖 Это у нас:${NC} ${CYAN}НОДА${NC}"
    echo -e "${YELLOW}📄 Вывожу логи Узла. Надеюсь, коннект есть...${NC}"
    echo ""
    cd "$CORE_PATH" && docker compose logs -f

else
    echo -e "${RED}🤡 Это у нас:${NC} ${CYAN}ХЗ ЧТО ТАКОЕ${NC}"
    echo -e "Конфиг есть, но я не ванга. Смотри логи сам:"
    echo ""
    cd "$CORE_PATH" && docker compose logs -f
fi
ENDOFFILE

chmod +x /root/don_remna_up.sh
