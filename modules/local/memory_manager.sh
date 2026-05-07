#!/bin/bash
# ============================================================ #
# ==           МОДУЛЬ УПРАВЛЕНИЯ ПАМЯТЬЮ И SWAP             == #
# ============================================================ #
#
# @menu.manifest
# @item( local_care | 6 | 🧠 Управление памятью и Swap | manage_swap | 60 | 3 | Интеллектуальное управление ОЗУ, ZRAM и Disk Swap. )
#

[[ "${BASH_SOURCE[0]}" == "${0}" ]] && exit 1 # Защита от прямого запуска

_get_swap_status() {
    local swp
    swp=$(free -m | awk '/^Swap:/ {print $2}')
    local has_zram
    has_zram=$(lsblk 2>/dev/null | grep -i zram)
    local has_file
    has_file=$(swapon --show --noheadings 2>/dev/null | grep -i "/swapfile")
    
    if [[ -n "$has_zram" && -n "$has_file" ]]; then
        echo -e "${C_GREEN}[ГИБРИД: ZRAM + Disk Swap]${C_RESET}"
    elif [[ -n "$has_zram" ]]; then
        echo -e "${C_GREEN}[ZRAM ВКЛЮЧЕН: ${swp} MB]${C_RESET}"
    elif [[ "$swp" != "0" && -n "$swp" ]]; then 
        echo -e "${C_YELLOW}[DISK SWAP: ${swp} MB]${C_RESET}"
    else 
        echo -e "${C_RED}[ВЫКЛЮЧЕН]${C_RESET}"
    fi
}

_show_memory_status() {
    clear
    menu_header "СТАТУС ОПЕРАТИВНОЙ ПАМЯТИ И SWAP"
    
    local mem_total
    mem_total=$(free -m | awk '/^Mem:/ {print $2}')
    local mem_used
    mem_used=$(free -m | awk '/^Mem:/ {print $3}')
    local mem_cache
    mem_cache=$(free -m | awk '/^Mem:/ {print $6}')
    local mem_avail
    mem_avail=$(free -m | awk '/^Mem:/ {print $7}')
    
    local swap_total
    swap_total=$(free -m | awk '/^Swap:/ {print $2}')
    local swap_used
    swap_used=$(free -m | awk '/^Swap:/ {print $3}')
    local swap_free
    swap_free=$(free -m | awk '/^Swap:/ {print $4}')

    echo -e "  ${C_CYAN}💻 Оперативная память (RAM):${C_RESET}"
    echo -e "    └─ Всего доступно: ${C_GREEN}${mem_total} MB${C_RESET}"
    echo -e "    └─ Использовано:   ${C_YELLOW}${mem_used} MB${C_RESET}"
    echo -e "    └─ Кэш/Буферы:     ${C_BLUE}${mem_cache} MB${C_RESET}"
    echo -e "    └─ Свободно:       ${C_GREEN}${mem_avail} MB${C_RESET}"

    echo -e "\n  ${C_CYAN}💽 Файл подкачки (ZRAM / Swap):${C_RESET}"
    if [[ "$swap_total" == "0" ]]; then
        echo -e "    └─ ${C_RED}ВЫКЛЮЧЕН (Рекомендуется включить ZRAM!)${C_RESET}"
    else
        if lsblk 2>/dev/null | grep -q zram; then
            echo -e "    └─ Тип:            ${C_GREEN}Умное сжатие (ZRAM)${C_RESET}"
        else
            echo -e "    └─ Тип:            ${C_YELLOW}Жесткий диск (Disk Swap)${C_RESET}"
        fi
        echo -e "    └─ Всего выделено: ${C_GREEN}${swap_total} MB${C_RESET}"
        echo -e "    └─ Использовано:   ${C_RED}${swap_used} MB${C_RESET}"
        echo -e "    └─ Свободно:       ${C_GREEN}${swap_free} MB${C_RESET}"
    fi
    echo ""
    wait_for_enter
}

_show_memory_instructions() {
    clear
    menu_header "ИНСТРУКЦИЯ: ПАМЯТЬ И DOCKER"
    printf_description "Правильная настройка памяти защитит ноду от зависаний (OOM)."
    echo ""
    
    echo -e "  ${C_CYAN}${C_BOLD}[ ЧАСТЬ 1 ] ЧТО ВЫБРАТЬ: ZRAM ИЛИ DISK SWAP?${C_RESET}"
    echo -e "  ${C_GREEN}🌪️ ZRAM (Сжатие в ОЗУ):${C_RESET} Идеально для VPN. Работает со скоростью ОЗУ."
    echo -e "     Сжимает неактивные данные. ${C_YELLOW}Обязателен для серверов 1-2 ГБ!${C_RESET}"
    echo -e "  ${C_RED}💽 Disk Swap (На диске):${C_RESET} Работает в 10-50 раз медленнее ZRAM."
    echo -e "     Использовать ТОЛЬКО если у сервера меньше 512 МБ ОЗУ.\n"

    echo -e "  ${C_CYAN}${C_BOLD}[ ЧАСТЬ 2 ] НАСТРОЙКА DOCKER-COMPOSE.YML${C_RESET}"
    echo -e "  Для защиты сервера нужно жестко ограничить аппетит ${C_YELLOW}remnanode${C_RESET}."
    echo -e "  В файле ${C_GREEN}docker-compose.yml${C_RESET} найдите блок ${C_YELLOW}remnanode${C_RESET} и добавьте лимиты:\n"

    echo -e "  ${C_BOLD}▶ ДЛЯ СЕРВЕРА НА 1 ГБ RAM (Минимальный):${C_RESET}"
    echo -e "  ${C_CYAN}    environment:
        - NODE_OPTIONS=--max-old-space-size=256
      deploy:
        resources:
          limits:
            memory: 768M
          reservations:
            memory: 256M${C_RESET}\n"

    echo -e "  ${C_BOLD}▶ ДЛЯ СЕРВЕРА НА 2 ГБ RAM (Оптимальный):${C_RESET}"
    echo -e "  ${C_CYAN}    environment:
        - NODE_OPTIONS=--max-old-space-size=512
      deploy:
        resources:
          limits:
            memory: 1536M
          reservations:
            memory: 512M${C_RESET}\n"

    echo -e "  ${C_BOLD}▶ ДЛЯ СЕРВЕРА НА 4 ГБ RAM И БОЛЬШЕ (Максимальный):${C_RESET}"
    echo -e "  ${C_CYAN}    environment:
        - NODE_OPTIONS=--max-old-space-size=1024
      deploy:
        resources:
          limits:
            memory: 3072M
          reservations:
            memory: 1024M${C_RESET}\n"

    print_separator "=" 60
    echo -e "  ${C_YELLOW}💡 ВАЖНО: После изменения docker-compose.yml выполните:${C_RESET}"
    echo -e "  ${C_CYAN}   docker compose down && docker compose up -d${C_RESET}"
    print_separator "=" 60
    echo ""
    wait_for_enter
}

_make_zram_smart() {
    local PERCENT=$1
    info "Установка и настройка ZRAM (${PERCENT}% от RAM)..."
    
    run_cmd swapoff -a 2>/dev/null || true
    run_cmd rm -f /swapfile 2>/dev/null
    run_cmd sed -i '/^\/swapfile/d' /etc/fstab

    ensure_package "zram-tools" "bc"

    cat << EOF | run_cmd tee /etc/default/zramswap >/dev/null
ALGO=lz4
PERCENT=${PERCENT}
PRIORITY=100
EOF

    run_cmd systemctl restart zramswap >/dev/null 2>&1
    run_cmd systemctl enable zramswap >/dev/null 2>&1
    
    ok "ZRAM успешно активирован! Ваша ОЗУ теперь сжимается на лету."
}

_install_hybrid_memory_optimization() {
    info "Настройка гибридной памяти (ZRAM + Disk Swap)..."
    
    # 1. Сначала ZRAM (50% RAM, высокий приоритет)
    ensure_package "zram-tools" "bc"
    
    cat << EOF | run_cmd tee /etc/default/zramswap >/dev/null
ALGO=lz4
PERCENT=50
PRIORITY=100
EOF
    run_cmd systemctl restart zramswap >/dev/null 2>&1
    run_cmd systemctl enable zramswap >/dev/null 2>&1

    # 2. Затем Disk Swap (2GB, низкий приоритет -2)
    if [[ ! -f /swapfile ]]; then
        info "Создание файла подкачки 2GB в качестве страховки..."
        run_cmd fallocate -l 2G /swapfile 2>/dev/null || run_cmd dd if=/dev/zero of=/swapfile bs=1M count=2048
        run_cmd chmod 600 /swapfile
        run_cmd mkswap /swapfile >/dev/null 2>&1
        run_cmd swapon -p -2 /swapfile 2>/dev/null || run_cmd swapon /swapfile
        grep -qE '^/swapfile\s' /etc/fstab || echo '/swapfile none swap sw,pri=-2 0 0' | run_cmd tee -a /etc/fstab
    else
        # Если файл есть, просто убеждаемся что приоритет верный
        run_cmd swapoff /swapfile 2>/dev/null
        run_cmd swapon -p -2 /swapfile 2>/dev/null
        run_cmd sed -i 's/.*\/swapfile.*/\/swapfile none swap sw,pri=-2 0 0/' /etc/fstab
    fi
    
    ok "Гибридная память настроена: ZRAM (Priority 100) + Disk Swap (Priority -2)."
}

_make_swap() {
    local SIZE=$1
    info "Создание классического Disk Swap на ${SIZE}GB..."
    
    run_cmd systemctl stop zramswap 2>/dev/null || true
    run_cmd apt-get remove --purge zram-tools -y >/dev/null 2>&1 || true
    
    run_cmd swapoff -a 2>/dev/null || true
    run_cmd rm -f /swapfile 2>/dev/null
    
    run_cmd fallocate -l ${SIZE}G /swapfile
    run_cmd chmod 600 /swapfile
    run_cmd mkswap /swapfile >/dev/null 2>&1
    run_cmd swapon /swapfile
    
    grep -qE '^/swapfile\s' /etc/fstab || echo '/swapfile none swap sw 0 0' | run_cmd tee -a /etc/fstab
    
    ok "Файл подкачки (Disk Swap) на ${SIZE}GB успешно создан!"
}

_remove_all_swap() {
    info "Полное удаление ZRAM и Disk Swap..."
    
    run_cmd systemctl stop zramswap 2>/dev/null || true
    run_cmd systemctl disable zramswap 2>/dev/null || true
    run_cmd apt-get remove --purge zram-tools -y >/dev/null 2>&1 || true
    
    run_cmd swapoff -a 2>/dev/null || true
    run_cmd rm -f /swapfile 2>/dev/null
    run_cmd sed -i '/^\/swapfile/d' /etc/fstab
    
    ok "Все файлы подкачки и модули сжатия отключены и удалены."
}

manage_swap() {
    enable_graceful_ctrlc
    while true; do
        clear
        menu_header "⚙️ Управление памятью"
        printf_description "Интеллектуальное управление ОЗУ сервера. $(_get_swap_status)"
        echo ""
        
        local RAM_KB
        RAM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
        local RAM_MB=$((RAM_KB / 1024))
        local RAM_GB=$(( (RAM_MB + 512) / 1024 )) # Округление вверх до ближайшего ГБ
        
        # Динамические рекомендации
        local REC_ZRAM
        local REC_SWAP
        if [ "$RAM_MB" -le 1024 ]; then
            REC_ZRAM="60%"; REC_SWAP="2"
        elif [ "$RAM_MB" -le 2048 ]; then
            REC_ZRAM="50%"; REC_SWAP="2"
        elif [ "$RAM_MB" -le 4096 ]; then
            REC_ZRAM="40%"; REC_SWAP="4"
        else
            REC_ZRAM="25%"; REC_SWAP="4"
        fi
        
        echo -e "  Текущая физическая RAM: ${C_GREEN}${RAM_GB} GB (${RAM_MB} MB)${C_RESET}"
        print_separator "-" 60
        
        printf_menu_option "1" "🌪️ Установка ГИБРИДНОГО режима (ZRAM + Swap) ${C_YELLOW}[ РЕКОМЕНДУЕТСЯ ]${C_RESET}"
        printf_description "     └ Идеально для VPN. Рекомендуется: ZRAM (${REC_ZRAM}) + Swap (${REC_SWAP} GB)"
        
        printf_menu_option "2" "🧩 Только ZRAM (Турбо-сжатие в ОЗУ)"
        printf_description "     └ Рекомендуемое сжатие: ${REC_ZRAM}"
        
        printf_menu_option "3" "💽 Только Disk Swap (На жестком диске)"
        printf_description "     └ Рекомендуемый размер: ${REC_SWAP} GB"
        
        print_separator "-" 60
        printf_menu_option "4" "🗑️ Полностью отключить и удалить ZRAM / Swap"
        printf_menu_option "5" "📊 Подробный статус оперативной памяти"
        print_separator "-" 60
        printf_menu_option "6" "📖 ЧИТАТЬ ИНСТРУКЦИЮ (Лимиты Docker и память)"
        echo ""
        printf_menu_option "b" "🔙 Назад"
        echo ""
        
        local choice
        choice=$(safe_read "Твой выбор" "") || break
        
        case "$choice" in
            1) 
                _install_hybrid_memory_optimization
                wait_for_enter ;;
            2)
                local custom_zram
                custom_zram=$(safe_read "Введите процент сжатия (10-100, по умолчанию 60)" "60") || continue
                _make_zram_smart "$custom_zram"
                wait_for_enter ;;
            3)
                local custom_swap
                custom_swap=$(safe_read "Введите размер в GB (например, 2)" "2") || continue
                _make_swap "$custom_swap"
                wait_for_enter ;;
            4) 
                _remove_all_swap
                wait_for_enter ;;
            5) _show_memory_status ;;
            6) _show_memory_instructions ;;
            [bB]) break ;;
            *) err "Неверный выбор."; sleep 1 ;;
        esac
    done
    disable_graceful_ctrlc
}
