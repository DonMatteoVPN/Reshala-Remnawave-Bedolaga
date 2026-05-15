#!/bin/bash
# modules/utils/migrations.sh - Движок критических обновлений и миграций Reshala
#
# ══════════════════════════════════════════════════════════════════════════
# 📖 ПРАВИЛА ДЛЯ РАЗРАБОТЧИКОВ (КАК ДОБАВИТЬ МИГРАЦИЮ):
# ══════════════════════════════════════════════════════════════════════════
# 1. Создайте новый файл в папке modules/utils/migrations/ (напр. 0002_fix.sh).
# 2. В файле обязательно должны быть определены:
#    - MIG_ID="УНИКАЛЬНЫЙ_ID"
#    - MIG_TITLE="Краткий заголовок патча"
#    - MIG_DESC="Подробное описание для пользователя"
# 3. Реализуйте две функции:
#    - migration_check() - должна вернуть 0, если миграция НУЖНА.
#    - migration_apply() - логика применения. Возвращает 0 при успехе.
# 4. Движок сам подхватит файл, проверит его и предложит пользователю.
# ══════════════════════════════════════════════════════════════════════════

MIGRATIONS_DIR="${SCRIPT_DIR}/modules/utils/migrations"
MIGRATIONS_LOG="/etc/reshala/applied_migrations.log"

# --- Вспомогательные функции движка ---

is_migration_applied() {
    local mig_id="$1"
    [[ ! -f "$MIGRATIONS_LOG" ]] && return 1
    grep -qx "${mig_id}" "$MIGRATIONS_LOG"
}

register_migration() {
    local mig_id="$1"
    mkdir -p "/etc/reshala"
    echo "$mig_id" >> "$MIGRATIONS_LOG"
}

# Возвращает количество доступных миграций
get_pending_migrations_count() {
    local count=0
    # Нам нужно загрузить модуль firewall для проверок, если они связаны с ним
    if [[ -f "${SCRIPT_DIR}/modules/security/firewall.sh" ]]; then
        source "${SCRIPT_DIR}/modules/security/firewall.sh"
    fi

    # Ищем все .sh файлы в папке миграций и сортируем их
    for mig_file in $(ls "$MIGRATIONS_DIR"/*.sh 2>/dev/null | sort); do
        (
            # Запускаем в subshell, чтобы переменные разных миграций не перемешивались
            source "$mig_file"
            if migration_check; then
                exit 0 # Нужна миграция
            else
                exit 1 # Не нужна
            fi
        )
        [[ $? -eq 0 ]] && ((count++))
    done
    echo "$count"
}

# Экран центра обновлений
show_critical_updates_wizard() {
    clear
    menu_header "🚀 Центр обновлений безопасности"
    
    info "Анализ системы на наличие необходимых патчей..."
    echo ""
    
    # Снова загружаем firewall для применения патчей
    if [[ -f "${SCRIPT_DIR}/modules/security/firewall.sh" ]]; then
        source "${SCRIPT_DIR}/modules/security/firewall.sh"
    fi

    local pending_files=()
    
    # Собираем список файлов миграций, которые нужно применить
    for mig_file in $(ls "$MIGRATIONS_DIR"/*.sh 2>/dev/null | sort); do
        local is_needed=0
        # Проверяем через subshell
        (
            source "$mig_file"
            migration_check && exit 0 || exit 1
        )
        [[ $? -eq 0 ]] && pending_files+=("$mig_file")
    done

    if [[ ${#pending_files[@]} -eq 0 ]]; then
        ok "Все критические обновления применены. Система в актуальном состоянии."
        wait_for_enter
        return
    fi

    info "Доступные обновления для версии $VERSION:"
    for mig_file in "${pending_files[@]}"; do
        # Читаем метаданные из файла (без полного сорсинга в основной шелл, чтобы не было конфликтов)
        local title; title=$(grep "MIG_TITLE=" "$mig_file" | cut -d'"' -f2)
        local desc; desc=$(grep "MIG_DESC=" "$mig_file" | cut -d'"' -f2)
        
        printf_description "  ${C_YELLOW}● ${title}${C_RESET}"
        printf_description "    ↳ ${desc}"
    done
    
    echo ""
    if ask_yes_no "Применить все найденные обновления (${#pending_files[@]} шт.)?"; then
        for mig_file in "${pending_files[@]}"; do
            # Теперь сорсим в текущий шелл для выполнения, но аккуратно
            # Чтобы избежать конфликтов имен функций, мы будем переопределять их при каждом сорсинге
            unset -f migration_check migration_apply
            source "$mig_file"
            
            info "Выполняю: $MIG_TITLE..."
            if migration_apply; then
                register_migration "$MIG_ID"
                ok "Успешно: $MIG_ID"
            else
                err "Ошибка при применении миграции: $MIG_ID"
            fi
        done
        
        ok "Процесс обновлений завершен."
        wait_for_enter
    fi
}
