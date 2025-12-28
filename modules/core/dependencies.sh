#!/bin/bash
# ============================================================ #
# ==           CORE: УПРАВЛЕНИЕ ЗАВИСИМОСТЯМИ               == #
# ============================================================ #
#
# Этот модуль предоставляет функции для автоматической проверки
# и установки необходимых системных пакетов.
#
[[ "${BASH_SOURCE[0]}" == "${0}" ]] && exit 1 # Защита от прямого запуска

# Определяем пакетный менеджер
_detect_package_manager() {
    if command -v apt-get &>/dev/null; then
        echo "apt-get"
    elif command -v dnf &>/dev/null; then
        echo "dnf"
    elif command -v yum &>/dev/null; then
        echo "yum"
    elif command -v apk &>/dev/null; then
        echo "apk"
    elif command -v pacman &>/dev/null; then
        echo "pacman"
    else
        echo "unknown"
    fi
}

# Кэшируем пакетный менеджер, чтобы не искать каждый раз
_PKG_MANAGER=$(_detect_package_manager)

# Устанавливает пакет, если он не найден
# Использование: ensure_dependency "имя_бинарника" ["имя_пакета"]
# Если имя_пакета не указано, считается, что оно совпадает с именем бинарника.
ensure_dependency() {
    local binary="$1"
    local package="${2:-$1}"

    if command -v "$binary" &>/dev/null; then
        return 0
    fi

    # Если бинарника нет, пробуем установить
    # Используем run_cmd из common.sh для прав root
    
    # Если запущен не интерактивно или в фоне (например, виджет), логируем, но не спамим в stdout если не критично
    # Но установка требует вывода, так что перенаправляем в /dev/null если нужно тихо
    
    # Для виджетов важно, чтобы это работало быстро и тихо.
    
    case "$_PKG_MANAGER" in
        apt-get)
            run_cmd apt-get update -qq >/dev/null 2>&1
            run_cmd apt-get install -y -qq "$package" >/dev/null 2>&1
            ;;
        dnf)
            run_cmd dnf install -y -q "$package" >/dev/null 2>&1
            ;;
        yum)
            run_cmd yum install -y -q "$package" >/dev/null 2>&1
            ;;
        apk)
            run_cmd apk add --no-cache -q "$package" >/dev/null 2>&1
            ;;
        pacman)
            run_cmd pacman -Sy --noconfirm --quiet "$package" >/dev/null 2>&1
            ;;
        *)
            # Неизвестный менеджер или его нет - ничего не можем сделать
            return 1
            ;;
    esac

    # Проверяем еще раз после попытки установки
    if command -v "$binary" &>/dev/null; then
        return 0
    else
        return 1
    fi
}

# Проверка списка зависимостей
# Использование: ensure_dependencies "curl" "jq" "wget"
ensure_dependencies() {
    for dep in "$@"; do
        ensure_dependency "$dep"
    done
}