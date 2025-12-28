#!/bin/bash
# ============================================================ #
# ==            ОБЩИЙ МОДУЛЬ (ЯЩИК С ИНСТРУМЕНТАМИ)         == #
# ============================================================ #
#
# Здесь лежат общие функции, которые нужны всем остальным модулям.
# Этот файл не запускается напрямую, а подключается (source).
#
[[ "${BASH_SOURCE[0]}" == "${0}" ]] && exit 1 # Защита от прямого запуска

# Подключаем модуль управления зависимостями
if [ -f "${SCRIPT_DIR}/modules/core/dependencies.sh" ]; then
    source "${SCRIPT_DIR}/modules/core/dependencies.sh"
fi

# --- Цвета для вывода в терминал ---
C_RESET='\033[0m'; C_RED='\033[0;31m'; C_GREEN='\033[0;32m';
C_YELLOW='\033[1;33m'; C_CYAN='\033[0;36m'; C_BLUE='\033[0;94m'; C_BOLD='\033[1m';
C_GRAY='\033[0;90m'; C_WHITE='\033[1;37m';

# Универсальный хедер для меню
menu_header() {
    local title="$1"
    local width="${2:-60}"
    local color="${3:-${C_CYAN}}"

    local visible_title_len=$(_get_visible_length "$title")
    
    # The effective width for the content between "║ " and "║"
    local effective_content_width=$(( width - 2 )) # Subtracting 2 for " " and the right "║"
    
    local padding_needed=$(( effective_content_width - visible_title_len ))

    if (( padding_needed < 0 )); then padding_needed=0; fi

    printf "%b\n" "${color}╔$(printf '%.0s═' $(seq 1 "$width"))╗${C_RESET}"
    printf "%b\n" "${color}║ ${title}$(printf '%*s' "$padding_needed" "")║${C_RESET}"
    printf "%b\n" "${color}╚$(printf '%.0s═' $(seq 1 "$width"))╝${C_RESET}"
}

# Универсальный футер для меню
menu_footer() {
    local width="${1:-60}" # New: width argument, default to 60
    local color="${2:-${C_CYAN}}" # New: color argument, default to C_CYAN
    printf "%b\n" "${color}╚$(printf '%.0s═' $(seq 1 "$width"))╝${C_RESET}"
}

# Выводит вертикальную линию (например, "║")
print_vertical_line() {
    local color="${1:-${C_CYAN}}" # Default color to C_CYAN
    printf "%b\n" "${color}║${C_RESET}"
}

# --- Функции вывода ---
printf_info() { printf "%b%b%b\n" "${C_CYAN}[i] " "$*" "${C_RESET}"; }
printf_ok() { printf "%b%b%b\n" "${C_GREEN}[✓] " "$*" "${C_RESET}"; }
printf_warning() { printf "%b%b%b\n" "${C_YELLOW}[!] " "$*" "${C_RESET}"; }
printf_error() { printf "%b%b%b\n" "${C_RED}[✗] " "$*" "${C_RESET}"; sleep 2; }

# Условный отладочный вывод
debug_log() {
    if [[ "${DEBUG_MODE:-off}" == "on" ]]; then
        printf "%b%b%b\n" "${C_GRAY}[DEBUG] " "$*" "${C_RESET}" >&2
    fi
}

# Критическое предупреждение (красный, жирный)
printf_critical_warning() { printf "\n%b‼️ %b ‼️%b\n" "${C_BOLD}${C_RED}" "$*" "${C_RESET}"; }

# Выводит обычное описание или инструкцию (без префикса)
printf_description() {
    local text="$1"
    debug_log "PRINT_DESC: TEXT: ${text}"
    printf "          ↳ %b%b\n" "$*" "${C_RESET}"
}

# Вычисляет видимую длину строки, удаляя ANSI-коды.
# Предполагается, что все видимые символы имеют ширину 1.
_get_visible_length() {
    local s="$1"
    # Удаляем ANSI escape-коды
    local stripped_s; stripped_s=$(echo "$s" | sed 's/\x1b\[[0-9;]*m//g')
    # Возвращаем видимую длину
    echo "${#stripped_s}"
}

# Универсальный разделитель
print_separator() {
    local char="${1:-=}" # Default to '='
    local length="${2:-60}" # Default to 60 characters
    printf "%b%s%b\n" "${C_GRAY}" "$(printf "%*s" "$length" "" | tr ' ' "$char")" "${C_RESET}"
}

# Генерирует визуальный индикатор прогресса (возвращает строку)
get_progress_bar_string() {
    local percentage="$1" # 0-100
    local bar_width="${2:-20}" # Default width of the bar
    local color="${3:-${C_GREEN}}" # Default color for filled part
    local empty_color="${4:-${C_GRAY}}" # Default color for empty part

    local filled_chars
    local empty_chars
    local bar_string=""

    # Calculate filled and empty characters
    filled_chars=$(( (percentage * bar_width) / 100 ))
    empty_chars=$(( bar_width - filled_chars ))

    # Build the bar string
    bar_string="${empty_color}["
    bar_string+="${color}"
    for ((i=0; i<filled_chars; i++)); do bar_string+="■"; done
    bar_string+="${empty_color}"
    for ((i=0; i<empty_chars; i++)); do bar_string+="□"; done
    bar_string+="] ${color}$(printf "%3s" "$percentage")%%${C_RESET}"
    echo "$bar_string"
}

# Выводит заголовок секции (например, "╠═[ СИСТЕМА ]")
print_section_title() {
    local title="$1"
    printf "%b╠═[ %s ]%b\n" "${C_CYAN}" "$title" "${C_RESET}"
}

# Выводит пару ключ-значение, например, "║ CPU Модель     : Intel Xeon"
print_key_value() {
    local label="$1"
    local value="$2"
    local target_width="${3:-${DASHBOARD_LABEL_WIDTH:-15}}"
    
    local visible_label_len=$(_get_visible_length "$label")
    local padding=$(( target_width - visible_label_len ))
    
    # Ensure padding is not negative
    if (( padding < 0 )); then padding=0; fi

    # Build the padded label string
    local padded_label="${label}$(printf '%*s' "$padding" "")"

    printf "║ %b%s:%b %b\n" "${C_GRAY}" "$padded_label" "${C_RESET}" "$value"
}

# Выводит форматированный пункт меню: "   [KEY] LABEL"
printf_menu_option() {
    local key="$1"
    local label="$2"
    local color="${3:-${C_WHITE}}" # Default color to C_WHITE
    debug_log "PRINT_MENU: KEY: ${key}, LABEL: ${label}"
    printf "   %b[%s] %b%b\n" "$color" "$key" "$label" "${C_RESET}"
}

# Алиасы
info() { printf_info "$@"; }
ok()   { printf_ok "$@"; }
warn() { printf_warning "$@"; }
err()  { printf_error "$@"; }

# --- Логирование ---
init_logger() {
    if ! [ -f "$LOGFILE" ]; then
        touch "$LOGFILE" &>/dev/null || true
        chmod 666 "$LOGFILE" &>/dev/null || true
    fi
}

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] - $*" | run_cmd tee -a "$LOGFILE" > /dev/null
}

# --- Запуск команд ---
run_cmd() {
    if [[ $EUID -eq 0 ]]; then
        "$@"
    elif command -v sudo &>/dev/null; then
        sudo "$@"
    else
        err "Команда 'sudo' не найдена. Запусти скрипт от имени root."
        return 1
    fi
}

# --- Обработка Ctrl+C (Trap Stack) ---
declare -a TRAP_STACK
declare -g _LAST_CTRLC_SIGNALED=0 # Global flag to indicate Ctrl+C was pressed

push_trap() {
    local new_trap="$1"
    local current_trap
    current_trap=$(trap -p INT | cut -d"'" -f2)
    TRAP_STACK+=("${current_trap:-}")
    trap "$new_trap" INT
}

pop_trap() {
    local prev_trap
    if [ ${#TRAP_STACK[@]} -gt 0 ]; then
        prev_trap="${TRAP_STACK[-1]}"
        unset 'TRAP_STACK[-1]'
        if [ -n "$prev_trap" ]; then
            trap "$prev_trap" INT
        else
            trap - INT
        fi
    else
        trap - INT
    fi
}

# Стандартный обработчик для подменю (возврат назад)
trap_return() {
    printf "\n%b%s%b\n" "${C_YELLOW}" "Возвращаемся назад..." "${C_RESET}"
    # Используем возврат каретки или просто break в циклах меню
    # Но так как trap выполняется асинхронно, лучше всего просто сбросить ввод
    # В большинстве случаев в меню используется read, который вернет код > 128
}

enable_graceful_ctrlc() {
    # Trap just sets a flag. The caller must check _LAST_CTRLC_SIGNALED
    push_trap 'printf "\n"; _LAST_CTRLC_SIGNALED=1;'
}

disable_graceful_ctrlc() {
    pop_trap
}



# --- Ввод данных ---

# Безопасный ввод с дефолтным значением
# safe_read "Вопрос" "Дефолт"
safe_read() {
    local prompt="$1"
    local default="${2:-}"
    local result
    
    local prompt_full="$prompt"
    if [ -n "$default" ]; then
        prompt_full="$prompt [${default}]: "
    else
        prompt_full="$prompt: "
    fi

    # Более надежная очистка буфера ввода
    while read -r -t 0; do read -r; done
        
    read -e -p "$prompt_full" result || return 130
    
    if [[ -z "$result" && -n "$default" ]]; then
        result="$default"
    fi
    
    echo "$result"
    return 0
}

ask_yes_no() {
    local prompt="$1"
    local def="${2:-n}"
    local answer

    case "$def" in
        y|Y) def="y" ;;
        *)   def="n" ;;
    esac

    while true; do
        answer=$(safe_read "$prompt" "$def") || return 130
        case "$answer" in
            y|Y|yes|Yes|YES) return 0 ;;
            n|N|no|No|NO) return 1 ;;
            *) warn "Отвечай 'y' или 'n'." ;;
        esac
    done
}

ask_non_empty() {
    local prompt="$1"
    local def="${2:-}"
    local value
    while true; do
        value=$(safe_read "$prompt" "$def") || return 130
        if [[ -n "$value" ]]; then
            echo "$value"
            return 0
        fi
        err "Поле не может быть пустым."
    done
}

ask_number_in_range() {
    local prompt="$1"
    local min="$2"
    local max="$3"
    local def="${4:-}"
    local value
    while true; do
        value=$(safe_read "$prompt" "$def") || return 130
        
        # Check for empty value if no default and non-empty is required implicitly
        if [[ -z "$value" && -z "$def" ]]; then
            err "Поле не может быть пустым."
            continue
        fi

        if [[ "$value" =~ ^[0-9]+$ ]]; then
            if [[ -n "$min" && "$value" -lt "$min" ]] || [[ -n "$max" && "$value" -gt "$max" ]]; then
                err "Вводи число от $min до $max."
                continue
            fi
            echo "$value"
            return 0
        fi
        err "Нужно ввести число."
    done
}

# Безопасный ввод пароля (без вывода на экран)
ask_password() {
    local prompt="$1"
    local password
    # Очистка буфера
    while read -r -t 0; do read -r; done
    read -s -p "$prompt" password || return 130
    echo # Перевод строки после ввода
    echo "$password"
    return 0
}

# Выбор из списка (интерактивное меню)
# ask_selection "Заголовок" "Вариант 1" "Вариант 2" ...
ask_selection() {
    local title="$1"
    shift
    local options=("$@")
    local cnt=${#options[@]}
    
    # Выводим меню в stderr, чтобы не загрязнять stdout
    >&2 echo "$title"
    local i=1
    for opt in "${options[@]}"; do
        >&2 printf "   [%d] %s\n" "$i" "$opt"
        ((i++))
    done
    
    local choice
    choice=$(ask_number_in_range "Твой выбор" 1 "$cnt" "") || return 130
    # Возвращаем индекс (1-based) в stdout
    echo "$choice"
    return 0
}

# Функция проверки IP адреса
validate_ip() {
    local ip="$1"
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        local IFS=.
        local -a octets=($ip)
        for octet in "${octets[@]}"; do
            if ((octet > 255)); then
                return 1
            fi
        done
        return 0
    fi
    return 1
}

# Функция проверки порта
validate_port() {
    local port="$1"
    if [[ $port =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ]; then
        return 0
    fi
    return 1
}

# --- Прочие утилиты ---
ensure_package() {
    local package_name="$1"
    if ! command -v "$package_name" &>/dev/null; then
        warn "Утилита '${package_name}' не найдена. Устанавливаю..."
        if command -v apt-get &>/dev/null; then
            run_cmd apt-get update
            run_cmd apt-get install -y "$package_name"
        elif command -v yum &>/dev/null; then
            run_cmd yum install -y "$package_name"
        else
            err "Не могу установить '${package_name}'. Сделай это вручную."
            return 1
        fi
    fi
    return 0
}

set_config_var() {
    local key="$1"
    local value="$2"
    local config_file="${SCRIPT_DIR}/config/reshala.conf"
    if grep -q "^${key}=" "$config_file" 2>/dev/null; then
        sed -i "s|^${key}=.*|${key}=\"${value}\"|" "$config_file"
    else
        echo "${key}=\"${value}\"" >> "$config_file"
    fi
}

get_config_var() {
    local key="$1"
    local config_file="${SCRIPT_DIR}/config/reshala.conf"
    if [ -f "$config_file" ]; then
        grep "^${key}=" "$config_file" 2>/dev/null | cut -d'=' -f2- | sed 's/"//g'
    fi
}

wait_for_enter() {
    read -rp $'\nНажми Enter, чтобы продолжить...' || return 130
}

# --- Логи (legacy wrappers) ---
view_logs_realtime() {
    local log_path="$1"
    local log_name="$2"
    if [ ! -f "$log_path" ]; then
        run_cmd touch "$log_path"
        run_cmd chmod 666 "$log_path"
    fi
    echo "[*] Смотрю журнал '$log_name'... (CTRL+C, чтобы свалить)"
    enable_graceful_ctrlc
    run_cmd tail -f -n 50 "$log_path"
    disable_graceful_ctrlc
    return 0
}

view_docker_logs() {
    local service_path="$1"
    local service_name="$2"
    if [ -z "$service_path" ] || [ ! -f "$service_path" ]; then
        err "Путь к Docker-compose не найден."
        sleep 2
        return
    fi
    echo "[*] Смотрю потроха '$service_name'... (CTRL+C, чтобы свалить)"
    enable_graceful_ctrlc
    ( cd "$(dirname "$service_path")" && run_cmd docker compose logs -f ) || true
    disable_graceful_ctrlc
    return 0
}
