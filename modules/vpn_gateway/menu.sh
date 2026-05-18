#!/bin/bash
# ============================================================ #
# ==        VPN GATEWAY MODULE: ДЛЯ RESHALA-ECOSYSTEM        == #
# ============================================================ #
#
# Упрощенное и автоматизированное меню управления лендингом/gateway.
#
# @menu.manifest
# @item( main | g | 🛡️ Маскировщик лендинга Bedolaga ${C_CYAN}(быстрый мастер)${C_RESET} | show_vpn_gateway_menu | 55 | 3 | Единый мастер настройки для маскировки лендинга Bedolaga. )
# @item( vpn_gateway | 1 | 🚀 Мастер: первичная настройка | vgw_install_wizard | 10 | 1 | Запрашивает параметры, обновляет конфиг и поднимает стек. )
# @item( vpn_gateway | 2 | 🔁 Мастер: изменить параметры | vgw_reconfigure_wizard | 20 | 1 | Обновляет quick_setup и перезапускает шлюз с nginx. )
# @item( vpn_gateway | 3 | ♻️ Перезапуск стека (анти-502) | vgw_run | 30 | 1 | Пересоздаёт контейнеры шлюза и перезапускает nginx. )
# @item( vpn_gateway | 4 | 📊 Статус и журналы | vgw_status_diagnostics | 40 | 2 | Показывает статус и последние логи edge-nginx и vpn-gateway. )
# @item( vpn_gateway | 5 | 🧪 Прогнать тесты | vgw_test | 50 | 2 | Запускает встроенные тесты проекта шлюза. )
# @item( vpn_gateway | 6 | 🔐 Сертификаты (выпуск/продление) | vgw_certs_full | 60 | 2 | Выпускает, продлевает сертификаты и настраивает cron. )
# @item( vpn_gateway | 7 | 💳 Скрытие return в платежке | vgw_toggle_hide_payment_return | 70 | 3 | Включает или отключает скрытие return-ссылки в платежах. )
# @item( vpn_gateway | x | 🧪 Удаление (предпросмотр) | vgw_uninstall_dry | 95 | 4 | Предпросмотр удаления без фактических изменений. )
# @item( vpn_gateway | d | 🗑️ Удаление выполнить (опасно) | vgw_uninstall_execute_confirmed | 96 | 4 | Удаление контейнеров шлюза (с подтверждением). )
# @item( vpn_gateway | D | ☠️ Полная очистка (очень опасно) | vgw_uninstall_purge_confirmed | 97 | 4 | Удаление контейнеров и локальных данных шлюза. )
#
[[ "${BASH_SOURCE[0]}" == "${0}" ]] && exit 1

_vgw_project_dir() { echo "${VPN_GATEWAY_MODULE_PROJECT_DIR:-/opt/vpn-gateway-project}"; }
_vgw_ctl_path() { local project_dir="$(_vgw_project_dir)"; local rel="${VPN_GATEWAY_MODULE_CTL_RELATIVE:-scripts/gatewayctl.sh}"; echo "${project_dir}/${rel}"; }

_vgw_validate_environment() {
    local project_dir="$(_vgw_project_dir)" ctl="$(_vgw_ctl_path)"
    [[ -d "$project_dir" ]] || { printf_error "Не найдена директория VPN Gateway: ${project_dir}"; return 1; }
    [[ -x "$ctl" ]] || { printf_error "Не найден исполняемый gatewayctl: ${ctl}"; return 1; }

    local py_bin; py_bin="$(_vgw_python)"
    # Проверяем PyYAML — если нет, пробуем установить автоматически
    if ! "$py_bin" -c "import yaml" 2>/dev/null; then
        warn "PyYAML не найден для ${py_bin}. Пробую установить автоматически..."

        local installed=0
        
        # 1. Пробуем системный пакет (самый надежный способ на Debian 12+)
        if command -v apt-get &>/dev/null; then
            info "Устанавливаю python3-yaml через apt..."
            if run_cmd apt-get update -qq && run_cmd apt-get install -y python3-yaml -qq; then
                ok "python3-yaml установлен через apt."
                installed=1
            fi
        fi

        # 2. Пробуем venv проекта
        if [[ "$installed" -eq 0 ]]; then
            local venv_pip="${project_dir}/.venv/bin/pip"
            if [[ -x "$venv_pip" ]]; then
                info "Устанавливаю через venv проекта: ${venv_pip}"
                if "$venv_pip" install pyyaml --quiet; then
                    ok "PyYAML установлен в venv проекта."
                    installed=1
                fi
            fi
        fi

        # 3. Пробуем системный pip3
        if [[ "$installed" -eq 0 ]] && command -v pip3 &>/dev/null; then
            info "Устанавливаю через системный pip3..."
            if pip3 install pyyaml --quiet 2>/dev/null || pip3 install pyyaml --quiet --break-system-packages 2>/dev/null; then
                ok "PyYAML установлен глобально."
                installed=1
            fi
        fi

        if [[ "$installed" -eq 0 ]]; then
            printf_error "Не удалось автоматически установить PyYAML."
            printf_warning "Установи вручную: apt install python3-yaml"
            printf_warning "Или: pip3 install pyyaml --break-system-packages"
            return 1
        fi

        # Повторная проверка после установки (обновляем py_bin на случай если что-то изменилось)
        py_bin="$(_vgw_python)"
        if ! "$py_bin" -c "import yaml" 2>/dev/null; then
            printf_error "PyYAML установлен, но ${py_bin} его не видит. Проверь окружение."
            return 1
        fi
    fi
}

_vgw_run_action() {
    local action="$1"; shift || true
    _vgw_validate_environment || return 1
    local project_dir="$(_vgw_project_dir)" ctl="$(_vgw_ctl_path)"
    ( cd "$project_dir"; "$ctl" "$action" "$@" )
}

_vgw_cfg_file()    { echo "$(_vgw_project_dir)/config/gateway.yml"; }

# ══════════════════════════════════════════════════════════════════
# Персистентное хранилище — вне git, git pull не трогает
# Путь: /etc/reshala-bedolaga/
#   gateway.yml        — конфиг шлюза
#   certs/fullchain.pem — TLS сертификат
#   certs/privkey.pem   — приватный ключ
# ══════════════════════════════════════════════════════════════════
_VGW_PERSIST_DIR="/etc/reshala-bedolaga"
_VGW_PERSIST_CERTS_DIR="${_VGW_PERSIST_DIR}/certs"

_vgw_cfg_backup_file()  { echo "${_VGW_PERSIST_DIR}/gateway.yml"; }
_vgw_certs_dir()        { echo "$(_vgw_project_dir)/edge/certs"; }

# ── Конфиг ────────────────────────────────────────────────────────
# Сохраняет рабочий конфиг в персистентное хранилище после каждого сохранения настроек
_vgw_cfg_save_persistent() {
    local cfg_file; cfg_file="$(_vgw_cfg_file)"
    local bak_file; bak_file="$(_vgw_cfg_backup_file)"
    [[ -f "$cfg_file" ]] || return 0
    mkdir -p "${_VGW_PERSIST_DIR}" 2>/dev/null || return 0
    cp -f "$cfg_file" "$bak_file" 2>/dev/null || true
}

# Автовосстановление конфига: если рабочий конфиг пустой/удалён, но бэкап есть — копируем без вопросов
_vgw_cfg_restore_if_needed() {
    local cfg_file; cfg_file="$(_vgw_cfg_file)"
    local bak_file; bak_file="$(_vgw_cfg_backup_file)"
    [[ -f "$bak_file" ]] || return 0          # Бэкапа нет — нечего восстанавливать

    # Читаем домен из рабочего конфига
    local current_domain=""
    if [[ -f "$cfg_file" ]]; then
        local py_bin; py_bin="$(_vgw_python 2>/dev/null)" || return 0
        current_domain=$(CFG_FILE="$cfg_file" "$py_bin" -c "
import os,yaml; from pathlib import Path
try:
    c=yaml.safe_load(Path(os.environ['CFG_FILE']).read_text('utf-8')) or {}
    print(c.get('quick_setup',{}).get('public_domain',''))
except: print('')" 2>/dev/null || echo "")
    fi

    local need_restore=0
    [[ ! -f "$cfg_file" ]] && need_restore=1
    [[ -z "$current_domain" || "$current_domain" == "vpn.example.com" ]] && need_restore=1

    if [[ "$need_restore" -eq 1 ]]; then
        mkdir -p "$(_vgw_project_dir)/config" 2>/dev/null || true
        cp -f "$bak_file" "$cfg_file" 2>/dev/null && \
            ok "Конфиг автоматически восстановлен из ${_VGW_PERSIST_DIR}" || true
    fi
}

# ── Сертификаты ───────────────────────────────────────────────────
# Сохраняет сертификаты в /etc/reshala-bedolaga/certs/ после выпуска/продления
_vgw_certs_save_persistent() {
    local certs_dir; certs_dir="$(_vgw_certs_dir)"
    local fullchain="${certs_dir}/fullchain.pem"
    local privkey="${certs_dir}/privkey.pem"
    [[ -f "$fullchain" && -f "$privkey" ]] || return 0
    mkdir -p "${_VGW_PERSIST_CERTS_DIR}" 2>/dev/null || return 0
    cp -f "$fullchain" "${_VGW_PERSIST_CERTS_DIR}/fullchain.pem" 2>/dev/null || true
    cp -f "$privkey"   "${_VGW_PERSIST_CERTS_DIR}/privkey.pem"   2>/dev/null || true
    chmod 600 "${_VGW_PERSIST_CERTS_DIR}/privkey.pem" 2>/dev/null || true
}

# Автовосстановление сертификатов: если в edge/certs/ их нет, но бэкап есть — копируем молча
_vgw_certs_restore_if_needed() {
    local certs_dir; certs_dir="$(_vgw_certs_dir)"
    local bak_full="${_VGW_PERSIST_CERTS_DIR}/fullchain.pem"
    local bak_key="${_VGW_PERSIST_CERTS_DIR}/privkey.pem"
    # Бэкапа нет — нечего восстанавливать
    [[ -f "$bak_full" && -f "$bak_key" ]] || return 0
    # Рабочие сертификаты уже есть — не трогаем
    [[ -f "${certs_dir}/fullchain.pem" && -f "${certs_dir}/privkey.pem" ]] && return 0

    mkdir -p "$certs_dir" 2>/dev/null || true
    cp -f "$bak_full" "${certs_dir}/fullchain.pem" 2>/dev/null || true
    cp -f "$bak_key"  "${certs_dir}/privkey.pem"   2>/dev/null || true
    chmod 600 "${certs_dir}/privkey.pem" 2>/dev/null || true
    ok "Сертификаты автоматически восстановлены из ${_VGW_PERSIST_CERTS_DIR}"
}


_vgw_is_ipv4() {
    local v="$1"
    [[ "$v" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    local IFS='.' octets=($v)
    for octet in "${octets[@]}"; do
        ((octet >= 0 && octet <= 255)) || return 1
    done
    return 0
}

_vgw_is_domain_like() {
    local v="$1"
    [[ "$v" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$ ]]
}

_vgw_is_offer_like() {
    local v="$1"
    [[ "$v" =~ ^[a-zA-Z0-9._-]{2,64}$ ]]
}

# Определяет путь к питону с PyYAML: сначала venv проекта, затем системный python3
# Причина: PyYAML установлен в venv, а не глобально — системный python3 его не видит
_vgw_python() {
    local venv_py="$(_vgw_project_dir)/.venv/bin/python"
    if [[ -x "$venv_py" ]]; then
        echo "$venv_py"
    else
        echo "python3"
    fi
}

_vgw_read_quick_field() {
    local field="$1" cfg_file="$(_vgw_cfg_file)"
    [[ -f "$cfg_file" ]] || { echo ""; return 0; }
    local py_bin; py_bin="$(_vgw_python)"
    CFG_FILE="$cfg_file" FIELD_NAME="$field" "$py_bin" - <<'PY2'
import os
from pathlib import Path
import yaml
cfg = yaml.safe_load(Path(os.environ['CFG_FILE']).read_text(encoding='utf-8')) or {}
print(str((cfg.get('quick_setup') or {}).get(os.environ['FIELD_NAME'], '')).strip())
PY2
}

_vgw_update_quick_setup() {
    local public_domain="$1" origin_domain="$2" default_offer="$3" acme_enabled="$4" acme_email="$5" cfg_file="$(_vgw_cfg_file)"
    local project_dir="$(_vgw_project_dir)"
    local example_file="${project_dir}/config/gateway.example.yml"

    # Если gateway.yml не существует — создаём из шаблона автоматически.
    # Это нормально после git pull, т.к. gateway.yml исключён из git.
    if [[ ! -f "$cfg_file" ]]; then
        if [[ -f "$example_file" ]]; then
            info "config/gateway.yml не найден. Создаю из шаблона..."
            cp "$example_file" "$cfg_file" || { printf_error "Не удалось скопировать шаблон: ${example_file} → ${cfg_file}"; return 1; }
            ok "Создан config/gateway.yml из шаблона."
        else
            printf_error "Не найдены ни config/gateway.yml, ни config/gateway.example.yml в: ${project_dir}/config/"
            return 1
        fi
    fi

    local py_bin; py_bin="$(_vgw_python)"
    CFG_FILE="$cfg_file" PUBLIC_DOMAIN="$public_domain" ORIGIN_DOMAIN="$origin_domain" DEFAULT_OFFER="$default_offer" ACME_ENABLED="$acme_enabled" ACME_EMAIL="$acme_email" "$py_bin" - <<'PY2'
import os
from pathlib import Path
import yaml
p=Path(os.environ['CFG_FILE'])
data=yaml.safe_load(p.read_text(encoding='utf-8')) or {}
if not isinstance(data, dict): data={}
q=data.get('quick_setup') if isinstance(data.get('quick_setup'), dict) else {}
q['public_domain']=os.environ['PUBLIC_DOMAIN'].strip()
q['origin_domain']=os.environ['ORIGIN_DOMAIN'].strip()
q['default_offer']=os.environ['DEFAULT_OFFER'].strip()
q['origin_scheme']=q.get('origin_scheme') or 'https'
q['acme_enabled'] = os.environ['ACME_ENABLED'].strip().lower() == 'true'
q['acme_email'] = os.environ['ACME_EMAIL'].strip()
data['quick_setup']=q
landing=data.get('landing')
if isinstance(landing, dict) and isinstance(landing.get('pages'), list) and landing['pages']:
    p0=landing['pages'][0]
    if isinstance(p0, dict) and p0.get('path')=='/':
        p0['mirror_target']=os.environ['DEFAULT_OFFER'].strip()
p.write_text(yaml.safe_dump(data, allow_unicode=True, sort_keys=False), encoding='utf-8')
print('ok')
PY2
    # Сохраняем копию в персистентное хранилище (/etc/bedolaga/) — не зависит от git
    _vgw_cfg_save_persistent
}


_vgw_prompt_and_apply_common() {
    local mode="$1"
    local current_public="$(_vgw_read_quick_field public_domain)"
    local current_origin="$(_vgw_read_quick_field origin_domain)"
    local current_offer="$(_vgw_read_quick_field default_offer)"
    local current_acme_enabled="$(_vgw_read_quick_field acme_enabled)"
    local current_acme_email="$(_vgw_read_quick_field acme_email)"

    echo -e "  ${C_CYAN}╔══════════════════════════════════════════════════════════╗${C_RESET}"
    echo -e "  ${C_CYAN}║${C_RESET}  ${C_YELLOW}Что нужно заполнить${C_RESET}                                    ${C_CYAN}║${C_RESET}"
    echo -e "  ${C_CYAN}╠══════════════════════════════════════════════════════════╣${C_RESET}"
    echo -e "  ${C_CYAN}║${C_RESET}  1) Домен лендинга: что видит клиент в браузере.          ${C_CYAN}║${C_RESET}"
    echo -e "  ${C_CYAN}║${C_RESET}     Где взять: ваш рекламный/публичный домен в DNS.       ${C_CYAN}║${C_RESET}"
    echo -e "  ${C_CYAN}║${C_RESET}  2) Домен кабинета: ваш настоящий домен панели/бэкенда.   ${C_CYAN}║${C_RESET}"
    echo -e "  ${C_CYAN}║${C_RESET}     Где взять: домен, который уже открыт у вас в браузере.${C_CYAN}║${C_RESET}"
    echo -e "  ${C_CYAN}║${C_RESET}  3) Оффер: код лендинга/тарифа для главной страницы.      ${C_CYAN}║${C_RESET}"
    echo -e "  ${C_CYAN}║${C_RESET}     Где взять: из ваших офферов в админке/конфиге.         ${C_CYAN}║${C_RESET}"
    echo -e "  ${C_CYAN}║${C_RESET}  4) Let's Encrypt: включайте, если домен настоящий.       ${C_CYAN}║${C_RESET}"
    echo -e "  ${C_CYAN}║${C_RESET}     Если IP/временный домен — лучше выключить.             ${C_CYAN}║${C_RESET}"
    echo -e "  ${C_CYAN}╚══════════════════════════════════════════════════════════╝${C_RESET}"
    echo ""

    local public_domain origin_domain default_offer
    local default_public="${current_public:-vpn.example.com}"
    local default_origin="${current_origin:-cabinet.example.com}"
    local default_offer_value="${current_offer:-wl-lte}"

    while true; do
        public_domain=$(safe_read "Домен лендинга" "${default_public}") || return 1
        [[ -n "$public_domain" ]] || { printf_error "Поле не может быть пустым."; continue; }
        if _vgw_is_domain_like "$public_domain" || _vgw_is_ipv4 "$public_domain"; then
            break
        fi
        printf_error "Домен лендинга заполнен неверно. Пример: vpn.example.com или 203.0.113.10"
    done

    while true; do
        origin_domain=$(safe_read "Домен кабинета" "${default_origin}") || return 1
        [[ -n "$origin_domain" ]] || { printf_error "Поле не может быть пустым."; continue; }
        if _vgw_is_domain_like "$origin_domain"; then
            break
        fi
        printf_error "Домен кабинета заполнен неверно. Пример: cabinet.example.com"
    done

    while true; do
        default_offer=$(safe_read "Оффер по умолчанию" "${default_offer_value}") || return 1
        [[ -n "$default_offer" ]] || { printf_error "Поле не может быть пустым."; continue; }
        if _vgw_is_offer_like "$default_offer"; then
            break
        fi
        printf_error "Оффер заполнен неверно. Используйте 2-64 символа: буквы, цифры, точка, дефис, подчёркивание."
    done

    local acme_default="y"
    if [[ "$public_domain" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        acme_default="n"
    elif [[ "$current_acme_enabled" == "false" ]]; then
        acme_default="n"
    fi

    local acme_enabled="false"
    local acme_email="$current_acme_email"
    if ask_yes_no "Включить авто-выпуск Let's Encrypt для публичного домена? (y/n)" "$acme_default"; then
        acme_enabled="true"
        local default_acme_email="${current_acme_email:-admin@example.com}"
        while true; do
            acme_email=$(safe_read "Email для Let's Encrypt" "${default_acme_email}") || return 1
            [[ -n "$acme_email" && "$acme_email" != "admin@example.com" ]] || { printf_error "Укажите реальный email (не admin@example.com)."; continue; }
            if [[ "$acme_email" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then
                break
            fi
            printf_error "Email заполнен неверно. Пример: admin@yourdomain.com"
        done
    fi

    _vgw_update_quick_setup "$public_domain" "$origin_domain" "$default_offer" "$acme_enabled" "$acme_email" || return 1
    printf_ok "Конфиг обновлен"

    if [[ "$mode" == "install" ]]; then
        _vgw_run_action install
    else
        _vgw_run_action run
    fi
}

show_vpn_gateway_menu() {
    enable_graceful_ctrlc
    while true; do
        clear
        menu_header "🛡️ Маскировщик лендинга Bedolaga" 64 "${C_CYAN}"
        # Автовосстановление конфига и сертификатов если git pull их удалил
        _vgw_cfg_restore_if_needed
        _vgw_certs_restore_if_needed
        # Умный статус-блок: установлен или нет
        _vgw_menu_status_block
        render_menu_items "vpn_gateway"
        echo ""
        printf_menu_option "b" "🔙 Назад в главное меню" "${C_CYAN}"
        print_separator "─" 64
        local choice; choice=$(safe_read "Твой выбор" "") || break
        [[ "$choice" =~ ^[bB]$ ]] && break
        local action; action=$(get_menu_action "vpn_gateway" "$choice")
        if [[ -n "$action" ]]; then eval "$action"; wait_for_enter; else printf_error "Нет такого пункта."; sleep 1; fi
    done
    disable_graceful_ctrlc
}

# Умный статус-блок шапки меню:
# — если лендинг не настроен → жёлтое уведомление «нужна установка»
# — если настроен           → синий статус с реальными данными
_vgw_menu_status_block() {
    local public_domain
    public_domain=$(_vgw_read_quick_field public_domain 2>/dev/null || echo "")
    local W="$C_YELLOW" C="$C_CYAN" G="$C_GREEN" R="$C_RED" B="$C_BOLD" E="$C_RESET"

    # ── Лендинг НЕ настроен ───────────────────────────────────────
    if [[ -z "$public_domain" || "$public_domain" == "vpn.example.com" || "$public_domain" == "cabinet.example.com" ]]; then
        # Проверяем — вдруг контейнеры всё равно запущены (осиротевшие после git pull)
        local orphan_running=0
        if docker ps --format '{{.Names}}' 2>/dev/null | grep -qE '^(vpn-gateway|vpn-edge-nginx)$'; then
            orphan_running=1
        fi

        # Уточняем: файл удалён git pull-ом или просто содержит плейсхолдеры
        local cfg_file; cfg_file="$(_vgw_cfg_file)"
        local cfg_missing=0
        [[ ! -f "$cfg_file" ]] && cfg_missing=1

        if [[ "$orphan_running" -eq 1 ]]; then
            echo ""
            echo -e "  ${W}${B}╔══════════════════════════════════════════════════════════════╗${E}"
            if [[ "$cfg_missing" -eq 1 ]]; then
                echo -e "  ${W}${B}║${E}  🔄  ${B}Конфиг удалён при обновлении — стек продолжает работать${E} ${W}${B}║${E}"
            else
                echo -e "  ${W}${B}║${E}  🔄  ${B}Конфиг сброшен — стек работает со старыми данными${E}      ${W}${B}║${E}"
            fi
            echo -e "  ${W}${B}╠══════════════════════════════════════════════════════════════╣${E}"
            echo -e "  ${W}${B}║${E}                                                              ${W}${B}║${E}"
            if [[ "$cfg_missing" -eq 1 ]]; then
                echo -e "  ${W}${B}║${E}  Файл ${R}config/gateway.yml${E} был удалён после ${W}${B}git pull${E}.         ${W}${B}║${E}"
            else
                echo -e "  ${W}${B}║${E}  Файл ${W}${B}config/gateway.yml${E} содержит плейсхолдеры.              ${W}${B}║${E}"
            fi
            echo -e "  ${W}${B}║${E}  Контейнеры ${G}vpn-gateway / vpn-edge-nginx${E} продолжают работать.  ${W}${B}║${E}"
            echo -e "  ${W}${B}║${E}                                                              ${W}${B}║${E}"
            echo -e "  ${W}${B}║${E}  ${G}${B}▶ Нажми [1]${E} — укажи домены заново, стек перезапустится    ${W}${B}║${E}"
            echo -e "  ${W}${B}║${E}    с правильным конфигом. Ничего не потеряется.              ${W}${B}║${E}"
            echo -e "  ${W}${B}║${E}                                                              ${W}${B}║${E}"
            echo -e "  ${W}${B}║${E}  ${R}${B}[d]${E} — Полностью удалить и начать с нуля                    ${W}${B}║${E}"
            echo -e "  ${W}${B}║${E}                                                              ${W}${B}║${E}"
            echo -e "  ${W}${B}╚══════════════════════════════════════════════════════════════╝${E}"
            echo ""
        else
            echo ""
            echo -e "  ${W}${B}╔══════════════════════════════════════════════════════════════╗${E}"
            echo -e "  ${W}${B}║${E}  🚧  ${B}Лендинг ещё не установлен${E}                              ${W}${B}║${E}"
            echo -e "  ${W}${B}╠══════════════════════════════════════════════════════════════╣${E}"
            echo -e "  ${W}${B}║${E}                                                              ${W}${B}║${E}"
            echo -e "  ${W}${B}║${E}  Для запуска маскировщика выполни первичную настройку:      ${W}${B}║${E}"
            echo -e "  ${W}${B}║${E}                                                              ${W}${B}║${E}"
            echo -e "  ${W}${B}║${E}    ${G}${B}[1] 🚀 Мастер: первичная настройка${E}                       ${W}${B}║${E}"
            echo -e "  ${W}${B}║${E}                                                              ${W}${B}║${E}"
            echo -e "  ${W}${B}║${E}  Мастер спросит домены и автоматически поднимет стек.       ${W}${B}║${E}"
            echo -e "  ${W}${B}╚══════════════════════════════════════════════════════════════╝${E}"
            echo ""
        fi
        return 0
    fi


    # ── Лендинг настроен — показываем статус ─────────────────────
    local hide_return acme_enabled
    hide_return=$(_vgw_read_hide_payment_return 2>/dev/null || echo "unknown")
    acme_enabled=$(_vgw_read_quick_field acme_enabled 2>/dev/null || echo "true")

    local gw_status="❌ не запущен" gw_color="$R"
    if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "vpn-gateway"; then
        gw_status="✅ запущен" gw_color="$G"
    fi

    local http_ok="⏳ проверка..." http_color="$W"
    if command -v curl > /dev/null 2>&1; then
        local http_code
        http_code=$(curl -o /dev/null -sS -w "%{http_code}" --max-time 3 \
            "https://${public_domain}/" 2>/dev/null || echo "000")
        if [[ "$http_code" =~ ^(200|301|302|307|308)$ ]]; then
            http_ok="✅ отвечает (HTTP ${http_code})" http_color="$G"
        elif [[ "$http_code" == "000" ]]; then
            http_ok="❌ нет ответа" http_color="$R"
        else
            http_ok="⚠️  HTTP ${http_code}" http_color="$W"
        fi
    fi

    local hide_icon="❌ выкл" hide_color="$R"
    [[ "$hide_return" == "true" ]] && { hide_icon="✅ вкл" hide_color="$G"; }

    local proto="https"
    [[ "$acme_enabled" == "false" ]] && proto="https*"

    echo ""
    echo -e "  ${C}╔══════════════════════════════════════════════════════════════╗${E}"
    echo -e "  ${C}║${E}  🌐  ${B}Статус лендинга${E}                                         ${C}║${E}"
    echo -e "  ${C}╠══════════════════════════════════════════════════════════════╣${E}"
    printf  "  ${C}║${E}  %-15s ${B}${proto}://${public_domain}${E}\n"  "Адрес:"
    printf  "  ${C}║${E}  %-15s ${gw_color}%s${E}\n"  "Контейнер:"  "$gw_status"
    printf  "  ${C}║${E}  %-15s ${http_color}%s${E}\n" "Доступность:" "$http_ok"
    printf  "  ${C}║${E}  %-15s ${hide_color}%s${E}\n" "Hide return:"  "$hide_icon"
    echo -e "  ${C}╚══════════════════════════════════════════════════════════════╝${E}"
    echo ""
}

# Проверяет доступность порта на хосте. Возвращает 0 если порт свободен, 1 если занят.
_vgw_check_port_free() {
    local port="$1"
    if command -v ss &>/dev/null; then
        ss -tlnp 2>/dev/null | grep -q ":${port} " && return 1
    elif command -v netstat &>/dev/null; then
        netstat -tlnp 2>/dev/null | grep -q ":${port} " && return 1
    fi
    return 0
}

# Проверяет UFW и открывает порты если он активен
_vgw_ensure_ufw_ports() {
    local http_port="${1:-80}" https_port="${2:-443}"
    if ! command -v ufw &>/dev/null; then return 0; fi
    if ! ufw status 2>/dev/null | grep -q "active"; then return 0; fi

    info "UFW активен. Проверяю открытие портов для VPN Gateway..."

    # Открываем HTTP-порт
    if ! ufw status | grep -q "^${http_port}/tcp.*ALLOW"; then
        run_cmd ufw allow "${http_port}/tcp" comment 'VPN Gateway HTTP' 2>/dev/null || true
        ok "UFW: открыт порт ${http_port}/tcp (HTTP)"
    else
        ok "UFW: порт ${http_port}/tcp уже открыт"
    fi

    # Открываем HTTPS-порт
    if ! ufw status | grep -q "^${https_port}/tcp.*ALLOW"; then
        run_cmd ufw allow "${https_port}/tcp" comment 'VPN Gateway HTTPS' 2>/dev/null || true
        ok "UFW: открыт порт ${https_port}/tcp (HTTPS)"
    else
        ok "UFW: порт ${https_port}/tcp уже открыт"
    fi

    # Проверяем Docker-сети — критично для работы контейнеров
    if command -v docker &>/dev/null && ! ufw status | grep -q '172.16.0.0/12'; then
        warn "Обнаружен Docker. Добавляю разрешение для Docker-сетей (иначе контейнеры будут заблокированы UFW)..."
        run_cmd ufw allow from 172.16.0.0/12 comment 'Docker networks' 2>/dev/null || true
        run_cmd ufw allow from 192.168.0.0/16 comment 'Docker bridge' 2>/dev/null || true
        ok "UFW: Docker-сети разрешены."
    fi

    run_cmd ufw reload 2>/dev/null || true
}

# Автоматически меняет порты в gateway.yml на свободные
_vgw_auto_fix_ports() {
    local cfg_file="$(_vgw_cfg_file)"
    local py_bin; py_bin="$(_vgw_python)"
    local new_http="${1:-8080}" new_https="${2:-8443}"

    CFG_FILE="$cfg_file" NEW_HTTP="$new_http" NEW_HTTPS="$new_https" "$py_bin" - <<'PY'
import os
from pathlib import Path
import yaml
p = Path(os.environ['CFG_FILE'])
data = yaml.safe_load(p.read_text(encoding='utf-8')) or {}
if not isinstance(data, dict): data = {}
edge = data.get('edge') if isinstance(data.get('edge'), dict) else {}
edge['http_port'] = int(os.environ['NEW_HTTP'])
edge['https_port'] = int(os.environ['NEW_HTTPS'])
data['edge'] = edge
p.write_text(yaml.safe_dump(data, allow_unicode=True, sort_keys=False), encoding='utf-8')
print('ok')
PY
    # Синхронизируем персистентный файл
    _vgw_cfg_save_persistent
}

# Сканирует nginx на хосте и в docker, возвращает тип: "host", "docker" или ""
_vgw_detect_nginx() {
    # Проверяем хостовый nginx
    if command -v nginx &>/dev/null && nginx -v &>/dev/null 2>&1; then
        echo "host"
        return
    fi
    # Проверяем Docker-контейнеры с nginx в имени/образе
    if command -v docker &>/dev/null; then
        local nginx_containers
        nginx_containers=$(docker ps --format '{{.Names}}\t{{.Image}}' 2>/dev/null | grep -i nginx | grep -v vpn-edge-nginx | head -1)
        if [[ -n "$nginx_containers" ]]; then
            echo "docker:$(echo "$nginx_containers" | awk '{print $1}')"
            return
        fi
    fi
    echo ""
}

# Находит конфиг-директорию хостового nginx
_vgw_find_nginx_conf_dir() {
    for d in /etc/nginx/sites-enabled /etc/nginx/conf.d /etc/nginx/vhosts.d; do
        [[ -d "$d" ]] && echo "$d" && return
    done
    echo "/etc/nginx/conf.d"
}

# Генерирует и показывает готовый nginx proxy_pass конфиг
_vgw_nginx_scan_and_show_config() {
    local http_port="$1" https_port="$2"
    local cfg_file="$(_vgw_cfg_file)"
    local py_bin; py_bin="$(_vgw_python)"

    local public_domain origin_domain
    public_domain=$(CFG_FILE="$cfg_file" "$py_bin" -c "
import os,yaml
from pathlib import Path
c=yaml.safe_load(Path(os.environ['CFG_FILE']).read_text('utf-8')) or {}
print(c.get('quick_setup',{}).get('public_domain','vpn.example.com'))" 2>/dev/null || echo "vpn.example.com")
    origin_domain=$(CFG_FILE="$cfg_file" "$py_bin" -c "
import os,yaml
from pathlib import Path
c=yaml.safe_load(Path(os.environ['CFG_FILE']).read_text('utf-8')) or {}
print(c.get('quick_setup',{}).get('origin_domain','cabinet.example.com'))" 2>/dev/null || echo "cabinet.example.com")

    local nginx_type; nginx_type=$("$(_vgw_detect_nginx)" 2>/dev/null; _vgw_detect_nginx)
    local conf_dir; conf_dir=$(_vgw_find_nginx_conf_dir)
    local conf_file="${conf_dir}/${public_domain}.conf"

    # Определяем сертификаты
    local ssl_block
    local cert_path="/etc/letsencrypt/live/${public_domain}"
    if [[ -f "${cert_path}/fullchain.pem" ]]; then
        ssl_block="    ssl_certificate     ${cert_path}/fullchain.pem;
    ssl_certificate_key ${cert_path}/privkey.pem;"
    else
        ssl_block="    # ⚠️ Сертификат Let's Encrypt не найден по стандартному пути!
    # Подставлен временный сертификат, чтобы Nginx смог запуститься.
    # Обязательно получите реальный сертификат с помощью certbot!
    ssl_certificate     /etc/ssl/certs/ssl-cert-snakeoil.pem;
    ssl_certificate_key /etc/ssl/private/ssl-cert-snakeoil.key;"
    fi

    local nginx_conf
    nginx_conf=$(cat <<NGINXCONF
# ================================================================
# VPN Gateway: proxy_pass конфиг для ${public_domain}
# Домен лендинга:  ${public_domain}
# Домен кабинета:  ${origin_domain}
# Gateway слушает: HTTP=${http_port}, HTTPS=${https_port}
# Сгенерировано:   $(date '+%Y-%m-%d %H:%M:%S')
# ================================================================

server {
    listen 80;
    listen [::]:80;
    server_name ${public_domain};

    # ACME challenge для Let's Encrypt
    location ^~ /.well-known/acme-challenge/ {
        root /var/www/acme-challenge;
        try_files \$uri =404;
    }

    location / {
        return 301 https://\$host\$request_uri;
    }
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name ${public_domain};

${ssl_block}
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    # Проксируем весь трафик в VPN Gateway контейнер
    location / {
        proxy_pass https://127.0.0.1:${https_port};
        proxy_http_version 1.1;
        proxy_ssl_verify off;  # gateway использует self-signed cert внутри

        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";

        proxy_connect_timeout 5s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
}
NGINXCONF
)

    echo ""
    echo -e "  ${C_CYAN}╔══════════════════════════════════════════════════════════╗${C_RESET}"
    echo -e "  ${C_CYAN}║${C_RESET}  ${C_GREEN}✅ Порты изменены автоматически${C_RESET}"
    echo -e "  ${C_CYAN}║${C_RESET}  Gateway теперь: HTTP=${C_YELLOW}${http_port}${C_RESET}, HTTPS=${C_YELLOW}${https_port}${C_RESET}"
    echo -e "  ${C_CYAN}╠══════════════════════════════════════════════════════════╣${C_RESET}"
    echo -e "  ${C_CYAN}║${C_RESET}  ${C_YELLOW}📋 Готовый nginx конфиг для вашего домена:${C_RESET}"
    echo -e "  ${C_CYAN}╚══════════════════════════════════════════════════════════╝${C_RESET}"
    echo ""
    echo "$nginx_conf"
    echo ""
    echo -e "  ${C_CYAN}══════════════════════════════════════════════════════════${C_RESET}"
    echo -e "  ${C_YELLOW}📁 Куда вставить:${C_RESET}  ${C_GREEN}${conf_file}${C_RESET}"
    echo ""
    local reload_cmd="nginx -t && systemctl reload nginx"
    if [[ "$nginx_type" == docker:* ]]; then
        local d_name="${nginx_type#docker:}"
        reload_cmd="docker exec ${d_name} nginx -t && docker exec ${d_name} nginx -s reload"
    fi

    echo -e "  ${C_WHITE}Команды для применения:${C_RESET}"
    echo -e "  ${C_CYAN}  nano ${conf_file}${C_RESET} ${C_GRAY}# Вставьте туда этот конфиг${C_RESET}"
    if [[ ! -f "${cert_path}/fullchain.pem" ]]; then
        echo -e "  ${C_YELLOW}  certbot --nginx -d ${public_domain}${C_RESET} ${C_GRAY}# Обязательно получите SSL сертификат!${C_RESET}"
    fi
    echo -e "  ${C_CYAN}  ${reload_cmd}${C_RESET}"
    echo -e "  ${C_CYAN}══════════════════════════════════════════════════════════${C_RESET}"
    echo ""
}

# Проверяет доступность лендинга через curl после применения nginx-конфига
_vgw_post_nginx_check() {
    local public_domain="$1"
    info "Проверяю доступность ${public_domain} через curl..."

    local ok=0
    for attempt in 1 2 3; do
        local code
        code=$(curl -sk -o /dev/null -w '%{http_code}' \
            -H "Host: ${public_domain}" \
            "https://127.0.0.1/" --max-time 5 2>/dev/null || echo "000")
        if [[ "$code" =~ ^(200|301|302|304)$ ]]; then
            ok=1
            break
        fi
        sleep 2
    done

    if [[ "$ok" -eq 1 ]]; then
        ok "Лендинг доступен через nginx! (HTTP ${code})"
        return 0
    else
        warn "Лендинг пока недоступен (код: ${code:-000}). Проверьте что:"
        warn "  1) Nginx конфиг вставлен и применён (nginx -t && reload)"
        warn "  2) Контейнер gateway запущен: docker ps"
        warn "  Если всё верно — возможно порты/сертификаты ещё не готовы."
        return 1
    fi
}

# Проверяет порты перед установкой и АВТОМАТИЧЕСКИ исправляет конфликты
_vgw_preflight_check() {
    local cfg_file="$(_vgw_cfg_file)"
    local py_bin; py_bin="$(_vgw_python)"
    local http_port https_port
    if [[ -f "$cfg_file" ]]; then
        http_port=$(CFG_FILE="$cfg_file" "$py_bin" -c "
import os,yaml
from pathlib import Path
c=yaml.safe_load(Path(os.environ['CFG_FILE']).read_text('utf-8')) or {}
print(c.get('edge',{}).get('http_port',80))" 2>/dev/null || echo "80")
        https_port=$(CFG_FILE="$cfg_file" "$py_bin" -c "
import os,yaml
from pathlib import Path
c=yaml.safe_load(Path(os.environ['CFG_FILE']).read_text('utf-8')) or {}
print(c.get('edge',{}).get('https_port',443))" 2>/dev/null || echo "443")
    else
        http_port=80; https_port=443
    fi

    # ── Определяем: порт занят нашим собственным контейнером? ────────────
    # Если vpn-edge-nginx уже запущен и слушает эти порты — это НЕ конфликт,
    # это наш стек. Пересоздание docker compose его освободит перед запуском.
    local our_container_owns_ports=0
    if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "vpn-edge-nginx"; then
        our_container_owns_ports=1
    fi

    local http_conflict=0 https_conflict=0
    if [[ "$our_container_owns_ports" -eq 0 ]]; then
        ! _vgw_check_port_free "$http_port"  && http_conflict=1
        ! _vgw_check_port_free "$https_port" && https_conflict=1
    fi

    if [[ "$http_conflict" -eq 1 || "$https_conflict" -eq 1 ]]; then
        # ── Проверяем: введены ли реальные домены? ────────────────────────
        local current_domain
        current_domain=$(_vgw_read_quick_field public_domain 2>/dev/null || echo "")
        local domains_configured=0
        if [[ -n "$current_domain" && "$current_domain" != "vpn.example.com" && "$current_domain" != "cabinet.example.com" ]]; then
            domains_configured=1
        fi

        echo ""
        echo -e "  ${C_CYAN}╔══════════════════════════════════════════════════════════╗${C_RESET}"
        echo -e "  ${C_CYAN}║${C_RESET}  ${C_YELLOW}⚠️  КОНФЛИКТ ПОРТОВ — исправляю автоматически...${C_RESET}"
        echo -e "  ${C_CYAN}╚══════════════════════════════════════════════════════════╝${C_RESET}"
        echo ""

        # Ищем свободные порты
        local new_http=8080 new_https=8443
        while ! _vgw_check_port_free "$new_http";   do ((new_http++));  done
        while ! _vgw_check_port_free "$new_https"; do ((new_https++)); done

        # Автоматически меняем в gateway.yml
        _vgw_auto_fix_ports "$new_http" "$new_https"
        ok "Порты в config/gateway.yml изменены: HTTP=${new_http}, HTTPS=${new_https}"

        if [[ "$domains_configured" -eq 0 ]]; then
            # Домены не введены — конфиг nginx будет показан ПОСЛЕ мастера
            echo ""
            echo -e "  ${C_YELLOW}╔══════════════════════════════════════════════════════════════${C_RESET}"
            echo -e "  ${C_YELLOW}║${C_RESET}  ${C_BOLD}⚠️  Nginx-конфиг будет сгенерирован ПОСЛЕ ввода доменов${C_RESET}"
            echo -e "  ${C_YELLOW}╠══════════════════════════════════════════════════════════════${C_RESET}"
            echo -e "  ${C_YELLOW}║${C_RESET}"
            echo -e "  ${C_YELLOW}║${C_RESET}  Порты заняты, поэтому Gateway будет работать на:"
            echo -e "  ${C_YELLOW}║${C_RESET}  ${C_GREEN}HTTP=${new_http}  HTTPS=${new_https}${C_RESET}"
            echo -e "  ${C_YELLOW}║${C_RESET}"
            echo -e "  ${C_YELLOW}║${C_RESET}  После того как укажешь домены — мастер покажет"
            echo -e "  ${C_YELLOW}║${C_RESET}  готовый nginx-конфиг с твоими реальными данными."
            echo -e "  ${C_YELLOW}║${C_RESET}"
            echo -e "  ${C_YELLOW}╚══════════════════════════════════════════════════════════════${C_RESET}"
            echo ""
        else
            # Домены уже есть — показываем готовый конфиг сразу
            _vgw_nginx_scan_and_show_config "$new_http" "$new_https"
            echo -e "  ${C_YELLOW}👆 Скопируй конфиг выше в нужный файл, примени nginx и нажми Enter.${C_RESET}"
            wait_for_enter
            local public_domain
            public_domain=$(CFG_FILE="$cfg_file" "$py_bin" -c "
import os,yaml
from pathlib import Path
c=yaml.safe_load(Path(os.environ['CFG_FILE']).read_text('utf-8')) or {}
print(c.get('quick_setup',{}).get('public_domain','localhost'))" 2>/dev/null || echo "localhost")
            _vgw_post_nginx_check "$public_domain" || true
        fi

        http_port="$new_http"
        https_port="$new_https"
    fi
    return 0
}


vgw_install_wizard(){
    _vgw_preflight_check || return 1

    # ── Проверяем: не запущен ли стек уже? ───────────────────────
    local W="$C_YELLOW" G="$C_GREEN" R="$C_RED" B="$C_BOLD" E="$C_RESET"
    if docker ps --format '{{.Names}}' 2>/dev/null | grep -qE '^(vpn-gateway|vpn-edge-nginx)$'; then
        echo ""
        echo -e "  ${W}${B}╔══════════════════════════════════════════════════════════════╗${E}"
        echo -e "  ${W}${B}║${E}  ⚡  ${B}Лендинг уже запущен!${E}                                   ${W}${B}║${E}"
        echo -e "  ${W}${B}╠══════════════════════════════════════════════════════════════╣${E}"
        echo -e "  ${W}${B}║${E}                                                              ${W}${B}║${E}"
        echo -e "  ${W}${B}║${E}  Контейнеры ${G}${B}vpn-gateway${E} и ${G}${B}vpn-edge-nginx${E} уже работают.   ${W}${B}║${E}"
        echo -e "  ${W}${B}║${E}  Первичная установка на существующий стек не нужна.         ${W}${B}║${E}"
        echo -e "  ${W}${B}║${E}                                                              ${W}${B}║${E}"
        echo -e "  ${W}${B}║${E}  ${W}${B}Что сделать вместо этого:${E}                                 ${W}${B}║${E}"
        echo -e "  ${W}${B}║${E}                                                              ${W}${B}║${E}"
        echo -e "  ${W}${B}║${E}  ${G}${B}[2]${E} Мастер изменить параметры — сменить домен/оффер        ${W}${B}║${E}"
        echo -e "  ${W}${B}║${E}       и перезапустить стек без пересоздания                 ${W}${B}║${E}"
        echo -e "  ${W}${B}║${E}                                                              ${W}${B}║${E}"
        echo -e "  ${W}${B}║${E}  ${G}${B}[3]${E} Перезапуск стека — если что-то не работает             ${W}${B}║${E}"
        echo -e "  ${W}${B}║${E}                                                              ${W}${B}║${E}"
        echo -e "  ${W}${B}║${E}  ${R}${B}[d]${E} Удаление — если хочешь начать с чистого листа          ${W}${B}║${E}"
        echo -e "  ${W}${B}║${E}       (затем запусти [1] снова)                             ${W}${B}║${E}"
        echo -e "  ${W}${B}║${E}                                                              ${W}${B}║${E}"
        echo -e "  ${W}${B}╚══════════════════════════════════════════════════════════════╝${E}"
        echo ""
        if ! ask_yes_no "Всё равно запустить первичную установку поверх? (y/n)" "n"; then
            return 0
        fi
        echo ""
    fi

    _vgw_prompt_and_apply_common install
    # После установки — открываем UFW порты если нужно
    local cfg_file="$(_vgw_cfg_file)"
    local py_bin; py_bin="$(_vgw_python)"
    local http_port https_port
    http_port=$(CFG_FILE="$cfg_file" "$py_bin" -c "import os,yaml; from pathlib import Path; c=yaml.safe_load(Path(os.environ['CFG_FILE']).read_text('utf-8')) or {}; print(c.get('edge',{}).get('http_port',80))" 2>/dev/null || echo "80")
    https_port=$(CFG_FILE="$cfg_file" "$py_bin" -c "import os,yaml; from pathlib import Path; c=yaml.safe_load(Path(os.environ['CFG_FILE']).read_text('utf-8')) or {}; print(c.get('edge',{}).get('https_port',443))" 2>/dev/null || echo "443")
    _vgw_ensure_ufw_ports "$http_port" "$https_port"
    # Показываем статус лендинга и уведомление о мерчанте
    _vgw_show_landing_status
    _vgw_warn_merchant_return
}
vgw_reconfigure_wizard(){
    _vgw_preflight_check || return 1
    _vgw_prompt_and_apply_common reconfigure
}
vgw_run(){ _vgw_run_action run; }
vgw_test(){ _vgw_run_action test; }
vgw_status(){ _vgw_run_action status; }
vgw_uninstall_dry(){ _vgw_run_action uninstall-dry; }

vgw_status_diagnostics() {
    _vgw_run_action status || true
    local project_dir="$(_vgw_project_dir)"
    # Поддерживаем и старый docker-compose, и новый docker compose (плагин)
    local dc_cmd
    if docker compose version &>/dev/null 2>&1; then
        dc_cmd="docker compose"
    elif command -v docker-compose &>/dev/null; then
        dc_cmd="docker-compose"
    else
        printf_error "Не найден ни 'docker compose', ни 'docker-compose'."
        return 1
    fi
    ( cd "$project_dir"; $dc_cmd -f docker-compose.yml -f docker-compose.edge.yml logs --tail=120 edge-nginx || true; echo ""; $dc_cmd -f docker-compose.yml -f docker-compose.edge.yml logs --tail=120 vpn-gateway || true )
}

vgw_certs_full(){ _vgw_run_action certs-ensure || return 1; _vgw_run_action certs-renew || return 1; _vgw_run_action certs-cron; }

vgw_uninstall_execute_confirmed(){ printf_critical_warning "ОПАСНО"; if ask_yes_no "Подтверждаешь удаление контейнеров gateway? (y/n)" "n"; then _vgw_run_action uninstall --non-interactive --yes; fi; }
vgw_uninstall_purge_confirmed(){ printf_critical_warning "ОЧЕНЬ ОПАСНО"; if ask_yes_no "Подтверждаешь PURGE gateway-данных? (y/n)" "n"; then _vgw_run_action uninstall-purge --non-interactive --yes-purge; fi; }

_vgw_read_hide_payment_return() {
    local cfg_file="$(_vgw_cfg_file)"; [[ -f "$cfg_file" ]] || { echo unknown; return 0; }
    local py_bin; py_bin="$(_vgw_python)"
    CFG_FILE="$cfg_file" "$py_bin" - <<'PY2'
import os
from pathlib import Path
import yaml
sec=(yaml.safe_load(Path(os.environ['CFG_FILE']).read_text(encoding='utf-8')) or {}).get('security') or {}
v=sec.get('hide_payment_return', None)
print('true' if v is True else 'false' if v is False else 'unknown')
PY2
}

_vgw_set_hide_payment_return() {
    local target="$1" cfg_file="$(_vgw_cfg_file)"
    local py_bin; py_bin="$(_vgw_python)"
    CFG_FILE="$cfg_file" TARGET_VALUE="$target" "$py_bin" - <<'PY2'
import os
from pathlib import Path
import yaml
p=Path(os.environ['CFG_FILE']); data=yaml.safe_load(p.read_text(encoding='utf-8')) or {}
if not isinstance(data, dict): data={}
sec=data.get('security') if isinstance(data.get('security'), dict) else {}
sec['hide_payment_return'] = os.environ['TARGET_VALUE'].strip().lower() == 'true'
data['security']=sec
p.write_text(yaml.safe_dump(data, allow_unicode=True, sort_keys=False), encoding='utf-8')
PY2
    # Синхронизируем персистентный файл
    _vgw_cfg_save_persistent
}

vgw_toggle_hide_payment_return() {
    local state="$(_vgw_read_hide_payment_return)"
    if [[ "$state" == "true" ]]; then
        if ask_yes_no "Сейчас true. Выключить? (y/n)" "n"; then _vgw_set_hide_payment_return false && printf_ok "hide_payment_return=false"; fi
    else
        if ask_yes_no "Сейчас false/unknown. Включить? (y/n)" "y"; then _vgw_set_hide_payment_return true && printf_ok "hide_payment_return=true"; fi
    fi
}

# ── Статус работающего лендинга ────────────────────────────────
_vgw_show_landing_status() {
    local cfg_file="$(_vgw_cfg_file)"
    local py_bin; py_bin="$(_vgw_python)"

    local public_domain acme_enabled hide_return
    public_domain=$(_vgw_read_quick_field public_domain)
    acme_enabled=$(_vgw_read_quick_field acme_enabled)
    hide_return=$(_vgw_read_hide_payment_return)

    [[ -z "$public_domain" || "$public_domain" == "vpn.example.com" ]] && return 0

    # Проверяем что контейнер vpn-gateway запущен
    local gw_status="❌ не запущен"
    local gw_color="$C_RED"
    if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "vpn-gateway"; then
        gw_status="✅ запущен"
        gw_color="$C_GREEN"
    fi

    # HTTP-проверка доступности лендинга
    local http_ok="❌ недоступен"
    local http_color="$C_RED"
    if command -v curl > /dev/null 2>&1; then
        local http_code
        http_code=$(curl -o /dev/null -sS -w "%{http_code}" --max-time 4 \
            "https://${public_domain}/" 2>/dev/null || echo "000")
        if [[ "$http_code" =~ ^(200|301|302|307|308)$ ]]; then
            http_ok="✅ отвечает (HTTP ${http_code})"
            http_color="$C_GREEN"
        elif [[ "$http_code" != "000" ]]; then
            http_ok="⚠️  HTTP ${http_code}"
            http_color="$C_YELLOW"
        fi
    fi

    local hide_icon="❌ выкл"
    local hide_color="$C_RED"
    [[ "$hide_return" == "true" ]] && { hide_icon="✅ вкл"; hide_color="$C_GREEN"; }

    local proto="https"
    [[ "$acme_enabled" == "false" ]] && proto="https (self-signed)"

    echo ""
    echo -e "  ${C_CYAN}╔══════════════════════════════════════════════════════════════╗${C_RESET}"
    echo -e "  ${C_CYAN}║${C_RESET}  🌐  ${C_BOLD}Статус лендинга${C_RESET}                                         ${C_CYAN}║${C_RESET}"
    echo -e "  ${C_CYAN}╠══════════════════════════════════════════════════════════════╣${C_RESET}"
    printf  "  ${C_CYAN}║${C_RESET}  %-14s ${C_BOLD}%s${C_RESET}%*s${C_CYAN}║${C_RESET}\n" \
        "Домен:" "${proto}://${public_domain}" \
        $((30 - ${#public_domain} - ${#proto})) ""
    printf  "  ${C_CYAN}║${C_RESET}  %-14s ${gw_color}%s${C_RESET}%*s${C_CYAN}║${C_RESET}\n" \
        "Контейнер:" "$gw_status" \
        $((46 - ${#gw_status})) ""
    printf  "  ${C_CYAN}║${C_RESET}  %-14s ${http_color}%s${C_RESET}%*s${C_CYAN}║${C_RESET}\n" \
        "Доступность:" "$http_ok" \
        $((46 - ${#http_ok})) ""
    printf  "  ${C_CYAN}║${C_RESET}  %-14s ${hide_color}%s${C_RESET}%*s${C_CYAN}║${C_RESET}\n" \
        "Hide return:" "$hide_icon" \
        $((46 - ${#hide_icon})) ""
    echo -e "  ${C_CYAN}╚══════════════════════════════════════════════════════════════╝${C_RESET}"
    echo ""
}

# ── Уведомление о return URL в мерчанте ────────────────────────
_vgw_warn_merchant_return() {
    local public_domain origin_domain hide_return
    public_domain=$(_vgw_read_quick_field public_domain)
    origin_domain=$(_vgw_read_quick_field origin_domain)
    hide_return=$(_vgw_read_hide_payment_return)

    [[ -z "$public_domain" || "$public_domain" == "vpn.example.com" ]] && return 0

    local W="$C_YELLOW" R="$C_RED" C="$C_CYAN" G="$C_GREEN" B="$C_BOLD" E="$C_RESET"

    echo ""
    echo -e "  ${R}${B}╔══════════════════════════════════════════════════════════════${E}"
    echo -e "  ${R}${B}║${E}  ${W}${B}⚠️  ОБЯЗАТЕЛЬНОЕ ДЕЙСТВИЕ: настройка платёжной системы${E}"
    echo -e "  ${R}${B}╠══════════════════════════════════════════════════════════════${E}"
    echo -e "  ${R}${B}║${E}"
    echo -e "  ${R}${B}║${E}  Домен кабинета попадает в поле ${W}${B}return${E} платёжной системы"
    echo -e "  ${R}${B}║${E}  напрямую из браузера. Gateway ${R}${B}не может${E} перехватить это."
    echo -e "  ${R}${B}║${E}"
    echo -e "  ${R}${B}║${E}  ${W}${B}Что изменить в настройках вашей платёжной системы:${E}"
    echo -e "  ${R}${B}║${E}"
    echo -e "  ${R}${B}║${E}  ${R}Было:${E}   https://${origin_domain}"
    echo -e "  ${R}${B}║${E}  ${G}Нужно:${E}  https://${public_domain}"
    echo -e "  ${R}${B}║${E}"
    echo -e "  ${R}${B}║${E}  ${W}${B}Замените Return / Webhook URL на:${E}"
    echo -e "  ${R}${B}║${E}  ${G}${B}  https://${public_domain}/ПЛАТЕЖКА-webhook${E}"
    echo -e "  ${R}${B}║${E}"
    echo -e "  ${R}${B}╠══════════════════════════════════════════════════════════════${E}"
    echo -e "  ${R}${B}║${E}  ${W}${B}🔒  Уровень угрозы для цензора:${E}"
    echo -e "  ${R}${B}║${E}"
    echo -e "  ${R}${B}║${E}  ${G}•${E} Без замены: цензор может получить origin при оплате."
    echo -e "  ${R}${B}║${E}  ${G}•${E} Уровень: ${W}${B}СРЕДНИЙ${E} — виден только тому, кто платит."
    echo -e "  ${R}${B}║${E}  ${G}•${E} Пассивный цензор (DPI) его ${G}${B}не видит${E} — он в JSON API."
    echo -e "  ${R}${B}║${E}  ${G}•${E} После замены в настройках: ${G}${B}утечка закрыта полностью${E}."
    echo -e "  ${R}${B}║${E}"
    echo -e "  ${R}${B}╚══════════════════════════════════════════════════════════════${E}"
    echo ""
}


