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
    # Автовосстановление конфига и сертификатов перед любой валидацией/действием
    _vgw_cfg_restore_if_needed
    _vgw_certs_restore_if_needed

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

    # Контейнер мог стартовать ДО восстановления (volume был пустым) — перезапускаем nginx
    if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "vpn-edge-nginx"; then
        ok "Перезапускаю nginx в контейнере чтобы подхватил сертификаты..."
        docker exec vpn-edge-nginx nginx -s reload 2>/dev/null || \
            docker restart vpn-edge-nginx 2>/dev/null || true
    fi
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
        # -k: принимаем self-signed (иначе curl вернёт 000 при ошибке TLS)
        # 2>/dev/null: stderr не должен попасть в %{http_code}
        http_code=$(curl -o /dev/null -sk -w "%{http_code}" --max-time 4 \
            "https://${public_domain}/" 2>/dev/null)
        http_code="${http_code:-000}"
        if [[ "$http_code" =~ ^(200|301|302|307|308)$ ]]; then
            http_ok="✅ отвечает (HTTP ${http_code})" http_color="$G"
        elif [[ "$http_code" == "000" ]]; then
            http_ok="❌ нет ответа (порт не слушает?)" http_color="$R"
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

# ══════════════════════════════════════════════════════════════════
# Умный детектор nginx-окружения (5 типов)
# Возвращает строку:
#   free                          — порты свободны
#   our_container                 — наш vpn-edge-nginx уже занимает порты
#   host:nginx                    — хостовый systemd nginx
#   docker:conf.d:NAME:PATH       — docker nginx с bind-mount conf.d (remnawave-panel)
#   docker:hostnet:NAME:CFGPATH   — docker nginx с network_mode:host (remnawave-node)
#   docker:nginx:NAME             — docker nginx прочий (порты 80:80)
#   unknown                       — занято чем-то неизвестным
# ══════════════════════════════════════════════════════════════════
_vgw_smart_nginx_detect() {
    local http_port="${1:-80}" https_port="${2:-443}"

    # Если мы сами (gateway) занимаем 80 и 443 — внешний nginx нам не нужен, инжект не нужен
    if [[ "$http_port" == "80" && "$https_port" == "443" ]]; then
        echo "free"; return 0
    fi

    # Ищем внешний Docker nginx
    if command -v docker &>/dev/null; then
        local cname cimage
        # ищем любой запущенный nginx-контейнер кроме нашего
        while IFS=$'\t' read -r cname cimage; do
            [[ "$cname" == "vpn-edge-nginx" ]] && continue
            [[ -z "$cname" ]] && continue

            # Тип 4: модульный conf.d (bind mount /etc/nginx/conf.d → хост-директория)
            local confd_host
            confd_host=$(docker inspect "$cname" 2>/dev/null \
                --format='{{range .Mounts}}{{if eq .Destination "/etc/nginx/conf.d"}}{{.Source}}{{end}}{{end}}' \
                | head -1)
            if [[ -n "$confd_host" && -d "$confd_host" ]]; then
                echo "docker:conf.d:${cname}:${confd_host}"; return 0
            fi

            # Тип 3: network_mode host (remnawave-node стиль)
            local netmode
            netmode=$(docker inspect "$cname" 2>/dev/null \
                --format='{{.HostConfig.NetworkMode}}' | head -1)
            if [[ "$netmode" == "host" ]]; then
                # пытаемся найти путь к nginx.conf через bind mounts
                local nginx_conf_host
                nginx_conf_host=$(docker inspect "$cname" 2>/dev/null \
                    --format='{{range .Mounts}}{{if eq .Destination "/etc/nginx/nginx.conf"}}{{.Source}}{{end}}{{end}}' \
                    | head -1)
                echo "docker:hostnet:${cname}:${nginx_conf_host:-/etc/nginx/nginx.conf}"
                return 0
            fi

            # Тип 5: прочий docker nginx
            echo "docker:nginx:${cname}"; return 0
        done < <(docker ps --format '{{.Names}}\t{{.Image}}' 2>/dev/null | grep -i nginx)
    fi

    # Хостовый nginx?
    if systemctl is-active --quiet nginx 2>/dev/null || \
       { command -v nginx &>/dev/null && nginx -v &>/dev/null 2>&1; }; then
        echo "host:nginx"; return 0
    fi

    echo "unknown"
}

# ══════════════════════════════════════════════════════════════════
# Поиск docker-compose.yml для конкретного контейнера.
# Стратегия:
#   1) com.docker.compose.project.working_dir label → ищем compose-файлы там
#   2) Перебираем стандартные пути /opt/<name>/ /opt/<name>-*/ и т.п.
#   3) Возвращаем ПЕРВЫЙ найденный docker-compose.yml (или docker-compose.yaml)
# ══════════════════════════════════════════════════════════════════
_vgw_find_compose_file() {
    local cname="$1"
    [[ -z "$cname" ]] && echo "" && return 1

    # 1. Из label com.docker.compose.project.working_dir
    local workdir
    workdir=$(docker inspect "$cname" 2>/dev/null \
        --format='{{index .Config.Labels "com.docker.compose.project.working_dir"}}' 2>/dev/null || echo "")
    if [[ -n "$workdir" && -d "$workdir" ]]; then
        for f in "${workdir}/docker-compose.yml" "${workdir}/docker-compose.yaml"\
                  "${workdir}/compose.yml" "${workdir}/compose.yaml"; do
            [[ -f "$f" ]] && echo "$f" && return 0
        done
    fi

    # 2. Из label com.docker.compose.project → ищем в /opt/<project>/
    local project_name
    project_name=$(docker inspect "$cname" 2>/dev/null \
        --format='{{index .Config.Labels "com.docker.compose.project"}}' 2>/dev/null || echo "")
    if [[ -n "$project_name" ]]; then
        for base in "/opt" "/srv" "/home" "/root"; do
            for f in "${base}/${project_name}/docker-compose.yml" \
                     "${base}/${project_name}/docker-compose.yaml" \
                     "${base}/${project_name}/compose.yml"; do
                [[ -f "$f" ]] && echo "$f" && return 0
            done
            # Fuzzy: /opt/<project>-*/ или /opt/*<project>*/
            for d in "${base}/${project_name}"*/ "${base}/"*"${project_name}"*/; do
                [[ -d "$d" ]] || continue
                for f in "${d}docker-compose.yml" "${d}docker-compose.yaml" "${d}compose.yml"; do
                    [[ -f "$f" ]] && echo "$f" && return 0
                done
            done
        done
    fi

    # 3. Из имени контейнера (убираем суффиксы -1 / -nginx и т.п.)
    local base_name; base_name=$(echo "$cname" | sed 's/-[0-9]*$//; s/-nginx$//; s/-admin$//')
    for base in "/opt" "/srv" "/root"; do
        for d in "${base}/${base_name}"*/ "${base}/"*"${base_name}"*/; do
            [[ -d "$d" ]] || continue
            for f in "${d}docker-compose.yml" "${d}docker-compose.yaml" "${d}compose.yml"; do
                [[ -f "$f" ]] && echo "$f" && return 0
            done
        done
    done

    echo ""
    return 1
}

# ══════════════════════════════════════════════════════════════════
# Безопасное добавление volume в docker-compose.yml через Python.
# Поддерживает:
#   - многосервисный compose (добавляет только в нужный сервис по имени контейнера)
#   - монолитный compose
# Возвращает 0 при успехе, 1 если volume уже есть или ошибка
# ══════════════════════════════════════════════════════════════════
_vgw_compose_add_volume() {
    local compose_file="$1"
    local cname="$2"        # имя контейнера для поиска нужного сервиса
    local host_path="$3"    # путь на хосте
    local container_path="$4" # путь внутри контейнера
    local mode="${5:-ro}"   # ro / rw

    [[ -f "$compose_file" ]] || return 1

    local py_bin; py_bin="$(_vgw_python)"

    COMPOSE_FILE="$compose_file" CNAME="$cname" HOST_PATH="$host_path" \
    CONTAINER_PATH="$container_path" VOLUME_MODE="$mode" \
    "$py_bin" - <<'PY'
import os, sys
from pathlib import Path
try:
    import yaml
except ImportError:
    sys.exit(2)

compose_path = Path(os.environ["COMPOSE_FILE"])
cname = os.environ["CNAME"]
host_path = os.environ["HOST_PATH"]
container_path = os.environ["CONTAINER_PATH"]
mode = os.environ.get("VOLUME_MODE", "ro")
new_volume = f"{host_path}:{container_path}:{mode}"

data = yaml.safe_load(compose_path.read_text(encoding="utf-8")) or {}
if not isinstance(data, dict):
    sys.exit(1)

services = data.get("services") or {}
if not isinstance(services, dict):
    sys.exit(1)

# Ищем нужный сервис по container_name или по имени сервиса похожему на контейнер
target_svc = None
for svc_name, svc in services.items():
    if not isinstance(svc, dict):
        continue
    if svc.get("container_name", "") == cname:
        target_svc = svc_name
        break

# Если не нашли по container_name — ищем по совпадению имени сервиса
if target_svc is None:
    for svc_name in services:
        if "nginx" in svc_name.lower() or cname.replace("-", "_") in svc_name.lower():
            target_svc = svc_name
            break

# Последний вариант — берём первый сервис с nginx-образом
if target_svc is None:
    for svc_name, svc in services.items():
        if isinstance(svc, dict):
            img = str(svc.get("image", "")).lower()
            if "nginx" in img:
                target_svc = svc_name
                break

if target_svc is None:
    print("SERVICE_NOT_FOUND")
    sys.exit(1)

svc = services[target_svc]
volumes = svc.get("volumes") or []
if not isinstance(volumes, list):
    volumes = []

def get_cont_path(val):
    if isinstance(val, dict): return val.get("target", "")
    parts = str(val).strip().split(":")
    if not parts: return ""
    if len(parts) == 1: return parts[0]
    last = parts[-1].strip()
    if last in ("ro", "rw", "z", "Z", "delegated", "cached", "consistent"):
        return parts[-2].strip() if len(parts) >= 2 else ""
    return last

# Проверяем: не добавлен ли уже этот volume?
for v in volumes:
    if get_cont_path(v) == container_path:
        print("ALREADY_EXISTS")
        sys.exit(0)

volumes.append(new_volume)
svc["volumes"] = volumes
services[target_svc] = svc
data["services"] = services

# Делаем backup
bak_path = compose_path.with_suffix(".yml.bak")
bak_path.write_text(compose_path.read_text(encoding="utf-8"), encoding="utf-8")

compose_path.write_text(
    yaml.safe_dump(data, allow_unicode=True, sort_keys=False, default_flow_style=False),
    encoding="utf-8"
)
print(f"ADDED:{target_svc}")
PY
}

# Определяет источник SSL-сертификатов для найденного nginx-контейнера
_vgw_detect_cert_source() {
    local container="${1:-}"
    # CertWarden?
    if [[ -n "$container" ]]; then
        local cw_host cw_dest
        cw_host=$(docker inspect "$container" 2>/dev/null \
            --format='{{range .Mounts}}{{.Source}}{{"\t"}}{{.Destination}}{{"\n"}}{{end}}' \
            | grep -i "certwardenclient\|certwarden" | head -1 | awk '{print $1}')
        cw_dest=$(docker inspect "$container" 2>/dev/null \
            --format='{{range .Mounts}}{{.Source}}{{"\t"}}{{.Destination}}{{"\n"}}{{end}}' \
            | grep -i "certwardenclient\|certwarden" | head -1 | awk '{print $2}')
        if [[ -n "$cw_host" && -n "$cw_dest" ]]; then
            echo "certwarden:${cw_host}:${cw_dest}"
            return 0
        fi

        # Let's Encrypt смонтирован?
        local le_host
        le_host=$(docker inspect "$container" 2>/dev/null \
            --format='{{range .Mounts}}{{if eq .Destination "/etc/letsencrypt"}}{{.Source}}{{end}}{{end}}' \
            | head -1)
        if [[ -n "$le_host" ]]; then
            echo "letsencrypt:${le_host}:/etc/letsencrypt"
            return 0
        fi
    fi
    # Let's Encrypt на хосте?
    if [[ -d /etc/letsencrypt/live ]]; then
        echo "letsencrypt:/etc/letsencrypt:/etc/letsencrypt"
        return 0
    fi
    # Наш рабочий каталог сертификатов (всегда отдаем его, так как авто-восстановление переносит бэкапы сюда)
    local live_certs_dir; live_certs_dir="$(_vgw_certs_dir)"
    if [[ -f "${live_certs_dir}/fullchain.pem" || -f /etc/reshala-bedolaga/certs/fullchain.pem ]]; then
        echo "reshala:${live_certs_dir}:/etc/nginx/certs"
        return 0
    fi
    echo "none"
}

# Находит конфиг-директорию хостового nginx (для sites-available → sites-enabled)
_vgw_find_nginx_conf_dir() {
    if [[ -d /etc/nginx/sites-available ]]; then echo "/etc/nginx/sites-available"; return; fi
    for d in /etc/nginx/conf.d /etc/nginx/vhosts.d; do
        [[ -d "$d" ]] && echo "$d" && return
    done
    echo "/etc/nginx/conf.d"
}

# Генерирует nginx server-block для proxy_pass на наш gateway
# Аргументы: public_domain gateway_port ssl_cert_path ssl_key_path [csrc]
# csrc используется для выбора правильных путей к сертификатам в конфиге
_vgw_nginx_generate_conf() {
    local domain="$1" gw_port="$2" cert="${3:-}" key="${4:-}" csrc="${5:-}" cname="${6:-}"
    
    # Определяем IP хоста для проксирования из контейнера
    local upstream_host="127.0.0.1"
    if [[ -n "$cname" ]] && command -v docker &>/dev/null; then
        local gw_ip
        gw_ip=$(docker inspect "$cname" --format '{{range .NetworkSettings.Networks}}{{.Gateway}}{{end}}' 2>/dev/null | head -n1)
        if [[ -n "$gw_ip" ]]; then
            upstream_host="$gw_ip"
        fi
    fi
    local ssl_block
    if [[ -n "$cert" ]]; then
        ssl_block="    ssl_certificate     ${cert};"$'\n'"    ssl_certificate_key ${key};"
    else
        ssl_block="    # ⚠️  Сертификат не найден. Установите certbot и выпустите сертификат!
    # certbot --nginx -d ${domain}
    # Временно используем snakeoil:
    ssl_certificate     /etc/ssl/certs/ssl-cert-snakeoil.pem;
    ssl_certificate_key /etc/ssl/private/ssl-cert-snakeoil.key;"
    fi
    cat <<NGINXCONF
# ================================================================
# BEDOLAGA LANDING GATEWAY — proxy_pass конфиг
# Домен:     ${domain}
# Gateway:   ${upstream_host}:${gw_port}
# Создан:    $(date '+%Y-%m-%d %H:%M:%S')
# ================================================================

server {
    listen 80;
    listen [::]:80;
    server_name ${domain};

    location ^~ /.well-known/acme-challenge/ {
        root /var/www/acme-challenge;
        try_files \$uri =404;
    }
    location / { return 301 https://\$host\$request_uri; }
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name ${domain};

${ssl_block}
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    location / {
        proxy_pass https://${upstream_host}:${gw_port};
        proxy_http_version 1.1;
        proxy_ssl_verify off;
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
}

# Сохраняет данные об инжектированном nginx-конфиге в /etc/reshala-bedolaga/
_vgw_nginx_injection_save() {
    local nginx_type="$1" conf_file="$2" domain="$3"
    mkdir -p "${_VGW_PERSIST_DIR}" 2>/dev/null || true
    cat > "${_VGW_PERSIST_DIR}/nginx_injection.env" <<EOF
NGINX_TYPE=${nginx_type}
CONF_FILE=${conf_file}
DOMAIN=${domain}
SAVED_AT=$(date '+%Y-%m-%d %H:%M:%S')
EOF
}

# Показывает план действий и спрашивает y/n
# Аргументы: nginx_type container confd_path cert_source domain gateway_port
_vgw_detect_show_plan() {
    local ntype="$1" cname="${2:-}" cpath="${3:-}" csrc="${4:-none}" domain="$5" gport="$6"
    local W="$C_YELLOW" C="$C_CYAN" G="$C_GREEN" R="$C_RED" B="$C_BOLD" E="$C_RESET"

    # Разрешаем реальные SSL-пути для корректного отображения и планирования
    local CERT KEY VOLUME_NEEDED VOLUME_HOST VOLUME_CONT CSRC_EFFECTIVE
    CERT="" KEY="" VOLUME_NEEDED="0" VOLUME_HOST="" VOLUME_CONT="" CSRC_EFFECTIVE=""
    if [[ -n "$cname" ]]; then
        _vgw_resolve_ssl_paths "$cname" "$csrc" "$domain" >/dev/null 2>&1
    else
        CSRC_EFFECTIVE=$(echo "$csrc" | cut -d: -f1)
        [[ -z "$CSRC_EFFECTIVE" ]] && CSRC_EFFECTIVE="none"
    fi

    echo ""
    echo -e "  ${C}╔══════════════════════════════════════════════════════════════╗${E}"
    echo -e "  ${C}║${E}  🔍  ${B}Обнаружено окружение${E}                                    ${C}║${E}"
    echo -e "  ${C}╠══════════════════════════════════════════════════════════════╣${E}"

    case "$ntype" in
        free)
            echo -e "  ${C}║${E}  Тип:        ${G}Порты свободны — прямой запуск${E}"
            echo -e "  ${C}║${E}  Стратегия:  edge-nginx возьмёт 80/443 напрямую"
            ;;
        host:nginx)
            echo -e "  ${C}║${E}  Тип:        ${W}Хостовый nginx (systemd)${E}"
            local cdir; cdir=$(_vgw_find_nginx_conf_dir)
            echo -e "  ${C}║${E}  conf-dir:   ${G}${cdir}${E}"
            echo -e "  ${C}║${E}  Gateway:    порт ${G}${gport}${E} (не 443)"
            ;;
        docker:conf.d:*)
            echo -e "  ${C}║${E}  Тип:        ${W}Docker nginx с модульным conf.d${E}"
            echo -e "  ${C}║${E}  Контейнер:  ${G}${cname}${E}"
            echo -e "  ${C}║${E}  conf.d:     ${G}${cpath}${E}"
            echo -e "  ${C}║${E}  Gateway:    порт ${G}${gport}${E}"
            ;;
        docker:hostnet:*)
            echo -e "  ${C}║${E}  Тип:        ${R}Docker nginx (network_mode:host, unix-сокеты)${E}"
            echo -e "  ${C}║${E}  Контейнер:  ${G}${cname}${E}"
            echo -e "  ${C}║${E}  ${W}Авто-инжект невозможен — потребуется ручная правка${E}"
            ;;
        docker:nginx:*)
            echo -e "  ${C}║${E}  Тип:        ${W}Docker nginx (прочий)${E}"
            echo -e "  ${C}║${E}  Контейнер:  ${G}${cname}${E}"
            ;;
        *)
            echo -e "  ${C}║${E}  Тип:        ${R}Неизвестный сервис занимает порты${E}"
            ;;
    esac

    if [[ "$csrc" == "certwarden"* && "$CSRC_EFFECTIVE" == "reshala" ]]; then
        echo -e "  ${C}║${E}  SSL:        ${G}certwarden -> Let's Encrypt (reshala)${E} ${W}(не совпадает домен!)${E}"
    else
        echo -e "  ${C}║${E}  SSL:        ${G}${CSRC_EFFECTIVE}${E}"
    fi

    echo -e "  ${C}╠══════════════════════════════════════════════════════════════╣${E}"
    echo -e "  ${C}║${E}  📋  ${B}План действий:${E}"

    case "$ntype" in
        free)
            echo -e "  ${C}║${E}  1. Запустить edge-nginx контейнер на 80/443"
            echo -e "  ${C}║${E}  2. Выпустить Let's Encrypt для ${G}${domain}${E}"
            ;;
        host:nginx)
            local cdir; cdir=$(_vgw_find_nginx_conf_dir)
            echo -e "  ${C}║${E}  1. Создать ${G}${cdir}/${domain}.conf${E}"
            echo -e "  ${C}║${E}  2. nginx -t && systemctl reload nginx"
            echo -e "  ${C}║${E}  3. Gateway запустится на порту ${G}${gport}${E}"
            ;;
        docker:conf.d:*)
            if [[ "$VOLUME_NEEDED" == "0" && ( "$CSRC_EFFECTIVE" == "certwarden" || "$CSRC_EFFECTIVE" == "letsencrypt" ) ]]; then
                echo -e "  ${C}║${E}  1. ${G}Сертификаты уже смонтированы (${CSRC_EFFECTIVE})${E}"
                echo -e "  ${C}║${E}  2. Создать ${G}${cpath}/80-bedolaga.conf${E}"
                echo -e "  ${C}║${E}  3. docker exec ${cname} nginx -t && nginx -s reload"
            else
                echo -e "  ${C}║${E}  1. Найти docker-compose.yml контейнера ${G}${cname}${E}"
                echo -e "  ${C}║${E}  2. ${G}Автоматически добавить volume сертификатов${E}"
                echo -e "     ${G}${VOLUME_HOST:-$(_vgw_certs_dir)}:${VOLUME_CONT:-/etc/nginx/certs}:ro${E}"
                echo -e "  ${C}║${E}  3. Перезапустить контейнер ${G}${cname}${E}"
                echo -e "  ${C}║${E}  4. Создать ${G}${cpath}/80-bedolaga.conf${E}"
                echo -e "  ${C}║${E}  5. docker exec ${cname} nginx -t && nginx -s reload"
            fi
            echo -e "  ${C}║${E}  Gateway на порту ${G}${gport}${E}"
            ;;
        *)
            echo -e "  ${C}║${E}  Требуется ручная настройка."
            echo -e "  ${C}║${E}  Будет показана подробная инструкция."
            ;;
    esac

    echo -e "  ${C}╚══════════════════════════════════════════════════════════════╝${E}"
    echo ""
    ask_yes_no "Выполнить автоматически? (y/n)" "y"
}

# ══════════════════════════════════════════════════════════════════
# Разрешает реальные пути к SSL-сертификатам внутри контейнера
# с учётом csrc (certwarden / letsencrypt / reshala / none)
# и public_domain (домен лендинга).
#
# Аргументы:
#   $1 cname         — имя nginx-контейнера
#   $2 csrc          — строка certwarden:HOST:CONTAINER_PATH / ...
#   $3 public_domain — домен лендинга (lendinghello.mooo.com)
#
# Устанавливает переменные:
#   CERT, KEY            — пути к сертификату внутри nginx (или на хосте)
#   VOLUME_NEEDED        — "1" если нужно добавить volume сертификатов
#   VOLUME_HOST          — хост-путь к папке с сертификатами
#   VOLUME_CONT          — путь внутри контейнера
#   CSRC_EFFECTIVE       — итоговый тип используемого источника
# ══════════════════════════════════════════════════════════════════
_vgw_resolve_ssl_paths() {
    local cname="$1" csrc="$2" public_domain="${3:-}"
    local csrc_type csrc_host csrc_cont
    csrc_type=$(echo "$csrc" | cut -d: -f1)
    csrc_host=$(echo  "$csrc" | cut -d: -f2)
    csrc_cont=$(echo  "$csrc" | cut -d: -f3)

    # Для облегчения диагностики — экспортируем итоговый тип
    CSRC_EFFECTIVE="$csrc_type"

    case "$csrc_type" in
        certwarden)
            # ── Ключевая проверка: certwarden для НАШЕГО домена или чужого? ──
            # csrc_cont содержит путь внутри контейнера, например:
            #   /etc/nginx/ssl/donmatteo.monster   → домен: donmatteo.monster
            #   /etc/nginx/ssl/lendinghello.mooo.com → домен: lendinghello.mooo.com
            #
            # Также поддерживаем Wildcard-сертификаты (например, если certwarden для домена donmatteo.monster,
            # а public_domain это lendinghello.donmatteo.monster — он подходит!).
            local cw_domain cw_clean
            cw_domain=$(basename "$csrc_cont")
            cw_clean="${cw_domain#\*.}" # Срезаем leading *. если есть

            if [[ -n "$public_domain" ]] && [[ "$cw_clean" == "$public_domain" || "$public_domain" == *".${cw_clean}" ]]; then
                # ✅ certwarden обслуживает наш домен или является его Wildcard-родителем — используем напрямую
                CERT="${csrc_cont}/fullchain.pem"
                KEY="${csrc_cont}/privkey.pem"
                VOLUME_NEEDED="0"
                CSRC_EFFECTIVE="certwarden"
            else
                # ❌ certwarden для ДРУГОГО домена (donmatteo.monster ≠ lendinghello.mooo.com)
                # → Используем наши reshala/acme сертификаты для public_domain
                warn "certwarden смонтирован для домена '${cw_domain}',"
                warn "  а домен лендинга '${public_domain:-?}' — это другой домен."
                warn "  Переключаюсь на наши reshala-сертификаты (Let's Encrypt / ACME)."
                CERT="/etc/nginx/certs/fullchain.pem"
                KEY="/etc/nginx/certs/privkey.pem"
                VOLUME_NEEDED="1"
                VOLUME_HOST="$(_vgw_certs_dir)"
                VOLUME_CONT="/etc/nginx/certs"
                CSRC_EFFECTIVE="reshala"
                # Проверяем что наши сертификаты уже существуют
                _vgw_check_our_certs_exist "$public_domain"
            fi
            ;;
        letsencrypt)
            # LE смонтирован в контейнер — используем наши reshala-сертификаты
            # т.к. LE live/<domain>/... требует знать точное имя домена внутри контейнера
            CERT="/etc/nginx/certs/fullchain.pem"
            KEY="/etc/nginx/certs/privkey.pem"
            VOLUME_NEEDED="1"
            VOLUME_HOST="$(_vgw_certs_dir)"
            VOLUME_CONT="/etc/nginx/certs"
            CSRC_EFFECTIVE="reshala"
            _vgw_check_our_certs_exist "$public_domain"
            ;;
        reshala)
            CERT="/etc/nginx/certs/fullchain.pem"
            KEY="/etc/nginx/certs/privkey.pem"
            VOLUME_NEEDED="1"
            VOLUME_HOST="$(_vgw_certs_dir)"
            VOLUME_CONT="/etc/nginx/certs"
            CSRC_EFFECTIVE="reshala"
            _vgw_check_our_certs_exist "$public_domain"
            ;;
        none|*)
            CERT="/etc/nginx/certs/fullchain.pem"
            KEY="/etc/nginx/certs/privkey.pem"
            VOLUME_NEEDED="1"
            VOLUME_HOST="$(_vgw_certs_dir)"
            VOLUME_CONT="/etc/nginx/certs"
            CSRC_EFFECTIVE="acme"
            _vgw_check_our_certs_exist "$public_domain"
            ;;
    esac
}

# ── Проверяет что наши edge/certs/ содержат сертификат для public_domain
# Предупреждает если файл не найден (acme ещё не выпустил / DNS не настроен)
_vgw_check_our_certs_exist() {
    local domain="${1:-}"
    local certs_dir; certs_dir="$(_vgw_certs_dir)"
    local cert_file="${certs_dir}/fullchain.pem"
    local key_file="${certs_dir}/privkey.pem"

    # Если Docker ошибочно создал директорию вместо файла, удаляем её
    if [[ -d "$cert_file" ]]; then rm -rf "$cert_file"; fi
    if [[ -d "$key_file" ]]; then rm -rf "$key_file"; fi

    if [[ ! -f "$cert_file" || ! -s "$cert_file" || ! -f "$key_file" || ! -s "$key_file" ]]; then
        info "Создаю временный самоподписанный SSL-сертификат для '${domain}'..."
        mkdir -p "${certs_dir}"
        chmod 755 "${certs_dir}" 2>/dev/null || true
        if command -v openssl &>/dev/null; then
            rm -f "${key_file}" "${cert_file}" 2>/dev/null || true
            openssl req -x509 -nodes -newkey rsa:2048 -days 30 \
              -keyout "${key_file}" \
              -out "${cert_file}" \
              -subj "/CN=${domain:-localhost}" &>/dev/null || true
            chmod 644 "${key_file}" "${cert_file}" 2>/dev/null || true
        else
            warn "  ⚠️  openssl не установлен на хосте! Не удалось создать временный сертификат."
        fi
    fi

    if [[ ! -f "$cert_file" ]]; then
        warn "  ⚠️  Сертификат для '${domain}' НЕ НАЙДЕН в ${certs_dir}/"
        warn "  Убедитесь что:"
        warn "    1. DNS A-запись для ${domain} указывает на этот server"
        warn "    2. Порты 80/443 (или настроенные) открыты"
        warn "    3. Запустите вручную: ./scripts/ensure-certs.sh"
        warn "  Nginx конфиг будет создан, но SSL может не работать до выпуска сертификата."
    else
        # Проверяем что сертификат именно для нашего домена (через openssl если есть)
        if command -v openssl &>/dev/null && [[ -n "$domain" ]]; then
            local cert_cn
            cert_cn=$(openssl x509 -noout -subject -in "$cert_file" 2>/dev/null | grep -oP 'CN\s*=\s*\K[^,/]+' | head -1 || echo "")
            local cert_san
            cert_san=$(openssl x509 -noout -text -in "$cert_file" 2>/dev/null | grep -A1 'Subject Alternative Name' | grep 'DNS:' | grep -oP 'DNS:[^,]+' | tr '\n' ' ' || echo "")
            if [[ -n "$cert_cn" && "$cert_cn" != *"$domain"* && "$cert_san" != *"$domain"* ]]; then
                warn "  ⚠️  Сертификат в ${certs_dir}/ выдан для '${cert_cn}',"
                warn "       а не для '${domain}'!"
                warn "  Запустите: ./scripts/ensure-certs.sh  (чтобы выпустить для ${domain})"
            fi
        fi
    fi
}

# ══════════════════════════════════════════════════════════════════
# Добавляет volume и acme-challenge volume в docker-compose.yml
# контейнера и перезапускает его если volumes изменились.
# Возвращает 0 если контейнер готов к инжекту конфига.
# ══════════════════════════════════════════════════════════════════
_vgw_ensure_container_volumes() {
    local cname="$1"
    local volume_host="$2"     # хост путь к сертификатам
    local volume_cont="$3"     # контейнер путь к сертификатам
    local acme_host="$(_vgw_project_dir)/edge/acme-challenge"
    local acme_cont="/var/www/acme-challenge"

    info "Ищу docker-compose.yml для контейнера ${cname}..."
    local compose_file
    compose_file=$(_vgw_find_compose_file "$cname")

    if [[ -z "$compose_file" ]]; then
        warn "Не удалось найти docker-compose.yml для ${cname}."
        warn "Volume для сертификатов нужно добавить вручную:"
        warn "  - ${volume_host}:${volume_cont}:ro"
        return 1
    fi

    ok "Найден: ${compose_file}"
    local compose_dir
    compose_dir=$(dirname "$compose_file")

    local cert_result acme_result
    # Добавляем volume сертификатов
    cert_result=$(COMPOSE_FILE="$compose_file" CNAME="$cname" \
        HOST_PATH="$volume_host" CONTAINER_PATH="$volume_cont" VOLUME_MODE="ro" \
        "$(_vgw_python)" - <<'PY'
import os, sys
from pathlib import Path
try:
    import yaml
except ImportError:
    sys.exit(2)
compose_path = Path(os.environ["COMPOSE_FILE"])
cname = os.environ["CNAME"]
host_path = os.environ["HOST_PATH"]
container_path = os.environ["CONTAINER_PATH"]
mode = os.environ.get("VOLUME_MODE", "ro")
new_volume = f"{host_path}:{container_path}:{mode}"
data = yaml.safe_load(compose_path.read_text(encoding="utf-8")) or {}
if not isinstance(data, dict): sys.exit(1)
services = data.get("services") or {}
if not isinstance(services, dict): sys.exit(1)
target_svc = None
for svc_name, svc in services.items():
    if not isinstance(svc, dict): continue
    if svc.get("container_name", "") == cname:
        target_svc = svc_name; break
if target_svc is None:
    for svc_name, svc in services.items():
        if not isinstance(svc, dict): continue
        img = str(svc.get("image", "")).lower()
        if "nginx" in img or "nginx" in svc_name.lower():
            target_svc = svc_name; break
if target_svc is None:
    print("SERVICE_NOT_FOUND"); sys.exit(1)
svc = services[target_svc]
vols = svc.get("volumes") or []
if not isinstance(vols, list): vols = []

def norm(p):
    if not p: return ""
    return os.path.normpath(p.strip()).replace('\\', '/').rstrip('/')

def parse_vol(v):
    if isinstance(v, dict):
        return (v.get("source", ""), v.get("target", ""), "ro" if v.get("read_only") else "rw")
    parts = str(v).strip().split(":")
    if not parts: return ("", "", "")
    if len(parts) == 1: return ("", parts[0], "")
    if len(parts) == 2: return (parts[0], parts[1], "")
    last = parts[-1].strip()
    if last in ("ro", "rw", "z", "Z", "delegated", "cached", "consistent"):
        return (parts[0], parts[1], last)
    return (parts[0], parts[1], last)

found = False
changed = False
for idx, v in enumerate(vols):
    h, c, m = parse_vol(v)
    if norm(c) == norm(container_path):
        found = True
        if norm(h) != norm(host_path):
            if isinstance(v, dict):
                v["source"] = host_path
                v["read_only"] = (mode == "ro")
            else:
                vols[idx] = f"{host_path}:{container_path}:{mode}"
            changed = True
            break

if found:
    if changed:
        svc["volumes"] = vols; services[target_svc] = svc; data["services"] = services
        bak = compose_path.with_suffix(".yml.bak")
        bak.write_text(compose_path.read_text(encoding="utf-8"), encoding="utf-8")
        compose_path.write_text(yaml.safe_dump(data, allow_unicode=True, sort_keys=False, default_flow_style=False), encoding="utf-8")
        print(f"ADDED:{target_svc}")
    else:
        print("ALREADY_EXISTS")
    sys.exit(0)

vols.append(new_volume)
svc["volumes"] = vols; services[target_svc] = svc; data["services"] = services
bak = compose_path.with_suffix(".yml.bak")
bak.write_text(compose_path.read_text(encoding="utf-8"), encoding="utf-8")
compose_path.write_text(yaml.safe_dump(data, allow_unicode=True, sort_keys=False, default_flow_style=False), encoding="utf-8")
print(f"ADDED:{target_svc}")
PY
    2>/dev/null || echo "ERROR")

    # Добавляем acme-challenge volume
    acme_result=$(COMPOSE_FILE="$compose_file" CNAME="$cname" \
        HOST_PATH="$acme_host" CONTAINER_PATH="$acme_cont" VOLUME_MODE="ro" \
        "$(_vgw_python)" - <<'PY'
import os, sys
from pathlib import Path
try:
    import yaml
except ImportError:
    sys.exit(2)
compose_path = Path(os.environ["COMPOSE_FILE"])
cname = os.environ["CNAME"]
host_path = os.environ["HOST_PATH"]
container_path = os.environ["CONTAINER_PATH"]
mode = os.environ.get("VOLUME_MODE", "ro")
new_volume = f"{host_path}:{container_path}:{mode}"
data = yaml.safe_load(compose_path.read_text(encoding="utf-8")) or {}
if not isinstance(data, dict): sys.exit(1)
services = data.get("services") or {}
target_svc = None
for svc_name, svc in services.items():
    if not isinstance(svc, dict): continue
    if svc.get("container_name", "") == cname:
        target_svc = svc_name; break
if target_svc is None:
    for svc_name, svc in services.items():
        if not isinstance(svc, dict): continue
        img = str(svc.get("image", "")).lower()
        if "nginx" in img or "nginx" in svc_name.lower():
            target_svc = svc_name; break
if target_svc is None:
    print("SKIP"); sys.exit(0)
svc = services[target_svc]
vols = svc.get("volumes") or []
if not isinstance(vols, list): vols = []

def norm(p):
    if not p: return ""
    return os.path.normpath(p.strip()).replace('\\', '/').rstrip('/')

def parse_vol(v):
    if isinstance(v, dict):
        return (v.get("source", ""), v.get("target", ""), "ro" if v.get("read_only") else "rw")
    parts = str(v).strip().split(":")
    if not parts: return ("", "", "")
    if len(parts) == 1: return ("", parts[0], "")
    if len(parts) == 2: return (parts[0], parts[1], "")
    last = parts[-1].strip()
    if last in ("ro", "rw", "z", "Z", "delegated", "cached", "consistent"):
        return (parts[0], parts[1], last)
    return (parts[0], parts[1], last)

found = False
changed = False
for idx, v in enumerate(vols):
    h, c, m = parse_vol(v)
    if norm(c) == norm(container_path):
        found = True
        if norm(h) != norm(host_path):
            if isinstance(v, dict):
                v["source"] = host_path
                v["read_only"] = (mode == "ro")
            else:
                vols[idx] = f"{host_path}:{container_path}:{mode}"
            changed = True
            break

if found:
    if changed:
        svc["volumes"] = vols; services[target_svc] = svc; data["services"] = services
        compose_path.write_text(yaml.safe_dump(data, allow_unicode=True, sort_keys=False, default_flow_style=False), encoding="utf-8")
        print(f"ADDED:{target_svc}")
    else:
        print("ALREADY_EXISTS")
    sys.exit(0)

vols.append(new_volume)
svc["volumes"] = vols; services[target_svc] = svc; data["services"] = services
compose_path.write_text(yaml.safe_dump(data, allow_unicode=True, sort_keys=False, default_flow_style=False), encoding="utf-8")
print(f"ADDED:{target_svc}")
PY
    2>/dev/null || echo "SKIP")

    local need_restart=0
    if [[ "$cert_result" == ADDED:* ]]; then
        ok "Volume сертификатов добавлен в ${compose_file}"
        need_restart=1
    elif [[ "$cert_result" == "ALREADY_EXISTS" ]]; then
        ok "Volume сертификатов уже смонтирован — перезапуск не нужен."
    elif [[ "$cert_result" == "ERROR" || "$cert_result" == "SERVICE_NOT_FOUND" ]]; then
        warn "Не удалось добавить volume в ${compose_file}: ${cert_result}"
        return 1
    fi
    if [[ "$acme_result" == ADDED:* ]]; then
        ok "Volume acme-challenge добавлен."
        need_restart=1
    fi

    if [[ "$need_restart" -eq 1 ]]; then
        info "Перезапускаю контейнер ${cname} чтобы применить новые volumes..."
        # Определяем команду compose
        local dc_cmd="docker compose"
        command -v docker-compose &>/dev/null && ! docker compose version &>/dev/null && dc_cmd="docker-compose"

        # Перезапускаем только нужный сервис (не весь стек)
        local svc_name; svc_name=$(echo "$cert_result" | cut -d: -f2-)
        if [[ -n "$svc_name" && "$svc_name" != "$cert_result" ]]; then
            ( cd "$compose_dir" && $dc_cmd up -d "$svc_name" 2>&1 ) || {
                warn "docker compose up -d ${svc_name} не прошёл. Пробую restart..."
                ( cd "$compose_dir" && $dc_cmd restart "$svc_name" 2>&1 ) || true
            }
        else
            # Fallback: перезапускаем весь compose
            ( cd "$compose_dir" && $dc_cmd up -d 2>&1 ) || true
        fi
        # Ждём пока nginx запустится
        local attempts=0
        while [[ $attempts -lt 10 ]]; do
            docker exec "$cname" nginx -v &>/dev/null && break
            sleep 1; ((attempts++))
        done
        ok "Контейнер ${cname} перезапущен с новыми volumes."
    fi
    return 0
}

# Авто-инжект nginx конфига. Возвращает 0 при успехе, 1 при ошибке.
_vgw_nginx_inject_auto() {
    local ntype="$1" cname="${2:-}" cpath="${3:-}" csrc="${4:-none}" domain="$5" gport="$6"
    local cert="" key=""

    # ── Очистка сиротских конфигураций старого домена ──────────────────
    local persist_inj="${_VGW_PERSIST_DIR}/nginx_injection.env"
    if [[ -f "$persist_inj" ]]; then
        local saved_domain
        saved_domain=$(grep '^DOMAIN=' "$persist_inj" | cut -d= -f2-)
        if [[ -n "$saved_domain" && "$saved_domain" != "$domain" ]]; then
            info "Обнаружено изменение домена с '${saved_domain}' на '${domain}'."
            info "Удаляю старые хостовые конфигурационные файлы nginx для '${saved_domain}'..."
            rm -f "/etc/nginx/sites-available/${saved_domain}.conf" 2>/dev/null || true
            rm -f "/etc/nginx/sites-enabled/${saved_domain}.conf" 2>/dev/null || true
            rm -f "/etc/nginx/conf.d/${saved_domain}.conf" 2>/dev/null || true
        fi
    fi

    local is_fallback="0"
    if [[ "$ntype" == *":hostnet"* || "$ntype" == "host:nginx" ]]; then
        if [[ -n "$cpath" && -f "$cpath" ]]; then
            if grep -q "nginx_http.sock" "$cpath"; then
                is_fallback="1"
            fi
        else
            for p in "/etc/nginx/nginx.conf" "/opt/remnawave/nginx.conf"; do
                if [[ -f "$p" ]] && grep -q "nginx_http.sock" "$p"; then
                    is_fallback="1"
                    break
                fi
            done
        fi
    fi

    if [[ "$is_fallback" == "1" ]]; then
        warn "Обнаружена сложная архитектура Xray Stream Fallback."
        warn "Автоматический инжект может нарушить сложную маршрутизацию VPN."
        return 1
    fi

    # ── Определяем пути к сертификатам ──────────────────────────
    local CERT KEY VOLUME_NEEDED VOLUME_HOST VOLUME_CONT CSRC_EFFECTIVE
    VOLUME_NEEDED="0" VOLUME_HOST="" VOLUME_CONT="" CSRC_EFFECTIVE=""
    if [[ -n "$cname" ]]; then
        _vgw_resolve_ssl_paths "$cname" "$csrc" "$domain"
    else
        CERT="$(_vgw_certs_dir)/fullchain.pem"
        KEY="$(_vgw_certs_dir)/privkey.pem"
        VOLUME_NEEDED="0"
    fi

    case "$ntype" in
        host:nginx)
            local cdir conf_file
            cdir=$(_vgw_find_nginx_conf_dir)
            conf_file="${cdir}/${domain}.conf"

            local new_conf_content
            new_conf_content=$(_vgw_nginx_generate_conf "$domain" "$gport" "$CERT" "$KEY" "$csrc")

            local config_changed="1"
            if [[ -f "$conf_file" ]]; then
                local current_content; current_content=$(cat "$conf_file")
                local current_clean; current_clean=$(echo "$current_content" | grep -v "# Создан:")
                local new_clean; new_clean=$(echo "$new_conf_content" | grep -v "# Создан:")
                if [[ "$current_clean" == "$new_clean" ]]; then
                    config_changed="0"
                fi
            fi

            if [[ "$config_changed" == "0" ]]; then
                ok "Конфигурация Nginx в ${conf_file} уже актуальна и не изменилась — перезапуск не требуется."
                _vgw_nginx_injection_save "host:nginx" "$conf_file" "$domain"
                return 0
            fi

            info "Создаю ${conf_file}..."
            echo "$new_conf_content" > "$conf_file" || {
                printf_error "Не удалось создать ${conf_file}"; return 1
            }
            # Если sites-available → создаём симлинк в sites-enabled
            if [[ "$cdir" == "/etc/nginx/sites-available" && -d /etc/nginx/sites-enabled ]]; then
                ln -sf "$conf_file" "/etc/nginx/sites-enabled/${domain}.conf" 2>/dev/null || true
            fi
            if ! nginx -t 2>/dev/null; then
                printf_error "nginx -t ОШИБКА! Откатываю..."
                rm -f "$conf_file" "/etc/nginx/sites-enabled/${domain}.conf"
                return 1
            fi
            systemctl reload nginx && ok "Хостовый nginx перезагружен!" || return 1
            _vgw_nginx_injection_save "host:nginx" "$conf_file" "$domain"
            ;;

        docker:conf.d:*)
            local conf_host="${cpath}/80-bedolaga.conf"

            # ── Шаг 1: Убеждаемся что volumes смонтированы ──────
            if [[ "$VOLUME_NEEDED" == "1" ]]; then
                info "Проверяю/добавляю volume сертификатов в docker-compose.yml..."
                if ! _vgw_ensure_container_volumes "$cname" "$VOLUME_HOST" "$VOLUME_CONT"; then
                    warn "Не удалось автоматически добавить volume. Продолжаю без него..."
                    # Используем временный snakeoil чтобы хоть что-то работало
                    CERT="/etc/ssl/certs/ssl-cert-snakeoil.pem"
                    KEY="/etc/ssl/private/ssl-cert-snakeoil.key"
                fi
            fi

            # ── Шаг 2: Создаём конфиг nginx ─────────────────────
            local new_conf_content
            new_conf_content=$(_vgw_nginx_generate_conf "$domain" "$gport" "$CERT" "$KEY" "$csrc" "$cname")

            local config_changed="1"
            if [[ -f "$conf_host" ]]; then
                local current_content; current_content=$(cat "$conf_host")
                local current_clean; current_clean=$(echo "$current_content" | grep -v "# Создан:")
                local new_clean; new_clean=$(echo "$new_conf_content" | grep -v "# Создан:")
                if [[ "$current_clean" == "$new_clean" ]]; then
                    config_changed="0"
                fi
            fi

            if [[ "$config_changed" == "0" ]]; then
                ok "Конфигурация Nginx в ${conf_host} уже актуальна и не изменилась — перезапуск не требуется."
                _vgw_nginx_injection_save "docker:conf.d" "$conf_host" "$domain"
                return 0
            fi

            info "Создаю ${conf_host}..."
            echo "$new_conf_content" > "$conf_host" || {
                printf_error "Не удалось создать ${conf_host}"; return 1
            }

            # ── Шаг 3: Проверяем конфиг nginx внутри контейнера ─
            local nginx_test_output
            nginx_test_output=$(docker exec "$cname" nginx -t 2>&1)
            if [[ $? -ne 0 ]]; then
                printf_error "nginx -t в контейнере ОШИБКА! Откатываю..."
                warn "Вывод nginx -t:"
                echo "$nginx_test_output" | head -20 | sed 's/^/  /'
                rm -f "$conf_host"
                # Восстанавливаем backup docker-compose.yml если он был создан
                local compose_file; compose_file=$(_vgw_find_compose_file "$cname")
                [[ -f "${compose_file}.bak" ]] && cp -f "${compose_file}.bak" "$compose_file" 2>/dev/null || true
                return 1
            fi

            # ── Шаг 4: Reload nginx ──────────────────────────────
            docker exec "$cname" nginx -s reload && ok "Docker nginx (${cname}) перезагружен!" || return 1
            _vgw_nginx_injection_save "docker:conf.d" "$conf_host" "$domain"
            ;;

        docker:nginx:*)
            # Прочий docker nginx: инжект через docker cp
            # ── Шаг 1: Проверяем/добавляем volumes ──────────────
            if [[ "$VOLUME_NEEDED" == "1" ]]; then
                info "Проверяю/добавляю volume сертификатов в docker-compose.yml..."
                _vgw_ensure_container_volumes "$cname" "$VOLUME_HOST" "$VOLUME_CONT" || true
            fi

            # ── Шаг 2: Инжект конфига через docker cp ───────────
            local tmp_conf="/tmp/_bedolaga_${domain}.conf"
            local new_conf_content
            new_conf_content=$(_vgw_nginx_generate_conf "$domain" "$gport" "$CERT" "$KEY" "$csrc" "$cname")

            local config_changed="1"
            local current_content
            current_content=$(docker exec "$cname" cat "/etc/nginx/conf.d/80-bedolaga.conf" 2>/dev/null || echo "")
            if [[ -n "$current_content" ]]; then
                local current_clean; current_clean=$(echo "$current_content" | grep -v "# Создан:")
                local new_clean; new_clean=$(echo "$new_conf_content" | grep -v "# Создан:")
                if [[ "$current_clean" == "$new_clean" ]]; then
                    config_changed="0"
                fi
            fi

            if [[ "$config_changed" == "0" ]]; then
                ok "Конфигурация Nginx внутри контейнера ${cname} уже актуальна и не изменилась — перезапуск не требуется."
                _vgw_nginx_injection_save "docker:nginx" "/etc/nginx/conf.d/80-bedolaga.conf" "$domain"
                return 0
            fi

            echo "$new_conf_content" > "$tmp_conf"
            docker cp "$tmp_conf" "${cname}:/etc/nginx/conf.d/80-bedolaga.conf" || return 1
            rm -f "$tmp_conf"
            docker exec "$cname" nginx -t && docker exec "$cname" nginx -s reload || return 1
            ok "Docker nginx (${cname}) перезагружен!"
            _vgw_nginx_injection_save "docker:nginx" "/etc/nginx/conf.d/80-bedolaga.conf" "$domain"
            ;;

        *)
            return 1
            ;;
    esac
    return 0
}

# Генерирует точную инструкцию для ручной установки под любой тип nginx
_vgw_nginx_manual_guide() {
    local ntype="$1" cname="${2:-}" cpath="${3:-}" csrc="${4:-none}" domain="$5" gport="$6"
    local W="$C_YELLOW" C="$C_CYAN" G="$C_GREEN" R="$C_RED" B="$C_BOLD" E="$C_RESET"

    local csrc_type="none" csrc_host="" csrc_container=""
    if [[ "$csrc" != "none" ]]; then
        csrc_type=$(echo "$csrc" | cut -d: -f1)
        csrc_host=$(echo "$csrc" | cut -d: -f2)
        csrc_container=$(echo "$csrc" | cut -d: -f3)
    fi
    [[ -z "$csrc_host" ]] && csrc_host="$(_vgw_certs_dir)"

    local CERT KEY VOLUME_NEEDED VOLUME_HOST VOLUME_CONT CSRC_EFFECTIVE
    VOLUME_NEEDED="0" VOLUME_HOST="" VOLUME_CONT="" CSRC_EFFECTIVE=""
    local cert="" key=""

    if [[ -n "$cname" ]]; then
        # Используем умное определение путей на основе csrc
        _vgw_resolve_ssl_paths "$cname" "$csrc" "$domain"
        cert="$CERT"
        key="$KEY"
    else
        CERT="$(_vgw_certs_dir)/fullchain.pem"
        KEY="$(_vgw_certs_dir)/privkey.pem"
        cert="$CERT"
        key="$KEY"
        VOLUME_NEEDED="0"
        VOLUME_HOST="$(_vgw_certs_dir)"
        VOLUME_CONT="/etc/nginx/certs"
        CSRC_EFFECTIVE="reshala"
        _vgw_check_our_certs_exist "$domain"
    fi

    # Настраиваем docker_mount_notice на основе VOLUME_NEEDED
    local docker_mount_notice="0"
    if [[ "$VOLUME_NEEDED" == "1" ]]; then
        docker_mount_notice="1"
    fi

    local conf_content
    conf_content=$(_vgw_nginx_generate_conf "$domain" "$gport" "$cert" "$key" "$csrc" "$cname")

    local is_fallback="0"
    local fallback_cfg=""
    if [[ "$ntype" == *":hostnet"* || "$ntype" == "host:nginx" ]]; then
        if [[ -n "$cpath" && -f "$cpath" ]]; then
            if grep -q "nginx_http.sock" "$cpath"; then
                is_fallback="1"
                fallback_cfg="$cpath"
            fi
        else
            for p in "/etc/nginx/nginx.conf" "/opt/remnawave/nginx.conf"; do
                if [[ -f "$p" ]] && grep -q "nginx_http.sock" "$p"; then
                    is_fallback="1"
                    fallback_cfg="$p"
                    break
                fi
            done
        fi
    fi

    if [[ "$is_fallback" == "1" ]]; then
        echo -e "  ${R}${B}╔══════════════════════════════════════════════════════════════╗${E}"
        echo -e "  ${R}${B}║${E}  ⚠️  ${B}ОБНАРУЖЕНА АРХИТЕКТУРА STREAM FALLBACK (UNIX-СОКЕТЫ)${E}        ${R}${B}║${E}"
        echo -e "  ${R}${B}╚══════════════════════════════════════════════════════════════╝${E}"
        echo -e "  Ваш Nginx использует пересылку через Xray (443 -> Stream -> Unix-сокет)."
        echo -e "  Для корректной работы домена ${G}${domain}${E} требуется ручная настройка."
        echo ""
        echo -e "  ${B}Шаг 1: Добавьте новый домен в роутер в блоке stream {}${E}"
        echo -e "     Открывайте файл конфигурации Nginx:"
        echo -e "  ${G}     nano ${fallback_cfg}${E}"
        echo ""
        echo -e "     Найдите блок ${B}stream {}${E} и карту ${B}map \$ssl_preread_server_name \$route_to${E}."
        echo -e "     Добавьте ваш домен в список перед ${B}default${E}:"
        echo ""
        echo -e "  ${C}       map \$ssl_preread_server_name \$route_to {${E}"
        echo -e "  ${C}           # ... существующие домены ...${E}"
        echo -e "  ${G}           ${domain}    unix:/dev/shm/nginx_http.sock;  # <--- Добавить эту строку!${E}"
        echo -e "  ${C}           default                       unix:/dev/shm/nginx_external.sock;${E}"
        echo -e "  ${C}       }${E}"
        echo ""
        echo -e "  ${B}Шаг 2: Добавьте server-блоки в блок http {}${E}"
        echo -e "     В этом же файле внутри блока ${B}http {}${E} (вне других server-блоков, перед закрывающей })"
        echo -e "     добавьте следующие блоки:"
        echo "  ────────────────────────────────────────────────────"

        local stream_ssl_cert="$cert"
        local stream_ssl_key="$key"

        cat <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${domain};

    location ^~ /.well-known/acme-challenge/ {
        root /var/www/acme-challenge;
        try_files \$uri =404;
    }
    location / {
        return 301 https://\$host\$request_uri;
    }
}

server {
    # Слушаем тот же Unix-сокет с включенным SSL и proxy_protocol!
    listen unix:/dev/shm/nginx_http.sock proxy_protocol ssl;
    http2 on;
    server_name ${domain};

    # Восстанавливаем реальный IP клиента
    set_real_ip_from unix:;
    real_ip_header proxy_protocol;

    # Логи
    access_log /var/log/nginx_custom/${domain}_access.log;
    error_log /var/log/nginx_custom/${domain}_error.log;

    # Сертификаты (используются пути, доступные Nginx)
    ssl_certificate     "${stream_ssl_cert}";
    ssl_certificate_key "${stream_ssl_key}";
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    location / {
        proxy_pass https://127.0.0.1:${gport};
        proxy_http_version 1.1;
        proxy_ssl_verify off;
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
EOF
        echo "  ────────────────────────────────────────────────────"
        echo ""
        if [[ -n "$cname" ]]; then
            echo -e "  ${R}${B}🐳 ОБЯЗАТЕЛЬНО: НАСТРОЙКА ТОМА (VOLUME) В DOCKER-COMPOSE ДЛЯ NGINX (${cname})${E}"
            echo -e "  Поскольку ваш Nginx работает в контейнере Docker, ему требуются SSL-сертификаты."
            echo -e "  Чтобы применить автоматические сертификаты Bedolaga / Reshala:"
            echo ""
            echo -e "  1. Откройте ваш ${B}docker-compose.yml${E} файл, где описан сервис Nginx (${cname}),"
            echo -e "     и добавьте в секцию ${B}volumes:${E} следующие строки монтирования:"
            echo -e "  ${G}       - $(_vgw_certs_dir):/etc/nginx/certs:ro${E}"
            echo -e "  ${G}       - $(_vgw_project_dir)/edge/acme-challenge:/var/www/acme-challenge:ro${E}"
            echo ""
            echo -e "  2. Перезапустите контейнеры и проверьте логи командами:"
            echo -e "  ${G}     docker compose down && docker compose up -d && docker compose logs -f${E}"
            echo "  ────────────────────────────────────────────────────"
            echo ""
        fi
        echo -e "  ${B}Шаг 3: Проверьте и перезагрузите Nginx${E}"
        if [[ -n "$cname" ]]; then
            echo -e "  ${G}  docker exec ${cname} nginx -t${E}"
            echo -e "  ${G}  docker exec ${cname} nginx -s reload${E}"
        else
            echo -e "  ${G}  nginx -t && systemctl reload nginx${E}"
        fi
        echo ""
        return 0
    fi

    echo ""
    echo -e "  ${W}${B}╔══════════════════════════════════════════════════════════════╗${E}"
    echo -e "  ${W}${B}║${E}  📋  ${B}Инструкция: ручная установка nginx${E}"
    echo -e "  ${W}${B}╚══════════════════════════════════════════════════════════════╝${E}"
    echo ""

    if [[ -n "$cname" ]]; then
        echo -e "  ${W}${B}╔══════════════════════════════════════════════════════════════╗${E}"
        echo -e "  ${W}${B}║${E}  🐳  ${B}ОБЯЗАТЕЛЬНО К ПРОЧТЕНИЮ ДЛЯ DOCKER NGINX (${cname})${E}"
        echo -e "  ${W}${B}╚══════════════════════════════════════════════════════════════╝${E}"
        echo -e "  Ваш Nginx работает в изолированном контейнере Docker."
        echo -e "  Ему требуются SSL-сертификаты. Проверьте ваш статус монтирования:"
        echo ""
        if [[ "$docker_mount_notice" == "1" ]]; then
            echo -e "  ${G}${B}👉 ИСПОЛЬЗОВАНИЕ АВТО-СЕРТИФИКАТОВ BEDOLAGA / RESHALA${E}"
            echo -e "     Для этого ${B}ОБЯЗАТЕЛЬНО${E} добавьте в секцию ${B}volumes:${E} вашего Nginx"
            echo -e "     в файле ${B}docker-compose.yml${E} (или аналогичном) следующие строки:"
            echo -e "  ${G}       - ${VOLUME_HOST:-$csrc_host}:/etc/nginx/certs:ro${E}"
            echo -e "  ${G}       - $(_vgw_project_dir)/edge/acme-challenge:/var/www/acme-challenge:ro${E}"
            echo ""
            echo -e "     После добавления volumes перезапустите контейнер Nginx:"
            echo -e "  ${G}     docker compose up -d${E}"
            echo ""
            echo -e "     (Конфиг Nginx ниже уже преднастроен на пути ${G}/etc/nginx/certs/...${E})"
        else
            echo -e "  ${G}${B}👉 ИСПОЛЬЗОВАНИЕ СУЩЕСТВУЮЩИХ СЕРТИФИКАТОВ (${CSRC_EFFECTIVE})${E}"
            echo -e "     Мы обнаружили, что ваш Nginx уже примонтирован к папке с сертификатами"
            echo -e "     на хосте: ${C}${VOLUME_HOST:-$csrc_host}${E} (внутри контейнера: ${C}${VOLUME_CONT:-$csrc_container}${E})."
            echo ""
            echo -e "     Поскольку папка ${B}УЖЕ примонтирована${E}, вносить изменения"
            echo -e "     в ${B}docker-compose.yml${E} для Nginx ${G}НЕ ТРЕБУЕТСЯ!${E} Всё уже готово."
            echo -e "     (Конфиг Nginx ниже автоматически настроен на пути внутри контейнера)"
            echo ""
            echo -e "  ${W}${B}👉 ЕСЛИ ВЫ ХОТИТЕ ПЕРЕЙТИ НА АВТО-СЕРТИФИКАТЫ BEDOLAGA / RESHALA${E}"
            echo -e "     Если хотите, чтобы наш встроенный Let's Encrypt сам получал/продлевал SSL:"
            echo -e "     1. Добавьте в секцию ${B}volumes:${E} вашего Nginx в ${B}docker-compose.yml${E}:"
            echo -e "  ${W}          - $(_vgw_certs_dir):/etc/nginx/certs:ro${E}"
            echo -e "     2. Перезапустите Nginx контейнер: ${W}docker compose up -d${E}"
            echo -e "     3. В конфиге Nginx ниже замените пути к SSL на:"
            echo -e "  ${W}          ssl_certificate     /etc/nginx/certs/fullchain.pem;${E}"
            echo -e "  ${W}          ssl_certificate_key /etc/nginx/certs/privkey.pem;${E}"
        fi
        echo "  ────────────────────────────────────────────────────"
        echo ""
    elif [[ "$CSRC_EFFECTIVE" == "reshala" && -z "$cname" ]]; then
        echo -e "  ${G}${B}🔑 ОБНАРУЖЕНЫ СЕРТИФИКАТЫ!${E}"
        echo -e "  На сервере найдены рабочие SSL-сертификаты в:"
        echo -e "  ${C}${VOLUME_HOST:-$csrc_host}${E}"
        echo ""
        echo -e "  Конфиг ниже уже настроен на их использование напрямую!"
        echo "  ────────────────────────────────────────────────────"
        echo ""
    fi

    case "$ntype" in
        host:nginx)
            local cdir; cdir=$(_vgw_find_nginx_conf_dir)
            echo -e "  ${B}Шаг 1${E}: Создайте файл конфига"
            echo -e "  ${G}  nano ${cdir}/${domain}.conf${E}"
            echo ""
            echo -e "  ${B}Шаг 2${E}: Вставьте содержимое:"
            echo "  ────────────────────────────────────────────────────"
            echo "$conf_content" | sed 's/^/  /'
            echo "  ────────────────────────────────────────────────────"
            echo ""
            if [[ "$cdir" == "/etc/nginx/sites-available" ]]; then
                echo -e "  ${B}Шаг 3${E}: Активируйте сайт"
                echo -e "  ${G}  ln -s ${cdir}/${domain}.conf /etc/nginx/sites-enabled/${E}"
                echo ""
            fi
            echo -e "  ${B}Шаг 4${E}: Получите сертификат"
            echo -e "  ${G}  certbot --nginx -d ${domain}${E}"
            echo ""
            echo -e "  ${B}Шаг 5${E}: Проверьте и примените"
            echo -e "  ${G}  nginx -t && systemctl reload nginx${E}"
            ;;

        docker:conf.d:*)
            if [[ "$docker_mount_notice" == "1" ]]; then
                # Volume нужен — показываем полную процедуру
                local compose_hint
                compose_hint=$(_vgw_find_compose_file "$cname" 2>/dev/null || echo "")
                echo -e "  ${G}${B}🐳 ШАГИ ДЛЯ DOCKER NGINX (${cname}):${E}"
                echo ""
                echo -e "  ${B}Шаг 1${E}: Добавьте volume сертификатов в docker-compose.yml"
                if [[ -n "$compose_hint" ]]; then
                    echo -e "  ${G}  nano ${compose_hint}${E}"
                else
                    echo -e "  ${G}  nano /путь/к/вашему/docker-compose.yml${E}  ${W}(найдите его по названию сервиса ${cname})${E}"
                fi
                echo ""
                echo -e "  Найдите сервис nginx и добавьте в секцию ${B}volumes:${E}:"
                echo -e "  ${G}       - $(_vgw_certs_dir):/etc/nginx/certs:ro${E}"
                echo -e "  ${G}       - $(_vgw_project_dir)/edge/acme-challenge:/var/www/acme-challenge:ro${E}"
                echo ""
                echo -e "  ${B}Шаг 2${E}: Перезапустите только nginx-сервис"
                if [[ -n "$compose_hint" ]]; then
                    local _cdir; _cdir=$(dirname "$compose_hint")
                    echo -e "  ${G}  cd ${_cdir}${E}"
                fi
                echo -e "  ${G}  docker compose up -d <имя-сервиса-nginx>${E}"
                echo ""
                echo -e "  ${B}Шаг 3${E}: Создайте файл конфига Bedolaga"
                echo -e "  ${G}  nano ${cpath}/80-bedolaga.conf${E}"
                echo ""
                echo -e "  ${B}Шаг 4${E}: Вставьте содержимое:"
            else
                # certwarden/letsencrypt уже смонтированы — сразу к конфигу
                echo -e "  ✅ Сертификаты уже смонтированы (${csrc_type}). Только создать конфиг."
                echo ""
                echo -e "  ${B}Шаг 1${E}: Создайте файл конфига Bedolaga"
                echo -e "  ${G}  nano ${cpath}/80-bedolaga.conf${E}"
                echo ""
                echo -e "  ${B}Шаг 2${E}: Вставьте содержимое:"
            fi
            echo "  ────────────────────────────────────────────────────"
            echo "$conf_content" | sed 's/^/  /'
            echo "  ────────────────────────────────────────────────────"
            echo ""
            if [[ "$docker_mount_notice" == "1" ]]; then
                echo -e "  ${B}Шаг 5${E}: Проверьте и перезагрузите nginx"
            else
                echo -e "  ${B}Шаг 3${E}: Проверьте и перезагрузите nginx"
            fi
            echo -e "  ${G}  docker exec ${cname} nginx -t${E}"
            echo -e "  ${G}  docker exec ${cname} nginx -s reload${E}"
            ;;

        docker:hostnet:*)
            local cfgpath="${cpath}"
            echo -e "  ${R}${B}⚠️  Этот nginx использует unix-сокеты (network_mode:host).${E}"
            echo -e "  ${R}  Авто-инжект невозможен. Требуется ручная правка nginx.conf.${E}"
            echo ""
            echo -e "  ${B}Шаг 1${E}: Откройте конфиг"
            echo -e "  ${G}  nano ${cfgpath}${E}"
            echo ""
            echo -e "  ${B}Шаг 2${E}: В блоке ${B}http {}${E} перед закрывающей } добавьте:"
            echo "  ────────────────────────────────────────────────────"
            echo "$conf_content" | sed 's/^/  /'
            echo "  ────────────────────────────────────────────────────"
            echo ""
            echo -e "  ${B}Шаг 3${E}: Примените"
            echo -e "  ${G}  docker exec ${cname} nginx -t${E}"
            echo -e "  ${G}  docker exec ${cname} nginx -s reload${E}"
            ;;

        *)
            echo -e "  Тип nginx не определён. Готовый конфиг для ручной установки:"
            echo ""
            echo "$conf_content" | sed 's/^/  /'
            echo ""
            echo -e "  Вставьте в директорию nginx конфигов вашего сервера."
            echo -e "  После вставки: ${G}nginx -t && nginx reload${E}"
            ;;
    esac

    echo ""
    echo -e "  ${B}Gateway запустится на порту ${G}${gport}${E}"
    echo ""
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
    local resolved_cert_path=""
    if [[ -f "/etc/letsencrypt/live/${public_domain}/fullchain.pem" ]]; then
        resolved_cert_path="/etc/letsencrypt/live/${public_domain}"
    elif [[ -f "/etc/reshala-bedolaga/certs/fullchain.pem" ]]; then
        resolved_cert_path="/etc/reshala-bedolaga/certs"
    elif [[ -f "$(_vgw_certs_dir)/fullchain.pem" ]]; then
        resolved_cert_path="$(_vgw_certs_dir)"
    fi

    if [[ -n "$resolved_cert_path" ]]; then
        ssl_block="    ssl_certificate     ${resolved_cert_path}/fullchain.pem;
    ssl_certificate_key ${resolved_cert_path}/privkey.pem;"
    else
        ssl_block="    # ⚠️ Сертификат Let's Encrypt не найден по стандартным путям!
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
    # После установки — читаем итоговые порты
    local cfg_file="$(_vgw_cfg_file)"
    local py_bin; py_bin="$(_vgw_python)"
    local http_port https_port
    http_port=$(CFG_FILE="$cfg_file" "$py_bin" -c "import os,yaml; from pathlib import Path; c=yaml.safe_load(Path(os.environ['CFG_FILE']).read_text('utf-8')) or {}; print(c.get('edge',{}).get('http_port',80))" 2>/dev/null || echo "80")
    https_port=$(CFG_FILE="$cfg_file" "$py_bin" -c "import os,yaml; from pathlib import Path; c=yaml.safe_load(Path(os.environ['CFG_FILE']).read_text('utf-8')) or {}; print(c.get('edge',{}).get('https_port',443))" 2>/dev/null || echo "443")
    _vgw_ensure_ufw_ports "$http_port" "$https_port"

    # ── УМНАЯ NGINX ИНТЕГРАЦИЯ ────────────────────────────────────
    local public_domain
    public_domain=$(CFG_FILE="$cfg_file" "$py_bin" -c "import os,yaml; from pathlib import Path; c=yaml.safe_load(Path(os.environ['CFG_FILE']).read_text('utf-8')) or {}; print(c.get('quick_setup',{}).get('public_domain',''))" 2>/dev/null || echo "")

    if [[ -n "$public_domain" && "$public_domain" != "vpn.example.com" ]]; then
        local nginx_type cname="" cpath="" csrc
        nginx_type=$(_vgw_smart_nginx_detect "$http_port" "$https_port")

        # Разбираем компоненты строки типа
        case "$nginx_type" in
            docker:conf.d:*:*)
                cname=$(echo "$nginx_type" | cut -d: -f3)
                cpath=$(echo "$nginx_type" | cut -d: -f4-)
                ;;
            docker:hostnet:*:*|docker:nginx:*)
                cname=$(echo "$nginx_type" | cut -d: -f3)
                cpath=$(echo "$nginx_type" | cut -d: -f4-)
                ;;
        esac

        csrc=$(_vgw_detect_cert_source "$cname")

        case "$nginx_type" in
            free|our_container)
                # edge-nginx сам занимает 80/443 — никаких инжектов не нужно
                ;;
            docker:hostnet:*|unknown)
                # Авто-инжект невозможен — сразу показываем инструкцию
                echo ""
                warn "Авто-инжект nginx невозможен. Показываю инструкцию..."
                _vgw_nginx_manual_guide "$nginx_type" "$cname" "$cpath" "$csrc" "$public_domain" "$https_port"
                ;;
            *)
                # Для host:nginx, docker:conf.d:*, docker:nginx:* — показываем план
                if _vgw_detect_show_plan "$nginx_type" "$cname" "$cpath" "$csrc" "$public_domain" "$https_port"; then
                    # Пользователь выбрал y
                    if ! _vgw_nginx_inject_auto "$nginx_type" "$cname" "$cpath" "$csrc" "$public_domain" "$https_port"; then
                        warn "Авто-инжект не удался. Показываю инструкцию для ручной установки..."
                        _vgw_nginx_manual_guide "$nginx_type" "$cname" "$cpath" "$csrc" "$public_domain" "$https_port"
                    else
                        ok "Nginx успешно настроен!"
                    fi
                else
                    # Пользователь выбрал n — показываем инструкцию
                    _vgw_nginx_manual_guide "$nginx_type" "$cname" "$cpath" "$csrc" "$public_domain" "$https_port"
                fi
                ;;
        esac
    fi

    # Показываем финальный статус
    _vgw_show_landing_status
    _vgw_warn_merchant_return
}

vgw_reconfigure_wizard(){
    _vgw_preflight_check || return 1
    _vgw_prompt_and_apply_common reconfigure
    # После смены параметров — обновляем nginx конфиг если инжект был ранее
    local persist_inj="${_VGW_PERSIST_DIR}/nginx_injection.env"
    if [[ -f "$persist_inj" ]]; then
        # Читаем сохранённый тип инжекта
        local saved_type saved_file saved_domain
        saved_type=$(grep '^NGINX_TYPE=' "$persist_inj" | cut -d= -f2-)
        saved_file=$(grep '^CONF_FILE=' "$persist_inj" | cut -d= -f2-)
        saved_domain=$(grep '^DOMAIN=' "$persist_inj" | cut -d= -f2-)
        local cfg_file="$(_vgw_cfg_file)"
        local py_bin; py_bin="$(_vgw_python)"
        local new_domain; new_domain=$(CFG_FILE="$cfg_file" "$py_bin" -c "import os,yaml; from pathlib import Path; c=yaml.safe_load(Path(os.environ['CFG_FILE']).read_text('utf-8')) or {}; print(c.get('quick_setup',{}).get('public_domain',''))" 2>/dev/null || echo "")
        if [[ -n "$saved_type" && -n "$new_domain" ]]; then
            local https_port
            https_port=$(CFG_FILE="$cfg_file" "$py_bin" -c "import os,yaml; from pathlib import Path; c=yaml.safe_load(Path(os.environ['CFG_FILE']).read_text('utf-8')) or {}; print(c.get('edge',{}).get('https_port',443))" 2>/dev/null || echo "443")
            info "Домен изменён — обновляю nginx конфиг..."
            # Получаем cname и cpath из сохранённого файла
            local cname="" cpath=""
            case "$saved_type" in
                docker:conf.d) cpath="$(dirname "$saved_file")" ;;
                docker:nginx)  cname="$(docker ps --format '{{.Names}}' 2>/dev/null | grep -i nginx | grep -v vpn-edge-nginx | head -1)" ;;
            esac
            local csrc; csrc=$(_vgw_detect_cert_source "$cname")
            _vgw_nginx_inject_auto "${saved_type}" "$cname" "$cpath" "$csrc" "$new_domain" "$https_port" || true
        fi
    fi
    _vgw_show_landing_status
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

vgw_certs_full(){ _vgw_run_action certs-ensure || return 1; _vgw_run_action certs-renew || return 1; _vgw_run_action certs-cron; _vgw_certs_save_persistent; }

_vgw_rollback_nginx_injection() {
    local persist_inj="${_VGW_PERSIST_DIR}/nginx_injection.env"
    if [[ -f "$persist_inj" ]]; then
        local saved_type saved_file saved_domain
        saved_type=$(grep '^NGINX_TYPE=' "$persist_inj" | cut -d= -f2-)
        saved_file=$(grep '^CONF_FILE=' "$persist_inj" | cut -d= -f2-)
        saved_domain=$(grep '^DOMAIN=' "$persist_inj" | cut -d= -f2-)
        
        info "Обнаружен внедрённый конфиг Nginx (${saved_type}): ${saved_file}"
        if ask_yes_no "Удалить внедрённый конфиг из основного Nginx? (y/n)" "y"; then
            case "$saved_type" in
                host:nginx)
                    rm -f "$saved_file" "/etc/nginx/sites-enabled/${saved_domain}.conf" 2>/dev/null
                    if nginx -t 2>/dev/null; then systemctl reload nginx 2>/dev/null || true; fi
                    ok "Конфиг удалён из хостового nginx"
                    ;;
                docker:conf.d)
                    rm -f "$saved_file" 2>/dev/null
                    # Ищем контейнер с nginx
                    local cname; cname=$(docker ps --format '{{.Names}}' | grep -i nginx | grep -v vpn-edge-nginx | head -1)
                    if [[ -n "$cname" ]]; then
                        if docker exec "$cname" nginx -t 2>/dev/null; then docker exec "$cname" nginx -s reload 2>/dev/null || true; fi
                        ok "Конфиг удалён из docker nginx (${cname})"
                    fi
                    ;;
                docker:nginx)
                    local cname; cname=$(docker ps --format '{{.Names}}' | grep -i nginx | grep -v vpn-edge-nginx | head -1)
                    if [[ -n "$cname" ]]; then
                        docker exec "$cname" rm -f "$saved_file" 2>/dev/null
                        if docker exec "$cname" nginx -t 2>/dev/null; then docker exec "$cname" nginx -s reload 2>/dev/null || true; fi
                        ok "Конфиг удалён из docker nginx (${cname})"
                    fi
                    ;;
            esac
            rm -f "$persist_inj"
        fi
    fi
}

vgw_uninstall_execute_confirmed(){ 
    printf_critical_warning "ОПАСНО"
    if ask_yes_no "Подтверждаешь удаление контейнеров gateway? (y/n)" "n"; then 
        _vgw_run_action uninstall --non-interactive --yes
        _vgw_rollback_nginx_injection
    fi
}
vgw_uninstall_purge_confirmed(){ 
    printf_critical_warning "ОЧЕНЬ ОПАСНО"
    if ask_yes_no "Подтверждаешь PURGE gateway-данных? (y/n)" "n"; then 
        _vgw_run_action uninstall-purge --non-interactive --yes-purge
        _vgw_rollback_nginx_injection
        rm -rf "${_VGW_PERSIST_DIR}" 2>/dev/null || true
    fi
}

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


