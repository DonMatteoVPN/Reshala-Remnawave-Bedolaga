#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")/.."

# Цвета для вывода
C_RED="\e[31m"
C_GREEN="\e[32m"
C_YELLOW="\e[33m"
C_BLUE="\e[34m"
C_CYAN="\e[36m"
C_WHITE="\e[97m"
C_GRAY="\e[90m"
C_BOLD="\e[1m"
C_RESET="\e[0m"

printf_title() { printf "\n%b═══ %b ═══%b\n" "${C_CYAN}" "$*" "${C_RESET}"; }
printf_ok()    { printf "%b[✓] %b%b\n" "${C_GREEN}" "$*" "${C_RESET}"; }
printf_warn()  { printf "%b[!] %b%b\n" "${C_YELLOW}" "$*" "${C_RESET}"; }
printf_err()   { printf "%b[✗] %b%b\n" "${C_RED}" "$*" "${C_RESET}"; }
printf_info()  { printf "%b[i] %b%b\n" "${C_GRAY}" "$*" "${C_RESET}"; }

echo -e "${C_CYAN}${C_BOLD}╔══════════════════════════════════════════════════════════════╗${C_RESET}"
echo -e "${C_CYAN}${C_BOLD}║${C_RESET}  ${C_YELLOW}${C_BOLD}🔬  ПРОФЕССИОНАЛЬНАЯ ДИАГНОСТИКА И ТЕСТИРОВАНИЕ BEDOLAGA${C_RESET}   ${C_CYAN}${C_BOLD}║${C_RESET}"
echo -e "${C_CYAN}${C_BOLD}╚══════════════════════════════════════════════════════════════╝${C_RESET}"

# Шаг 0: Проверка и создание виртуального окружения
if [[ ! -x ".venv/bin/python" ]]; then
  printf_warn "Виртуальное окружение .venv не найдено. Создаю автоматически..."
  if ! python3 -m venv .venv 2>/dev/null; then
    printf_err "Не удалось создать .venv. Пожалуйста, установите пакет python3-venv:"
    echo "    apt update && apt install -y python3-venv"
    exit 1
  fi
  printf_info "Устанавливаю необходимые зависимости из requirements.txt..."
  if ! .venv/bin/pip install --quiet -r requirements.txt 2>/dev/null; then
    printf_err "Не удалось установить зависимости через pip."
    echo "    Проверьте подключение к интернету или права доступа."
    exit 1
  fi
  printf_ok "Виртуальное окружение успешно подготовлено."
fi

PYTHON=".venv/bin/python"

# Шаг 1: Запуск автоматических тестов (pytest)
printf_title "Шаг 1: Проверка целостности и логики кода (pytest)"
printf_info "Запускаю 12 автоматических юнит-тестов..."

# Run pytest but hide warnings to keep it readable, showing only failures/successes
TEST_OUTPUT=$($PYTHON -m pytest -q --tb=short -W ignore 2>&1)
TEST_STATUS=$?

if [[ $TEST_STATUS -eq 0 ]]; then
  printf_ok "Все юнит-тесты успешно пройдены! (12 passed)"
else
  printf_err "Обнаружены ошибки в логике или конфигурации кода!"
  echo -e "\n${C_RED}${C_BOLD}Вывод тестов:${C_RESET}"
  echo "$TEST_OUTPUT"
  echo -e "\n${C_YELLOW}${C_BOLD}💡 Рекомендация по решению:${C_RESET}"
  echo "   1. Проверьте правильность заполнения config/gateway.yml."
  echo "      Синтаксис YAML не должен содержать ошибок разметки."
  echo "   2. Если вы изменяли файлы в папке app/, возможно, была допущена ошибка."
  echo "      Вы можете вернуть оригинальный код команды через git:"
  echo "      git checkout app/"
  echo "   3. Попробуйте сбросить конфигурацию или запустить перенастройку из меню Решалы."
fi

# Шаг 2: Компиляция файлов Python (Синтаксический анализ)
printf_title "Шаг 2: Проверка синтаксиса файлов приложения (compileall)"
printf_info "Анализирую синтаксис файлов в папке app/..."

COMP_OUTPUT=$($PYTHON -m compileall app 2>&1)
COMP_STATUS=$?

if [[ $COMP_STATUS -eq 1 ]] || echo "$COMP_OUTPUT" | grep -q "*** Error"; then
  printf_err "Обнаружена синтаксическая ошибка в коде приложения!"
  echo -e "\n${C_RED}${C_BOLD}Вывод компилятора:${C_RESET}"
  echo "$COMP_OUTPUT"
  echo -e "\n${C_YELLOW}${C_BOLD}💡 Рекомендация по решению:${C_RESET}"
  echo "   В одном из файлов Python в папке app/ допущена синтаксическая ошибка."
  echo "   Изучите вывод выше, откройте указанный файл и исправьте опечатку."
  echo "   Для полного сброса изменений кода выполните: git checkout app/"
else
  printf_ok "Синтаксических ошибок в файлах приложения не обнаружено."
fi

# Шаг 3: Проверка статуса Docker контейнеров
printf_title "Шаг 3: Проверка состояния Docker-контейнеров стека"

GW_RUNNING=0
NX_RUNNING=0

if command -v docker &>/dev/null; then
  # vpn-gateway
  if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "vpn-gateway"; then
    printf_ok "Контейнер vpn-gateway: ЗАПУЩЕН"
    GW_RUNNING=1
  else
    printf_err "Контейнер vpn-gateway: ОСТАНОВЛЕН"
  fi

  # nginx proxy (vpn-edge-nginx или внедрённый)
  local_nginx_active=0
  if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "vpn-edge-nginx"; then
    printf_ok "Контейнер vpn-edge-nginx (встроенный прокси): ЗАПУЩЕН"
    NX_RUNNING=1
    local_nginx_active=1
  fi

  persist_inj="/etc/reshala-bedolaga/nginx_injection.env"
  if [[ -f "$persist_inj" ]]; then
    saved_type=$(grep '^NGINX_TYPE=' "$persist_inj" | cut -d= -f2-)
    if [[ "$saved_type" == "host:nginx" ]]; then
      if systemctl is-active --quiet nginx 2>/dev/null || service nginx status &>/dev/null; then
        printf_ok "Служба nginx (хостовой прокси): РАБОТАЕТ"
        NX_RUNNING=1
      else
        printf_err "Служба nginx (хостовой прокси): ОСТАНОВЛЕНА"
      fi
    elif [[ "$saved_type" == docker:* ]]; then
      cname=$(docker ps --format '{{.Names}}' 2>/dev/null | grep -i nginx | grep -v vpn-edge-nginx | head -1)
      if [[ -n "$cname" ]]; then
        printf_ok "Контейнер ${cname} (внешний прокси): ЗАПУЩЕН"
        NX_RUNNING=1
      else
        printf_err "Внешний контейнер Nginx (указанный в nginx_injection.env): ОСТАНОВЛЕН"
      fi
    fi
  elif [[ $local_nginx_active -eq 0 ]]; then
    printf_err "Контейнер vpn-edge-nginx (встроенный прокси): ОСТАНОВЛЕН"
  fi
else
  printf_err "Утилита docker не найдена на этом сервере!"
fi

if [[ $GW_RUNNING -eq 0 ]]; then
  echo -e "\n${C_YELLOW}${C_BOLD}💡 Рекомендация по решению:${C_RESET}"
  echo "   Контейнер ядра шлюза остановлен. Для его запуска выполните:"
  echo "   Пункт 3 меню Решалы (Перезапуск стека) или Пункт 1/2 (Мастер настройки)."
fi

# Шаг 4: Тест сетевого отклика веб-сервера (Smoke Test)
printf_title "Шаг 4: Тестирование сетевых ответов шлюза (HTTP/HTTPS)"

# Пробуем проверить локальный отклик ядра шлюза внутри контейнера
if [[ $GW_RUNNING -eq 1 ]]; then
  printf_info "Проверяю отклик ядра vpn-gateway внутри контейнера (порт 8080)..."
  GATEWAY_HEALTH=$(docker exec vpn-gateway curl -fsS http://localhost:8080/health 2>&1)
  if [[ $? -eq 0 ]] || [[ "$GATEWAY_HEALTH" == *"ok"* ]] || [[ "$GATEWAY_HEALTH" == *"status"* ]]; then
    printf_ok "Ядро шлюза внутри контейнера успешно отвечает на запросы!"
  else
    printf_err "Ядро шлюза внутри контейнера вернуло пустой или некорректный ответ."
    echo -e "   Получено: $GATEWAY_HEALTH"
  fi
fi

# Читаем домен и порты для проверки проксирования
if [[ -f "config/gateway.yml" ]]; then
  readarray -t CFG_VALUES < <(CFG_FILE="config/gateway.yml" "${PYTHON}" - <<'PY'
import os, yaml
from pathlib import Path
try:
    cfg = yaml.safe_load(Path(os.environ["CFG_FILE"]).read_text(encoding="utf-8")) or {}
    quick = cfg.get("quick_setup", {})
    edge = cfg.get("edge", {})
    print(quick.get("public_domain") or "")
    print(str(edge.get("http_port", 80)))
    print(str(edge.get("https_port", 443)))
except:
    print("")
    print("80")
    print("443")
PY
)
  DOMAIN="${CFG_VALUES[0]:-}"
  HTTP_PORT="${CFG_VALUES[1]:-80}"
  HTTPS_PORT="${CFG_VALUES[2]:-443}"

  if [[ -n "$DOMAIN" && "$DOMAIN" != "vpn.example.com" ]]; then
    printf_info "Тестирую внешние порты прокси Nginx на хосте для домена '${DOMAIN}'..."

    # Проверка HTTP порта
    printf_info "Проверка HTTP (запрос на порт ${HTTP_PORT} с Host: ${DOMAIN})..."
    HTTP_RESP=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: ${DOMAIN}" http://127.0.0.1:${HTTP_PORT}/health --connect-timeout 3 2>&1)
    HTTP_STATUS=$?
    
    if [[ $HTTP_STATUS -eq 0 ]]; then
      printf_ok "HTTP-порт ${HTTP_PORT} активен. Ответ сервера: HTTP ${HTTP_RESP}"
    else
      printf_err "Не удалось подключиться к HTTP-порту ${HTTP_PORT}."
      printf_info "Код ошибки curl: ${HTTP_STATUS} ($HTTP_RESP)"
    fi

    # Проверка HTTPS порта
    printf_info "Проверка HTTPS (запрос на порт ${HTTPS_PORT} с Host: ${DOMAIN})..."
    HTTPS_RESP=$(curl -s -k -o /dev/null -w "%{http_code}" -H "Host: ${DOMAIN}" https://127.0.0.1:${HTTPS_PORT}/health --connect-timeout 3 2>&1)
    HTTPS_STATUS=$?

    if [[ $HTTPS_STATUS -eq 0 ]]; then
      printf_ok "HTTPS-порт ${HTTPS_PORT} активен (проверка SSL пропущена). Ответ сервера: HTTP ${HTTPS_RESP}"
    else
      printf_err "Не удалось подключиться к HTTPS-порту ${HTTPS_PORT}."
      printf_info "Код ошибки curl: ${HTTPS_STATUS} ($HTTPS_RESP)"
    fi

    # Общие рекомендации по сетевым ошибкам
    if [[ $HTTP_STATUS -ne 0 ]] || [[ $HTTPS_STATUS -ne 0 ]]; then
      echo -e "\n${C_YELLOW}${C_BOLD}💡 Рекомендация по решению:${C_RESET}"
      echo "   Один из внешних портов проксирования не отвечает."
      echo "   1. Убедитесь, что порты ${HTTP_PORT} и ${HTTPS_PORT} не заняты другими веб-серверами"
      echo "      (например, Apache или другим Nginx на хосте). Проверить занятость портов:"
      echo "      netstat -tulpn | grep -E '${HTTP_PORT}|${HTTPS_PORT}'"
      echo "   2. Проверьте логи Nginx:"
      echo "      В меню Решалы выберите пункт 4 (Статус и журналы)"
      echo "   3. Если домен '${DOMAIN}' только что куплен, DNS A-запись могла ещё не обновиться."
    fi
  else
    printf_warn "Домен лендинга не настроен. Проверка внешних портов пропущена."
  fi
else
  printf_warn "Файл config/gateway.yml не найден. Проверка внешних портов пропущена."
fi

echo -e "\n${C_CYAN}══════════════════════════════════════════════════════════════${C_RESET}"
