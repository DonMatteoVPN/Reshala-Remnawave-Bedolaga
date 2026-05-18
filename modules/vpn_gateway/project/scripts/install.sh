#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# Автоустановка VPN Gateway в один запуск.
# Цель: максимально простой старт без ручной рутины.
# ============================================================

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CFG_FILE="${ROOT_DIR}/config/gateway.yml"
CFG_EXAMPLE_FILE="${ROOT_DIR}/config/gateway.example.yml"
VENV_PYTHON="${ROOT_DIR}/.venv/bin/python"

log() { echo "[install] $*"; }
warn() { echo "[warn] $*"; }
err() { echo "[error] $*" >&2; }

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    err "Не найдена команда: ${cmd}"
    return 1
  fi
}

# ============================================================
# Авто-установка Docker Engine + Docker Compose Plugin
# Источник: https://get.docker.com (официальный скрипт Docker Inc.)
# Ставит самую свежую стабильную версию docker-ce + docker-compose-plugin
# ============================================================
auto_install_docker() {
  if command -v docker > /dev/null 2>&1; then
    log "Docker уже установлен: $(docker --version)"
    return 0
  fi

  log "Docker не найден. Устанавливаю автоматически..."

  if [[ "$(id -u)" -ne 0 ]]; then
    err "Для установки Docker нужны права root. Запустите скрипт через sudo или от root."
    exit 1
  fi

  # Требуется curl или wget
  if command -v curl > /dev/null 2>&1; then
    log "Скачиваю официальный install-скрипт Docker (get.docker.com)..."
    curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
  elif command -v wget > /dev/null 2>&1; then
    log "Скачиваю официальный install-скрипт Docker через wget..."
    wget -qO /tmp/get-docker.sh https://get.docker.com
  else
    err "Не найден ни curl, ни wget. Установите один из них: apt install curl"
    exit 1
  fi

  log "Запускаю установку Docker Engine..."
  sh /tmp/get-docker.sh
  rm -f /tmp/get-docker.sh

  # Включаем и запускаем docker.service
  if command -v systemctl > /dev/null 2>&1; then
    systemctl enable docker --now 2>/dev/null || true
  fi

  if ! command -v docker > /dev/null 2>&1; then
    err "Установка Docker завершилась, но команда 'docker' недоступна. Проверьте PATH."
    exit 1
  fi

  log "Docker успешно установлен: $(docker --version)"
}

# ============================================================
# Авто-установка python3 если не найден
# ============================================================
auto_install_python3() {
  if command -v python3 > /dev/null 2>&1; then
    return 0
  fi

  log "python3 не найден. Пробую установить через apt..."
  if command -v apt-get > /dev/null 2>&1; then
    apt-get update -qq && apt-get install -y python3 python3-venv python3-pip -qq
  else
    err "Не удалось установить python3 автоматически. Установите вручную: apt install python3"
    exit 1
  fi

  if ! command -v python3 > /dev/null 2>&1; then
    err "python3 не найден после установки."
    exit 1
  fi
  log "python3 установлен: $(python3 --version)"
}

validate_config() {
  CFG_FILE="${CFG_FILE}" python3 - <<'PY'
import os
from pathlib import Path
import yaml

cfg_path = Path(os.environ["CFG_FILE"])
if not cfg_path.exists():
    raise SystemExit("config/gateway.yml отсутствует")

cfg = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
quick = cfg.get("quick_setup", {})
required = ["public_domain", "origin_domain", "origin_scheme", "default_offer"]
missing = [k for k in required if not str(quick.get(k, "")).strip()]
if missing:
    raise SystemExit("Не заполнены обязательные поля quick_setup: " + ", ".join(missing))

print("OK")
PY
}

show_next_steps_and_exit() {
  cat <<'EOF'

[install] Создан config/gateway.yml из шаблона.
[install] Заполните блок "БЛОК ДЛЯ РЕДАКТИРОВАНИЯ" и запустите снова:

  nano config/gateway.yml
  ./scripts/install.sh

EOF
  exit 0
}

# ── Авто-установка всех зависимостей ──────────────────────────
auto_install_python3
auto_install_docker

log "Проверяю зависимости..."
require_cmd python3

# Поддерживаем docker compose plugin (v2+) и legacy docker-compose
if docker compose version > /dev/null 2>&1; then
  DC_CMD="docker compose"
elif command -v docker-compose > /dev/null 2>&1; then
  DC_CMD="docker-compose"
else
  # docker-compose-plugin ставится вместе с docker-ce через get.docker.com
  # но на некоторых системах может потребоваться отдельная установка
  log "Docker Compose Plugin не найден. Пробую установить через apt..."
  if command -v apt-get > /dev/null 2>&1; then
    apt-get update -qq && apt-get install -y docker-compose-plugin -qq
    if docker compose version > /dev/null 2>&1; then
      DC_CMD="docker compose"
    else
      err "Не удалось установить Docker Compose Plugin."
      exit 1
    fi
  else
    err "Не найден ни 'docker compose', ни 'docker-compose'. Установите Docker Compose Plugin."
    exit 1
  fi
fi
log "Docker Compose: ${DC_CMD} ($(${DC_CMD} version --short 2>/dev/null || echo 'ok'))"

# Проверяем PyYAML — если нет, устанавливаем автоматически
if ! python3 -c "import yaml" 2>/dev/null; then
  log "PyYAML не найден. Пробую установить автоматически..."
  PYYAML_INSTALLED=0

  # 1. Пробуем apt (наиболее надежно)
  if command -v apt-get &>/dev/null; then
    log "Устанавливаю python3-yaml через apt..."
    apt-get update -qq && apt-get install -y python3-yaml -qq && PYYAML_INSTALLED=1
  fi

  # 2. Пробуем venv
  if [[ "${PYYAML_INSTALLED}" -eq 0 ]] && [[ -x "${ROOT_DIR}/.venv/bin/pip" ]]; then
    log "Устанавливаю через venv: ${ROOT_DIR}/.venv/bin/pip"
    "${ROOT_DIR}/.venv/bin/pip" install pyyaml --quiet && PYYAML_INSTALLED=1 || warn "Установка через venv не удалась."
  fi

  # 3. Пробуем pip3
  if [[ "${PYYAML_INSTALLED}" -eq 0 ]] && command -v pip3 &>/dev/null; then
    log "Устанавливаю через системный pip3..."
    (pip3 install pyyaml --quiet || pip3 install pyyaml --quiet --break-system-packages) && PYYAML_INSTALLED=1 || warn "Установка через pip3 не удалась."
  fi

  if [[ "${PYYAML_INSTALLED}" -eq 0 ]]; then
    err "Не удалось автоматически установить PyYAML."
    err "Установите вручную: apt install python3-yaml"
    exit 1
  fi

  if ! python3 -c "import yaml" 2>/dev/null; then
    err "PyYAML установлен, но python3 его не видит. Проверь PATH и окружение."
    exit 1
  fi
  log "PyYAML успешно установлен."
fi

# Venv — создаём автоматически если не существует
if [[ ! -x "${VENV_PYTHON}" ]]; then
  log "venv не найден. Создаю окружение: ${ROOT_DIR}/.venv ..."
  if python3 -m venv "${ROOT_DIR}/.venv"; then
    log "venv создан успешно."
    # Устанавливаем зависимости если есть requirements.txt
    if [[ -f "${ROOT_DIR}/requirements.txt" ]]; then
      log "Устанавливаю зависимости из requirements.txt..."
      "${ROOT_DIR}/.venv/bin/pip" install -r "${ROOT_DIR}/requirements.txt" --quiet \
        && log "Зависимости установлены." \
        || warn "Не удалось установить часть зависимостей. Продолжаю..."
    fi
  else
    warn "Не удалось создать venv. Тесты будут пропущены."
  fi
fi

if [[ ! -f "${CFG_FILE}" ]]; then
  if [[ -f "${CFG_EXAMPLE_FILE}" ]]; then
    log "config/gateway.yml не найден, копирую из шаблона..."
    cp "${CFG_EXAMPLE_FILE}" "${CFG_FILE}"
    show_next_steps_and_exit
  else
    err "Не найдены ни config/gateway.yml, ни config/gateway.example.yml"
    exit 1
  fi
fi

log "Проверяю корректность config/gateway.yml..."
validate_config >/dev/null

cd "${ROOT_DIR}"

# Тесты запускаем только если venv доступен (не блокируем production-установку)
if [[ -x "${VENV_PYTHON}" ]]; then
  log "Запускаю тесты проекта..."
  "${VENV_PYTHON}" -m pytest -q || warn "Часть тестов не прошла. Продолжаю установку..."
else
  warn "venv недоступен — тесты пропущены. Это нормально для production-установки."
fi

log "Запускаю production-стек..."
./scripts/run-prod.sh


log "Проверяю контейнеры..."
if ! docker ps --format '{{.Names}}' | grep -q '^vpn-gateway$'; then
  err "Контейнер vpn-gateway не запущен"
  exit 1
fi
if ! docker ps --format '{{.Names}}' | grep -q '^vpn-edge-nginx$'; then
  err "Контейнер vpn-edge-nginx не запущен"
  exit 1
fi

log "Проверяю health endpoint внутри gateway-контейнера..."
for i in {1..20}; do
  if docker exec vpn-gateway python - <<'PY' >/dev/null 2>&1
import urllib.request
urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=2)
print('ok')
PY
  then
    log "Health-check успешен"
    break
  fi
  if [[ "$i" -eq 20 ]]; then
    err "Health-check не прошел за отведенное время"
    exit 1
  fi
  sleep 1
done

log "Проверяю редирект /start внутри gateway-контейнера..."
START_CODE_INNER="$(docker exec -i vpn-gateway python - <<'PY'
import urllib.request

req = urllib.request.Request('http://127.0.0.1:8080/start?target=test-offer', method='GET')

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

opener = urllib.request.build_opener(NoRedirect)
try:
    resp = opener.open(req, timeout=3)
    print(resp.getcode())
except Exception as e:
    if hasattr(e, 'code'):
        print(e.code)
    else:
        print('000')
PY
)"
if [[ "${START_CODE_INNER}" != "302" ]]; then
  err "Ожидался HTTP 302 на /start внутри gateway, получено: ${START_CODE_INNER}"
  exit 1
fi
log "Проверка /start внутри gateway успешна (HTTP 302)"

log "Проверяю /start через edge (информационная проверка)..."
# Читаем реальный порт и домен из конфига — edge nginx слушает НЕ на стандартном 443
_EDGE_HTTPS_PORT=$(CFG_FILE="${CFG_FILE}" python3 - <<'PY'
import os, yaml
from pathlib import Path
cfg = yaml.safe_load(Path(os.environ["CFG_FILE"]).read_text(encoding="utf-8")) or {}
print(cfg.get("edge", {}).get("https_port", 443))
PY
2>/dev/null || echo "443")
_EDGE_DOMAIN=$(CFG_FILE="${CFG_FILE}" python3 - <<'PY'
import os, yaml
from pathlib import Path
cfg = yaml.safe_load(Path(os.environ["CFG_FILE"]).read_text(encoding="utf-8")) or {}
q = cfg.get("quick_setup", {})
print(q.get("public_domain", "localhost"))
PY
2>/dev/null || echo "localhost")
START_CODE_EDGE="$(curl -k -s -o /dev/null \
  -H "Host: ${_EDGE_DOMAIN}" \
  -w '%{http_code}' \
  "https://127.0.0.1:${_EDGE_HTTPS_PORT}/start?target=test-offer" || true)"
if [[ "${START_CODE_EDGE}" != "302" ]]; then
  warn "Через edge (127.0.0.1:${_EDGE_HTTPS_PORT}) получен код ${START_CODE_EDGE}."
  warn "Это нормально если внешний трафик идёт через reverse-proxy (Caddy/Nginx) на другом порту."
  warn "Проверь: curl -k -H 'Host: ${_EDGE_DOMAIN}' https://127.0.0.1:${_EDGE_HTTPS_PORT}/start"
else
  log "Проверка /start через edge успешна (HTTP 302)"
fi

log "Установка и базовая проверка завершены успешно ✅"
