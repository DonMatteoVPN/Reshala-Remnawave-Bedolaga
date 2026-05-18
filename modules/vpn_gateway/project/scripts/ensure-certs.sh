#!/usr/bin/env bash
set -euo pipefail

# Автоматический выпуск TLS-сертификата Let's Encrypt для рекламного домена.
# Если сертификат уже есть, ничего не делает.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CFG_FILE="${ROOT_DIR}/config/gateway.yml"
CERTS_DIR="${ROOT_DIR}/edge/certs"
ACME_WEBROOT_DIR="${ROOT_DIR}/edge/acme-challenge"
LE_DIR="${ROOT_DIR}/edge/letsencrypt"
FULLCHAIN="${CERTS_DIR}/fullchain.pem"
PRIVKEY="${CERTS_DIR}/privkey.pem"

# Используем venv python если есть (PyYAML может быть только там), иначе системный python3
if [[ -x "${ROOT_DIR}/.venv/bin/python" ]]; then
  PYTHON="${ROOT_DIR}/.venv/bin/python"
else
  PYTHON="python3"
fi

# Определяем docker compose команду заранее — нужна для проверки bind mount
if docker compose version &>/dev/null 2>&1; then
  DC_CMD="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
  DC_CMD="docker-compose"
else
  echo "[error] Не найден ни 'docker compose', ни 'docker-compose'." >&2; exit 1
fi

mkdir -p "${CERTS_DIR}" "${ACME_WEBROOT_DIR}" "${LE_DIR}"

readarray -t CFG_VALUES < <(CFG_FILE="${CFG_FILE}" "${PYTHON}" - <<'PY'
import os
import yaml
from pathlib import Path
cfg = yaml.safe_load(Path(os.environ["CFG_FILE"]).read_text(encoding="utf-8"))
quick = cfg.get("quick_setup", {})
project = cfg.get("project", {})
edge = cfg.get("edge", {})
print(quick.get("public_domain") or project.get("public_domain") or "")
print(quick.get("acme_email") or "")
print(str(quick.get("acme_enabled", True)).lower())
print(str(edge.get("http_port", 80)))
print(str(edge.get("https_port", 443)))
PY
)

EDGE_DOMAIN="${CFG_VALUES[0]:-}"
ACME_EMAIL="${CFG_VALUES[1]:-}"
ACME_ENABLED="${CFG_VALUES[2]:-true}"
EDGE_HTTP_PORT="${CFG_VALUES[3]:-80}"
EDGE_HTTPS_PORT="${CFG_VALUES[4]:-443}"

if [[ -z "${EDGE_DOMAIN}" ]]; then
  echo "[error] Не задан public_domain в config/gateway.yml" >&2
  exit 1
fi

if [[ -f "${FULLCHAIN}" && -f "${PRIVKEY}" ]]; then
  echo "[ok] Сертификаты уже существуют на хосте"

  # Проверяем что контейнер видит файлы через bind mount (защита от неправильного CWD при запуске)
  if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "vpn-edge-nginx"; then
    if ! docker exec vpn-edge-nginx test -f /etc/nginx/certs/fullchain.pem 2>/dev/null; then
      echo "[warn] Контейнер не видит сертификат — bind mount сломан. Пересоздаю контейнер..."
      EDGE_HTTP_PORT="${EDGE_HTTP_PORT}" EDGE_HTTPS_PORT="${EDGE_HTTPS_PORT}" \
        $DC_CMD -f docker-compose.yml -f docker-compose.edge.yml up -d --force-recreate edge-nginx
      sleep 2
      echo "[ok] Контейнер пересоздан, сертификат доступен"
    else
      echo "[ok] Контейнер видит сертификат — всё в порядке"
    fi
  fi

  exit 0
fi

# Временный self-signed сертификат для запуска edge
openssl req -x509 -nodes -newkey rsa:2048 -days 30 \
  -keyout "${PRIVKEY}" \
  -out "${FULLCHAIN}" \
  -subj "/CN=${EDGE_DOMAIN}" >/dev/null 2>&1

if [[ "${ACME_ENABLED}" != "true" ]]; then
  echo "[ok] ACME отключен, создан self-signed сертификат для ${EDGE_DOMAIN}"
  exit 0
fi

if [[ "${EDGE_DOMAIN}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "[warn] Для IP-адреса Let's Encrypt недоступен, оставляю self-signed сертификат"
  exit 0
fi

if [[ -z "${ACME_EMAIL}" || "${ACME_EMAIL}" == "admin@example.com" ]]; then
  echo "[error] Укажите валидный quick_setup.acme_email в config/gateway.yml" >&2
  exit 1
fi

cd "${ROOT_DIR}"

# Генерируем edge/.env.edge из конфига (нужен docker-compose.edge.yml для парсинга)
mkdir -p "${ROOT_DIR}/edge"
cat > "${ROOT_DIR}/edge/.env.edge" << ENVEOF
EDGE_DOMAIN=${EDGE_DOMAIN}
EDGE_HTTP_PORT=${EDGE_HTTP_PORT}
EDGE_HTTPS_PORT=${EDGE_HTTPS_PORT}
ENVEOF

EDGE_HTTP_PORT="${EDGE_HTTP_PORT}" EDGE_HTTPS_PORT="${EDGE_HTTPS_PORT}" $DC_CMD -f docker-compose.yml -f docker-compose.edge.yml up -d --build

# Выпуск сертификата через webroot-челлендж
if command -v certbot >/dev/null 2>&1; then
  certbot certonly \
    --webroot \
    -w "${ACME_WEBROOT_DIR}" \
    -d "${EDGE_DOMAIN}" \
    --email "${ACME_EMAIL}" \
    --agree-tos \
    --non-interactive \
    --rsa-key-size 4096 \
    --keep-until-expiring

  cp "/etc/letsencrypt/live/${EDGE_DOMAIN}/fullchain.pem" "${FULLCHAIN}"
  cp "/etc/letsencrypt/live/${EDGE_DOMAIN}/privkey.pem" "${PRIVKEY}"
else
  docker run --rm \
    -v "${ACME_WEBROOT_DIR}:/var/www/acme-challenge" \
    -v "${LE_DIR}:/etc/letsencrypt" \
    certbot/certbot:latest certonly \
      --webroot \
      -w /var/www/acme-challenge \
      -d "${EDGE_DOMAIN}" \
      --email "${ACME_EMAIL}" \
      --agree-tos \
      --non-interactive \
      --rsa-key-size 4096 \
      --keep-until-expiring

  cp "${LE_DIR}/live/${EDGE_DOMAIN}/fullchain.pem" "${FULLCHAIN}"
  cp "${LE_DIR}/live/${EDGE_DOMAIN}/privkey.pem" "${PRIVKEY}"
fi

EDGE_HTTP_PORT="${EDGE_HTTP_PORT}" EDGE_HTTPS_PORT="${EDGE_HTTPS_PORT}" $DC_CMD -f docker-compose.yml -f docker-compose.edge.yml restart edge-nginx

# Сохраняем сертификаты в персистентное хранилище — переживут git pull и пересоздание контейнеров
PERSIST_CERTS_DIR="/etc/reshala-bedolaga/certs"
if [[ -f "${FULLCHAIN}" && -f "${PRIVKEY}" ]]; then
  mkdir -p "${PERSIST_CERTS_DIR}" 2>/dev/null && \
    cp -f "${FULLCHAIN}" "${PERSIST_CERTS_DIR}/fullchain.pem" && \
    cp -f "${PRIVKEY}"   "${PERSIST_CERTS_DIR}/privkey.pem"   && \
    chmod 600 "${PERSIST_CERTS_DIR}/privkey.pem" && \
    echo "[ok] Сертификат сохранён в ${PERSIST_CERTS_DIR}" || \
    echo "[warn] Не удалось сохранить сертификат в ${PERSIST_CERTS_DIR}"
fi

echo "[ok] Сертификат Let's Encrypt выпущен и применён для ${EDGE_DOMAIN}"