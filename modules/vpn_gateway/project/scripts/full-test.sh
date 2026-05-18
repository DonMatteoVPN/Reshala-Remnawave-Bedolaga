#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

# Запускаем тесты и компиляцию через виртуальное окружение проекта.
if [[ ! -x ".venv/bin/python" ]]; then
  echo "[warn] .venv не найден, создаю автоматически..." >&2
  python3 -m venv .venv || { echo "[error] Не удалось создать venv (нужен python3-venv)" >&2; exit 1; }
  .venv/bin/pip install --quiet -r requirements.txt || { echo "[error] Не удалось установить зависимости" >&2; exit 1; }
  echo "[ok] venv создан и зависимости установлены" >&2
fi

.venv/bin/python -m pytest -q
.venv/bin/python -m compileall app
curl -fsS http://127.0.0.1:8080/health > /dev/null || true
