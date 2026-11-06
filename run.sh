#!/usr/bin/env bash
# Запуск одной командой (Linux/macOS):  ./run.sh            — локально
#                                       ./run.sh --remote   — доступ с других компьютеров
# Ключ Gemini можно передать заранее:   LLM_API_KEY=... ./run.sh
set -euo pipefail
cd "$(dirname "$0")"
PORT="${PORT:-8000}"
PY="${PYTHON:-python3}"; command -v "$PY" >/dev/null 2>&1 || PY=python

[ -d .venv ] || "$PY" -m venv .venv
# shellcheck disable=SC1091
. .venv/bin/activate
python -m pip install -q -r requirements.txt

PORT="$PORT" python -m tools.setup_env "$@"
python -m tools.check_llm || echo "! ИИ недоступен — сервер всё равно запустится в режиме rules_only."

HOST=127.0.0.1; [ "${1:-}" = "--remote" ] && HOST=0.0.0.0
echo "Запуск: http://127.0.0.1:$PORT (Ctrl+C — остановить)"
exec python -m uvicorn backend.main:app --host "$HOST" --port "$PORT"
