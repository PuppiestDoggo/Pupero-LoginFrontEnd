#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
[ -d .venv ] && source .venv/bin/activate || true
export FLASK_APP=app.py
export FLASK_RUN_HOST=0.0.0.0
export FLASK_RUN_PORT=${PORT:-5000}
flask run --host "$FLASK_RUN_HOST" --port "$FLASK_RUN_PORT"