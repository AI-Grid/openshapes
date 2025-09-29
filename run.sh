#!/usr/bin/env bash
set -euo pipefail
export FLASK_APP=server.app
export FLASK_RUN_PORT="${FLASK_RUN_PORT:-5000}"
export FLASK_ENV=production
flask run --host=0.0.0.0 --port="$FLASK_RUN_PORT"
