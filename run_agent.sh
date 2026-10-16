#!/bin/sh
set -eu

PROJECT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
AGENT_PYTHON="$HOME/.network_security_agent/venv/bin/python"

if [ ! -x "$AGENT_PYTHON" ]; then
    echo "Run bash setup_unix.sh first." >&2
    exit 1
fi

cd "$PROJECT_DIR"
exec "$AGENT_PYTHON" -B network_threat_detection.py "$@"
