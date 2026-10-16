#!/bin/sh
set -eu

PROJECT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PYTHON=${PYTHON:-python3}
AGENT_ENV="$HOME/.network_security_agent/venv"

if ! command -v "$PYTHON" >/dev/null 2>&1; then
    echo "Python 3.10 or newer is required (set PYTHON to its executable)." >&2
    exit 1
fi

"$PYTHON" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' || {
    echo "Python 3.10 or newer is required." >&2
    exit 1
}

mkdir -p "$HOME/.network_security_agent"
"$PYTHON" -m venv "$AGENT_ENV"
"$AGENT_ENV/bin/python" -m pip install --upgrade pip
"$AGENT_ENV/bin/python" -m pip install -r "$PROJECT_DIR/requirements.txt"

echo "Python setup completed."
echo "Run: bash \"$PROJECT_DIR/run_dashboard.sh\""
echo "For optional local AI, install Ollama and run: ollama pull qwen2.5:3b"
