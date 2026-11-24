#!/usr/bin/env sh
# DARK-JWT-INSPECTOR launcher - no root, no sudo. Works from any directory.
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
if [ -x "$SCRIPT_DIR/.venv/bin/python" ]; then
    PY="$SCRIPT_DIR/.venv/bin/python"
else
    PY=$(command -v python3 || command -v python || true)
fi
if [ -z "$PY" ]; then
    echo "[!] Python 3 not found. Run: sh install.sh   (it prints the right install command)" >&2
    exit 1
fi
exec "$PY" "$SCRIPT_DIR/main.py" "$@"
