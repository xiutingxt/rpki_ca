#!/usr/bin/env bash
set -Eeuo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [[ -n "${PYTHON:-}" ]]; then
    PYTHON_BIN="$PYTHON"
elif command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN=python3
else
    PYTHON_BIN=python
fi
exec "$PYTHON_BIN" "$SCRIPT_DIR/independent_verify.py" "$@"
