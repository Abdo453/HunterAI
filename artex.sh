#!/usr/bin/env bash
# ==============================================================================
#  ARTEX-Pro Unified Multi-Agent Offensive Security Architecture Launcher
#  ONE COMMAND FOR EVERYTHING: PostgreSQL + Go Core + Django ASGI + Next.js
# ==============================================================================

set -e

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$BASE_DIR"

if command -v python3 &>/dev/null; then
    PYTHON_BIN="python3"
else
    PYTHON_BIN="python"
fi

exec "$PYTHON_BIN" pentest.py artex "$@"
