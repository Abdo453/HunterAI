#!/usr/bin/env bash
# Quick Launcher for HunterAI
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/pentest.py" ]; then
    PROJECT_DIR="$SCRIPT_DIR"
elif [ -n "${HUNTERAI_ROOT:-}" ] && [ -f "$HUNTERAI_ROOT/pentest.py" ]; then
    PROJECT_DIR="$HUNTERAI_ROOT"
else
    echo "Error: Could not locate HunterAI repository (pentest.py not found in $SCRIPT_DIR)." >&2
    exit 1
fi

cd "$PROJECT_DIR"
export PATH="$HOME/.local/bin:$PATH"

# Default to localhost Ollama unless already configured
if [ -z "${OLLAMA_HOST:-}" ]; then
    if curl -s -m 1 http://127.0.0.1:11434/api/version >/dev/null 2>&1; then
        export OLLAMA_HOST="http://127.0.0.1:11434"
    else
        WSL_GATEWAY=$(ip route 2>/dev/null | awk '/default/ {print $3; exit}' || true)
        if [ -n "$WSL_GATEWAY" ] && curl -s -m 1 "http://${WSL_GATEWAY}:11434/api/version" >/dev/null 2>&1; then
            export OLLAMA_HOST="http://${WSL_GATEWAY}:11434"
        fi
    fi
fi

if [ -z "${1:-}" ]; then
    echo "=========================================================="
    echo "  HunterAI — Unified CLI Launcher"
    echo "=========================================================="
    echo "  Project Dir:     $PROJECT_DIR"
    echo "  Ollama Service:  ${OLLAMA_HOST:-http://127.0.0.1:11434 (offline)}"
    echo "  Usage examples:"
    echo "    ./run_hunter.sh artex             # Launch ARTEX-Pro UI (:3000 + :8000)"
    echo "    ./run_hunter.sh web               # Launch Unified Web UI (:3000 + :8000)"
    echo "    ./run_hunter.sh opencode          # Launch OpenCode Studio Hub (:3000/studio)"
    echo "    ./run_hunter.sh status            # View AI Provider & Engine status"
    echo "    ./run_hunter.sh arsenal           # View Kali tools arsenal"
    echo "=========================================================="
    python3 pentest.py --help
else
    python3 pentest.py "$@"
fi
