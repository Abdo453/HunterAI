#!/usr/bin/env bash
# Quick Launcher for PentestAI Unified / HunterAI
set -e

# Detect script directory and project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/pentest.py" ]; then
    PROJECT_DIR="$SCRIPT_DIR"
elif [ -f "$SCRIPT_DIR/PentestAI-Unified/pentest.py" ]; then
    PROJECT_DIR="$SCRIPT_DIR/PentestAI-Unified"
elif [ -f "/mnt/e/Agant/PentestAI-Unified/pentest.py" ]; then
    PROJECT_DIR="/mnt/e/Agant/PentestAI-Unified"
else
    PROJECT_DIR="$HOME/Desktop/PentestAI-Unified"
fi

cd "$PROJECT_DIR"
export PATH="$HOME/.local/bin:$PATH"

# Auto-detect Ollama Host for WSL or Native Linux
if curl -s -m 1 http://127.0.0.1:11434/api/version >/dev/null 2>&1; then
    export OLLAMA_HOST="http://127.0.0.1:11434"
elif curl -s -m 1 http://172.17.80.1:11434/api/version >/dev/null 2>&1; then
    export OLLAMA_HOST="http://172.17.80.1:11434"
else
    WSL_GATEWAY=$(ip route | grep default | awk '{print $3}')
    if [ -n "$WSL_GATEWAY" ] && curl -s -m 1 "http://${WSL_GATEWAY}:11434/api/version" >/dev/null 2>&1; then
        export OLLAMA_HOST="http://${WSL_GATEWAY}:11434"
    fi
fi

if [ -z "$1" ]; then
    echo "=========================================================="
    echo "  🛡️  PentestAI Unified / HunterAI — Launcher"
    echo "=========================================================="
    echo "  Project Dir:     $PROJECT_DIR"
    echo "  Ollama Service:  ${OLLAMA_HOST:-Offline / Localhost}"
    echo "  Usage examples:"
    echo "    ./run_hunter.sh web               # Launch Unified Web UI (:8000)"
    echo "    ./run_hunter.sh opencode          # Launch OpenCode Studio Hub (:8000/opencode)"
    echo "    ./run_hunter.sh status            # View AI Provider & Engine status"
    echo "    ./run_hunter.sh arsenal           # View 63 Kali tools arsenal"
    echo "    ./run_hunter.sh wordlist pass     # Cognitive SecLists search"
    echo "=========================================================="
    python3 pentest.py --help
else
    python3 pentest.py "$@"
fi
