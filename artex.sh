#!/usr/bin/env bash
# ==============================================================================
#  ARTEX-Pro Unified Multi-Agent Offensive Security Architecture Launcher
#  Go High-Concurrency Core + PostgreSQL 16+ + Next.js 15 Reactive Dashboard
# ==============================================================================

set -e

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$BASE_DIR/backend"
FRONTEND_DIR="$BASE_DIR/frontend"

echo "=================================================================="
echo "  ⚡ ARTEX-Pro Unified Autonomous System Launcher"
echo "=================================================================="

# Check PostgreSQL service
if ! pgrep -x "postgres" > /dev/null; then
    echo "[*] Starting PostgreSQL service..."
    sudo service postgresql start
fi

MODE="${1:-server}"
TARGET="${2:-}"

if [ "$MODE" = "scan" ] && [ -n "$TARGET" ]; then
    echo "[+] Launching Headless Go Autonomous Scan on: $TARGET"
    cd "$BACKEND_DIR"
    bin/artex-server -target "$TARGET"
elif [ "$MODE" = "server" ] || [ "$MODE" = "web" ]; then
    echo "[+] Starting ARTEX-Pro Go API Core on http://127.0.0.1:7071..."
    cd "$BACKEND_DIR"
    bin/artex-server -server -port 7071 &
    GO_PID=$!

    echo "[+] Starting Next.js 15 Modern Dashboard on http://127.0.0.1:3000..."
    cd "$FRONTEND_DIR"
    npm run dev &
    FRONT_PID=$!

    echo "=================================================================="
    echo "  [✓] ARTEX-Pro System Active:"
    echo "      • Go API Backend:    http://127.0.0.1:7071/api/v1/health"
    echo "      • Next.js Dashboard: http://127.0.0.1:3000"
    echo "      • PostgreSQL DB:     127.0.0.1:5432 (artex_pro)"
    echo "=================================================================="

    trap "kill $GO_PID $FRONT_PID 2>/dev/null; exit 0" SIGINT SIGTERM
    wait
else
    echo "Usage: ./artex.sh [web|server|scan <domain>]"
fi
