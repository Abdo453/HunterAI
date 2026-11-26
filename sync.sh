#!/usr/bin/env bash
# ==============================================================================
# HunterAI — Local Manifest & Skill Mirror Synchronization Script
# Synchronizes canonical tool manifests and project skill mirrors strictly from
# local repository sources (never fetches remote code over unauthenticated HTTP).
# ==============================================================================
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_DIR"

PYTHON_BIN="${PYTHON_BIN:-python3}"
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
    PYTHON_BIN="python"
fi

echo "[*] Synchronizing canonical tool manifests from config/tools.catalog.yaml..."
"$PYTHON_BIN" scripts/sync_tool_manifests.py --write
"$PYTHON_BIN" scripts/sync_tool_manifests.py --check

echo "[*] Synchronizing canonical HunterAI project skill mirrors..."
"$PYTHON_BIN" tools/install_opencode_skills.py --clean
"$PYTHON_BIN" tools/install_opencode_skills.py --check

echo "[+] Local sync completed cleanly."
