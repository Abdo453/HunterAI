#!/usr/bin/env bash
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
python3 "$REPO_DIR/scripts/network_analyst.py" "$@"
