#!/usr/bin/env python3
"""Validate the canonical HunterAI project skill and generated mirrors."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    installer = REPO_ROOT / "tools" / "install_opencode_skills.py"
    result = subprocess.run([sys.executable, str(installer), "--check"], cwd=REPO_ROOT)
    if result.returncode:
        print("Skill validation failed. Edit skills/registry.json or the canonical skills/ tree, then synchronize with --clean.")
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
