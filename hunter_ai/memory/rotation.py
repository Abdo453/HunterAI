"""
HunterAI Memory Rotation — JSONL file rotation for hunt memory
==============================================================
Size-based rotation (10MB cap, keep 3 backups).
"""
from __future__ import annotations

import os
from pathlib import Path


def rotate_memory(cap_mb: int = 10, backups: int = 3, memory_dir: str = "memory/leads") -> None:
    """Rotate JSONL memory files exceeding cap_mb."""
    mem_dir = Path(memory_dir)
    if not mem_dir.exists():
        print(f"[Memory GC] {memory_dir} does not exist — nothing to rotate")
        return

    cap_bytes = cap_mb * 1024 * 1024
    for jsonl_file in mem_dir.glob("*.jsonl"):
        size = jsonl_file.stat().st_size
        if size > cap_bytes:
            # Rotate: rename current to .1, shift others
            for i in range(backups, 0, -1):
                backup = jsonl_file.with_suffix(f".jsonl.{i}")
                if backup.exists():
                    if i == backups:
                        backup.unlink()
                    else:
                        backup.rename(jsonl_file.with_suffix(f".jsonl.{i + 1}"))
            jsonl_file.rename(jsonl_file.with_suffix(".jsonl.1"))
            jsonl_file.touch()
            print(f"[Memory GC] Rotated {jsonl_file.name} ({size / 1024 / 1024:.1f} MB)")
