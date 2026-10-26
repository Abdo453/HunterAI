"""Process-tree termination helpers.

``asyncio.subprocess.Process.kill()`` only terminates the immediate child.  When
a command is launched through a shell (``create_subprocess_shell`` on Windows
spawns ``cmd.exe``), the real workload survives as an orphan after a timeout and
can keep scanning the target.  ``kill_process_tree`` walks the descendants with
psutil, kills them, and reaps the asyncio transport so no pipes leak.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Optional

logger = logging.getLogger(__name__)


async def kill_process_tree(
    proc: Optional["asyncio.subprocess.Process"],
    wait_timeout: float = 5.0,
) -> None:
    """Terminate ``proc`` and every descendant, then reap it. Never raises."""
    if proc is None:
        return

    try:
        import psutil

        try:
            parent = psutil.Process(proc.pid)
            children = parent.children(recursive=True)
        except psutil.NoSuchProcess:
            children = []
            parent = None

        for child in children:
            try:
                child.kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        if parent is not None:
            try:
                parent.kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        targets = ([parent] if parent is not None else []) + children
        if targets:
            await asyncio.to_thread(psutil.wait_procs, targets, wait_timeout)
    except Exception as exc:  # pragma: no cover - defensive fallback
        logger.debug("kill_process_tree fallback: %s", exc)
        try:
            proc.kill()
        except Exception:
            pass

    try:
        await proc.wait()
    except Exception:
        pass
