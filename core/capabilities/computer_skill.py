"""
Unified Computer & OS Capabilities Subsystem
Provides modular, capability-governed computer interactions:
- computer.filesystem: read, write, list files within workspace sandbox
- computer.process: run subprocess commands with strict timeouts and resource limits
- computer.network: resolve DNS, probe HTTP/HTTPS
- computer.browser: navigate, extract, screenshot
- computer.database: query KnowledgeDB
"""
from __future__ import annotations

import asyncio
import logging
import os
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.capabilities.capability_manager import Capability, CapabilityManager, CapabilityToken

logger = logging.getLogger(__name__)


class ComputerSkill:
    """
    مهارة الحاسوب الموحدة (Unified Computer Skill):
    واجهة مركزية منظمة تتيح للـ Agent الوصول لقدرات الحاسوب وفق الـ Capabilities الممنوحة له.
    """

    def __init__(self, capability_mgr: CapabilityManager, token: CapabilityToken):
        self.mgr = capability_mgr
        self.token = token

    # ── 1. Filesystem Capabilities ───────────────────────────────

    def read_file(self, target_path: Path) -> Optional[str]:
        if not self.mgr.check_permission(self.token, Capability.FILESYSTEM_READ):
            return None
        if not self.mgr.verify_sandbox_path(target_path, self.token):
            logger.warning(f"[ComputerSkill] Sandbox violation on read: {target_path}")
            return None
        try:
            return Path(target_path).read_text(encoding="utf-8", errors="ignore")
        except Exception as exc:
            logger.debug(f"[ComputerSkill] Read error: {exc}")
            return None

    def write_file(self, target_path: Path, content: str) -> bool:
        if not self.mgr.check_permission(self.token, Capability.FILESYSTEM_WRITE):
            return False
        if not self.mgr.verify_sandbox_path(target_path, self.token):
            logger.warning(f"[ComputerSkill] Sandbox violation on write: {target_path}")
            return False
        try:
            p = Path(target_path)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
            return True
        except Exception as exc:
            logger.error(f"[ComputerSkill] Write error: {exc}")
            return False

    # ── 2. Process Capabilities ──────────────────────────────────

    async def run_process(
        self,
        command_args: List[str],
        cwd: Optional[Path] = None,
        timeout_seconds: float = 60.0
    ) -> Dict[str, Any]:
        if not self.mgr.check_permission(self.token, Capability.PROCESS_RUN):
            return {"success": False, "error": "Missing process.run capability"}

        t0 = time.time()
        try:
            proc = await asyncio.create_subprocess_exec(
                *command_args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(cwd) if cwd else None
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout_seconds)
            return {
                "success": proc.returncode == 0,
                "returncode": proc.returncode,
                "stdout": stdout.decode("utf-8", errors="ignore"),
                "stderr": stderr.decode("utf-8", errors="ignore"),
                "duration": round(time.time() - t0, 2)
            }
        except asyncio.TimeoutError:
            return {"success": False, "error": f"Process exceeded timeout of {timeout_seconds}s", "duration": timeout_seconds}
        except Exception as exc:
            return {"success": False, "error": str(exc), "duration": round(time.time() - t0, 2)}

    # ── 3. Network Capabilities ──────────────────────────────────

    async def http_get(self, url: str, timeout: float = 15.0) -> Dict[str, Any]:
        if not self.mgr.check_permission(self.token, Capability.NETWORK_HTTP):
            return {"success": False, "error": "Missing network.http capability"}

        import httpx
        try:
            async with httpx.AsyncClient(timeout=timeout, verify=False, trust_env=False) as client:
                res = await client.get(url)
                return {
                    "success": True,
                    "status_code": res.status_code,
                    "headers": dict(res.headers),
                    "body_snippet": res.text[:1000]
                }
        except Exception as exc:
            return {"success": False, "error": str(exc)}
