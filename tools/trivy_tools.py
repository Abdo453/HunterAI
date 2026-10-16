"""Trivy Tool Adapter — L1"""
from __future__ import annotations

from typing import Optional, List
from tools.tool_manager import ToolManager, ToolResult


class TrivyTools:
    def __init__(self, mgr: ToolManager):
        self.mgr = mgr

    def is_available(self) -> bool:
        return self.mgr.is_available("trivy")

    async def scan(self, target: str, scan_type: str = "fs", timeout: int = 600) -> ToolResult:
        cmd_parts = ["trivy", scan_type, "--format", "json", target]
        return await self.mgr.execute(" ".join(cmd_parts), timeout=timeout)
