"""Gitleaks Tool Adapter — L1"""
from __future__ import annotations

from typing import Optional, List
from tools.tool_manager import ToolManager, ToolResult


class GitleaksTools:
    def __init__(self, mgr: ToolManager):
        self.mgr = mgr

    def is_available(self) -> bool:
        return self.mgr.is_available("gitleaks")

    async def scan(self, target: str, timeout: int = 600) -> ToolResult:
        cmd_parts = ["gitleaks", "detect", "--source", target, "--format", "json"]
        return await self.mgr.execute(" ".join(cmd_parts), timeout=timeout)
