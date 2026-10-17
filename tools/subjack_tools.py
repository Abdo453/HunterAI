"""Subjack Tool Adapter — L1"""
from __future__ import annotations

from typing import Optional, List
from tools.tool_manager import ToolManager, ToolResult


class SubjackTools:
    def __init__(self, mgr: ToolManager):
        self.mgr = mgr

    def is_available(self) -> bool:
        return self.mgr.is_available("subjack")

    async def scan(self, targets_file: str, timeout: int = 300) -> ToolResult:
        cmd_parts = ["subjack", "-w", targets_file, "-o", "json", "-t", "50"]
        cmd = " ".join(cmd_parts)
        return await self.mgr.execute(cmd, timeout=timeout)
