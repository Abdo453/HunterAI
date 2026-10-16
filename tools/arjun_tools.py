"""Arjun Tool Adapter — L1"""
from __future__ import annotations

from typing import Optional, List
from tools.tool_manager import ToolManager, ToolResult


class ArjunTools:
    def __init__(self, mgr: ToolManager):
        self.mgr = mgr

    def is_available(self) -> bool:
        return self.mgr.is_available("arjun")

    async def scan(self, url: str, timeout: int = 600) -> ToolResult:
        cmd_parts = ["arjun", "-u", url, "--json"]
        return await self.mgr.execute(" ".join(cmd_parts), timeout=timeout)
