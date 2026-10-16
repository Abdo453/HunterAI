"""Dalfox Tool Adapter — L1"""
from __future__ import annotations

from typing import Optional, List
from tools.tool_manager import ToolManager, ToolResult


class DalfoxTools:
    def __init__(self, mgr: ToolManager):
        self.mgr = mgr

    def is_available(self) -> bool:
        return self.mgr.is_available("dalfox")

    async def scan(self, url: str, timeout: int = 600) -> ToolResult:
        cmd_parts = ["dalfox", "url", url, "--format", "json"]
        return await self.mgr.execute(" ".join(cmd_parts), timeout=timeout)
