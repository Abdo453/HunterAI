"""BBOT Tool Adapter — L1"""
from __future__ import annotations

from typing import Optional, List
from tools.tool_manager import ToolManager, ToolResult


class BBOTTools:
    def __init__(self, mgr: ToolManager):
        self.mgr = mgr

    def is_available(self) -> bool:
        return self.mgr.is_available("bbot")

    async def scan(self, target: str, modules: Optional[str] = None, timeout: int = 600) -> ToolResult:
        cmd_parts = ["bbot", "-t", target, "-f", "json"]
        if modules:
            cmd_parts += ["-m", modules]
        return await self.mgr.execute(" ".join(cmd_parts), timeout=timeout)
