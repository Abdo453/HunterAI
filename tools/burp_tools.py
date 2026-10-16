"""Burp Suite Tool Adapter — L1"""
from __future__ import annotations

from typing import Optional, List
from tools.tool_manager import ToolManager, ToolResult


class BurpTools:
    def __init__(self, mgr: ToolManager):
        self.mgr = mgr

    def is_available(self) -> bool:
        return self.mgr.is_available("burp")

    async def scan(self, target: str, config: Optional[str] = None, timeout: int = 600) -> ToolResult:
        cmd_parts = ["burp", "-scan", target, "-format", "json"]
        if config:
            cmd_parts += ["-config", config]
        return await self.mgr.execute(" ".join(cmd_parts), timeout=timeout)
