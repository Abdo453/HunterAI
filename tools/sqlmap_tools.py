"""SQLmap Tool Adapter — L1"""
from __future__ import annotations

from typing import Optional, List
from tools.tool_manager import ToolManager, ToolResult


class SQLmapTools:
    def __init__(self, mgr: ToolManager):
        self.mgr = mgr

    def is_available(self) -> bool:
        return self.mgr.is_available("sqlmap")

    async def scan(self, url: str, data: Optional[str] = None, level: int = 1, risk: int = 1, timeout: int = 600) -> ToolResult:
        cmd_parts = ["sqlmap", "-u", url, "--batch", "--level", str(level), "--risk", str(risk), "--output", "json"]
        if data:
            cmd_parts += ["--data", data]
        return await self.mgr.execute(" ".join(cmd_parts), timeout=timeout)
