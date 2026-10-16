"""testssl.sh Tool Adapter — L1"""
from __future__ import annotations

from typing import Optional, List
from tools.tool_manager import ToolManager, ToolResult


class TestsslTools:
    def __init__(self, mgr: ToolManager):
        self.mgr = mgr

    def is_available(self) -> bool:
        return self.mgr.is_available("testssl.sh")

    async def scan(self, target: str, timeout: int = 600) -> ToolResult:
        cmd_parts = ["testssl.sh", "--json", target]
        return await self.mgr.execute(" ".join(cmd_parts), timeout=timeout)
