"""Subfinder Tool Adapter — L1: واجهة تشغيل موحدة لـ Subfinder مع مخرجات JSON منظمة"""
from __future__ import annotations

from typing import Optional, List
from tools.tool_manager import ToolManager, ToolResult


class SubfinderTools:
    """
    L1 Tool Adapter لـ Subfinder.
    يشغل subfinder بخروج JSON (-json -silent) ويُعيد ToolResult موحد.
    """

    def __init__(self, mgr: ToolManager):
        self.mgr = mgr

    def is_available(self) -> bool:
        return self.mgr.is_available("subfinder")

    async def enum(
        self,
        domain: str,
        sources: Optional[str] = None,
        recursive: bool = False,
        timeout: int = 300,
    ) -> ToolResult:
        cmd_parts = ["subfinder", "-d", domain, "-json", "-silent"]
        if sources:
            cmd_parts += ["-bs", sources]
        if recursive:
            cmd_parts.append("-recursive")
        return await self.mgr.execute(" ".join(cmd_parts), timeout=timeout)
