"""LinkFinder Tool Adapter — L1: واجهة تشغيل موحدة لـ linkfinder مع مخرجات JSON منظمة"""
from __future__ import annotations

from typing import Optional, List
from tools.tool_manager import ToolManager, ToolResult


class LinkFinderTools:
    """
    L1 Tool Adapter لـ linkfinder.
    يشغل linkfinder ضد ملف JavaScript أو رابط مع مخرجات JSON (-o json).
    لا يعدل في الكود الأصلي للأداة؛ طبقة خارجية فقط.
    """

    def __init__(self, mgr: ToolManager):
        self.mgr = mgr

    def is_available(self) -> bool:
        return self.mgr.is_available("linkfinder")

    async def scan(
        self,
        target: str,
        timeout: int = 300,
    ) -> ToolResult:
        """
        يشغل linkfinder ضد ملف JavaScript أو رابط.
        يرجع JSON عبر stdout (-o json) لسهولةパレスينج.
        """
        cmd_parts = [
            "linkfinder",
            "-i", target,
            "-o", "json",
        ]
        cmd = " ".join(cmd_parts)
        return await self.mgr.execute(cmd, timeout=timeout)

    async def scan_file(
        self,
        filepath: str,
        timeout: int = 300,
    ) -> ToolResult:
        """
        يشغل linkfinder ضد ملف JavaScript محلي.
        """
        cmd_parts = [
            "linkfinder",
            "-i", filepath,
            "-o", "json",
        ]
        cmd = " ".join(cmd_parts)
        return await self.mgr.execute(cmd, timeout=timeout)
