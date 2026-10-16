"""Nuclei Tool Adapter — L1: واجهة تشغيل موحدة لـ Nuclei مع مخرجات JSON منظمة"""
from __future__ import annotations

from typing import Optional, List
from tools.tool_manager import ToolManager, ToolResult


class NucleiTools:
    """
    L1 Tool Adapter لـ Nuclei.
    يشغل nuclei بخروج JSON (-json -o -) ويُعيد ToolResult موحد.
    لا يعدل في الكود الأصلي للأداة؛ طبقة خارجية فقط.
    """

    def __init__(self, mgr: ToolManager):
        self.mgr = mgr

    def is_available(self) -> bool:
        return self.mgr.is_available("nuclei")

    async def scan(
        self,
        target: str,
        templates: Optional[str] = None,
        severity: Optional[str] = None,
        tags: Optional[str] = None,
        rate_limit: int = 50,
        timeout: int = 300,
    ) -> ToolResult:
        """
        يشغل nuclei ضد الهدف.
       返回 JSON عبر stdout (-json -o -) لسهولةパרסينغ.
        """
        cmd_parts = ["nuclei", "-u", target, "-json", "-o", "-", "-rl", str(rate_limit)]

        if templates:
            cmd_parts += ["-t", templates]
        if severity:
            cmd_parts += ["-severity", severity]
        if tags:
            cmd_parts += ["-tags", tags]

        cmd = " ".join(cmd_parts)
        return await self.mgr.execute(cmd, timeout=timeout)

    async def scan_list(
        self,
        targets_file: str,
        templates: Optional[str] = None,
        severity: Optional[str] = None,
        timeout: int = 600,
    ) -> ToolResult:
        """فحص قائمة أهداف من ملف."""
        cmd_parts = ["nuclei", "-l", targets_file, "-json", "-o", "-", "-rl", "50"]
        if templates:
            cmd_parts += ["-t", templates]
        if severity:
            cmd_parts += ["-severity", severity]
        return await self.mgr.execute(" ".join(cmd_parts), timeout=timeout)
