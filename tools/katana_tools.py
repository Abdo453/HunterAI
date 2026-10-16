"""Katana Tool Adapter — L1: واجهة تشغيل موحدة لـ Katana مع مخرجات JSON منظمة"""
from __future__ import annotations

from typing import Optional, List
from tools.tool_manager import ToolManager, ToolResult


class KatanaTools:
    """
    L1 Tool Adapter لـ Katana.
    يشغل katana بخروج JSON (-jc -oj) ويُعيد ToolResult موحد.
    لا يعدل في الكود الأصلي للأداة؛ طبقة خارجية فقط.
    """

    def __init__(self, mgr: ToolManager):
        self.mgr = mgr

    def is_available(self) -> bool:
        return self.mgr.is_available("katana")

    async def crawl(
        self,
        url: str,
        depth: int = 2,
        rate_limit: int = 50,
        timeout: int = 300,
        js: bool = True,
        forms: bool = True,
    ) -> ToolResult:
        """
        يشغل katana ضد الهدف مع خيارات استخراج JS والنماذج.
        يرجع JSON عبر stdout (-jc -oj) لسهولةパレスينج.
        """
        cmd_parts = [
            "katana",
            "-u", url,
            "-d", str(depth),
            "-rl", str(rate_limit),
            "-jc",   # JSON output
            "-oj",   # output to stdout
        ]

        if js:
            cmd_parts.append("-js")
        if forms:
            cmd_parts.append("-fq")  # forms query

        cmd = " ".join(cmd_parts)
        return await self.mgr.execute(cmd, timeout=timeout)

    async def crawl_list(
        self,
        targets_file: str,
        depth: int = 2,
        rate_limit: int = 50,
        timeout: int = 600,
    ) -> ToolResult:
        """زحف قائمة أهداف من ملف."""
        cmd_parts = [
            "katana",
            "-list", targets_file,
            "-d", str(depth),
            "-rl", str(rate_limit),
            "-jc",
            "-oj",
        ]
        return await self.mgr.execute(" ".join(cmd_parts), timeout=timeout)
