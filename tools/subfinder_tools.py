"""Subfinder Tool Adapter — L1: واجهة تشغيل موحدة لـ Subfinder مع مخرجات JSON منظمة"""
from __future__ import annotations

from typing import Optional, List
from tools.tool_manager import ToolManager, ToolResult


class SubfinderTools:
    """
    L1 Tool Adapter لـ Subfinder.
    يشغل subfinder ضد النطاقات مع مخرجات JSON (-json -silent).
    لا يعدل في الكود الأصلي للأداة؛ طبقة خارجية فقط.
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
        """
        يشغل subfinder ضد النطاق.
        يرجع JSON عبر stdout (-json -silent) لسهولةパレスينج.
        """
        cmd_parts = ["subfinder", "-d", domain, "-json", "-silent"]

        if sources:
            cmd_parts += ["-bs", sources]  # sources filter
        if recursive:
            cmd_parts.append("-recursive")  # التعداد المتكرر

        cmd = " ".join(cmd_parts)
        return await self.mgr.execute(cmd, timeout=timeout)

    async def enum_list(
        self,
        domains_file: str,
        timeout: int = 600,
    ) -> ToolResult:
        """
        يشغل subfinder ضد قائمة النطاقات من ملف.
        """
        cmd_parts = [
            "subfinder",
            "-L", domains_file,  # list file
            "-json",
            "-silent",
        ]
        cmd = " ".join(cmd_parts)
        return await self.mgr.execute(cmd, timeout=timeout)
