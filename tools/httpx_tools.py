"""HTTPx Tool Adapter — L1: واجهة تشغيل موحدة لـ HTTPx مع مخرجات JSON منظمة"""
from __future__ import annotations

from typing import Optional, List
from tools.tool_manager import ToolManager, ToolResult


class HTTPxTools:
    """
    L1 Tool Adapter لـ HTTPx.
    يشغل httpx بخروج JSON (-json -silent) ويُعيد ToolResult موحد.
    لا يعدل في الكود الأصلي للأداة؛ طبقة خارجية فقط.
    """

    def __init__(self, mgr: ToolManager):
        self.mgr = mgr

    def is_available(self) -> bool:
        return self.mgr.is_available("httpx")

    async def probe(
        self,
        targets: List[str],
        status_code: bool = True,
        title: bool = True,
        tech_detect: bool = True,
        vhost: bool = False,
        rate_limit: int = 150,
        timeout: int = 300,
    ) -> ToolResult:
        """
        يشغل httpx ضد قائمة الأهداف مع خيارات تحليل التقنيات والستاتس والعناوين.
        يرجع JSON عبر stdout (-json -silent) لسهولةパרסينغ.
        """
        cmd_parts = ["httpx", "-list", "-", "-json", "-silent", "-rl", str(rate_limit)]

        if status_code:
            cmd_parts.append("-sc")
        if title:
            cmd_parts.append("-title")
        if tech_detect:
            cmd_parts.append("-td")
        if vhost:
            cmd_parts.append("-vhost")

        cmd = " ".join(cmd_parts)
        targets_input = "\n".join(targets)
        return await self.mgr.execute(cmd, input_text=targets_input, timeout=timeout)

    async def probe_single(
        self,
        target: str,
        **kwargs,
    ) -> ToolResult:
        """فحص هدف واحد."""
        return await self.probe([target], **kwargs)
