"""Cloud-Enum Tool Adapter — L1: واجهة تشغيل موحدة لـ cloud-enum مع مخرجات JSON منظمة"""
from __future__ import annotations

from typing import Optional, List
from tools.tool_manager import ToolManager, ToolResult


class CloudEnumTools:
    """
    L1 Tool Adapter لـ cloud-enum.
    يشغل cloud-enum ضد هدف للبحث عن سحابات (S3, Azure, GCP buckets).
    لا يعدل في الكود الأصلي للأداة؛ طبقة خارجية فقط.
    """

    def __init__(self, mgr: ToolManager):
        self.mgr = mgr

    def is_available(self) -> bool:
        return self.mgr.is_available("cloud-enum")

    async def scan(
        self,
        target: str,
        timeout: int = 300,
    ) -> ToolResult:
        """
        يشغل cloud-enum ضد الهدف.
        يرجع مخرجات عبر stdout لسهولة парсинغ.
        """
        cmd_parts = [
            "cloud-enum",
            "-t", target,       # target keyword/domain
        ]
        cmd = " ".join(cmd_parts)
        return await self.mgr.execute(cmd, timeout=timeout)
