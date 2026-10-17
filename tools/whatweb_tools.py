"""WhatWeb Tool Adapter — L1: واجهة تشغيل موحدة لـ whatweb مع مخرجات JSON منظمة."""
from __future__ import annotations

from typing import List, Optional

from tools.tool_manager import ToolManager, ToolResult


class WhatWebTools:
    """
    L1 Tool Adapter لـ whatweb.
    يشغّل whatweb مع خروج JSON إلى stdout عبر --log-json=- ويعيد ToolResult موحد.
    لا يعدل في الكود الأصلي للأداة؛ طبقة خارجية فقط.
    """

    def __init__(self, mgr: ToolManager):
        self.mgr = mgr

    def is_available(self) -> bool:
        return self.mgr.is_available("whatweb")

    async def scan(
        self,
        target: str,
        timeout: int = 120,
        aggressive: int = 3,
        plugins: Optional[List[str]] = None,
    ) -> ToolResult:
        """
        يشغّل whatweb ضد الهدف ويعيد ToolResult.stdout = محتوى JSON.
        """
        cmd_parts = [
            "whatweb",
            "--color=never",
            "--log-json=-",
            f"-a {aggressive}",
        ]
        if plugins:
            cmd_parts.append(f"--plugins={','.join(plugins)}")
        cmd_parts.append(target)

        return await self.mgr.execute(" ".join(cmd_parts), timeout=timeout)

    async def scan_url(self, url: str, timeout: int = 120) -> ToolResult:
        """مسح عنوان URL كامل (بما في ذلك المخطط)."""
        return await self.scan(target=url, timeout=timeout)
