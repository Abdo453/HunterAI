"""SSLScan Tool Adapter — L1: واجهة تشغيل موحدة لـ sslscan مع مخرجات XML منظمة."""
from __future__ import annotations

import os
import tempfile
from typing import Optional

from tools.tool_manager import ToolManager, ToolResult


class SSLScanTools:
    """
    L1 Tool Adapter لـ sslscan.
    يشغّل sslscan ويكتب XML إلى ملف مؤقت ثم يقرؤه إلى stdout الموحّد
    (بعض إصدارات sslscan لا تدعم الكتابة الموثوقة إلى stdout).
    لا يعدل في الكود الأصلي للأداة؛ طبقة خارجية فقط.
    """

    def __init__(self, mgr: ToolManager):
        self.mgr = mgr

    def is_available(self) -> bool:
        return self.mgr.is_available("sslscan")

    async def scan(
        self,
        target: str,
        timeout: int = 120,
    ) -> ToolResult:
        """
        يشغّل sslscan ضد الهدف ويعيد ToolResult.stdout = محتوى XML.
        الهدف يمكن أن يكون host أو host:port.
        """
        fd, out_path = tempfile.mkstemp(suffix=".xml", prefix="sslscan_")
        os.close(fd)
        try:
            cmd_parts = ["sslscan", "--xml=" + out_path, target]
            res = await self.mgr.execute(" ".join(cmd_parts), timeout=timeout)

            try:
                with open(out_path, "r", encoding="utf-8", errors="replace") as f:
                    data = f.read()
                if data.strip():
                    res.stdout = data
            except OSError:
                pass
            return res
        finally:
            try:
                os.unlink(out_path)
            except OSError:
                pass
