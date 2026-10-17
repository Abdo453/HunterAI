"""enum4linux-ng Tool Adapter — L1: واجهة تشغيل موحدة مع مخرجات JSON منظمة."""
from __future__ import annotations

import os
import tempfile
from typing import List, Optional

from tools.tool_manager import ToolManager, ToolResult


class Enum4LinuxTools:
    """
    L1 Tool Adapter لـ enum4linux-ng.
    يشغّل التعداد ويكتب JSON إلى ملف مؤقت ثم يقرؤه إلى stdout الموحّد
    (enum4linux-ng يكتب JSON إلى ملف عبر -oJ، لا إلى stdout).
    لا يعدّل في الكود الأصلي للأداة؛ طبقة خارجية فقط.
    """

    def __init__(self, mgr: ToolManager):
        self.mgr = mgr

    def is_available(self) -> bool:
        return self.mgr.is_available("enum4linux-ng") or self.mgr.is_available("enum4linux")

    def _binary(self) -> str:
        if self.mgr.is_available("enum4linux-ng"):
            return "enum4linux-ng"
        return "enum4linux"

    async def scan(
        self,
        target: str,
        all_simple: bool = True,
        username: Optional[str] = None,
        password: Optional[str] = None,
        timeout: int = 300,
    ) -> ToolResult:
        """
        يشغّل enum4linux-ng ويكتب JSON، ويعيد ToolResult.stdout = محتوى JSON.
        """
        fd, out_path = tempfile.mkstemp(suffix=".json", prefix="e4l_")
        os.close(fd)
        try:
            cmd_parts = [self._binary(), "-oJ", out_path]
            if all_simple:
                cmd_parts.append("-A")
            if username:
                cmd_parts += ["-u", username]
            if password:
                cmd_parts += ["-p", password]
            cmd_parts.append(target)

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

    async def scan_quick(self, target: str, timeout: int = 180) -> ToolResult:
        """تعداد مبسّط عبر -A فقط (سريع نسبيًا)."""
        return await self.scan(target=target, all_simple=True, timeout=timeout)
