"""Soft-404 Detector Tool Adapter — L1: واجهة تشغيل موحدة لـ soft-404-detector مع مخرجات منظمة"""
from __future__ import annotations

from typing import Optional, List
from tools.tool_manager import ToolManager, ToolResult


class Soft404Tools:
    """
    L1 Tool Adapter لـ soft-404-detector.
    يشغل soft-404-detector ضد هدف للكشف عن صفحات Soft-404 (صفحات ترجع 200 لكنها تقول "غير موجودة").
    لا يعدل في الكود الأصلي للأداة؛ طبقة خارجية فقط.
    """

    def __init__(self, mgr: ToolManager):
        self.mgr = mgr

    def is_available(self) -> bool:
        return self.mgr.is_available("soft-404-detector")

    async def scan(
        self,
        target: str,
        timeout: int = 300,
    ) -> ToolResult:
        """
        يشغل soft-404-detector ضد الهدف.
        يرجع مخرجات عبر stdout لسهولة 파レスينج.
        """
        cmd_parts = [
            "soft-404-detector",
            "-u", target,
        ]
        cmd = " ".join(cmd_parts)
        return await self.mgr.execute(cmd, timeout=timeout)

    async def scan_list(
        self,
        targets: List[str],
        timeout: int = 300,
    ) -> ToolResult:
        """
        يشغل soft-404-detector ضد قائمة أهداف.
        """
        import tempfile
        import os
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt") as tf:
            tf.write("\n".join(targets))
            tf_path = tf.name
        try:
            cmd_parts = [
                "soft-404-detector",
                "-f", tf_path,   # file input
            ]
            cmd = " ".join(cmd_parts)
            return await self.mgr.execute(cmd, timeout=timeout)
        finally:
            os.unlink(tf_path)
