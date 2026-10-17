"""SSH-Audit Tool Adapter — L1: واجهة تشغيل موحدة لـ ssh-audit مع مخرجات JSON منظمة"""
from __future__ import annotations

from typing import Optional, List
from tools.tool_manager import ToolManager, ToolResult


class SSHAuditTools:
    """
    L1 Tool Adapter لـ ssh-audit.
    يشغل ssh-audit ضد هدف SSH مع مخرجات JSON (-j).
    لا يعدل في الكود الأصلي للأداة؛ طبقة خارجية فقط.
    """

    def __init__(self, mgr: ToolManager):
        self.mgr = mgr

    def is_available(self) -> bool:
        return self.mgr.is_available("ssh-audit")

    async def scan(
        self,
        target: str,
        port: int = 22,
        timeout: int = 60,
    ) -> ToolResult:
        """
        يشغل ssh-audit ضد الهدف.
        يرجع JSON عبر stdout (-j) لسهولةパレスينج.
        """
        cmd_parts = [
            "ssh-audit",
            "-j",                # JSON output
            "-p", str(port),     # port
            target,
        ]
        cmd = " ".join(cmd_parts)
        return await self.mgr.execute(cmd, timeout=timeout)

    async def scan_list(
        self,
        targets: List[str],
        port: int = 22,
        timeout: int = 120,
    ) -> ToolResult:
        """فحص قائمة أهداف من ملف."""
        import tempfile
        import os
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt") as tf:
            tf.write("\n".join(targets))
            tf_path = tf.name
        try:
            cmd_parts = [
                "ssh-audit",
                "-j",
                "-p", str(port),
                "-f", tf_path,   # file input
            ]
            cmd = " ".join(cmd_parts)
            return await self.mgr.execute(cmd, timeout=timeout)
        finally:
            os.unlink(tf_path)
