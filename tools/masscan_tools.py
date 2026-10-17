"""Masscan Tool Adapter — L1: واجهة تشغيل موحدة لـ masscan مع مخرجات JSON منظمة"""
from __future__ import annotations

import os
import tempfile
from typing import Optional, List

from tools.tool_manager import ToolManager, ToolResult


class MasscanTools:
    """
    L1 Tool Adapter لـ masscan.
    يشغّل masscan ويكتب مخرجات JSON إلى ملف مؤقت ثم يقرأه إلى stdout الموحّد
    (masscan لا يدعم الكتابة إلى stdout بشكل موثوق، لذا نعتمد ملفًا مؤقتًا).
    لا يعدّل في الكود الأصلي للأداة؛ طبقة خارجية فقط.
    """

    def __init__(self, mgr: ToolManager):
        self.mgr = mgr

    def is_available(self) -> bool:
        return self.mgr.is_available("masscan")

    async def scan(
        self,
        target: str,
        ports: str = "1-65535",
        rate: int = 1000,
        wait: int = 0,
        interface: Optional[str] = None,
        timeout: int = 900,
    ) -> ToolResult:
        """
        يشغّل masscan ضد الهدف مع كتابة JSON، ويعيد ToolResult.stdout = محتوى JSON.
        """
        fd, out_path = tempfile.mkstemp(suffix=".json", prefix="masscan_")
        os.close(fd)
        try:
            cmd_parts = [
                "masscan",
                "-p", str(ports),
                "--rate", str(rate),
                "-oJ", out_path,
            ]
            if wait:
                cmd_parts += ["--wait", str(wait)]
            if interface:
                cmd_parts += ["-e", interface]
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

    async def scan_top_ports(
        self,
        target: str,
        rate: int = 1000,
        timeout: int = 600,
    ) -> ToolResult:
        """مسح سريع لأشهر 1000 منفذ (بديل عملي عند قيود الوقت)."""
        common = (
            "21,22,23,25,53,80,110,111,135,139,143,161,389,443,445,465,512,513,"
            "514,587,636,873,993,995,1080,1433,1521,2049,2375,2376,3306,3389,"
            "5432,5900,5985,5986,6379,8080,8443,9200,9300,10250,27017"
        )
        return await self.scan(target=target, ports=common, rate=rate, timeout=timeout)
