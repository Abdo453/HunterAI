"""Nmap Tool Adapter — L1: واجهة تشغيل موحدة لـ Nmap مع مخرجات XML/JSON منظمة"""
from __future__ import annotations

from typing import Optional, List
from tools.tool_manager import ToolManager, ToolResult


class NmapTools:
    """
    L1 Tool Adapter لـ Nmap.
    يشغل nmap بخروج XML (-oX -) ويُعيد ToolResult موحد.
    لا يعدل في الكود الأصلي للأداة؛ طبقة خارجية فقط.
    """

    def __init__(self, mgr: ToolManager):
        self.mgr = mgr

    def is_available(self) -> bool:
        return self.mgr.is_available("nmap")

    async def scan(
        self,
        target: str,
        ports: Optional[str] = None,
        service_detection: bool = True,
        version_detection: bool = True,
        scripts: Optional[str] = None,
        timing: str = "T4",
        timeout: int = 600,
    ) -> ToolResult:
        """
        يشغل nmap ضد الهدف مع خيارات اكتشاف الخدمات والإصدارات والنصوص.
        يرجع XML عبر stdout (-oX -) لسهولةパレスينج.
        """
        cmd_parts = [
            "nmap",
            "-oX", "-",           # XML output to stdout
            "-T" + timing,
            target,
        ]

        if ports:
            cmd_parts += ["-p", ports]
        if service_detection:
            cmd_parts.append("-sV")
        if version_detection:
            cmd_parts.append("-sV")
        if scripts:
            cmd_parts += ["--script", scripts]

        cmd = " ".join(cmd_parts)
        return await self.mgr.execute(cmd, timeout=timeout)

    async def quick_scan(
        self,
        target: str,
        timeout: int = 120,
    ) -> ToolResult:
        """مسح سريع للمنافذ الأكثر شيوعاً."""
        return await self.scan(
            target=target,
            ports="21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080",
            timing="T4",
            timeout=timeout,
        )
