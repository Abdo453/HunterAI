"""OT Tool Adapter — L1: واجهة تشغيل موحدة لـ nmap ICS scripts / modbus-cli."""
from __future__ import annotations

from typing import List, Optional

from tools.tool_manager import ToolManager, ToolResult


class OTTools:
    """
    L1 Tool Adapter للأصول الصناعية (OT / ICS): nmap ICS scripts، modbus-cli.
    لا يعدل في الكود الأصلي للأداة؛ طبقة خارجية فقط.
    """

    def __init__(self, mgr: ToolManager):
        self.mgr = mgr

    def is_available(self, tool: str = "nmap") -> bool:
        return self.mgr.is_available(tool)

    async def nmap_ics(
        self,
        target: str,
        ports: str = "502,102,44818",
        timeout: int = 300,
    ) -> ToolResult:
        """ي شغّل nmap مع سكريبتات ICS/OT."""
        cmd_parts = [
            "nmap",
            "-p",
            ports,
            "--script",
            "modbus-discover,s7-info,ethernet-ip-info,profinet-info",
            "-oX",
            "-",
            target,
        ]
        return await self.mgr.execute(" ".join(cmd_parts), timeout=timeout)

    async def modbus_read(
        self,
        target: str,
        unit_id: int = 1,
        address: int = 0,
        count: int = 1,
        timeout: int = 60,
    ) -> ToolResult:
        """يقرأ مسجلات Modbus (قراءة فقط — اختبار تأثير محدود)."""
        cmd_parts = [
            "modbus-cli",
            "read-holding-registers",
            "-a",
            target,
            "-u",
            str(unit_id),
            "-r",
            str(address),
            "-n",
            str(count),
        ]
        return await self.mgr.execute(" ".join(cmd_parts), timeout=timeout)
