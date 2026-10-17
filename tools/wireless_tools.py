"""Wireless Tool Adapter — L1: واجهة تشغيل موحدة لـ kismet / airodump-ng."""
from __future__ import annotations

from typing import List, Optional

from tools.tool_manager import ToolManager, ToolResult


class WirelessTools:
    """
    L1 Tool Adapter للكشف اللاسلكي (kismet / airodump-ng).
    يُشغّل الأداة ويقرأ المخرجات إلى stdout الموحّد (JSON أو CSV).
    لا يعدل في الكود الأصلي للأداة؛ طبقة خارجية فقط.
    """

    def __init__(self, mgr: ToolManager):
        self.mgr = mgr

    def is_available(self, tool: str = "kismet") -> bool:
        return self.mgr.is_available(tool)

    async def kismet_json(
        self, target: Optional[str] = None, timeout: int = 300
    ) -> ToolResult:
        """ي чтёт مخرجات kismet JSON (يفترض --json-or-csv أو نفس المخرج)."""
        cmd_parts = ["kismet"]
        if target:
            cmd_parts += ["-c", target]
        cmd_parts += ["--json"]
        return await self.mgr.execute(" ".join(cmd_parts), timeout=timeout)

    async def airodump_csv(
        self,
        interface: str = "wlan0mon",
        channels: Optional[str] = None,
        timeout: int = 300,
    ) -> ToolResult:
        """ي شغّل airodump-ng بمخرجات CSV."""
        cmd_parts = ["airodump-ng", "--output-format", "csv", "-w", "-"]
        if channels:
            cmd_parts += ["-c", channels]
        cmd_parts.append(interface)
        return await self.mgr.execute(" ".join(cmd_parts), timeout=timeout)

    async def aircrack(
        self,
        capture_file: str,
        wordlist: Optional[str] = None,
        bssid: Optional[str] = None,
        timeout: int = 600,
    ) -> ToolResult:
        """ي شغّل aircrack-ng ضد ملف capturing."""
        cmd_parts = ["aircrack-ng", capture_file]
        if wordlist:
            cmd_parts += ["-w", wordlist]
        if bssid:
            cmd_parts += ["-b", bssid]
        return await self.mgr.execute(" ".join(cmd_parts), timeout=timeout)

    async def wifite(
        self,
        interface: str = "wlan0mon",
        wps: bool = False,
        timeout: int = 600,
    ) -> ToolResult:
        """ي شغّل wifite (التدقيق التلقائي اللاسلكي)."""
        cmd_parts = ["wifite", "-i", interface]
        if wps:
            cmd_parts.append("--wps")
        return await self.mgr.execute(" ".join(cmd_parts), timeout=timeout)
