"""IoT Tool Adapter — L1: واجهة تشغيل موحدة لـ zigbee2mqtt / nmap IoT scripts."""
from __future__ import annotations

from typing import List, Optional

from tools.tool_manager import ToolManager, ToolResult


class IoTTools:
    """
    L1 Tool Adapter لاكتشاف أجهزة إنترنت الأشياء (zigbee2mqtt / nmap iot scripts).
    لا يعدل في الكود الأصلي للأداة؛ طبقة خارجية فقط.
    """

    def __init__(self, mgr: ToolManager):
        self.mgr = mgr

    def is_available(self, tool: str = "zigbee2mqtt") -> bool:
        return self.mgr.is_available(tool)

    async def zigbee2mqtt(
        self,
        target: Optional[str] = None,
        timeout: int = 120,
    ) -> ToolResult:
        """يقرأ مخرجات zigbee2mqtt JSON (الأجهزة المتصلة)."""
        cmd_parts = ["zigbee2mqtt"]
        if target:
            cmd_parts += ["-c", target]
        return await self.mgr.execute(" ".join(cmd_parts), timeout=timeout)

    async def nmap_iot(
        self,
        target: str,
        timeout: int = 180,
    ) -> ToolResult:
        """ي شغّل nmap مع سكريبتات IoT."""
        cmd_parts = [
            "nmap",
            "--script",
            "iot-*,upnp-info,mqtt-subscribe,ssdp-discover",
            "-oX",
            "-",
            target,
        ]
        return await self.mgr.execute(" ".join(cmd_parts), timeout=timeout)

    async def ble_scan(
        self,
        interface: str = "hci0",
        timeout: int = 120,
    ) -> ToolResult:
        """ي شغّل فحص BLE عبر hcitool/bluetoothctl."""
        cmd_parts = ["hcitool", "lescan", "--interface", interface]
        return await self.mgr.execute(" ".join(cmd_parts), timeout=timeout)
