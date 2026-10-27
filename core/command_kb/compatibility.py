"""
مُحقِّق توافق البيئة (Environment Compatibility Checker)
============================================================
قبل تنفيذ أي أمر من قاعدة المعرفة، يتحقق هذا المكون من:
1. وجود الأداة المطلوبة في النظام (nmap, ffuf, sqlmap, ...).
2. توفر المنافذ المطلوبة مفتوحة على الهدف.
3. توفر النقاط النهائية المطلوبة مكتشفة.
4. توفر الصلاحيات المطلوبة (root, sudo).

إذا لم يتوافر أي شرط، يُرفض الأمر ويُعاد تقرير بالسبب.
"""
from __future__ import annotations

import logging
import shutil
import socket
from typing import Optional, Dict, Any, List

from core.command_kb.models import CommandEntry

log = logging.getLogger("core.command_kb.compatibility")


class CompatibilityResult:
    """نتيجة فحص التوافق."""
    def __init__(
        self,
        compatible: bool,
        missing_tools: Optional[List[str]] = None,
        missing_ports: Optional[List[int]] = None,
        missing_endpoints: Optional[List[str]] = None,
        missing_privileges: Optional[List[str]] = None,
        reason: str = "",
    ):
        self.compatible = compatible
        self.missing_tools = missing_tools or []
        self.missing_ports = missing_ports or []
        self.missing_endpoints = missing_endpoints or []
        self.missing_privileges = missing_privileges or []
        self.reason = reason

    def to_dict(self) -> Dict[str, Any]:
        return {
            "compatible": self.compatible,
            "missing_tools": self.missing_tools,
            "missing_ports": self.missing_ports,
            "missing_endpoints": self.missing_endpoints,
            "missing_privileges": self.missing_privileges,
            "reason": self.reason,
        }


class EnvironmentCompatibilityChecker:
    """
    يتحقق من توافق أمر مع البيئة الحالية قبل تنفيذه.
    """

    def __init__(self, open_ports: Optional[Dict[str, List[int]]] = None,
                 discovered_endpoints: Optional[List[str]] = None,
                 current_privileges: Optional[List[str]] = None):
        """
        open_ports: {"10.10.10.10": [80, 443, 22], ...}
        discovered_endpoints: ["http://target.com/search?id=", ...]
        current_privileges: ["root", "sudo"] أو []
        """
        self.open_ports = open_ports or {}
        self.discovered_endpoints = discovered_endpoints or []
        self.current_privileges = current_privileges or []

    # ------------------------------------------------------------------ #
    # الفحص الرئيسي
    # ------------------------------------------------------------------ #
    def check(self, command: CommandEntry, target: str = "") -> CompatibilityResult:
        """
        فحص توافق الأمر مع البيئة.
        ترجع CompatibilityResult مع compatible=True لو جميع الشروط متوافرة.
        """
        missing_tools: List[str] = []
        missing_ports: List[int] = []
        missing_endpoints: List[str] = []
        missing_privileges: List[str] = []

        # 1. الأدوات المطلوبة
        for tool in command.required_tools:
            if not self._tool_installed(tool):
                missing_tools.append(tool)

        # 2. المنافذ المطلوبة (إذا كان الهدف محدد)
        if target and command.required_ports:
            ports = self.open_ports.get(target, [])
            for port in command.required_ports:
                if port not in ports:
                    missing_ports.append(port)

        # 3. النقاط النهائية المطلوبة
        if command.required_endpoints:
            for endpoint in command.required_endpoints:
                if endpoint not in self.discovered_endpoints:
                    missing_endpoints.append(endpoint)

        # 4. الصلاحيات المطلوبة
        for priv in command.required_privileges:
            if priv not in self.current_privileges:
                missing_privileges.append(priv)

        # تحديد النتيجة
        missing_any = bool(missing_tools or missing_ports or missing_endpoints or missing_privileges)
        reason_parts: List[str] = []
        if missing_tools:
            reason_parts.append(f"missing tools: {', '.join(missing_tools)}")
        if missing_ports:
            reason_parts.append(f"missing ports: {', '.join(map(str, missing_ports))}")
        if missing_endpoints:
            reason_parts.append(f"missing endpoints: {', '.join(missing_endpoints)}")
        if missing_privileges:
            reason_parts.append(f"missing privileges: {', '.join(missing_privileges)}")

        reason = "; ".join(reason_parts) if reason_parts else "All requirements satisfied"

        return CompatibilityResult(
            compatible=not missing_any,
            missing_tools=missing_tools,
            missing_ports=missing_ports,
            missing_endpoints=missing_endpoints,
            missing_privileges=missing_privileges,
            reason=reason,
        )

    # ------------------------------------------------------------------ #
    # مساعدات داخلية
    # ------------------------------------------------------------------ #
    @staticmethod
    def _tool_installed(tool: str) -> bool:
        """التحقق من وجود أداة في مسار النظام (PATH)."""
        return shutil.which(tool) is not None

    # ------------------------------------------------------------------ #
    # تحديث السياق البيئي
    # ------------------------------------------------------------------ #
    def update_open_ports(self, target: str, ports: List[int]) -> None:
        self.open_ports[target] = ports
        log.debug(f"[COMPAT] Updated open ports for {target}: {ports}")

    def update_discovered_endpoints(self, endpoints: List[str]) -> None:
        self.discovered_endpoints = endpoints
        log.debug(f"[COMPAT] Updated discovered endpoints: {len(endpoints)} items")

    def update_privileges(self, privileges: List[str]) -> None:
        self.current_privileges = privileges
        log.debug(f"[COMPAT] Updated privileges: {privileges}")
