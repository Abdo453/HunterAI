"""NetExec (nxc) Tool Adapter — L1: واجهة تشغيل موحدة عبر البروتوكولات."""
from __future__ import annotations

from typing import List, Optional

from tools.tool_manager import ToolManager, ToolResult


class NetExecTools:
    """
    L1 Tool Adapter لـ NetExec (netexec / nxc).
    يوفّر أغلفة لكل بروتوكول (smb/ldap/winrm/mssql/rdp) مع مخرجات نصية موحّدة.
    لا يعدّل في الكود الأصلي للأداة؛ طبقة خارجية فقط.
    """

    def __init__(self, mgr: ToolManager):
        self.mgr = mgr

    def is_available(self) -> bool:
        return self.mgr.is_available("netexec") or self.mgr.is_available("nxc")

    def _binary(self) -> str:
        return "netexec" if self.mgr.is_available("netexec") else "nxc"

    async def _run(self, protocol: str, target: str, args: str = "", timeout: int = 180) -> ToolResult:
        cmd = f"{self._binary()} {protocol} {target}"
        if args:
            cmd += f" {args}"
        return await self.mgr.execute(cmd, timeout=timeout)

    async def smb(self, target: str, args: str = "--shares --users --pass-pol", timeout: int = 180) -> ToolResult:
        return await self._run("smb", target, args, timeout)

    async def ldap(self, target: str, args: str = "", timeout: int = 120) -> ToolResult:
        return await self._run("ldap", target, args, timeout)

    async def winrm(self, target: str, username: str = "", password: str = "", args: str = "", timeout: int = 120) -> ToolResult:
        creds = f"-u {username} -p {password}" if username and password else ""
        return await self._run("winrm", target, f"{creds} {args}".strip(), timeout)

    async def mssql(self, target: str, username: str = "", password: str = "", args: str = "", timeout: int = 120) -> ToolResult:
        creds = f"-u {username} -p {password}" if username and password else ""
        return await self._run("mssql", target, f"{creds} {args}".strip(), timeout)

    async def rdp(self, target: str, args: str = "", timeout: int = 120) -> ToolResult:
        return await self._run("rdp", target, args, timeout)

    async def multi(self, protocol: str, targets: List[str], args: str = "", timeout: int = 300) -> ToolResult:
        """تشغيل مقابل قائمة أهداف (netexec يقبل --targets أو مسافات)."""
        joined = " ".join(targets)
        return await self._run(protocol, joined, args, timeout)
