"""Network Tools — nmap, masscan, rustscan, netexec, enum4linux"""
from tools.tool_manager import ToolManager, ToolResult


class NetworkTools:
    def __init__(self, mgr: ToolManager):
        self.mgr = mgr

    @staticmethod
    def _clean_host(target: str) -> str:
        from urllib.parse import urlparse
        if "://" in target:
            parsed = urlparse(target)
            return parsed.hostname or parsed.netloc.split(":")[0] or target
        return target.split("/")[0].split(":")[0].strip()

    async def nmap_scan(self, target: str, ports: str = "80,443,8080,8443,8000,8888,3000,5000,21,22,25,3306,5432,6379,27017,9200", args: str = "-sV -T4 --open") -> ToolResult:
        host = self._clean_host(target)
        return await self.mgr.execute(f"nmap {args} -p {ports} {host}", timeout=60)

    async def nmap_full(self, target: str) -> ToolResult:
        host = self._clean_host(target)
        return await self.mgr.execute(f"nmap -p- -T4 --open {host}", timeout=600)

    async def rustscan(self, target: str) -> ToolResult:
        host = self._clean_host(target)
        return await self.mgr.execute(f"rustscan -a {host} -- -sV -sC", timeout=120)

    async def masscan(self, target: str, ports: str = "0-65535", rate: int = 1000) -> ToolResult:
        return await self.mgr.execute(f"masscan {target} -p{ports} --rate={rate}", timeout=120)

    async def enum4linux(self, target: str) -> ToolResult:
        return await self.mgr.execute(f"enum4linux-ng -A {target}", timeout=180)

    async def netexec_smb(self, target: str) -> ToolResult:
        return await self.mgr.execute(f"netexec smb {target}", timeout=60)

    async def netexec_winrm(self, target: str, user: str = "", pwd: str = "") -> ToolResult:
        creds = f"-u {user} -p {pwd}" if user and pwd else ""
        return await self.mgr.execute(f"netexec winrm {target} {creds}", timeout=60)
