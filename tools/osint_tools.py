"""OSINT Tools — theHarvester, subfinder, amass, sherlock, shodan"""
from tools.tool_manager import ToolManager, ToolResult


class OSINTTools:
    def __init__(self, mgr: ToolManager):
        self.mgr = mgr

    async def theharvester(self, domain: str, sources: str = "google,bing,yahoo") -> ToolResult:
        return await self.mgr.execute(f"theHarvester -d {domain} -b {sources} -l 100", timeout=300)

    async def subfinder(self, domain: str) -> ToolResult:
        return await self.mgr.execute(f"subfinder -d {domain} -silent", timeout=120)

    async def assetfinder(self, domain: str) -> ToolResult:
        return await self.mgr.execute(f"assetfinder --subs-only {domain}", timeout=60)

    async def findomain(self, domain: str) -> ToolResult:
        return await self.mgr.execute(f"findomain -t {domain} -q", timeout=120)

    async def sherlock(self, username: str) -> ToolResult:
        return await self.mgr.execute(f"sherlock {username} --print-found", timeout=300)

    async def shodan_host(self, ip: str) -> ToolResult:
        return await self.mgr.execute(f"shodan host {ip}", timeout=30)
