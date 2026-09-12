"""OSINT Tools — theHarvester, subfinder, amass, sherlock, shodan"""
from tools.tool_manager import ToolManager, ToolResult


class OSINTTools:
    def __init__(self, mgr: ToolManager):
        self.mgr = mgr

    async def theharvester(self, domain: str, sources: str = "google,bing,yahoo") -> ToolResult:
        return await self.mgr.execute(f"theHarvester -d {domain} -b {sources} -l 100", timeout=300)

    async def subfinder(self, domain: str) -> ToolResult:
        return await self.mgr.execute(f"subfinder -d {domain} -silent", timeout=120)

    async def amass(self, domain: str) -> ToolResult:
        return await self.mgr.execute(f"amass enum -d {domain} -passive", timeout=600)

    async def assetfinder(self, domain: str) -> ToolResult:
        return await self.mgr.execute(f"assetfinder --subs-only {domain}", timeout=60)

    async def sherlock(self, username: str) -> ToolResult:
        return await self.mgr.execute(f"sherlock {username} --print-found", timeout=300)

    async def shodan_host(self, ip: str) -> ToolResult:
        return await self.mgr.execute(f"shodan host {ip}", timeout=30)

    async def findomain(self, domain: str) -> ToolResult:
        return await self.mgr.execute(f"findomain -t {domain} -q", timeout=120)

    async def dnsx_ptr(self, cidr_or_domain: str) -> ToolResult:
        return await self.mgr.execute(f"echo {cidr_or_domain} | dnsx -silent -resp-only -ptr", timeout=120)

    async def hakrevdns(self, cidr: str, resolver: str = "1.1.1.1") -> ToolResult:
        return await self.mgr.execute(f"echo {cidr} | hakrevdns -r {resolver}", timeout=120)

    async def asnmap(self, asn: str) -> ToolResult:
        return await self.mgr.execute(f"asnmap -a {asn} -silent", timeout=60)

    async def gobuster_dns(self, domain: str, wordlist: str = "") -> ToolResult:
        from core.wordlist_manager import WordlistManager
        wl = wordlist or WordlistManager().get_wordlist("dns", profile="safe")
        return await self.mgr.execute(f"gobuster dns -d {domain} -w {wl} -q --no-error", timeout=180)

    async def dnsx_brute(self, domain: str, wordlist: str = "") -> ToolResult:
        from core.wordlist_manager import WordlistManager
        wl = wordlist or WordlistManager().get_wordlist("dns", profile="safe")
        return await self.mgr.execute(f"dnsx -d {domain} -w {wl} -silent", timeout=180)

    async def amass_brute(self, domain: str, wordlist: str = "") -> ToolResult:
        from core.wordlist_manager import WordlistManager
        wl = wordlist or WordlistManager().get_wordlist("dns", profile="safe")
        return await self.mgr.execute(f"amass enum -d {domain} -brute -w {wl} -silent", timeout=300)

    async def puredns_brute(self, domain: str, wordlist: str = "", resolvers: str = "") -> ToolResult:
        from core.wordlist_manager import WordlistManager
        wl = wordlist or WordlistManager().get_wordlist("dns", profile="safe")
        r_arg = f"-r {resolvers}" if resolvers else ""
        return await self.mgr.execute(f"puredns bruteforce {wl} {domain} {r_arg} -q", timeout=300)
