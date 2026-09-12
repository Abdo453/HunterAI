import os
import asyncio
import time
from typing import Optional, List
from urllib.parse import urljoin
from tools.tool_manager import ToolManager, ToolResult


def _get_default_wordlist() -> str:
    try:
        from core.wordlist_manager import WordlistManager
        return WordlistManager().get_wordlist("directories", profile="safe")
    except Exception:
        kali_wl = "/usr/share/wordlists/dirb/common.txt"
        if os.path.isfile(kali_wl):
            return kali_wl
        local_wl = os.path.join(os.getcwd(), "data", "wordlists", "common.txt")
        return local_wl


WL = _get_default_wordlist()


class WebTools:
    def __init__(self, mgr: ToolManager):
        self.mgr = mgr

    async def python_dir_fuzz(self, url: str, wordlist: Optional[str] = None, concurrency: int = 10) -> ToolResult:
        """Async Python HTTP Directory Fuzzer Fallback for when gobuster/ffuf are not installed"""
        import httpx
        t0 = time.time()
        wl_path = wordlist or WL
        words = []
        if os.path.isfile(wl_path):
            with open(wl_path, "r", encoding="utf-8", errors="replace") as f:
                words = [line.strip().lstrip("/") for line in f if line.strip() and not line.startswith("#")]
        if not words:
            words = ["admin", "login", "api", "dashboard", "portal", "config", "backup", ".git", ".env", "robots.txt"]

        base_url = url.rstrip("/")
        hits = []
        sem = asyncio.Semaphore(concurrency)

        async def _check_word(client: httpx.AsyncClient, word: str):
            target_url = f"{base_url}/{word}"
            try:
                async with sem:
                    resp = await client.get(target_url, timeout=5.0, follow_redirects=False)
                    if resp.status_code in (200, 204, 301, 302, 307, 308, 401, 403):
                        content_len = len(resp.content)
                        hit_line = f"/{word} (Status: {resp.status_code}) [Size: {content_len}]"
                        hits.append(hit_line)
            except Exception:
                pass

        async with httpx.AsyncClient(verify=False, timeout=8.0) as client:
            tasks = [_check_word(client, w) for w in words[:150]]
            await asyncio.gather(*tasks)

        dur = time.time() - t0
        stdout_text = "\n".join(hits)
        cmd_str = f"python_dir_fuzz {base_url} (wordlist: {len(words)} items)"
        out_f = self.mgr._save_tool_output("gobuster", cmd_str, stdout_text, "", 0, dur)
        return ToolResult(
            tool="gobuster",
            command=cmd_str,
            stdout=stdout_text,
            stderr="",
            returncode=0,
            duration=dur,
            output_file=out_f
        )

    async def gobuster_dir(self, url: str, wordlist: str = WL) -> ToolResult:
        if not self.mgr.is_available("gobuster"):
            return await self.python_dir_fuzz(url, wordlist)
        return await self.mgr.execute(f"gobuster dir -u {url} -w {wordlist} -q --no-error", timeout=300)

    async def ffuf(self, url: str, wordlist: str = WL) -> ToolResult:
        if not self.mgr.is_available("ffuf"):
            clean_url = url.replace("/FUZZ", "").replace("FUZZ", "")
            return await self.python_dir_fuzz(clean_url, wordlist)
        u = url if "FUZZ" in url else f"{url.rstrip('/')}/FUZZ"
        return await self.mgr.execute(f"ffuf -u {u} -w {wordlist} -mc 200,301,302,403 -s", timeout=300)

    async def nuclei_scan(self, url: str, templates: str = "") -> ToolResult:
        t = f"-t {templates}" if templates else ""
        return await self.mgr.execute(f"nuclei -u {url} {t} -silent", timeout=600)

    async def nuclei_cves(self, url: str) -> ToolResult:
        return await self.mgr.execute(f"nuclei -u {url} -t cves -silent", timeout=600)

    async def sqlmap(self, url: str, params: str = "", extra: str = "") -> ToolResult:
        d = f"--data '{params}'" if params else ""
        return await self.mgr.execute(f"sqlmap -u {url} {d} {extra} --batch --level=3 --risk=2 --silent", timeout=300)

    async def nikto(self, url: str) -> ToolResult:
        return await self.mgr.execute(f"nikto -h {url} -nointeractive", timeout=300)

    async def dalfox(self, url: str) -> ToolResult:
        return await self.mgr.execute(f"dalfox url {url} -S", timeout=180)

    async def wpscan(self, url: str) -> ToolResult:
        return await self.mgr.execute(f"wpscan --url {url} --enumerate vp,u --no-banner", timeout=180)

    async def httpx_probe(self, target: str) -> ToolResult:
        return await self.mgr.execute(f"httpx -u {target} -silent -status-code -title -tech-detect", timeout=60)

    async def wafw00f(self, url: str) -> ToolResult:
        return await self.mgr.execute(f"wafw00f {url}", timeout=60)

    async def katana_crawl(self, url: str) -> ToolResult:
        return await self.mgr.execute(f"katana -u {url} -silent -depth 3", timeout=120)

    async def arjun_params(self, url: str, method: str = "get") -> ToolResult:
        m = f"-m {method}" if method else ""
        return await self.mgr.execute(f"arjun -u {url} {m} --passive", timeout=180)

    async def waybackurls(self, domain: str) -> ToolResult:
        return await self.mgr.execute(f"waybackurls {domain}", timeout=120)

    async def gau_urls(self, domain: str) -> ToolResult:
        return await self.mgr.execute(f"gau {domain} --threads 50", timeout=120)

    async def subzy_takeover(self, targets_file: str) -> ToolResult:
        return await self.mgr.execute(f"subzy run --targets {targets_file} --vuln --hide_fails", timeout=180)

    async def smuggler(self, url: str) -> ToolResult:
        return await self.mgr.execute(f"python smuggler.py -u {url}", timeout=120)

    async def dirsearch_sensitive(self, url: str) -> ToolResult:
        exts = "php,asp,aspx,jsp,json,xml,txt,log,ini,cfg,config,conf,bak,old,backup,zip,tar,tgz,gz,rar,7z,swp,swo,db,sql,env"
        return await self.mgr.execute(
            f"dirsearch -u {url} -e {exts} --include-status=200,204,301,302,307,308,401,403 --exclude-status=404 -q",
            timeout=300
        )

    async def ffuf_403_bypass(self, url: str, wordlist: str = WL) -> ToolResult:
        u = url if "FUZZ" in url else f"{url.rstrip('/')}/FUZZ"
        return await self.mgr.execute(
            f"ffuf -u {u} -w {wordlist} -H 'X-Forwarded-For: 127.0.0.1' -H 'X-Original-URL: /FUZZ' -mc 200,301,302,307,401 -s",
            timeout=240
        )
