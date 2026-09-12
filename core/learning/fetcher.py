"""
Intelligence Fetcher — Phase 1 of Self-Learning Pipeline
يجلب من مصادر متعددة بالتوازي: NVD، CISA، GitHub، HackerOne، Medium، PortSwigger، Exploit-DB
مبدأ أساسي: يجلب فقط من مصادر عامة + APIs رسمية — لا يتجاوز أي auth barriers
"""
import asyncio
import json
import logging
import os
import re
import time
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

import httpx
from bs4 import BeautifulSoup

log = logging.getLogger("learning.fetcher")

RAW_DIR = Path("data/raw_writeups")
RAW_DIR.mkdir(parents=True, exist_ok=True)

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) "
        "Gecko/20100101 Firefox/120.0"
    ),
    "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}

# ─── Source Configs ──────────────────────────────────────────────────────────
SOURCES: Dict[str, Dict] = {
    "nvd_cves": {
        "url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
        "type": "api_json",
        "frequency_hours": 24,
        "params": {"resultsPerPage": 50, "startIndex": 0},
        "enabled": True,
    },
    "cisa_kev": {
        "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "type": "api_json",
        "frequency_hours": 24,
        "enabled": True,
    },
    "exploit_db": {
        "url": "https://www.exploit-db.com/search",
        "type": "html",
        "frequency_hours": 24,
        "params": {"type": "webapps", "order_by": "date", "sort": "desc"},
        "enabled": True,
    },
    "github_nuclei_templates": {
        "url": "https://api.github.com/repos/projectdiscovery/nuclei-templates/releases/latest",
        "type": "api_json",
        "frequency_hours": 48,
        "enabled": True,
    },
    "github_trending_security": {
        "url": "https://api.github.com/search/repositories",
        "type": "api_json",
        "frequency_hours": 48,
        "params": {
            "q": "topic:penetration-testing stars:>500",
            "sort": "stars",
            "per_page": 30,
        },
        "enabled": True,
    },
    "portswigger_labs": {
        "url": "https://portswigger.net/web-security/all-labs",
        "type": "html",
        "frequency_hours": 72,
        "enabled": True,
    },
    "hacktricks_web": {
        "url": "https://book.hacktricks.wiki/en/pentesting-web/index.html",
        "type": "html",
        "frequency_hours": 72,
        "enabled": True,
    },
    "owasp_top10": {
        "url": "https://owasp.org/www-project-top-ten/",
        "type": "html",
        "frequency_hours": 168,
        "enabled": True,
    },
    "payloads_all_things": {
        "url": "https://api.github.com/repos/swisskyrepo/PayloadsAllTheThings/contents",
        "type": "api_json",
        "frequency_hours": 72,
        "enabled": True,
    },
    "medium_cybersec": {
        "url": "https://api.rss2json.com/v1/api.json",
        "type": "api_json",
        "frequency_hours": 12,
        "params": {"rss_url": "https://medium.com/feed/tag/cybersecurity"},
        "enabled": True,
    },
    "medium_bugbounty": {
        "url": "https://api.rss2json.com/v1/api.json",
        "type": "api_json",
        "frequency_hours": 12,
        "params": {"rss_url": "https://medium.com/feed/tag/bug-bounty"},
        "enabled": True,
    },
}


class IntelligenceFetcher:
    """
    يجلب من كل المصادر بالتوازي ويحفظ النتائج الخام.
    مبدأ: fetch-only, لا parsing هنا — الـ Analyzer يتولى الفهم.
    """

    def __init__(self, timeout: float = 20.0, max_concurrent: int = 6):
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self._github_token = os.getenv("GITHUB_TOKEN", "")

    def _build_client(self) -> httpx.AsyncClient:
        hdrs = dict(HEADERS)
        if self._github_token:
            hdrs["Authorization"] = f"token {self._github_token}"
        return httpx.AsyncClient(
            headers=hdrs, timeout=self.timeout,
            follow_redirects=True, verify=False
        )

    async def _fetch_one(
        self, source_id: str, cfg: Dict
    ) -> Optional[Dict[str, Any]]:
        """يجلب مصدراً واحداً مع rate limiting"""
        if not cfg.get("enabled", True):
            return None
        async with self.semaphore:
            try:
                async with self._build_client() as client:
                    params = cfg.get("params", {})
                    resp = await client.get(cfg["url"], params=params)
                    resp.raise_for_status()
                    content_type = cfg.get("type", "html")
                    if content_type == "api_json":
                        raw = resp.json()
                    else:
                        raw = resp.text
                    # save raw
                    out = RAW_DIR / f"{source_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                    out.write_text(
                        json.dumps({"source": source_id, "url": cfg["url"], "raw": raw}, ensure_ascii=False),
                        encoding="utf-8"
                    )
                    log.info(f"[FETCH] {source_id}: OK ({len(str(raw))} chars)")
                    return {"source_id": source_id, "url": cfg["url"], "raw": raw, "ts": time.time()}
            except Exception as e:
                log.warning(f"[FETCH] {source_id}: failed — {e}")
                return None

    async def fetch_all(self, sources: Optional[List[str]] = None) -> List[Dict]:
        """يجلب كل المصادر أو مجموعة محددة بالتوازي"""
        targets = {
            k: v for k, v in SOURCES.items()
            if (sources is None or k in sources) and v.get("enabled")
        }
        log.info(f"[FETCH] Starting parallel fetch: {list(targets.keys())}")
        tasks = [self._fetch_one(sid, cfg) for sid, cfg in targets.items()]
        results = await asyncio.gather(*tasks, return_exceptions=False)
        return [r for r in results if r is not None]

    # ── Specialized extractors ───────────────────────────────────────────────

    async def fetch_nvd_cves(self, keyword: str = "", days_back: int = 7) -> List[Dict]:
        """يجلب CVEs من NVD API حسب كلمة مفتاحية أو فترة زمنية"""
        params: Dict = {"resultsPerPage": 50, "startIndex": 0}
        if keyword:
            params["keywordSearch"] = keyword
        try:
            async with self._build_client() as client:
                resp = await client.get(
                    "https://services.nvd.nist.gov/rest/json/cves/2.0",
                    params=params
                )
                data = resp.json()
                return data.get("vulnerabilities", [])
        except Exception as e:
            log.warning(f"NVD fetch error: {e}")
            return []

    async def fetch_cisa_kev(self) -> List[Dict]:
        """يجلب قائمة الـ Known Exploited Vulnerabilities من CISA"""
        try:
            async with self._build_client() as client:
                resp = await client.get(
                    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
                )
                return resp.json().get("vulnerabilities", [])
        except Exception as e:
            log.warning(f"CISA KEV fetch error: {e}")
            return []

    async def fetch_github_pocs(self, cve_id: str) -> List[Dict]:
        """يبحث في GitHub عن POCs لـ CVE محدد"""
        params = {"q": f"{cve_id} poc exploit", "sort": "stars", "per_page": 10}
        try:
            async with self._build_client() as client:
                resp = await client.get(
                    "https://api.github.com/search/repositories", params=params
                )
                data = resp.json()
                return [
                    {
                        "name": r["full_name"],
                        "url": r["html_url"],
                        "stars": r["stargazers_count"],
                        "description": r.get("description", ""),
                        "language": r.get("language", ""),
                        "updated_at": r.get("updated_at", ""),
                    }
                    for r in data.get("items", [])
                ]
        except Exception as e:
            log.warning(f"GitHub POC search error: {e}")
            return []

    async def fetch_payloads_all_things(self, category: str = "") -> str:
        """يجلب payloads من PayloadsAllTheThings"""
        if not category:
            category = "XSS Injection"
        encoded = category.replace(" ", "%20")
        url = f"https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/{encoded}/README.md"
        try:
            async with self._build_client() as client:
                resp = await client.get(url)
                return resp.text
        except Exception as e:
            log.warning(f"PayloadsAllTheThings fetch error: {e}")
            return ""

    async def fetch_portswigger_labs(self) -> List[Dict]:
        """يجلب قائمة مختبرات PortSwigger المتاحة"""
        labs = []
        try:
            async with self._build_client() as client:
                resp = await client.get("https://portswigger.net/web-security/all-labs")
                soup = BeautifulSoup(resp.text, "html.parser")
                for item in soup.select(".widgetcontainer-lab-link"):
                    title_el = item.select_one("h4")
                    link_el = item.select_one("a")
                    if title_el and link_el:
                        labs.append({
                            "title": title_el.get_text(strip=True),
                            "url": urljoin("https://portswigger.net", link_el.get("href", "")),
                            "difficulty": item.select_one(".difficulty-badge", "").get_text(strip=True) if item.select_one(".difficulty-badge") else "",
                        })
        except Exception as e:
            log.warning(f"PortSwigger fetch error: {e}")
        return labs

    async def fetch_medium_rss(self, tag: str = "bug-bounty", limit: int = 20) -> List[Dict]:
        """يجلب مقالات Medium عبر RSS → JSON"""
        articles = []
        try:
            rss_url = f"https://medium.com/feed/tag/{tag}"
            async with self._build_client() as client:
                resp = await client.get(
                    "https://api.rss2json.com/v1/api.json",
                    params={"rss_url": rss_url}
                )
                data = resp.json()
                for item in data.get("items", [])[:limit]:
                    # strip HTML from content
                    soup = BeautifulSoup(item.get("content", ""), "html.parser")
                    text = soup.get_text(separator="\n", strip=True)
                    articles.append({
                        "title": item.get("title", ""),
                        "url": item.get("link", ""),
                        "author": item.get("author", ""),
                        "published": item.get("pubDate", ""),
                        "text": text[:5000],
                        "tags": item.get("categories", []),
                    })
        except Exception as e:
            log.warning(f"Medium RSS fetch error ({tag}): {e}")
        return articles

    async def fetch_exploit_db_search(self, keyword: str, limit: int = 20) -> List[Dict]:
        """يبحث في Exploit-DB عن exploits"""
        exploits = []
        try:
            async with self._build_client() as client:
                resp = await client.get(
                    "https://www.exploit-db.com/search",
                    params={"description": keyword, "order_by": "date", "sort": "desc"}
                )
                soup = BeautifulSoup(resp.text, "html.parser")
                for row in soup.select("table#exploit_db_table tbody tr")[:limit]:
                    cols = row.find_all("td")
                    if len(cols) >= 4:
                        exploits.append({
                            "date": cols[0].get_text(strip=True),
                            "title": cols[1].get_text(strip=True),
                            "type": cols[2].get_text(strip=True),
                            "platform": cols[3].get_text(strip=True),
                            "url": urljoin("https://www.exploit-db.com",
                                          row.find("a", href=True)["href"] if row.find("a", href=True) else ""),
                        })
        except Exception as e:
            log.warning(f"Exploit-DB search error: {e}")
        return exploits
