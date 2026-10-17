"""
Bug Bounty GitHub Resources Loader
==================================
يجلب المعرفة والقوائم من مستودعات GitHub مفتوحة المصدر مع:

  - Cache محلي في data/wordlists/github/ (يُخدم أولاً — يسرّع التشغيل ويعمل بدون شبكة)
  - Fallback داخلي مدقَّق يدوياً (قوائم payloads لا تُستهلك أبداً من الشبكة —
    حتى لا يتسرب محتوى غير مدقق إلى محرك الحقن)
  - جلب الشبكة للمنهجيات فقط، وبشكل opt-in صريح عبر force_refresh=True
  - Provenance لكل مورد (المستودع + الرابط + sha256)

مصادر (مستودعات مشهورة مفتوحة المصدر):
  swisskyrepo/PayloadsAllTheThings  — payloads & methodology
  nahamsec/Resources                — bug bounty recon checklist
  danielmiessler/SecLists           — (مرجع عام للقوائم؛ لم يُسحب تلقائياً)
"""
from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)

CACHE_ROOT = Path("data/wordlists/github")
DEFAULT_TIMEOUT = 15.0


@dataclass
class GitHubResource:
    name: str
    category: str            # payloads | methodology
    url: str                 # رابط المستودع/المجلد در بوابة GitHub (توثيقي)
    fallback: List[str] = field(default_factory=list)   # القائمة المدققة الداخلية
    source_git: str = ""


SOURCES: Dict[str, GitHubResource] = {
    # ── Open redirect vectors ──────────────────────────────────────────────
    "open_redirect_payloads": GitHubResource(
        name="open_redirect_payloads",
        category="payloads",
        url="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Open%20Redirect",
        fallback=[
            "//hunter-canary.invalid", r"\/hunter-canary.invalid", "///hunter-canary.invalid",
            "https://hunter-canary.invalid", "https: hunter-canary.invalid",
            "//{canary}", "/%2F%2E", "//%2F%2Eexample.com", "https://.example.com",
        ],
        source_git="swisskyrepo/PayloadsAllTheThings (Open Redirect)",
    ),
    # ── SSRF bypass variants (localhost encodings) ─────────────────────────
    "ssrf_bypass_variants": GitHubResource(
        name="ssrf_bypass_variants",
        category="payloads",
        url="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery",
        fallback=[
            "http://127.0.0.1", "http://localhost", "http://2130706433",
            "http://0x7f000001", "http://0177.0.0.1", "http://[::1]",
            "http://127.1", "http://0.0.0.0", "http://0/",
        ],
        source_git="swisskyrepo/PayloadsAllTheThings (SSRF)",
    ),
    # ── NoSQL injection vectors ───────────────────────────────────────────
    "nosql_injection_payloads": GitHubResource(
        name="nosql_injection_payloads",
        category="payloads",
        url="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection",
        fallback=[
            {"$ne": None}, {"$ne": ""}, {"$gt": ""}, {"$regex": "^a"},
            {"$regex": ".*"}, "{$where: true}", "true, $where: '1 == 1'",
        ],
        source_git="swisskyrepo/PayloadsAllTheThings (NoSQL Injection)",
    ),
    # ── Host header injection / Web cache poisoning methodology ───────────
    "methodology_web_cache": GitHubResource(
        name="methodology_web_cache",
        category="methodology",
        url="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Web%20Cache%20Poisoning",
        fallback=[
            "X-Forwarded-Host: {canary}",
            "X-HTTP-Host-Override: {canary}",
            "Forwarded: host={canary}",
        ],
        source_git="swisskyrepo/PayloadsAllTheThings (Web Cache Poisoning)",
    ),
    # ── Bug bounty recon methodology checklist ────────────────────────────
    "bug_bounty_recon_checklist": GitHubResource(
        name="bug_bounty_recon_checklist",
        category="methodology",
        url="https://github.com/nahamsec/Resources",
        fallback=[
            "crt.sh", "subfinder", "amass", "assetfinder", "hackertarget",
            "waybackurls", "gau", "gospider", "httpx", "nuclei", "dnsx",
        ],
        source_git="nahamsec/Resources (Recon checklist)",
    ),
    # ── CRLF / response splitting vectors ─────────────────────────────────
    "crlf_payloads": GitHubResource(
        name="crlf_payloads",
        category="payloads",
        url="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CRLF%20Injection",
        fallback=[
            "%0d%0aX-Injection-Header: canary",
            "%0AX-Injection-Header: canary",
            "%0d%0aSet-Cookie: injected=1",
        ],
        source_git="swisskyrepo/PayloadsAllTheThings (CRLF Injection)",
    ),
}


class GitHubResources:
    """Loader مع cache محلي و fallback داخلي وجلب شبكة opt-in."""

    def __init__(self, cache_root: Optional[Path] = None, timeout: float = DEFAULT_TIMEOUT):
        self.cache_root = Path(cache_root or CACHE_ROOT)
        self.cache_root.mkdir(parents=True, exist_ok=True)
        self.timeout = timeout
        self._loaded: Dict[str, List[Any]] = {}

    def _cache_path(self, name: str) -> Path:
        return self.cache_root / f"{name}.txt"

    def _sha(self, data: str) -> str:
        return hashlib.sha256(data.encode("utf-8", "ignore")).hexdigest()

    def fetch(self, resource: GitHubResource, force_refresh: bool = False) -> Dict[str, Any]:
        """
        ترتيب الجلب:
          1. Cache محلي (إن لم يُطلب تحديث قسري)
          2. GitHub Raw (للمنهجيات فقط + فقط عند force_refresh=True صريحاً)
          3. القائمة المدققة الداخلية (fallback) — raid payloads تمر عبر هنا دائماً
        يرجّع {"name", "items", "origin", "sha256", "source_git", "fetched_at"}
        """
        cache = self._cache_path(resource.name)

        # 1. Cache محلي
        if not force_refresh and cache.exists():
            try:
                body = cache.read_text(encoding="utf-8")
                items = self._parse_local(body)
                if items:
                    self._loaded[resource.name] = items
                    return self._pack(resource, items, "cache", body, cache.stat().st_mtime)
            except Exception:
                pass

        # 2. GitHub Raw — منهجيات فقط، وopt-in صريح عبر force_refresh
        if resource.category != "payloads" and force_refresh:
            try:
                resp = httpx.get(resource.url, timeout=self.timeout, follow_redirects=True)
                if resp.status_code == 200:
                    body = resp.text
                    items = self._parse_local(body) or resource.fallback
                    if items:
                        try:
                            cache.write_text("".join(str(i) + "\n" for i in items),
                                             encoding="utf-8")
                        except Exception:
                            pass
                        self._loaded[resource.name] = items
                        return self._pack(resource, items, "github", body, time.time())
            except Exception as e:
                logger.warning(f"[GitHubResources] fetch failed for {resource.name}: {e}")

        # 3. Fallback داخلي (بلا شبكة) — القائمة المدققة
        if resource.fallback:
            self._loaded[resource.name] = resource.fallback
            return self._pack(resource, resource.fallback, "fallback",
                              "\n".join(map(str, resource.fallback)), time.time())
        return {"name": resource.name, "items": [], "origin": "none", "sha256": ""}

    def names_for(self, resource_name: str, force_refresh: bool = False) -> List[Any]:
        """واجهة عامة: اسم المورد → قائمة العناصر"""
        res = SOURCES.get(resource_name)
        if res is None:
            return []
        return self.fetch(res, force_refresh=force_refresh).get("items", [])

    def provenance(self, resource_name: str) -> Dict[str, Any]:
        res = SOURCES.get(resource_name)
        if res is None:
            return {}
        return {"source_git": res.source_git, "url": res.url, "category": res.category}

    # ─── helpers ───────────────────────────────────────────────────────────
    @staticmethod
    def _parse_local(body: str) -> List[str]:
        return [l.strip() for l in body.splitlines() if l.strip() and not l.lstrip().startswith("#")]

    def _pack(self, resource: GitHubResource, items: List[Any], origin: str,
              body: str, fetched_at: float) -> Dict[str, Any]:
        return {
            "name": resource.name,
            "category": resource.category,
            "items": items,
            "count": len(items),
            "origin": origin,
            "sha256": self._sha(body),
            "source_git": resource.source_git,
            "url": resource.url,
            "fetched_at": fetched_at,
        }


# Singleton عالمي
_github_resources: Optional[GitHubResources] = None

def get_github_resources() -> GitHubResources:
    global _github_resources
    if _github_resources is None:
        _github_resources = GitHubResources()
    return _github_resources


if __name__ == "__main__":
    for name in SOURCES:
        data = get_github_resources().fetch(SOURCES[name])
        print(f"[{name}] items={data['count']} origin={data['origin']} :: {data['source_git']}")
