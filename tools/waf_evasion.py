"""
WAF & Rate-Limit Adaptive Evasion Engine
مستوحى من HexStrike AI — يكتشف الـ WAF ويحدد بروفايل الفحص لتفادي الحظر
"""
import httpx
import random
import time
import asyncio
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
]

WAF_SIGNATURES = {
    "Cloudflare": ["cf-ray", "cf-cache-status", "__cfduid", "cloudflare", "cf-chl-bypass"],
    "AWS WAF": ["x-amz-cf-id", "awselb", "aws-waf"],
    "Akamai": ["akamai", "x-akamai-transformed", "ak_bmsc"],
    "Imperva / Incapsula": ["x-cdn: incapsula", "_incap_ses", "visid_incap"],
    "ModSecurity": ["mod_security", "modsecurity", "NOYB"],
    "F5 BIG-IP": ["bigipserver", "x-cnection: close", "f5_cspm"],
    "Sucuri": ["x-sucuri-id", "sucuri_cloudproxy", "x-sucuri-cache"],
    "Wordfence": ["wordfence_verifiedhuman", "wfvt_"],
}


@dataclass
class WAFProfile:
    target: str
    waf_detected: bool = False
    waf_names: List[str] = field(default_factory=list)
    rate_limit_detected: bool = False
    recommended_mode: str = "NORMAL"  # STEALTH | CONSERVATIVE | NORMAL | AGGRESSIVE
    delay_range: Tuple[float, float] = (0.2, 0.5)
    headers: Dict[str, str] = field(default_factory=dict)
    confidence: float = 0.0


class WAFEvasionEngine:
    """
    محرك تفادي الـ WAF والـ Rate Limiting
    يكتشف الحماية ويعدل المعاملات تلقائياً
    """

    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout

    async def detect_waf(self, target_url: str) -> WAFProfile:
        """فحص الهدف واكتشاف نوع الـ WAF ومستوى الحماية"""
        if not target_url.startswith("http://") and not target_url.startswith("https://"):
            target_url = f"https://{target_url}"

        detected_wafs = []
        rate_limited = False
        headers_found = {}

        try:
            async with httpx.AsyncClient(verify=False, timeout=self.timeout, follow_redirects=True) as client:
                headers = {"User-Agent": random.choice(USER_AGENTS)}
                resp = await client.get(target_url, headers=headers)
                
                resp_headers_str = str(resp.headers).lower()
                resp_body_str = resp.text.lower()[:3000]

                # Check headers & cookies
                for waf, sigs in WAF_SIGNATURES.items():
                    for sig in sigs:
                        if sig.lower() in resp_headers_str or sig.lower() in resp_body_str:
                            if waf not in detected_wafs:
                                detected_wafs.append(waf)
                            break

                # Check rate limiting
                if resp.status_code in (429, 503) or "rate limit" in resp_body_str or "too many requests" in resp_body_str:
                    rate_limited = True

                headers_found = dict(resp.headers)
        except Exception:
            pass

        waf_present = len(detected_wafs) > 0
        
        # اختيار الوضع التكيفي
        if waf_present and rate_limited:
            mode = "STEALTH"
            delay = (2.0, 4.0)
            confidence = 0.95
        elif waf_present:
            mode = "CONSERVATIVE"
            delay = (0.8, 1.8)
            confidence = 0.85
        elif rate_limited:
            mode = "CONSERVATIVE"
            delay = (1.0, 2.5)
            confidence = 0.80
        else:
            mode = "NORMAL"
            delay = (0.1, 0.4)
            confidence = 0.60

        evasion_headers = self.generate_evasion_headers(detected_wafs)

        return WAFProfile(
            target=target_url,
            waf_detected=waf_present,
            waf_names=detected_wafs,
            rate_limit_detected=rate_limited,
            recommended_mode=mode,
            delay_range=delay,
            headers=evasion_headers,
            confidence=confidence
        )

    def generate_evasion_headers(self, detected_wafs: List[str]) -> Dict[str, str]:
        """توليد ترويسات مراوغة مخصصة"""
        ua = random.choice(USER_AGENTS)
        headers = {
            "User-Agent": ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9,ar;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
        }

        # Header rotation tricks
        fake_ip = f"192.168.{random.randint(1,254)}.{random.randint(1,254)}"
        headers["X-Forwarded-For"] = fake_ip
        headers["X-Originating-IP"] = fake_ip
        headers["X-Remote-IP"] = fake_ip
        headers["X-Client-IP"] = fake_ip

        return headers

    async def sleep_adaptive(self, profile: WAFProfile):
        """تأخير تكيفي قبل الطلب التالي لتجنب الحظر"""
        min_d, max_d = profile.delay_range
        delay = random.uniform(min_d, max_d)
        await asyncio.sleep(delay)
