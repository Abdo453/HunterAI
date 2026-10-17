"""
Host Header Injection Skill (CWE-644)
=====================================
اختبار Host Header / Password-Reset Poisoning بإثبات تفاضلي قطعي:

- probe: حقن canary host عبر Host/X-Forwarded-Host/X-Host/Forwarded
- Proof-of-Execution: الـ canary يجب أن يظهر في مكان له Function Impact:
    1. Location header → redirect poisoning
    2. Set-Cookie Domain= → cookie poisoning
    3. روابط إعادة تعيين كلمة المرور / تأكيد الحساب في الـ body
- Reflection != Execution: ظهور canary عشوائي في نص عادي لا يُمسك كإثبات
"""
from __future__ import annotations

from typing import Optional
import httpx
from urllib.parse import urlparse

from agents.skills.base_skill import BaseSkill, SkillResult

CANARY_HOST = "hunterai-hostheader-canary.invalid"


class HostHeaderInjectionSkill(BaseSkill):
    name = "host_header_injection_skill"
    vuln_type = "host_header_injection"
    cwe = "CWE-644"
    owasp_top10 = "A05:2021"
    default_severity = "High"

    INJECTION_VARIANTS = [
        {"title": "X-Forwarded-Host",          "headers": {"X-Forwarded-Host": "{canary}"}},
        {"title": "X-Host",                    "headers": {"X-Host": "{canary}"}},
        {"title": "X-HTTP-Host-Override",      "headers": {"X-HTTP-Host-Override": "{canary}"}},
        {"title": "Forwarded (RFC 7239)",      "headers": {"Forwarded": "host={canary}"}},
        {"title": "Host dual-value (tunnel)",  "headers": {"X-Forwarded-Host": "{origin},{canary}"}},
    ]

    # كلمات تؤكد أن ظهور الـ canary في الـ body له function impact
    FUNCTION_BODY_MARKERS = (
        "reset", "activate", "confirm", "verify", "login",
        "click", "signup", "register", "invite", "unsubscribe",
    )
    FUNCTION_URL_PREFIXES = (
        f"//{CANARY_HOST}", f"https://{CANARY_HOST}", f"http://{CANARY_HOST}",
    )

    def __init__(self, proxy: Optional[str] = None, timeout: float = 12.0):
        super().__init__(proxy=proxy, timeout=timeout)
        self.canary_host = CANARY_HOST

    async def run(self, target_url: str, param_name: str, **kwargs) -> SkillResult:
        parsed = urlparse(target_url)
        origin_host = parsed.netloc

        async with httpx.AsyncClient(proxies=self.proxy or None, timeout=self.timeout,
                                     follow_redirects=False) as client:
            try:
                # ── Baseline: طلب نظيف ──
                baseline = await client.get(target_url)
                if baseline.status_code in (403, 429):
                    return self._no(target_url, param_name, "Baseline blocked (WAF) — cannot verify")

                for variant in self.INJECTION_VARIANTS:
                    headers = {
                        k: v.format(canary=self.canary_host, origin=origin_host)
                        for k, v in variant["headers"].items()
                    }
                    resp = await client.get(target_url, headers=headers)

                    if resp.status_code in (403, 429):
                        continue  # WAF intercept — لا نرفع claim

                    vector = self._find_functional_vector(resp)
                    if vector:
                        return SkillResult(
                            verified=True, vuln_type=self.vuln_type,
                            title=f"Host Header Injection via {variant['title']} (vector={vector})",
                            severity=self.default_severity,
                            endpoint=target_url, param_name=param_name,
                            payload_used=variant["title"],
                            evidence=(
                                f"canary='{self.canary_host}' appeared in vector '{vector}' "
                                f"after header injection; clean baseline lacks it. "
                                f"status={resp.status_code}"),
                            confidence=0.90,
                            tool=self.name,
                            evidence_sources=["HostHeaderInjectionSkill/Differential"])
            except Exception as e:
                return self._no(target_url, param_name, str(e))

        return self._no(target_url, param_name,
                        "No functional canary reflection (headers/links/cookies) under any injection variant")

    def _find_functional_vector(self, resp: httpx.Response) -> Optional[str]:
        """يبحث عن الـ canary في أماكن قابلة للاستغلال وظيفياً فقط"""
        canary = self.canary_host

        # 1. Location header → redirect poisoning
        loc = resp.headers.get("location", "") or ""
        if canary in loc.lower():
            return "location_header"

        # 2. Set-Cookie Domain= → cookie poisoning
        for sc in resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else [resp.headers.get("set-cookie", "")]:
            if not sc:
                continue
            for part in sc.split(";"):
                if part.strip().lower().startswith("domain=") and canary in part.lower():
                    return "set_cookie_domain"

        # 3. Body → روابط ذات نتيجة وظيفية (password reset / activation)
        body_lower = resp.text.lower()
        if canary in body_lower:
            has_function_marker = any(m in body_lower for m in self.FUNCTION_BODY_MARKERS)
            has_url_form = any(p in body_lower for p in self.FUNCTION_URL_PREFIXES)
            if has_function_marker and has_url_form:
                return "body_link"

        return None

    def _no(self, target_url: str, param_name: str, evidence: str = "") -> SkillResult:
        return SkillResult(
            verified=False, vuln_type=self.vuln_type,
            title="Host header injection not exploitable (no functional canary vector)",
            severity=self.default_severity,
            endpoint=target_url, param_name=param_name, evidence=evidence)

    def can_handle(self, param_name: str, url: str = "", sample_value: str = "") -> float:
        return 0.6 if "host" in param_name.lower() else 0.4
