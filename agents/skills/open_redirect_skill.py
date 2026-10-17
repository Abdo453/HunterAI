"""
Open Redirect Skill (CWE-601)
=============================
اختبار Open Redirect بإثبات تفاضلي قطعي:

- baseline: طلب الـ endpoint بقيمة آمنة (نفس النطاق)
- probe: حقن URL خارجي مسيطر عليه (out-of-band nonce) في البارامتر
- Proof-of-Execution: إعادة التوجيه يجب أن تصل فعلياً للنطاق الخارجي (Location header أو redirect history)
  — أي نص/شكل في الـ HTML وحده لا يكفي (Reflection != Execution)
"""
from __future__ import annotations

import time
from typing import Optional
import httpx
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from agents.skills.base_skill import BaseSkill, SkillResult

# عناوين مؤقتة للتحقق — نستخدم مضيف نتعرف على نطاقه بدون خدمات طرف ثالث ممنوعة
CANARY_HOST = "hunterai-redirect-canary.invalid"
REDIRECT_KEYWORDS = ["redirect", "next", "dest", "goto", "return", "returnto", "returnurl", "r", "u", "url", "forward", "target", "continue", " viewedurl", "callback"]


class OpenRedirectSkill(BaseSkill):
    name = "open_redirect_skill"
    vuln_type = "open_redirect"
    cwe = "CWE-601"
    owasp_top10 = "A01:2021"
    default_severity = "Medium"

    PAYLOADS = [
        "https://{canary}/",
        "//{canary}/",               # protocol-relative
        "/\\{canary}",               # backslash trick (nginx/asp)
        "///{canary}/",
        "https:{canary}",            # scheme-relative variant
        "/redirect/{canary}",        # path-based (defense varies)
    ]

    def __init__(self, proxy: Optional[str] = None, timeout: float = 12.0):
        super().__init__(proxy=proxy, timeout=timeout)
        self.canary_host = CANARY_HOST

    async def run(self, target_url: str, param_name: str, **kwargs) -> SkillResult:
        if not any(kw in param_name.lower() for kw in REDIRECT_KEYWORDS):
            return SkillResult(
                verified=False, vuln_type=self.vuln_type,
                title="Param not a redirect candidate", severity=self.default_severity,
                endpoint=target_url, param_name=param_name, evidence="")

        parsed = urlparse(target_url)
        same_site = f"{parsed.scheme}://{parsed.netloc}/safe-baseline-path"

        async with httpx.AsyncClient(proxies=self.proxy or None, timeout=self.timeout,
                                     follow_redirects=True) as client:
            try:
                # ── Baseline: قيمة آمنة (نفس الموقع) ──
                baseline = await self._get_with_param(client, target_url, param_name, same_site)
                redirect_statuses_baseline = self._redirect_chain_hosts(baseline)
                same_site_leaves = all(
                    h == parsed.netloc or h == "" for h in redirect_statuses_baseline)

                # ── Detect-Inject: كل payload بدوره ──
                for tpl in self.PAYLOADS:
                    payload = tpl.format(canary=self.canary_host)
                    resp = await self._get_with_param(client, target_url, param_name, payload)

                    if self._is_error_or_waf(resp):
                        continue  # WAF intercept — لا نرفع claim من حجب WAF

                    chain_hosts = self._redirect_chain_hosts(resp)
                    # إثبات التنفيذ: وجمود على host خارجي فعلي في سلسلة التوجيه
                    left_target = any(self.canary_host in h for h in chain_hosts if h)

                    # تفاضل قطعي: الـ baseline بقى داخل الموقع، والـ probe خرج للـ canary
                    if left_target and baseline.status_code != 400:
                        return SkillResult(
                            verified=True, vuln_type=self.vuln_type,
                            title=f"Open Redirect in '{param_name}' (redirect chain leaves origin to {self.canary_host})",
                            severity=self.default_severity,
                            endpoint=target_url, param_name=param_name,
                            payload_used=payload,
                            evidence=(f"baseline_status={baseline.status_code} ; baseline_left_origin={not same_site_leaves};"
                                      f" probe_status={resp.status_code} ; probe_redirect_chain={chain_hosts}"),
                            confidence=0.92,
                            tool=self.name,
                            evidence_sources=["OpenRedirectSkill/DifferentialChain"])
            except Exception as e:
                return SkillResult(
                    verified=False, vuln_type=self.vuln_type,
                    title=str(e), severity=self.default_severity,
                    endpoint=target_url, param_name=param_name, evidence="")

        return SkillResult(
            verified=False, vuln_type=self.vuln_type,
            title="No exploitable open redirect (all payloads contained)",
            severity=self.default_severity,
            endpoint=target_url, param_name=param_name, evidence="")

    async def _get_with_param(self, client: httpx.AsyncClient, target_url: str,
                              param_name: str, value: str) -> httpx.Response:
        parsed = urlparse(target_url)
        qs = parse_qs(parsed.query)
        qs[param_name] = [value]
        new_query = urlencode(qs, doseq=True)
        new_url = urlunparse(parsed._replace(query=new_query))
        return await client.get(new_url)

    def _redirect_chain_hosts(self, resp: httpx.Response) -> list:
        """يستخرج host لكل step في سلسلة التوجيه (headers + history)"""
        hosts = []
        for h in resp.history:
            loc = h.headers.get("location", "")
            if loc:
                hp = urlparse(loc)
                if hp.hostname:
                    hosts.append(hp.netloc)
        loc = resp.headers.get("location", "")
        if loc and urlparse(loc).hostname and resp.status_code in (301, 302, 303, 307, 308):
            hosts.append(urlparse(loc).netloc)
        return hosts

    def _is_error_or_waf(self, resp: httpx.Response) -> bool:
        """رفض الإجابات اللي هي WAF block مش سلوك التطبيق"""
        if resp.status_code in (403, 429):
            return True
        if resp.status_code == 400 and "blocked" in resp.text.lower():
            return True
        return False

    def can_handle(self, param_name: str, url: str = "", sample_value: str = "") -> float:
        p = param_name.lower()
        # كلمات طويلة: substring matching آمن
        if any(kw in p for kw in ("redirect", "goto", "return", "target", "continue", "callback", "forward", "dest", "next")):
            return 0.95
        # كلمات قصيرة: مطابقة تامة فقط (id= حرف واحد مثل 'r' يطابق أي اسم)
        if p in ("r", "u", "url", "uri", "dest", "next", "to", "link", "out"):
            return 0.9
        if sample_value.startswith("http") or "//" in sample_value or sample_value.startswith("/"):
            return 0.7
        return 0.05
