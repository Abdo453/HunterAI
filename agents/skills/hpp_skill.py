"""
HTTP Parameter Pollution (CWE-235)
==================================
اختبار HPP بإثبات تفاضلي قطعي:

- الفرضية: تكرار نفس البارامتر مرتين بقيمتيهم قد تلُغى (override) أو تحفّز سلوكاً نظيرياً
  على خوادم/إطارات تحلل آخر/أول occurrence
- Proof-of-Execution:
    * درجة قيمة (price/amount/qty) تتفاضل فعلياً بين baseline و HPP probe
    * سلوك auth/access differ: baseline=401/redirect و probe=200 (agus cross-params)
- Reflection-only أو اختلاف formatting فقط → لا يُرفع claim
"""
from __future__ import annotations

from typing import Optional, List, Tuple
import httpx
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from agents.skills.base_skill import BaseSkill, SkillResult

# بارامترات يُملّح معها حقن HPP — financial/identity أولوية
HPP_PARAM_HINTS = ("id", "price", "amount", "qty", "user_id", "account", "discount", "seller", "owner")

# قيم محلوبة لحقن توأم للبارامتر — تُستخدم في التفاضل
TWIN_INJECT_VALUES = [
    "1",          # إلغاء (last-wins) بالممنوع
    "0",
    "999999",
    "-1",         # negative (salary/price) testing
]

class HTTPParameterPollutionSkill(BaseSkill):
    name = "hpp_skill"
    vuln_type = "http_parameter_pollution"
    cwe = "CWE-235"
    owasp_top10 = "A04:2021"
    default_severity = "Medium"

    def __init__(self, proxy: Optional[str] = None, timeout: float = 12.0):
        super().__init__(proxy=proxy, timeout=timeout)

    async def run(self, target_url: str, param_name: str, **kwargs) -> SkillResult:
        if not any(kw in param_name.lower() for kw in HPP_PARAM_HINTS):
            return SkillResult(
                verified=False, vuln_type=self.vuln_type,
                title="Param not an HPP candidate", severity=self.default_severity,
                endpoint=target_url, param_name=param_name, evidence="")

        async with httpx.AsyncClient(proxies=self.proxy or None, timeout=self.timeout,
                                     follow_redirects=True) as client:
            try:
                # ── Baseline: القيمة الحالية بحد ذاتها ──
                parsed = urlparse(target_url)
                qs = parse_qs(parsed.query)
                original = qs.get(param_name, [None])[0]
                if original is None:
                    return self._no(target_url, param_name, "Param absent from URL — cannot baseline")

                baseline = await client.get(target_url)
                if baseline.status_code in (403, 429):
                    return self._no(target_url, param_name, "Baseline blocked (WAF)")
                base_status = baseline.status_code
                base_len = len(baseline.text)

                for inj in TWIN_INJECT_VALUES:
                    # حقن توأم القيمة الأصلية + قيمة الحقن
                    twin = [original, inj] if inj != original else [original, original]
                    new_q = urlencode({k: v for k, v in qs.items() if k != param_name}, doseq=True)
                    new_q = (new_q + "&" if new_q else "") + urlencode({param_name: twin}, doseq=True)
                    new_url = urlunparse(parsed._replace(query=new_q))

                    resp = await client.get(new_url)
                    if resp.status_code in (403, 429):
                        continue

                    # ── إثبات التنفيذ: تغيّر قطعي في الحالة/السلوك تفاضل قطعي ──
                    if resp.status_code != base_status and self._is_improvement(base_status, resp.status_code):
                        return SkillResult(
                            verified=True, vuln_type=self.vuln_type,
                            title=f"HPP in '{param_name}' — state transition {base_status}→{resp.status_code} "
                                  f"via duplicate param ({param_name}={inj})",
                            severity=self.default_severity,
                            endpoint=target_url, param_name=param_name,
                            payload_used=f"{param_name}={original}&{param_name}={inj}",
                            evidence=f"baseline status={base_status}, polluted status={resp.status_code} — differential confirmed",
                            confidence=0.88,
                            tool=self.name,
                            evidence_sources=["HPPSkill/Differential"])

                    # فرق دال في طول الاستجابة (تشير لسلوك نظيرًا مختلف) مع بقاء status
                    if resp.status_code == base_status and abs(len(resp.text) - base_len) / max(base_len, 1) > 0.35:
                        return SkillResult(
                            verified=False, vuln_type=self.vuln_type,
                            title=f"Suspected HPP in '{param_name}' — response size delta {base_len}→{len(resp.text)} (weak)",
                            severity="Low",
                            endpoint=target_url, param_name=param_name,
                            payload_used=f"{param_name}={original}&{param_name}={inj}",
                            evidence="body-length differential only — treated as UNVERIFIED_SIGNAL",
                            confidence=0.55,
                            tool=self.name,
                            evidence_sources=["HPPSkill/LengthSignal"])
            except Exception as e:
                return self._no(target_url, param_name, str(e))

        return self._no(target_url, param_name, "No exploitable HPP differential")

    def _is_improvement(self, base: int, probe: int) -> bool:
        """الحالة الأخير 'أفضل' لنا — قفزة حقيقية نحو 2xx من أي 4xx (401/402/403) أو 3xx أو 5xx"""
        if base >= 400 and 200 <= probe < 300:
            return True
        if base in (301, 302, 307, 308) and 200 <= probe < 300:
            return True
        return False

    def _no(self, target_url: str, param_name: str, evidence: str = "") -> SkillResult:
        return SkillResult(
            verified=False, vuln_type=self.vuln_type,
            title="HPP not verified (no differential improvement)",
            severity=self.default_severity,
            endpoint=target_url, param_name=param_name, evidence=evidence)

    def can_handle(self, param_name: str, url: str = "", sample_value: str = "") -> float:
        p = param_name.lower()
        if any(kw in p for kw in HPP_PARAM_HINTS):
            return 0.75
        return 0.1
