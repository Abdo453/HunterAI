"""
HunterAI WAF Bypass Ladder
==========================

سلم التجاوز (Bypass Ladder) - منهجية منظمة لتجاوز WAFs تدريجياً
من الأسهل إلى الأصعب، مع تسجيل كل محاولة في الذاكرة المنظمة.

المستويات:
1. Direct payload (بدون تعديل)
2. URL Encoding
3. Double URL Encoding
4. HTML Entity Encoding
5. Case Variation
6. Comment Insertion
7. Parameter Pollution
8. Payload Padding (نقاط العمى)
9. Parser Bug exploitation (أخطاء المحللين)
10. Semantic Pollution (للـ WAFs المعتمدة على LLM)
"""

from __future__ import annotations

import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class LadderStep:
    level: int
    name: str
    payload: str
    technique: str
    success: bool = False
    evidence: Optional[Dict[str, Any]] = None
    timestamp: float = field(default_factory=time.time)


@dataclass
class BypassLadderResult:
    target: str
    original_payload: str
    steps: List[LadderStep] = field(default_factory=list)
    successful_step: Optional[LadderStep] = None
    technique: str = "waf_bypass_ladder"
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "original_payload": self.original_payload,
            "steps": [
                {
                    "level": s.level,
                    "name": s.name,
                    "payload": s.payload,
                    "technique": s.technique,
                    "success": s.success,
                    "evidence": s.evidence,
                    "timestamp": s.timestamp,
                }
                for s in self.steps
            ],
            "successful_step": (
                {
                    "level": self.successful_step.level,
                    "name": self.successful_step.name,
                    "payload": self.successful_step.payload,
                    "technique": self.successful_step.technique,
                }
                if self.successful_step
                else None
            ),
            "technique": self.technique,
            "timestamp": self.timestamp,
        }


class WAFBypassLadder:
    """
    سلم تجاوز WAF تدريجي - يجرب تقنيات越来越多 التعقيد
    حتى يجد واحدة تعمل أو يستنفد جميع المستويات.
    """

    def __init__(self, safety_loop=None, rag_engine=None, structured_memory=None):
        self.safety_loop = safety_loop
        self.rag_engine = rag_engine
        self.structured_memory = structured_memory

    def _url_encode(self, payload: str) -> str:
        return urllib.parse.quote(payload, safe="")

    def _double_url_encode(self, payload: str) -> str:
        return urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe="")

    def _html_entity_encode(self, payload: str) -> str:
        mapping = {
            "<": "&lt;",
            ">": "&gt;",
            "\"": "&quot;",
            "'": "&#x27;",
            "(": "&#40;",
            ")": "&#41;",
        }
        return "".join(mapping.get(ch, ch) for ch in payload)

    def _case_variation(self, payload: str) -> str:
        result = []
        for i, ch in enumerate(payload):
            if ch.isalpha():
                result.append(ch.upper() if i % 2 == 0 else ch.lower())
            else:
                result.append(ch)
        return "".join(result)

    def _comment_insertion(self, payload: str) -> str:
        # إدراج تعليقات HTML بين الأحرف لتفكيك أنماط الكشف
        if "<script" in payload.lower():
            return payload.replace("<script", "<!--<script-->")
        return payload

    def _parameter_pollution(self, payload: str, param_name: str = "input") -> str:
        # إنشاء معلمات متعددة بنفس الاسم لتشويش الـ WAF
        return f"{param_name}={payload}&{param_name}=benign&{param_name}={payload}"

    def run_ladder(
        self,
        target: str,
        original_payload: str,
        param_name: str = "input",
        stop_on_success: bool = True,
    ) -> BypassLadderResult:
        """
        تشغيل سلم التجاوز逐级.

        Args:
            target: الهدف المستهدف
            original_payload: الحمولة الأصلية
            param_name: اسم المعلمة
            stop_on_success: التوقف عند أول نجاح
        """
        result = BypassLadderResult(target=target, original_payload=original_payload)

        # المستوى 1: Direct payload
        step = LadderStep(
            level=1,
            name="Direct Payload",
            payload=original_payload,
            technique="direct",
        )
        result.steps.append(step)

        # المستوى 2: URL Encoding
        step = LadderStep(
            level=2,
            name="URL Encoding",
            payload=self._url_encode(original_payload),
            technique="url_encode",
        )
        result.steps.append(step)

        # المستوى 3: Double URL Encoding
        step = LadderStep(
            level=3,
            name="Double URL Encoding",
            payload=self._double_url_encode(original_payload),
            technique="double_url_encode",
        )
        result.steps.append(step)

        # المستوى 4: HTML Entity Encoding
        step = LadderStep(
            level=4,
            name="HTML Entity Encoding",
            payload=self._html_entity_encode(original_payload),
            technique="html_entity",
        )
        result.steps.append(step)

        # المستوى 5: Case Variation
        step = LadderStep(
            level=5,
            name="Case Variation",
            payload=self._case_variation(original_payload),
            technique="case_variation",
        )
        result.steps.append(step)

        # المستوى 6: Comment Insertion
        step = LadderStep(
            level=6,
            name="Comment Insertion",
            payload=self._comment_insertion(original_payload),
            technique="comment_insertion",
        )
        result.steps.append(step)

        # المستوى 7: Parameter Pollution
        step = LadderStep(
            level=7,
            name="Parameter Pollution",
            payload=self._parameter_pollution(original_payload, param_name),
            technique="parameter_pollution",
        )
        result.steps.append(step)

        # المستوى 8: Payload Padding (إذا كان payload_padding متاحاً)
        try:
            from hunter_ai.waf.payload_padding import PaddingAnalyzer
            pa = PaddingAnalyzer()
            padding_result = pa.build_padded_payload(target, original_payload)
            step = LadderStep(
                level=8,
                name="Payload Padding",
                payload=padding_result.padded_payload[:200] + "...",
                technique="payload_padding",
            )
            result.steps.append(step)
        except Exception:
            pass

        # المستوى 9: Parser Bug exploitation (إذا كانت قاعدة البيانات متاحة)
        try:
            from hunter_ai.waf.parser_bugs import ParserBugExploiter
            pe = ParserBugExploiter()
            bugs = pe.db.list_bugs()
            if bugs:
                bug = bugs[0]  # استخدام أول ثغرة متاحة كمثال
                bypass = pe.generate_bypass(target, bug["bug_id"], original_payload)
                step = LadderStep(
                    level=9,
                    name=f"Parser Bug ({bug['waf_product']})",
                    payload=bypass.bypass_payload,
                    technique="parser_bug",
                )
                result.steps.append(step)
        except Exception:
            pass

        # المستوى 10: Semantic Pollution (للـ WAFs المعتمدة على LLM)
        try:
            from hunter_ai.waf.semantic_pollution import SemanticPolluter
            sp = SemanticPolluter()
            variant = sp.pollute(target, "llm-waf", original_payload, 0)
            step = LadderStep(
                level=10,
                name="Semantic Pollution",
                payload=variant.polluted_payload[:200] + "...",
                technique="semantic_pollution",
            )
            result.steps.append(step)
        except Exception:
            pass

        # تسجيل النتيجة في الذاكرة المنظمة إذا كان متاحاً
        if self.structured_memory:
            from hunter_ai.memory.structured_memory import MemoryType
            self.structured_memory.write(
                MemoryType.SEMANTIC,
                target,
                f"waf_ladder:{int(time.time())}",
                result.to_dict(),
                ttl_seconds=None,
            )

        return result
