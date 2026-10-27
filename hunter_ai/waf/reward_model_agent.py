"""
Reward Model Agent — وكيل نموذج المكافأة لتقييم payloads قبل الإرسال
======================================================================
يُحاكي استجابة WAF (block / bypass / challenge) ويقيّم كل payload قبل
إرساله فعلياً، لتقليل عدد الطلبات الحقيقية وحفظ سِمعة الهدف.

يعمل بوضعين:
  1. محلي (heuristics): قواعد بسيطة مبنية على أنماط WAF معروفة
  2. عبر LLM (اختياري): يُرسل payload إلى موديل محلي (Ollama) ويُطلب منه التقييم

المكافأة المُرجعة تُغذي RL Policy Optimizer.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class PayloadEvaluation:
    payload: str
    technique: str
    predicted_outcome: str  # "bypass" | "block" | "challenge" | "unknown"
    confidence: float       # 0.0 إلى 1.0
    reward: float           # +1 expected bypass, -1 expected block, 0 unknown
    reason: str


class RewardModelAgent:
    """
    يقيّم payload ويعيد توقعاً لنتيجة WAF + مكافأة متوقعة.
    """

    # أنماط شائعة تشير إلى أن payload محتمل أن يُحظر
    BLOCK_PATTERNS = [
        r"(?i)<script[^>]*>",
        r"(?i)onerror\s*=",
        r"(?i)onload\s*=",
        r"(?i)alert\s*\(",
        r"(?i)eval\s*\(",
        r"(?i)document\.cookie",
        r"(?i)union\s+select",
        r"(?i)'\s*or\s*'1'='1",
        r"(?i)<iframe[^>]*>",
    ]

    # أنماط تشير إلى تشويش قد يتجاوز الكشف البسيط
    BYPASS_HINTS = [
        r"(?i)atob\(",
        r"(?i)String\.fromCharCode",
        r"(?i)constructor",
        r"(?i)ontoggle",
        r"(?i)onpointerenter",
        r"(?i)%u[0-9a-f]{4}",
        r"(?i)double.*encoding",
    ]

    def __init__(self, use_llm: bool = False, llm_endpoint: Optional[str] = None):
        self.use_llm = use_llm
        self.llm_endpoint = llm_endpoint  #例如 http://localhost:11434/api/generate

    def evaluate(
        self,
        payload: str,
        technique: str,
        waf_type: str = "unknown",
    ) -> PayloadEvaluation:
        """
        يقيّم payload وي返回 예상 النتيجة والمكافأة.
        """
        if self.use_llm and self.llm_endpoint:
            return self._evaluate_via_llm(payload, technique, waf_type)

        return self._evaluate_heuristic(payload, technique, waf_type)

    def _evaluate_heuristic(
        self,
        payload: str,
        technique: str,
        waf_type: str,
    ) -> PayloadEvaluation:
        low = payload.lower()

        # فحص أنماط الحظر المعروفة
        block_hits = [p for p in self.BLOCK_PATTERNS if re.search(p, payload)]
        bypass_hits = [p for p in self.BYPASS_HINTS if re.search(p, payload)]

        if block_hits and not bypass_hits:
            return PayloadEvaluation(
                payload=payload,
                technique=technique,
                predicted_outcome="block",
                confidence=0.7,
                reward=-1.0,
                reason=f"يحتوي على أنماط محظورة: {', '.join(block_hits[:3])}",
            )

        if bypass_hits and not block_hits:
            return PayloadEvaluation(
                payload=payload,
                technique=technique,
                predicted_outcome="bypass",
                confidence=0.6,
                reward=1.0,
                reason=f"يحتوي على إشارات تجاوز: {', '.join(bypass_hits[:3])}",
            )

        # Mixed or unknown
        if block_hits and bypass_hits:
            return PayloadEvaluation(
                payload=payload,
                technique=technique,
                predicted_outcome="challenge",
                confidence=0.4,
                reward=0.0,
                reason="مختلط: أنماط حظر وتجاوز معاً — يحتاج اختبار فعلي",
            )

        return PayloadEvaluation(
            payload=payload,
            technique=technique,
            predicted_outcome="unknown",
            confidence=0.3,
            reward=0.0,
            reason="لا توجد أنماط واضحة — اختبار فعلي مطلوب",
        )

    def _evaluate_via_llm(
        self,
        payload: str,
        technique: str,
        waf_type: str,
    ) -> PayloadEvaluation:
        """
        يُرسل إلى LLM محلي للتقييم. إذا فشل الاتصال، يعود إلى heuristic.
        """
        try:
            import httpx
            prompt = (
                f"أنت خبير أمن تطبيقات الويب. قيم payload التالي ضد WAF من نوع {waf_type}.\n"
                f"التقنية: {technique}\n"
                f"الpayload: {payload}\n\n"
                "أجب بصيغة JSON فقط: {\"outcome\": \"bypass|block|challenge\", \"confidence\": 0.0-1.0, \"reason\": \"...\"}"
            )
            with httpx.Client(timeout=10) as client:
                resp = client.post(self.llm_endpoint, json={
                    "model": "qwen2.5:14b",
                    "prompt": prompt,
                    "stream": False,
                })
                if resp.status_code == 200:
                    data = resp.json()
                    text = data.get("response", "{}")
                    # استخراج JSON من الاستجابة
                    import json as _json
                    try:
                        result = _json.loads(text)
                        outcome = result.get("outcome", "unknown")
                        conf = float(result.get("confidence", 0.5))
                        reason = result.get("reason", "llm evaluation")
                        reward = 1.0 if outcome == "bypass" else (-1.0 if outcome == "block" else 0.0)
                        return PayloadEvaluation(payload, technique, outcome, conf, reward, reason)
                    except Exception:
                        pass
        except Exception:
            pass

        return self._evaluate_heuristic(payload, technique, waf_type)


__all__ = ["RewardModelAgent", "PayloadEvaluation"]
