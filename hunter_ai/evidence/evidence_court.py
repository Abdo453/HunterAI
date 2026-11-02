"""
محكمة الأدلة (Evidence Court) لـ HunterAI
يحقق في نجاح تجاوز WAF ويؤكد أن النتيجة جاءت من تجاوز الدفاع فعلاً،
وليس من ثغرة في منطق التطبيق فقط.
يدعم غير المتزامن (async)، السجلات، والتكوينات المركزية
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from core.config.settings import config
from core.exceptions import EvidenceCourtError, HunterAIError
from core.logging.logger import logger


class CourtVerdict(str, Enum):
    PROVEN_BYPASS = "proven_bypass"
    PROVEN_DIRECT = "proven_direct"
    REFUTED = "refuted"
    INCONCLUSIVE = "inconclusive"


@dataclass
class BypassContext:
    """سياق محاولة التجاوز للتحقق من المحكمة."""
    target: str
    endpoint: str
    original_payload: str
    bypass_payload: str
    waf_type: str
    waf_detected: bool
    status_code: int
    response_body: str
    response_headers: Dict[str, str]
    request_headers: Dict[str, str]
    response_time_ms: float
    technique_level: str
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "endpoint": self.endpoint,
            "original_payload": self.original_payload,
            "bypass_payload": self.bypass_payload,
            "waf_type": self.waf_type,
            "waf_detected": self.waf_detected,
            "status_code": self.status_code,
            "response_body_hash": hashlib.sha256(
                self.response_body.encode("utf-8")
            ).hexdigest()[:16],
            "response_headers": self.response_headers,
            "request_headers": self.request_headers,
            "response_time_ms": self.response_time_ms,
            "technique_level": self.technique_level,
            "timestamp": self.timestamp,
        }


@dataclass
class CourtResult:
    """نتيجة حكم المحكمة."""
    verdict: CourtVerdict
    confidence: float
    reasoning: str
    evidence: Dict[str, Any]
    bypass_confirmed: bool
    direct_vuln_confirmed: bool
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "confidence": self.confidence,
            "reasoning": self.reasoning,
            "evidence": self.evidence,
            "bypass_confirmed": self.bypass_confirmed,
            "direct_vuln_confirmed": self.direct_vuln_confirmed,
            "timestamp": self.timestamp,
        }


class EvidenceCourt:
    """
    محكمة الأدلة للتحقق من نجاح تجاوز WAF.
    
    المحكمة تطرح أسئلة على كل نتيجة "ناجحة" للتأكد من:
    1. هل الطلب وصل فعلاً للخادم أم حُجب من WAF؟
    2. هل الاستجابة تحتوي على دليل على تنفيذ الحمولة؟
    3. هل الفرق بين الطلب الأصلي والطلب المُجاوز مؤشر على تجاوز الدفاع؟
    4. هل يمكن إعادة إنتاج النتيجة؟
    """

    def __init__(self, config_override: Optional[Any] = None):
        self.court_config = config_override or config.evidence_court
        self.cases: Dict[str, CourtResult] = {}
        self._lock = asyncio.Lock()

    async def verify_bypass_async(
        self,
        context: BypassContext,
        case_id: Optional[str] = None,
    ) -> CourtResult:
        """التحقق من نجاح تجاوز WAF بشكل غير متزامن."""
        async with self._lock:
            return self._verify_bypass_sync(context, case_id)

    def verify_bypass(
        self,
        context: BypassContext,
        case_id: Optional[str] = None,
    ) -> CourtResult:
        """التحقق من نجاح تجاوز WAF بشكل متزامن."""
        return self._verify_bypass_sync(context, case_id)

    def _verify_bypass_sync(
        self,
        context: BypassContext,
        case_id: Optional[str] = None,
    ) -> CourtResult:
        case_id = case_id or f"court-{int(time.time() * 1000)}"
        reasoning_parts: List[str] = []
        evidence: Dict[str, Any] = {}

        bypass_confirmed = False
        direct_vuln_confirmed = False
        confidence = 0.0

        # Frage 1: هل وصل الطلب للخادم أم حُجب؟
        if context.status_code in (403, 406, 429, 503):
            reasoning_parts.append(
                f"الطلب حُجب برمز حالة {context.status_code} — لم يصل للخادم"
            )
            verdict = CourtVerdict.REFUTED
            confidence = 0.95
        elif context.status_code == 200:
            reasoning_parts.append(
                f"الطلب وصل للخادم برمز حالة 200 — مرر الحاجز الأول"
            )
            confidence += 0.3
        else:
            reasoning_parts.append(
                f"رمز حالة غير معتاد: {context.status_code}"
            )
            confidence += 0.1

        # Frage 2: هل تستجيب الاستجابة للحمولة المُجاوزة؟
        response_body_lower = context.response_body.lower()
        if context.bypass_payload.lower() in response_body_lower:
            reasoning_parts.append(
                "الحمولة المُجاوزة ظهرت في الاستجابة — دليل على التنفيذ"
            )
            bypass_confirmed = True
            confidence += 0.3
            evidence["payload_reflected"] = True
        else:
            reasoning_parts.append(
                "الحمولة المُجاوزة لم تظهر في الاستجابة"
            )
            evidence["payload_reflected"] = False

        # Frage 3: هل كان هناك WAF مفعل وتم تجاوزه؟
        if context.waf_detected:
            reasoning_parts.append(
                f"تم كشف WAF ({context.waf_type}) وتم تجاوزه عبر المستوى {context.technique_level}"
            )
            bypass_confirmed = True
            confidence += self.court_config.bypass_confidence_boost
            evidence["waf_bypassed"] = True
        else:
            reasoning_parts.append(
                "لم يُكشف WAF — قد تكون ثغرة مباشرة"
            )
            direct_vuln_confirmed = True
            confidence += 0.1
            evidence["waf_bypassed"] = False

        # Frage 4: هل زمن الاستجابة يشير إلى معالجة فعلية؟
        if context.response_time_ms > 0:
            reasoning_parts.append(
                f"زمن الاستجابة: {context.response_time_ms:.0f}ms — indicates processing"
            )
            confidence += 0.1
        evidence["response_time_ms"] = context.response_time_ms

        # Determine final verdict
        if bypass_confirmed and context.waf_detected:
            verdict = CourtVerdict.PROVEN_BYPASS
            confidence = min(confidence, 0.98)
        elif direct_vuln_confirmed and not context.waf_detected:
            verdict = CourtVerdict.PROVEN_DIRECT
            confidence = min(confidence, 0.90)
        elif context.status_code in (403, 406, 429, 503):
            verdict = CourtVerdict.REFUTED
            confidence = min(confidence, 0.95)
        else:
            verdict = CourtVerdict.INCONCLUSIVE
            confidence = min(confidence, 0.50)

        reasoning = " | ".join(reasoning_parts)

        result = CourtResult(
            verdict=verdict,
            confidence=confidence,
            reasoning=reasoning,
            evidence=evidence,
            bypass_confirmed=bypass_confirmed,
            direct_vuln_confirmed=direct_vuln_confirmed,
        )

        self.cases[case_id] = result
        logger.info(
            f"[Court] حالة '{case_id}': الحكم={verdict.value}, الثقة={confidence:.2f}, "
            f"التجاوز={bypass_confirmed}, directa={direct_vuln_confirmed}"
        )
        return result

    def get_case(self, case_id: str) -> Optional[CourtResult]:
        return self.cases.get(case_id)

    def stats(self) -> Dict[str, Any]:
        total = len(self.cases)
        if total == 0:
            return {"total": 0}
        bypass_count = sum(1 for c in self.cases.values() if c.bypass_confirmed)
        direct_count = sum(1 for c in self.cases.values() if c.direct_vuln_confirmed)
        refuted_count = sum(1 for c in self.cases.values() if c.verdict == CourtVerdict.REFUTED)
        return {
            "total": total,
            "proven_bypass": bypass_count,
            "proven_direct": direct_count,
            "refuted": refuted_count,
            "bypass_rate": round(bypass_count / total, 2),
        }

    def clear_cases(self) -> int:
        """مسح جميع القضايا المخزنة."""
        count = len(self.cases)
        self.cases.clear()
        logger.info(f"[Court] تم مسح {count} قضية")
        return count


# مثيل عام للمحكمة
evidence_court = EvidenceCourt()
