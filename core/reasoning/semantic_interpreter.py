"""
Internal Semantic Interpreter
Translates raw HTTP codes, headers, and payload behaviors into high-level cognitive propositions (SemanticFacts).
Protects the LLM from raw string overload while enabling structured, domain-grounded reasoning.
"""
import uuid
import time
import logging
from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field

from agents.burp_agent.normalization.request_normalizer import NormalizedRequest
from agents.burp_agent.normalization.response_normalizer import NormalizedResponse

log = logging.getLogger("core.reasoning.semantic_interpreter")


class SemanticFact(BaseModel):
    """حقيقة معرفية دلالية مستخلصة من ترافيك الـ HTTP"""
    fact_id: str = Field(default_factory=lambda: f"FACT-{uuid.uuid4().hex[:6]}")
    fact_kind: str             # AUTH_TRANSITION, DYNAMIC_FILTERING, DB_ERROR_DISCLOSURE, INPUT_REFLECTED_SAFE, ACCESS_DENIED_WAF
    confidence: float = 0.90
    evidence_tx_id: str = ""
    description_en: str
    description_ar: str
    implicated_hypothesis: Optional[str] = None
    created_at: float = Field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


class SemanticInterpreter:
    """
    المترجم الدلالي الداخلي:
    يحول أحداث الـ HTTP الخام إلى تمثيل معرفي منظم يفهمه العقل الاستدلالي فوراً
    """

    @classmethod
    def interpret_transaction(
        cls,
        tx_id: str,
        norm_req: NormalizedRequest,
        norm_resp: NormalizedResponse,
        diff_score: Optional[float] = None
    ) -> List[SemanticFact]:
        facts: List[SemanticFact] = []

        # 1. Authentication Transitions
        if norm_resp.status_code in [302, 303, 307] and "login" in norm_req.path.lower():
            facts.append(SemanticFact(
                fact_kind="AUTH_TRANSITION",
                confidence=0.95,
                evidence_tx_id=tx_id,
                description_en=f"Client redirected from {norm_req.path} with status {norm_resp.status_code}.",
                description_ar="تحول في حالة المصادقة: إعادة توجيه العميل مع تغيير حالة الجلسة.",
                implicated_hypothesis="Authentication_State_Change"
            ))

        # 2. Database Error Disclosure
        if norm_resp.error_signature:
            facts.append(SemanticFact(
                fact_kind="DB_ERROR_DISCLOSURE",
                confidence=0.98,
                evidence_tx_id=tx_id,
                description_en=f"Underlying database engine exception revealed: {norm_resp.error_signature}.",
                description_ar=f"تسريب استثناء داخلي لمحرك قاعدة البيانات: {norm_resp.error_signature}.",
                implicated_hypothesis="SQL_INJECTION_ERROR_BASED"
            ))

        # 3. Dynamic Filtering & Differential Behavior
        if diff_score is not None and diff_score >= 0.50:
            facts.append(SemanticFact(
                fact_kind="DYNAMIC_FILTERING",
                confidence=0.92,
                evidence_tx_id=tx_id,
                description_en=f"Observable behavioral divergence detected (score: {diff_score}). Input directly influences backend execution.",
                description_ar=f"رصد تباعد سلوكي مؤثر (درجة: {diff_score})؛ المدخل يؤثر مباشرة على تنفيذ الاستعلام في السيرفر.",
                implicated_hypothesis="SQL_INJECTION_BOOLEAN_OR_AUTHZ"
            ))

        # 4. Safe Input Reflection (Observation != Vulnerability)
        if "session_cookies" in norm_req.signals and norm_resp.status_code == 200 and not norm_resp.error_signature and (diff_score is None or diff_score < 0.20):
            facts.append(SemanticFact(
                fact_kind="INPUT_REFLECTED_SAFE",
                confidence=0.85,
                evidence_tx_id=tx_id,
                description_en="Input safely processed without query execution alteration.",
                description_ar="معالجة الإدخال بشكل طبيعي وآمن دون أي شذوذ في الاستعلام.",
                implicated_hypothesis="SAFE_PARAMETERIZED"
            ))

        # 5. WAF or Filter Interception
        if norm_resp.status_code == 403 or "waf_detected" in norm_resp.signals:
            facts.append(SemanticFact(
                fact_kind="ACCESS_DENIED_WAF",
                confidence=0.90,
                evidence_tx_id=tx_id,
                description_en="Request blocked or filtered by application firewall / input validation rule.",
                description_ar="حظر الطلب بواسطة جدار الحماية أو قاعدة تصفية المدخلات.",
                implicated_hypothesis="WAF_FILTERING_PRESENT"
            ))

        return facts
