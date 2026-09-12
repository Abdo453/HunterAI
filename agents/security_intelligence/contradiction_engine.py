"""
Contradiction Engine
Actively searches for counter-evidence, defensive controls, and response anomalies that refute attack hypotheses.
"""
import logging
from typing import List, Optional
from agents.security_intelligence.schemas import (
    SecurityHypothesis,
    EvidenceItem,
    EvidenceType,
    SecurityContext,
    ContradictionResult
)

log = logging.getLogger("security_intelligence.contradiction")


class ContradictionEngine:
    """محرك البحث عن التناقضات: البحث المنهجي عن أدلة تنفي وجود الثغرة أو تثبت فاعلية الحماية"""

    def find_contradictions(
        self,
        hypothesis: SecurityHypothesis,
        evidence_items: List[EvidenceItem],
        context: Optional[SecurityContext] = None
    ) -> ContradictionResult:
        """
        فحص هل توجد أدلة قطعية تنفي الفرضية (مثل 403 Forbidden أو رفض صريح للحقن أو تطهير المدخلات)
        """
        contradictions: List[str] = []
        penalty = 0.0

        for ev in evidence_items:
            data = ev.data or {}
            status = data.get("status")
            body_str = str(data.get("body", "") or data.get("details", "")).lower()

            # 1. BOLA / BFLA Contradictions (Server explicitly returned 403 Forbidden or 401 Unauthorized)
            if hypothesis.vulnerability_type in ["BOLA", "BFLA", "IDOR", "Auth_Bypass"]:
                if status in [401, 403]:
                    contradictions.append(f"Server enforced authorization check returning HTTP {status} (Access Denied).")
                    penalty += 0.50
                if "access denied" in body_str or "unauthorized" in body_str or "forbidden" in body_str:
                    contradictions.append("Response explicitly states access is forbidden by policy.")
                    penalty += 0.30

            # 2. SQLi Contradictions (Input was strictly validated or parameterized)
            if hypothesis.vulnerability_type == "SQLi":
                if status == 400 and ("invalid format" in body_str or "must be integer" in body_str):
                    contradictions.append("Server performed strict client input type validation (HTTP 400 Type Error).")
                    penalty += 0.40

            # 3. SSRF Contradictions (Loopback/Private IP filtering detected)
            if hypothesis.vulnerability_type == "SSRF":
                if "blocked internal ip" in body_str or "private address not allowed" in body_str:
                    contradictions.append("Server network filter blocked internal IP address.")
                    penalty += 0.50

        has_contra = len(contradictions) > 0
        explanation = " \n".join(contradictions) if has_contra else "No contradictory evidence detected."

        return ContradictionResult(
            has_contradiction=has_contra,
            contradictory_evidence=contradictions,
            penalty_score=round(min(1.0, penalty), 3),
            explanation=explanation
        )
