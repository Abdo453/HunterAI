"""
Differential Behavioral Analyzer
Compares Baseline Response vs Test Response to mathematically evaluate behavioral divergence:
- Status code matching
- Body content length delta
- Cryptographic hash differences
- Error signature emergence
- Conditional state change detection
Produces tamper-evident UnifiedEvidence records.
"""
import hashlib
import logging
from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field

from agents.burp_agent.evidence.evidence_model import UnifiedEvidence, BurpEvidenceType, UnifiedEvidenceStore

log = logging.getLogger("core.evidence.differential_analyzer")


class ResponseDifference(BaseModel):
    status_match: bool
    status_baseline: int
    status_test: int
    length_delta: int
    body_hash_match: bool
    error_signature_observed: Optional[str] = None
    differential_score: float = 0.0      # 0.0 = identical, 1.0 = completely divergent
    is_statistically_significant: bool = False
    evidence_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


class DifferentialAnalyzer:
    """
    محلل التباعد والتفاضل السلوكي:
    يقارن استجابة الأساس باستجابة الاختبار ويولد دليلاً تفاضلياً مشفراً
    """

    def __init__(self, evidence_store: Optional[UnifiedEvidenceStore] = None):
        self.evidence_store = evidence_store or UnifiedEvidenceStore()

    def compare_responses(
        self,
        baseline_status: int,
        baseline_body: str,
        test_status: int,
        test_body: str,
        transaction_id: str = "tx_diff"
    ) -> ResponseDifference:
        status_match = (baseline_status == test_status)
        len_base = len(baseline_body)
        len_test = len(test_body)
        length_delta = abs(len_base - len_test)

        hash_base = hashlib.sha256(baseline_body.encode("utf-8")).hexdigest()
        hash_test = hashlib.sha256(test_body.encode("utf-8")).hexdigest()
        body_hash_match = (hash_base == hash_test)

        # Look for SQL or DB error signatures in test_body
        error_sig = None
        if "syntax error" in test_body.lower() or "postgresql" in test_body.lower():
            error_sig = "PostgreSQL_Syntax"
        elif "mysql" in test_body.lower():
            error_sig = "MySQL_Syntax"
        elif "sqlite" in test_body.lower():
            error_sig = "SQLite_Syntax"

        # Calculate differential score
        diff_score = 0.0
        if not status_match:
            diff_score += 0.30
        if not body_hash_match:
            diff_score += 0.40
        if length_delta > 50:
            diff_score += 0.20
        if error_sig is not None:
            diff_score += 0.30

        diff_score = round(min(1.0, diff_score), 2)
        is_significant = (diff_score >= 0.50)

        # Store Diff as UnifiedEvidence
        diff_summary = f"Differential score: {diff_score} (Status: {baseline_status}->{test_status}, Delta: {length_delta} bytes)"
        evid = UnifiedEvidence(
            evidence_type=BurpEvidenceType.DIFF,
            source="DifferentialAnalyzer",
            sha256=hashlib.sha256(f"{hash_base}:{hash_test}".encode("utf-8")).hexdigest(),
            parent_transaction_id=transaction_id,
            summary=diff_summary,
            metadata={
                "status_baseline": baseline_status,
                "status_test": test_status,
                "length_delta": length_delta,
                "error_signature": error_sig,
                "differential_score": diff_score
            }
        )
        self.evidence_store.store_evidence(evid)

        return ResponseDifference(
            status_match=status_match,
            status_baseline=baseline_status,
            status_test=test_status,
            length_delta=length_delta,
            body_hash_match=body_hash_match,
            error_signature_observed=error_sig,
            differential_score=diff_score,
            is_statistically_significant=is_significant,
            evidence_id=evid.id
        )
