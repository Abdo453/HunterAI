"""Evidence-first deliberation for selecting the next safe investigation step."""
from __future__ import annotations

from typing import Any, Dict, List

from agents.security_intelligence.schemas import EvidenceItem, EvidenceType, SecurityContext, SecurityHypothesis


class DeliberationEngine:
    """Ranks competing hypotheses without treating a single noisy signal as proof."""

    _RELEVANT_EVIDENCE = {
        "BOLA": {EvidenceType.AUTH_ANOMALY, EvidenceType.BEHAVIOR_DIFF, EvidenceType.PARAMETER_CONTROL},
        "BFLA": {EvidenceType.AUTH_ANOMALY, EvidenceType.BEHAVIOR_DIFF, EvidenceType.STATUS_CODE},
        "SQLi": {EvidenceType.ERROR_DISCLOSURE, EvidenceType.BEHAVIOR_DIFF, EvidenceType.TIMING_LEAK},
        "SSRF": {EvidenceType.BEHAVIOR_DIFF, EvidenceType.TIMING_LEAK, EvidenceType.ERROR_DISCLOSURE},
        "Mass_Assignment": {EvidenceType.BEHAVIOR_DIFF, EvidenceType.PARAMETER_CONTROL},
    }

    def deliberate(
        self,
        hypotheses: List[SecurityHypothesis],
        evidence: List[EvidenceItem],
        context: SecurityContext,
    ) -> List[Dict[str, Any]]:
        """Return a transparent ranking and the smallest safe next check for each hypothesis."""
        sources = {item.source for item in evidence if item.verified}
        source_bonus = min(0.12, max(0, len(sources) - 1) * 0.06)
        results: List[Dict[str, Any]] = []

        for hypothesis in hypotheses:
            relevant_types = self._RELEVANT_EVIDENCE.get(hypothesis.vulnerability_type, set())
            relevant = [item for item in evidence if item.type in relevant_types and item.verified]
            support = sum(item.weight for item in relevant) / max(1, len(relevant))
            coverage = min(1.0, len(relevant) / max(1, len(hypothesis.evidence_required)))
            contradiction_penalty = 0.45 if hypothesis.contradictions and hypothesis.contradictions.has_contradiction else 0.0

            score = max(0.0, min(1.0, hypothesis.confidence * 0.45 + support * 0.35 + coverage * 0.08 + source_bonus - contradiction_penalty))
            missing = hypothesis.evidence_required[len(relevant):]
            results.append({
                "hypothesis_id": hypothesis.id,
                "vulnerability_type": hypothesis.vulnerability_type,
                "score": round(score, 3),
                "supporting_evidence_ids": [item.id for item in relevant],
                "independent_sources": len(sources),
                "missing_evidence": missing,
                "counter_arguments": hypothesis.counter_arguments,
                "next_safe_check": self._next_safe_check(hypothesis, context, missing),
            })

        return sorted(results, key=lambda item: item["score"], reverse=True)

    @staticmethod
    def _next_safe_check(hypothesis: SecurityHypothesis, context: SecurityContext, missing: List[str]) -> str:
        if hypothesis.vulnerability_type in {"BOLA", "BFLA"}:
            return "Compare an authorized low-privilege response with its own permitted resource; do not access another user's data."
        if hypothesis.vulnerability_type == "SQLi":
            return "Run a benign baseline/control comparison and require a reproducible semantic difference before escalation."
        if hypothesis.vulnerability_type == "SSRF":
            return "Use an approved controlled callback endpoint and verify server-side egress without contacting internal addresses."
        if hypothesis.vulnerability_type == "Mass_Assignment":
            return "Submit a harmless unknown field in an authorized test account and confirm whether the schema rejects it."
        return "Collect one independent observation before considering an active check."
