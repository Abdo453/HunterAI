"""
Finding Validator & Lifecycle State Engine (Shannon & Dark-Moon Inspired)
Enforces evidence-gated promotion across the 5-stage vulnerability lifecycle:
OBSERVED -> SUSPECTED -> CONFIRMED -> EXPLOITED -> IMPACT_VERIFIED
Zero-tolerance for unverified AI hallucinations.
"""
import logging
import time
from typing import Dict, List, Any, Optional, Tuple

from agents.security_intelligence.schemas import (
    IntelligenceFinding,
    FindingStatus,
    EvidenceItem,
    EvidenceType,
    ConfidenceLevel
)

log = logging.getLogger("security_intelligence.finding_validator")


class FindingValidator:
    """
    مدقق ومحقق دورة حياة الثغرات:
    يمنع ترقية أي نتيجة أمنية إلى حالة مؤكدة أو مستغلة دون أدلة تفاضلية قابلة للتكرار
    مستوحى من معمارية Shannon و Dark-Moon
    """

    # Valid forward state transitions
    _ALLOWED_TRANSITIONS: Dict[FindingStatus, List[FindingStatus]] = {
        FindingStatus.OBSERVED: [FindingStatus.SUSPECTED, FindingStatus.CONFIRMED],
        FindingStatus.SUSPECTED: [FindingStatus.CONFIRMED, FindingStatus.OBSERVED],
        FindingStatus.CONFIRMED: [FindingStatus.EXPLOITED, FindingStatus.IMPACT_VERIFIED, FindingStatus.SUSPECTED],
        FindingStatus.EXPLOITED: [FindingStatus.IMPACT_VERIFIED, FindingStatus.CONFIRMED],
        FindingStatus.IMPACT_VERIFIED: [FindingStatus.CONFIRMED]  # Demotion allowed if refuted
    }

    # Evidence types considered conclusive for confirmation
    _CONFIRMATORY_EVIDENCE_TYPES = {
        EvidenceType.BEHAVIOR_DIFF,
        EvidenceType.AUTH_ANOMALY,
        EvidenceType.ERROR_DISCLOSURE,
        EvidenceType.TIMING_LEAK,
        EvidenceType.CVE_MATCH
    }

    def can_transition(
        self,
        finding: IntelligenceFinding,
        target_status: FindingStatus,
        new_evidence: Optional[List[EvidenceItem]] = None,
        poc_steps: Optional[List[str]] = None,
        reproduction_curl: Optional[str] = None,
        impact_description: Optional[str] = None
    ) -> Tuple[bool, str]:
        """
        التحقق من أهلية النتيجة للانتقال إلى الحالة المستهدفة وفقاً للشروط الصارمة
        """
        curr = finding.status

        # Self transition is idempotent
        if curr == target_status:
            return True, f"Finding is already in status '{target_status.value}'."

        # Check allowed transition graph
        allowed_targets = self._ALLOWED_TRANSITIONS.get(curr, [])
        if target_status not in allowed_targets:
            return False, f"Invalid transition: Cannot transition from '{curr.value}' directly to '{target_status.value}'."

        all_evidence = list(finding.evidence) + (new_evidence or [])

        # Rule 1: Transition to SUSPECTED
        if target_status == FindingStatus.SUSPECTED:
            if not finding.hypotheses_validated and not finding.reasoning_chain:
                return False, "Transition to SUSPECTED requires at least one validated hypothesis or reasoning step."
            return True, "Eligible for SUSPECTED status."

        # Rule 2: Transition to CONFIRMED (Shannon principle: must have reproducible differential evidence)
        if target_status == FindingStatus.CONFIRMED:
            has_confirmatory = any(e.type in self._CONFIRMATORY_EVIDENCE_TYPES for e in all_evidence)
            if not has_confirmatory:
                return False, "Transition to CONFIRMED rejected: Missing differential behavior, auth anomaly, or execution proof in evidence."
            if finding.confidence_score < 0.60:
                return False, f"Transition to CONFIRMED rejected: Confidence score {finding.confidence_score:.2f} is below 0.60 threshold."
            return True, "Eligible for CONFIRMED status with verified evidence."

        # Rule 3: Transition to EXPLOITED
        if target_status == FindingStatus.EXPLOITED:
            has_poc = bool(poc_steps or finding.poc_steps or reproduction_curl or finding.reproduction_curl)
            if not has_poc:
                return False, "Transition to EXPLOITED rejected: Requires concrete non-destructive PoC steps or reproduction curl."
            if finding.confidence_score < 0.70:
                return False, f"Transition to EXPLOITED rejected: Confidence score {finding.confidence_score:.2f} is below 0.70 threshold."
            return True, "Eligible for EXPLOITED status with controlled PoC."

        # Rule 4: Transition to IMPACT_VERIFIED
        if target_status == FindingStatus.IMPACT_VERIFIED:
            has_impact = bool(impact_description or finding.impact_description)
            has_curl = bool(reproduction_curl or finding.reproduction_curl or poc_steps or finding.poc_steps)
            if not has_impact:
                return False, "Transition to IMPACT_VERIFIED rejected: Requires documented business/security impact description."
            if not has_curl:
                return False, "Transition to IMPACT_VERIFIED rejected: Requires reproduction PoC or curl."
            return True, "Eligible for IMPACT_VERIFIED status."

        return True, "Transition permitted."

    def transition_finding(
        self,
        finding: IntelligenceFinding,
        target_status: FindingStatus,
        actor: str = "FindingValidator",
        rationale: str = "",
        new_evidence: Optional[List[EvidenceItem]] = None,
        poc_steps: Optional[List[str]] = None,
        reproduction_curl: Optional[str] = None,
        impact_description: Optional[str] = None
    ) -> Tuple[bool, str, IntelligenceFinding]:
        """
        تنفيذ انتقال الحالة وتسجيل الأثر في سجل تاريخ دورة الحياة (Lifecycle History)
        """
        allowed, reason = self.can_transition(
            finding=finding,
            target_status=target_status,
            new_evidence=new_evidence,
            poc_steps=poc_steps,
            reproduction_curl=reproduction_curl,
            impact_description=impact_description
        )

        if not allowed:
            log.warning(f"[FindingValidator] Denied transition for finding {finding.id} ({finding.status} -> {target_status}): {reason}")
            return False, reason, finding

        prev_status = finding.status
        finding.status = target_status

        # Append new evidence if provided
        if new_evidence:
            existing_ids = {e.id for e in finding.evidence}
            for ev in new_evidence:
                if ev.id not in existing_ids:
                    finding.evidence.append(ev)

        # Update PoC / impact if provided
        if poc_steps:
            finding.poc_steps.extend(poc_steps)
        if reproduction_curl:
            finding.reproduction_curl = reproduction_curl
        if impact_description:
            finding.impact_description = impact_description

        # Adjust confidence level if confirmed/exploited
        if target_status in [FindingStatus.CONFIRMED, FindingStatus.EXPLOITED, FindingStatus.IMPACT_VERIFIED]:
            if finding.confidence_score < 0.85:
                finding.confidence_score = max(finding.confidence_score, 0.85)
                finding.confidence_level = ConfidenceLevel.HIGH

        # Record history entry
        finding.lifecycle_history.append({
            "from_status": prev_status.value,
            "to_status": target_status.value,
            "timestamp": time.time(),
            "actor": actor,
            "rationale": rationale or reason,
            "evidence_count": len(finding.evidence)
        })

        log.info(f"[FindingValidator] Finding {finding.id} successfully transitioned: {prev_status.value} -> {target_status.value} ({reason})")
        return True, reason, finding

    def evaluate_max_eligible_status(self, finding: IntelligenceFinding) -> FindingStatus:
        """
        فحص أقصى حالة مؤهلة للنتيجة بناءً على الأدلة والبيانات المتوفرة حالياً
        """
        all_evidence = finding.evidence
        has_confirmatory = any(e.type in self._CONFIRMATORY_EVIDENCE_TYPES for e in all_evidence)
        has_poc = bool(finding.poc_steps or finding.reproduction_curl)
        has_impact = bool(finding.impact_description)

        if has_impact and has_poc and has_confirmatory and finding.confidence_score >= 0.75:
            return FindingStatus.IMPACT_VERIFIED
        elif has_poc and has_confirmatory and finding.confidence_score >= 0.70:
            return FindingStatus.EXPLOITED
        elif has_confirmatory and finding.confidence_score >= 0.60:
            return FindingStatus.CONFIRMED
        elif finding.hypotheses_validated or finding.reasoning_chain or all_evidence:
            return FindingStatus.SUSPECTED
        else:
            return FindingStatus.OBSERVED
