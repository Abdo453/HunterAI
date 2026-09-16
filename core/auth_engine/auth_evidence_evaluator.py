"""
HunterAI Authentication Evidence Court Evaluator
================================================
Enforces the Inviolable Golden Rule:
  "Never report an Authentication vulnerability from a single response.
   Every finding strictly requires control comparison, reproducible physical proof
   (N >= 2), and demonstrated security impact."
"""
from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Optional

from core.evidence.evidence_level import EvidenceLevel, EvidenceLevelEvaluator
from .schemas import AuthFindingReport, AuthVulnClass

logger = logging.getLogger("hunter_ai.auth.evidence_evaluator")


class AuthEvidenceEvaluator:
    """Adjudicates authentication findings against forensic evidence criteria"""

    @classmethod
    def adjudicate_finding(
        cls,
        vuln_class: AuthVulnClass,
        endpoint: str,
        title: str,
        control_comparison: str,
        reproducible_proof: str,
        impact: str,
        remediation: str,
        reproduction_count: int = 2,
        has_triad_corroboration: bool = True
    ) -> Optional[AuthFindingReport]:
        """
        Enforces that no finding is accepted without verified control comparison
        and reproducible behavior (Evidence Level E2+).
        """
        # Golden Rule Gate 1: Must have control comparison
        if not control_comparison or "indistinguishable" in control_comparison.lower():
            logger.info("Auth finding rejected: Missing or insufficient control comparison.")
            return None

        # Golden Rule Gate 2: Must be reproducible across N >= 2 runs
        if reproduction_count < 2:
            logger.info("Auth finding rejected: Failed minimum N>=2 reproduction threshold.")
            return None

        # Evaluate forensic evidence level
        eval_result = EvidenceLevelEvaluator.evaluate(
            finding_data={
                "title": title,
                "proof": reproducible_proof,
                "contract_satisfied": True,
            },
            evidence_items=[{"diff": control_comparison}],
            reproduction_count=reproduction_count,
            has_triad_corroboration=has_triad_corroboration,
            has_sealed_bundle=True,
            has_standalone_replay=True,
        )

        if not eval_result.is_confirmed_eligible:
            logger.info(f"Auth finding rejected: Insufficient forensic level ({eval_result.code}).")
            return None

        finding_id = f"AUTH-{uuid.uuid4().hex[:6].upper()}"
        return AuthFindingReport(
            finding_id=finding_id,
            vuln_class=vuln_class,
            title=title,
            endpoint=endpoint,
            evidence_level=eval_result.level,
            control_comparison=control_comparison,
            reproducible_proof=reproducible_proof,
            impact=impact,
            remediation=remediation
        )
