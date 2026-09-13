"""
HunterAI Research Mode
======================
Transforms inconclusive or uncertain findings into structured scientific research cases.
Rather than guessing or prematurely accepting/rejecting a finding:
1. Identifies the precise missing evidence elements
2. Formulates bounded, targeted scientific experiments
3. Resolves the case to CONFIRMED or REJECTED with empirical proof
"""
from __future__ import annotations

import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class MissingEvidenceType(str, Enum):
    MISSING_BENIGN_CONTROL = "MISSING_BENIGN_CONTROL"
    INSUFFICIENT_DIFFERENTIAL = "INSUFFICIENT_DIFFERENTIAL"
    DOM_EXECUTION_UNCONFIRMED = "DOM_EXECUTION_UNCONFIRMED"
    WAF_INTERFERENCE_SUSPECTED = "WAF_INTERFERENCE_SUSPECTED"
    SESSION_STABILITY_UNCERTAIN = "SESSION_STABILITY_UNCERTAIN"


@dataclass
class ResearchExperimentPlan:
    experiment_id: str = field(default_factory=lambda: f"EXP-{uuid.uuid4().hex[:6].upper()}")
    target_endpoint: str = ""
    parameter: str = ""
    missing_type: MissingEvidenceType = MissingEvidenceType.MISSING_BENIGN_CONTROL
    probe_strategy: str = ""
    expected_discriminator: str = ""
    risk_level: str = "LOW"


@dataclass
class ResearchCase:
    case_id: str = field(default_factory=lambda: f"RC-{uuid.uuid4().hex[:8].upper()}")
    finding_id: str = ""
    endpoint: str = ""
    parameter: str = ""
    original_uncertainty_reason: str = ""
    missing_elements: List[MissingEvidenceType] = field(default_factory=list)
    experiments: List[ResearchExperimentPlan] = field(default_factory=list)
    status: str = "OPEN"  # OPEN, RESOLVED_CONFIRMED, RESOLVED_REJECTED
    final_verdict: Optional[str] = None
    opened_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["missing_elements"] = [m.value for m in self.missing_elements]
        return d


class ResearchModeEngine:
    """Orchestrates structured scientific investigation of inconclusive findings"""

    @classmethod
    def open_research_case(
        cls,
        finding_id: str,
        endpoint: str,
        parameter: str,
        uncertainty_reason: str
    ) -> ResearchCase:
        missing = []
        low_reason = uncertainty_reason.lower()
        if "control" in low_reason or "baseline" in low_reason:
            missing.append(MissingEvidenceType.MISSING_BENIGN_CONTROL)
        if "dom" in low_reason or "reflection" in low_reason:
            missing.append(MissingEvidenceType.DOM_EXECUTION_UNCONFIRMED)
        if "waf" in low_reason or "block" in low_reason:
            missing.append(MissingEvidenceType.WAF_INTERFERENCE_SUSPECTED)
        if "session" in low_reason or "auth" in low_reason:
            missing.append(MissingEvidenceType.SESSION_STABILITY_UNCERTAIN)

        if not missing:
            missing.append(MissingEvidenceType.INSUFFICIENT_DIFFERENTIAL)

        case = ResearchCase(
            finding_id=finding_id,
            endpoint=endpoint,
            parameter=parameter,
            original_uncertainty_reason=uncertainty_reason,
            missing_elements=missing
        )

        # Generate targeted experiment plans
        for m in missing:
            if m == MissingEvidenceType.MISSING_BENIGN_CONTROL:
                case.experiments.append(ResearchExperimentPlan(
                    target_endpoint=endpoint,
                    parameter=parameter,
                    missing_type=m,
                    probe_strategy="Send neutral alphanumeric string 'HunterTestAlpha' to establish benign baseline.",
                    expected_discriminator="Response status 200 with standard template length.",
                    risk_level="LOW"
                ))
            elif m == MissingEvidenceType.DOM_EXECUTION_UNCONFIRMED:
                case.experiments.append(ResearchExperimentPlan(
                    target_endpoint=endpoint,
                    parameter=parameter,
                    missing_type=m,
                    probe_strategy="Launch headless Chromium browser and attach DOM mutation observer for canary token.",
                    expected_discriminator="window.__hunter_poe token execution in JavaScript runtime.",
                    risk_level="LOW"
                ))

        return case

    @classmethod
    def resolve_case(cls, case: ResearchCase, outcomes: Dict[str, bool]) -> ResearchCase:
        """Evaluates experiment outcomes and resolves the research case"""
        # If all missing evidence experiments succeeded
        all_passed = bool(outcomes) and all(outcomes.values())
        if all_passed:
            case.status = "RESOLVED_CONFIRMED"
            case.final_verdict = "CONFIRMED"
        else:
            case.status = "RESOLVED_REJECTED"
            case.final_verdict = "REJECTED"

        return case
