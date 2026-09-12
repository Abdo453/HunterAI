"""
HunterAI Formal Evidence Contract
==================================
Defines the strict Lifecycle and Verification Contract for every finding.
Lifecycle:
OBSERVATION -> SIGNAL -> HYPOTHESIS -> VERIFICATION -> CONFIRMATION -> REPORTABLE
"""
from enum import Enum
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field
import time
import uuid

class LifecycleStage(str, Enum):
    OBSERVATION = "OBSERVATION"      # Raw telemetry, reflection, response delta
    SIGNAL = "SIGNAL"                # Pattern matches, error substrings
    HYPOTHESIS = "HYPOTHESIS"        # AI-formulated theory
    TESTING = "TESTING"              # Active verification probe in flight
    UNVERIFIED = "UNVERIFIED"        # Inconclusive probe, failed arithmetic, or timeout
    CONFIRMED = "CONFIRMED"          # Deterministic proof confirmed (arithmetic, extracted data, auth bypass)
    REJECTED = "REJECTED"            # Refutation proven (mere reflection, WAF challenge, normal navigation)

class EvidenceContract(BaseModel):
    finding_id: str = Field(default_factory=lambda: f"fnd_{uuid.uuid4().hex[:8]}")
    target: str
    parameter: str = ""
    vulnerability: str
    stage: LifecycleStage = LifecycleStage.UNVERIFIED
    confidence: float = 0.0
    evidence: List[Dict[str, Any]] = Field(default_factory=list)
    negative_evidence: List[str] = Field(default_factory=list)
    reproduction: Dict[str, Any] = Field(default_factory=dict)
    independent_verification: bool = False
    scope_valid: bool = False
    reportable: bool = False  # NEVER True unless all strict criteria pass
    arbitration_verdict: Optional[str] = None
    created_at: float = Field(default_factory=time.time)

    def evaluate_reportability(self) -> bool:
        """
        Inviolable Reportability Rule:
        A finding is ONLY reportable if:
        1. Scope is strictly valid (scope_valid == True).
        2. Lifecycle stage is CONFIRMED.
        3. Confidence >= 0.85.
        4. Independent verification or deterministic proof exists.
        5. Negative evidence is empty (no fatal contradictions).
        """
        if not self.scope_valid:
            self.reportable = False
            self.stage = LifecycleStage.REJECTED
            self.negative_evidence.append("Target URL is outside authorized scope.")
            return False

        if self.stage != LifecycleStage.CONFIRMED:
            self.reportable = False
            return False

        if self.confidence < 0.85:
            self.reportable = False
            return False

        if not self.independent_verification and not self.reproduction.get("confirmed"):
            self.reportable = False
            return False

        if len(self.negative_evidence) > 0:
            self.reportable = False
            return False

        self.reportable = True
        return True
