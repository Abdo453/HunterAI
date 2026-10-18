"""
HunterAI 7-Question Gate — Validation Gate
==========================================
Inspired by Agentic-Bug-Hunter's `/validate` command.

Runs a strict 7-question gate on every finding before it can be reported.
Kills weak findings early — N/A hurts your validity ratio.

Gate questions:
1. Can an attacker do this RIGHT NOW? (reproducible)
2. Is it in scope? (authorized target)
3. Is there deterministic proof? (PoE, not just reflection)
4. Is it a real bug, not theoretical?
5. Is impact clear? (impact first)
6. Is evidence complete? (request/response hashes, nonce proof)
7. Is it worth reporting? (not a false positive)

Verdicts: PROVEN | REFUTED | UNPROVEN | INCONCLUSIVE
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Optional


class GateVerdict(str, Enum):
    PROVEN = "PROVEN"
    REFUTED = "REFUTED"
    UNPROVEN = "UNPROVEN"
    INCONCLUSIVE = "INCONCLUSIVE"


@dataclass
class GateResult:
    question: str
    passed: bool
    reason: str


@dataclass
class ValidationResult:
    finding_id: str
    title: str
    target: str
    status: GateVerdict = GateVerdict.INCONCLUSIVE
    confidence: float = 0.0
    gates: list[GateResult] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    rationale: str = ""
    timestamp: float = field(default_factory=time.time)
    never_submit: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "target": self.target,
            "status": self.status.value,
            "confidence": self.confidence,
            "gates": [asdict(g) for g in self.gates],
            "evidence": self.evidence,
            "rationale": self.rationale,
            "never_submit": self.never_submit,
            "timestamp": self.timestamp,
        }


class ValidationGate:
    """
    7-Question Gate — kills weak findings before reporting.
    Only PROVEN findings are reportable.
    """

    NEVER_SUBMIT_PATTERNS = [
        "reflection only",
        "theoretical",
        "no impact",
        "out of scope",
        "self-xss",
        "clickjacking without impact",
        "missing hsts",
        "cookie without httponly",
    ]

    def __init__(self, min_confidence: float = 0.85):
        self.min_confidence = min_confidence

    def validate(
        self,
        finding: dict[str, Any] | str,
        target: str = "",
        evidence: Optional[dict[str, Any]] = None,
    ) -> ValidationResult:
        """
        Run the 7-Question Gate on a finding.
        """
        if isinstance(finding, str):
            title = finding
            finding_id = hashlib.md5(f"{target}:{title}".encode()).hexdigest()[:8]
        else:
            title = finding.get("title", "Untitled Finding")
            target = finding.get("target", target)
            finding_id = finding.get("id", hashlib.md5(f"{target}:{title}".encode()).hexdigest()[:8])
            evidence = finding.get("evidence", {})

        result = ValidationResult(
            finding_id=finding_id,
            title=title,
            target=target,
            evidence=evidence or {},
        )

        # Question 1: Reproducible RIGHT NOW?
        q1 = self._q1_reproducible(evidence)
        result.gates.append(q1)
        if not q1.passed:
            result.status = GateVerdict.REFUTED
            result.rationale = "Not reproducible right now (reflection without execution)"
            return result

        # Question 2: In scope?
        q2 = self._q2_in_scope(target)
        result.gates.append(q2)
        if not q2.passed:
            result.status = GateVerdict.REFUTED
            result.rationale = "Target out of authorized scope"
            return result

        # Question 3: Deterministic proof?
        q3 = self._q3_deterministic_proof(evidence)
        result.gates.append(q3)
        if not q3.passed:
            result.status = GateVerdict.UNPROVEN
            result.rationale = "No deterministic proof (PoE missing)"
            return result

        # Question 4: Real bug, not theoretical?
        q4 = self._q4_real_bug(evidence)
        result.gates.append(q4)
        if not q4.passed:
            result.status = GateVerdict.REFUTED
            result.rationale = "Theoretical only, no real exploit path"
            return result

        # Question 5: Impact clear?
        q5 = self._q5_impact(evidence)
        result.gates.append(q5)

        # Question 6: Evidence complete?
        q6 = self._q6_evidence_complete(evidence)
        result.gates.append(q6)

        # Question 7: Worth reporting?
        q7 = self._q7_worth_reporting(evidence)
        result.gates.append(q7)

        passed = all(g.passed for g in result.gates)
        confidence = sum(1 for g in result.gates if g.passed) / len(result.gates)
        result.confidence = confidence

        if passed and confidence >= self.min_confidence:
            result.status = GateVerdict.PROVEN
            result.rationale = "All 7 gate questions passed — reportable"
        elif confidence >= 0.60:
            result.status = GateVerdict.UNPROVEN
            result.rationale = "Partial gate pass — needs more evidence"
        else:
            result.status = GateVerdict.REFUTED
            result.rationale = "Failed gate questions — suppressed"

        # Never-submit check
        text = (title + " " + json.dumps(evidence, ensure_ascii=False)).lower()
        for pattern in self.NEVER_SUBMIT_PATTERNS:
            if pattern in text:
                result.never_submit = True
                if result.status == GateVerdict.PROVEN:
                    result.status = GateVerdict.REFUTED
                    result.rationale = f"Never-submit pattern matched: {pattern}"
                break

        return result

    # ── Gate Questions ──────────────────────────────────────────

    def _q1_reproducible(self, evidence: dict) -> GateResult:
        """Q1: Can an attacker do this RIGHT NOW?"""
        has_poc = bool(evidence.get("poc") or evidence.get("reproduction"))
        has_nonce = bool(evidence.get("nonce") or evidence.get("arithmetic_proof"))
        has_diff = bool(evidence.get("differential_response"))
        if has_poc and (has_nonce or has_diff):
            return GateResult("Q1: Reproducible RIGHT NOW?", True, "PoC with nonce/differential proof present")
        return GateResult("Q1: Reproducible RIGHT NOW?", False, "Only reflection, no execution proof")

    def _q2_in_scope(self, target: str) -> GateResult:
        """Q2: Is it in scope?"""
        from hunter_ai.core.scope_engine import StrictScopeEngine
        engine = StrictScopeEngine()
        if engine.is_allowed(target):
            return GateResult("Q2: In scope?", True, f"{target} is authorized")
        return GateResult("Q2: In scope?", False, f"{target} is outside authorized scope")

    def _q3_deterministic_proof(self, evidence: dict) -> GateResult:
        """Q3: Is there deterministic proof?"""
        if evidence.get("poe_verified") or evidence.get("deterministic_proof"):
            return GateResult("Q3: Deterministic proof?", True, "PoE engine verified the execution")
        return GateResult("Q3: Deterministic proof?", False, "No PoE — reflection ≠ execution")

    def _q4_real_bug(self, evidence: dict) -> GateResult:
        """Q4: Real bug, not theoretical?"""
        if evidence.get("real_exploit_path") or evidence.get("exploit_verified"):
            return GateResult("Q4: Real bug?", True, "Exploit path confirmed")
        return GateResult("Q4: Real bug?", False, "Theoretical only")

    def _q5_impact(self, evidence: dict) -> GateResult:
        """Q5: Impact clear?"""
        impact = evidence.get("impact", "")
        if impact and len(impact) > 10:
            return GateResult("Q5: Impact clear?", True, f"Impact: {impact[:80]}")
        return GateResult("Q5: Impact clear?", False, "Impact not described")

    def _q6_evidence_complete(self, evidence: dict) -> GateResult:
        """Q6: Evidence complete?"""
        has_req = bool(evidence.get("request_hash") or evidence.get("request"))
        has_resp = bool(evidence.get("response_hash") or evidence.get("response"))
        if has_req and has_resp:
            return GateResult("Q6: Evidence complete?", True, "Request/response hashes present")
        return GateResult("Q6: Evidence complete?", False, "Missing request/response artifacts")

    def _q7_worth_reporting(self, evidence: dict) -> GateResult:
        """Q7: Worth reporting?"""
        severity = evidence.get("severity", "").lower()
        if severity in ("critical", "high", "medium"):
            return GateResult("Q7: Worth reporting?", True, f"Severity: {severity}")
        return GateResult("Q7: Worth reporting?", False, "Low or unknown severity")


def validate_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """Convenience function — validate a finding dict."""
    gate = ValidationGate()
    result = gate.validate(finding)
    return result.to_dict()


if __name__ == "__main__":
    import sys
    finding = {
        "title": "Example SQL Injection",
        "target": "https://example.com/search",
        "evidence": {
            "poc": "' OR 1=1 --",
            "arithmetic_proof": "72",
            "differential_response": True,
            "poe_verified": True,
            "real_exploit_path": True,
            "impact": "Database extraction possible",
            "severity": "high",
            "request_hash": "abc123",
            "response_hash": "def456",
        },
    }
    print(json.dumps(validate_finding(finding), indent=2, ensure_ascii=False))
