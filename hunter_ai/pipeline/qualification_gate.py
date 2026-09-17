"""
HunterAI Finding Qualification Gate & Observation Store
========================================================
Enforces strict architectural separation:
  TOOLS -> OBSERVATIONS -> CORRELATION -> HYPOTHESIS -> CONTROLLED VALIDATION -> EVIDENCE COURT -> CONFIRMED FINDINGS

Axiom 1: No tool, scanner, or recon stage is permitted to set status="CONFIRMED".
Axiom 2: Standard expected web behavior (robots.txt, sitemap.xml, open web ports) has zero security impact
         and is strictly REJECTED as a vulnerability finding, routed instead to Attack Surface Inventory.
Axiom 3: Every CONFIRMED finding MUST possess an unbroken Evidence Chain validated by Evidence Court.
"""
from __future__ import annotations

import time
import uuid
import logging
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field

from hunter_ai.pipeline.schemas import (
    HunterFinding,
    FindingStatus,
    FindingTier,
    VerificationEvidence,
    ReproductionArtifact,
)
from core.evidence_court import EvidenceCourt, CourtVerdict, CourtJudgment

logger = logging.getLogger("hunter_ai.qualification_gate")


class ObservationType(str, Enum):
    NETWORK_PORT = "network_port"
    HTTP_ENDPOINT = "http_endpoint"
    CRAWLED_FILE = "crawled_file"
    PARAMETER = "parameter"
    JS_SECRET = "js_secret"
    PROBE_ANOMALY = "probe_anomaly"


class ObservationRecord(BaseModel):
    id: str = Field(default_factory=lambda: f"obs_{uuid.uuid4().hex[:8]}")
    source_tool: str
    obs_type: ObservationType
    target: str
    evidence_snippet: str
    confidence: float = 0.90
    timestamp: float = Field(default_factory=time.time)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class EvidenceChainStep(BaseModel):
    stage: str
    source: str
    type: str
    value: str
    timestamp: float = Field(default_factory=time.time)


class FindingQualificationGate:
    """
    Authoritative Gatekeeper filtering candidate signals before reporting.
    """

    NON_VULN_PATTERNS = {
        "robots.txt": "Standard web crawler instruction file (RFC 9309). Expected public behavior.",
        "sitemap.xml": "Standard search engine navigation index. Expected public behavior.",
        "open_ports": "Open TCP/UDP services are infrastructure attack surface observations, not vulnerabilities.",
    }

    @classmethod
    def evaluate_candidate(
        cls,
        title: str,
        asset: str,
        endpoint: str,
        vuln_type: str,
        raw_evidence: str,
        source_tool: str,
        parameter: Optional[str] = None,
        verifier_result: Optional[Dict[str, Any]] = None,
        is_in_scope: bool = True,
        reproduction: Optional[ReproductionArtifact] = None,
        evidence_chain: Optional[List[Dict[str, Any]]] = None,
    ) -> Tuple[bool, Optional[HunterFinding], str]:
        """
        Evaluates whether a candidate claim qualifies as a legitimate vulnerability finding.
        Returns: (is_qualified, HunterFinding or None, rejection_rationale)
        """
        # 1. Security Impact Qualification (Zero False Positive Rule)
        ep_lower = endpoint.lower()

        if "robots.txt" in ep_lower:
            return False, None, "REJECT: /robots.txt existence is expected web behavior with zero security impact."

        if "sitemap.xml" in ep_lower:
            return False, None, "REJECT: /sitemap.xml existence is expected web behavior with zero security impact."

        if vuln_type.lower() in ("openports", "exposedservice") and "riskymanagement" not in vuln_type.lower():
            return False, None, "REJECT: Standard exposed network port is an inventory observation, not a vulnerability."

        # 2. Scope Validation
        if not is_in_scope:
            return False, None, "REJECT: Target is outside authorized scope."

        # 3. Adjudication via Evidence Court
        finder_claim = {
            "title": title,
            "tool": source_tool,
            "vuln_type": vuln_type,
            "raw_evidence": raw_evidence,
            "is_reflection": verifier_result.get("is_reflection", False) if verifier_result else False
        }

        judgment: CourtJudgment = EvidenceCourt.adjudicate(
            target_url=endpoint,
            parameter=parameter or "",
            vuln_class=vuln_type,
            finder_claim=finder_claim,
            verifier_result=verifier_result,
            is_in_scope=is_in_scope
        )

        if judgment.verdict != CourtVerdict.CONFIRMED:
            return False, None, f"REJECT by Evidence Court: {judgment.adjudication_rationale} (Verdict: {judgment.verdict.value})"

        # 4. Construct Verified Finding with complete Evidence Chain
        chain_steps = evidence_chain or []
        if not chain_steps:
            chain_steps = [
                {"stage": "01_OBSERVE", "source": source_tool, "type": "signal", "value": endpoint},
                {"stage": "02_VERIFY", "source": "EvidenceCourt", "type": "adjudication", "value": judgment.adjudication_rationale}
            ]

        evidence_items = [
            VerificationEvidence(
                type="controlled_execution",
                description=judgment.adjudication_rationale,
                proof_snippet=raw_evidence[:300],
                verified=True
            )
        ]

        # Calculate CVSS calibrated by Court
        calibrated_cvss = 9.8 if judgment.calibrated_severity == "Critical" else (
            7.5 if judgment.calibrated_severity == "High" else (
                5.0 if judgment.calibrated_severity == "Medium" else 2.0
            )
        )

        finding = HunterFinding(
            finding=title,
            asset=asset,
            endpoint=endpoint,
            parameter=parameter,
            vuln_type=vuln_type,
            status=FindingStatus.CONFIRMED,
            tier=FindingTier.VERIFIED_FINDING,
            severity=judgment.calibrated_severity,
            confidence=judgment.confidence_score,
            cvss_score=calibrated_cvss,
            evidence=evidence_items,
            reproduction=reproduction,
            remediation=cls._get_remediation(vuln_type)
        )

        return True, finding, "CONFIRMED by Evidence Court with complete Evidence Chain."

    @staticmethod
    def _get_remediation(vuln_type: str) -> str:
        vt = vuln_type.lower()
        if "cmdi" in vt or "command" in vt or "rce" in vt:
            return "Never concatenate untrusted input into system commands. Use subprocess with execve argument vectors."
        elif "sqli" in vt or "sql" in vt:
            return "Use parameterized queries and prepared statements. Never format or concatenate input into SQL statements."
        elif "xss" in vt:
            return "Apply contextual output encoding and enforce a restrictive Content Security Policy (CSP)."
        elif "ssrf" in vt:
            return "Validate target URLs against a strict whitelist and disable access to private subnets (169.254.0.0/16, RFC1918)."
        elif "idor" in vt or "bola" in vt:
            return "Enforce object-level access control checks verifying user ownership on every request."
        elif "secret" in vt:
            return "Revoke exposed keys immediately, rotate credentials, and store secrets in an environment secret manager."
        return "Apply defense-in-depth input validation and least-privilege access control."
