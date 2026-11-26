"""
WAF Bypass Evidence Court Compatibility Adapter
===============================================
Delegates all WAF-bypass verification decisions to the single authoritative
``core.evidence_court.EvidenceCourt.adjudicate()``.

Naive substring reflection (``bypass_payload in response_body``) NEVER confirms
a WAF bypass or direct vulnerability (Reflection != Execution).
"""
from __future__ import annotations

import asyncio
import hashlib
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from core.config.settings import config
from core.evidence_court import (
    CourtJudgment,
    CourtVerdict as CanonicalCourtVerdict,
    EvidenceCourt as AuthoritativeEvidenceCourt,
    ProofPayload,
    ProofStrength,
)
from core.logging.logger import logger


class CourtVerdict(str, Enum):
    PROVEN_BYPASS = "proven_bypass"
    PROVEN_DIRECT = "proven_direct"
    REFUTED = "refuted"
    INCONCLUSIVE = "inconclusive"


@dataclass
class BypassContext:
    """Context of a WAF bypass verification probe."""
    target: str
    endpoint: str
    original_payload: str
    bypass_payload: str
    waf_type: str
    waf_detected: bool
    status_code: int
    response_body: str
    response_headers: Dict[str, str]
    request_headers: Dict[str, str]
    response_time_ms: float
    technique_level: str
    timestamp: float = field(default_factory=time.time)
    baseline_body: str = ""
    expected_token: str = ""
    expected_result: str = ""
    vuln_class: str = ""
    proof_payload: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "endpoint": self.endpoint,
            "original_payload": self.original_payload,
            "bypass_payload": self.bypass_payload,
            "waf_type": self.waf_type,
            "waf_detected": self.waf_detected,
            "status_code": self.status_code,
            "response_body_hash": hashlib.sha256(
                self.response_body.encode("utf-8", errors="replace")
            ).hexdigest()[:16],
            "response_headers": self.response_headers,
            "request_headers": self.request_headers,
            "response_time_ms": self.response_time_ms,
            "technique_level": self.technique_level,
            "timestamp": self.timestamp,
        }


@dataclass
class CourtResult:
    """Result mapped back from canonical EvidenceCourt adjudication."""
    verdict: CourtVerdict
    confidence: float
    reasoning: str
    evidence: Dict[str, Any]
    bypass_confirmed: bool
    direct_vuln_confirmed: bool
    canonical_verdict: str = CanonicalCourtVerdict.INCONCLUSIVE.value
    proof_strength: str = ProofStrength.NONE.value
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "canonical_verdict": self.canonical_verdict,
            "proof_strength": self.proof_strength,
            "confidence": self.confidence,
            "reasoning": self.reasoning,
            "evidence": self.evidence,
            "bypass_confirmed": self.bypass_confirmed,
            "direct_vuln_confirmed": self.direct_vuln_confirmed,
            "timestamp": self.timestamp,
        }


class EvidenceCourt:
    """WAF bypass court adapter delegating adjudication to canonical core.evidence_court.EvidenceCourt."""

    def __init__(self, config_override: Optional[Any] = None):
        self.court_config = config_override or config.evidence_court
        self.cases: Dict[str, CourtResult] = {}
        self._lock = asyncio.Lock()

    async def verify_bypass_async(
        self,
        context: BypassContext,
        case_id: Optional[str] = None,
    ) -> CourtResult:
        async with self._lock:
            return self._verify_bypass_sync(context, case_id)

    def verify_bypass(
        self,
        context: BypassContext,
        case_id: Optional[str] = None,
    ) -> CourtResult:
        return self._verify_bypass_sync(context, case_id)

    def _verify_bypass_sync(
        self,
        context: BypassContext,
        case_id: Optional[str] = None,
    ) -> CourtResult:
        case_id = case_id or f"court-{int(time.time() * 1000)}"

        waf_blocked = context.status_code in (403, 406, 429, 503)
        payload_reflected = bool(
            context.bypass_payload
            and context.bypass_payload.lower() in (context.response_body or "").lower()
        )

        # Build checkable ProofPayload ONLY from explicit proof artifacts (never bare reflection)
        proof_payload: Optional[ProofPayload] = None
        if context.proof_payload is not None:
            proof_payload = ProofPayload.from_mapping(context.proof_payload)
        elif context.expected_token or context.expected_result or context.vuln_class:
            proof_payload = ProofPayload(
                response_text=context.response_body or "",
                baseline_text=context.baseline_body or "",
                artifact_type=context.vuln_class or ("token" if context.expected_token else ""),
                probed_expression=context.bypass_payload or context.original_payload,
                expected_result=context.expected_result or "",
                expected_token=context.expected_token or "",
                metadata={
                    "status_code": context.status_code,
                    "response_headers": dict(context.response_headers or {}),
                },
            )
        else:
            # Attempt deterministic PoE signature derivation (e.g. DBMS banner / /etc/passwd)
            proof_payload = ProofPayload.from_vuln_evidence(
                context.vuln_class or "",
                context.response_body or "",
            )

        # Mere substring reflection without deterministic proof is explicitly flagged as reflection
        is_reflection_only = payload_reflected and proof_payload is None

        verifier_result: Dict[str, Any] = {
            "reproduced": (not waf_blocked) and (not is_reflection_only) and context.status_code > 0,
            "status_code": context.status_code,
            "response_body": context.response_body,
            "waf_blocked": waf_blocked,
            "is_reflection": is_reflection_only,
        }

        target_url = (
            context.endpoint
            if str(context.endpoint).startswith(("http://", "https://"))
            else f"{context.target.rstrip('/')}/{context.endpoint.lstrip('/')}"
        )

        judgment: CourtJudgment = AuthoritativeEvidenceCourt.adjudicate(
            target_url=target_url,
            parameter="",
            vuln_class=context.vuln_class or "waf_bypass",
            finder_claim={
                "waf_type": context.waf_type,
                "technique_level": context.technique_level,
                "original_payload": context.original_payload,
                "bypass_payload": context.bypass_payload,
            },
            verifier_result=verifier_result,
            is_in_scope=True,
            is_blocked_by_waf=waf_blocked,
            proof_payload=proof_payload,
            allow_declared_proof=False,
        )

        canon = judgment.canonical_verdict
        bypass_confirmed = False
        direct_vuln_confirmed = False

        if canon == CanonicalCourtVerdict.CONFIRMED and judgment.proof_strength == ProofStrength.DERIVED.value:
            if context.waf_detected:
                verdict = CourtVerdict.PROVEN_BYPASS
                bypass_confirmed = True
            else:
                verdict = CourtVerdict.PROVEN_DIRECT
                direct_vuln_confirmed = True
        elif canon == CanonicalCourtVerdict.REJECTED:
            verdict = CourtVerdict.REFUTED
        else:
            verdict = CourtVerdict.INCONCLUSIVE

        evidence: Dict[str, Any] = {
            "payload_reflected": payload_reflected,
            "waf_blocked": waf_blocked,
            "waf_bypassed": bypass_confirmed,
            "response_time_ms": context.response_time_ms,
            "canonical_verdict": canon.value,
            "proof_strength": judgment.proof_strength,
            "proof_kind": judgment.proof_kind,
            "court_judgment_id": judgment.judgment_id,
        }

        result = CourtResult(
            verdict=verdict,
            confidence=judgment.confidence_score,
            reasoning=judgment.adjudication_rationale,
            evidence=evidence,
            bypass_confirmed=bypass_confirmed,
            direct_vuln_confirmed=direct_vuln_confirmed,
            canonical_verdict=canon.value,
            proof_strength=judgment.proof_strength,
        )

        self.cases[case_id] = result
        logger.info(
            "[Court-WAF-Adapter] case='%s': legacy=%s canonical=%s proof_strength=%s",
            case_id,
            verdict.value,
            canon.value,
            judgment.proof_strength,
        )
        return result

    def get_case(self, case_id: str) -> Optional[CourtResult]:
        return self.cases.get(case_id)

    def stats(self) -> Dict[str, Any]:
        total = len(self.cases)
        if total == 0:
            return {"total": 0}
        bypass_count = sum(1 for c in self.cases.values() if c.bypass_confirmed)
        direct_count = sum(1 for c in self.cases.values() if c.direct_vuln_confirmed)
        refuted_count = sum(1 for c in self.cases.values() if c.verdict == CourtVerdict.REFUTED)
        return {
            "total": total,
            "proven_bypass": bypass_count,
            "proven_direct": direct_count,
            "refuted": refuted_count,
            "bypass_rate": round(bypass_count / total, 2),
        }

    def clear_cases(self) -> int:
        count = len(self.cases)
        self.cases.clear()
        logger.info("[Court] Cleared %d cases", count)
        return count


evidence_court = EvidenceCourt()
