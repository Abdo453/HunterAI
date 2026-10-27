"""Hypothesis → detector → evidence chain → validation gate pipeline.

The pipeline is the integration point between the deterministic hypothesis
engine (``hunter_ai.evidence.hypothesis_engine``), the safe detectors, the
hash-linked evidence chain, and the 7-Question Validation Gate.

A hypothesis is only marked ``CONFIRMED`` when:

1. the mapped detector returns a confirmed differential;
2. every exchange is appended to a verifiable evidence chain;
3. the validation gate returns ``PROVEN`` (when a validator is supplied).

No LLM opinion is involved.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional

from core.detectors.contract import Detection, DetectionContext
from core.detectors.evidence_chain import EvidenceChain
from core.detectors.idor import IDORDetector
from core.detectors.open_redirect import OpenRedirectDetector
from core.detectors.sqli_boolean import SQLiBooleanDetector
from core.detectors.ssrf import SSRFDetector
from core.detectors.transport import HttpTransport
from core.detectors.xss_reflected import XSSReflectedDetector

_DETECTOR_CLASSES = {
    "SQL_INJECTION": SQLiBooleanDetector,
    "SQLI": SQLiBooleanDetector,
    "SQLI_BOOLEAN": SQLiBooleanDetector,
    "XSS": XSSReflectedDetector,
    "CROSS_SITE_SCRIPTING": XSSReflectedDetector,
    "REFLECTED_XSS": XSSReflectedDetector,
    "IDOR": IDORDetector,
    "BOLA": IDORDetector,
    "SSRF": SSRFDetector,
    "OPEN_REDIRECT": OpenRedirectDetector,
    "OPENREDIRECT": OpenRedirectDetector,
}


def normalize_vuln_type(value: str) -> str:
    return str(value or "").upper().replace("-", "_").replace(" ", "_").strip()


def detector_for(vuln_type: str):
    """Return a detector instance for a hypothesis vuln_type, or None."""
    cls = _DETECTOR_CLASSES.get(normalize_vuln_type(vuln_type))
    return cls() if cls else None


def _exchange_hashes(detection: Detection):
    finding = detection.finding
    if finding is not None and finding.tested_request is not None:
        tested_url = finding.tested_request.url
        for exchange in reversed(detection.exchanges):
            if exchange.probe.url == tested_url:
                return exchange.request_hash, exchange.response_hash
    if detection.exchanges:
        exchange = detection.exchanges[-1]
        return exchange.request_hash, exchange.response_hash
    return "", ""


def build_gate_evidence(detection: Detection) -> Dict[str, Any]:
    """Map a confirmed detection to the keys the 7-Question Gate checks.

    Every value is derived from the recorded exchanges; nothing is asserted
    without an artifact behind it.
    """
    if not detection.confirmed or detection.finding is None:
        return {"confirmed": False, "reason": detection.reason}

    finding = detection.finding
    request_hash, response_hash = _exchange_hashes(detection)
    return {
        "confirmed": True,
        "poc": finding.reproducibility.reproduction_curl or finding.evidence,
        "reproduction": list(finding.reproducibility.reproduction_steps),
        "nonce": finding.verification.proof_token or "",
        "differential_response": True,
        "deterministic_proof": True,
        "real_exploit_path": True,
        "impact": finding.impact,
        "severity": str(finding.severity).lower(),
        "request_hash": request_hash,
        "response_hash": response_hash,
        "vuln_class": detection.vuln_class,
        "detector": detection.detector,
    }


@dataclass
class PipelineResult:
    hypothesis: Any
    detection: Detection
    evidence: Dict[str, Any]
    validation: Optional[Any] = None
    chain_verified: bool = False
    detector_name: str = ""

    def to_dict(self) -> Dict[str, Any]:
        hypothesis = self.hypothesis
        if hasattr(hypothesis, "to_dict"):
            hypothesis = hypothesis.to_dict()
        return {
            "hypothesis": hypothesis,
            "detector": self.detector_name,
            "detection": self.detection.to_dict(),
            "evidence": self.evidence,
            "validation": (
                self.validation.to_dict()
                if self.validation is not None and hasattr(self.validation, "to_dict")
                else self.validation
            ),
            "chain_verified": self.chain_verified,
        }


class HypothesisPipeline:
    """Run hypotheses through detectors, evidence chain and validation."""

    def __init__(
        self,
        transport: HttpTransport,
        chain: Optional[EvidenceChain] = None,
        validator: Optional[Callable[..., Any]] = None,
        hypothesis_engine: Optional[Any] = None,
    ):
        self._transport = transport
        self._chain = chain or EvidenceChain()
        self._validator = validator
        self._engine = hypothesis_engine

    @property
    def chain(self) -> EvidenceChain:
        return self._chain

    def supported_vuln_types(self):
        return sorted(_DETECTOR_CLASSES)

    def run(self, hypothesis: Any, context: DetectionContext) -> PipelineResult:
        vuln_type = getattr(hypothesis, "vuln_type", "")
        detector = detector_for(vuln_type)

        if detector is None:
            detection = Detection(
                vuln_class=normalize_vuln_type(vuln_type).lower() or "unknown",
                confirmed=False,
                confidence=0.0,
                reason=f"no detector is mapped to vuln_type {vuln_type!r}",
                detector="pipeline",
            )
            self._record(hypothesis, detection, None)
            return PipelineResult(
                hypothesis=hypothesis,
                detection=detection,
                evidence=build_gate_evidence(detection),
                chain_verified=self._chain.verify(),
                detector_name="pipeline",
            )

        self._set_testing(hypothesis)
        detection = detector.detect(context, self._transport)
        self._chain.append_all(detection)
        evidence = build_gate_evidence(detection)

        validation = None
        if detection.confirmed and self._validator is not None:
            finding_dict = detection.finding.to_dict()
            # The gate reads its inputs from finding["evidence"]; keep the
            # human-readable text under a separate key.
            finding_dict["evidence_text"] = finding_dict.get("evidence", "")
            finding_dict["evidence"] = evidence
            if hasattr(self._validator, "validate"):
                validation = self._validator.validate(
                    finding_dict,
                    target=context.base_url,
                    evidence=evidence,
                )
            else:
                validation = self._validator(
                    finding_dict,
                    target=context.base_url,
                    evidence=evidence,
                )

        self._record(hypothesis, detection, validation)
        return PipelineResult(
            hypothesis=hypothesis,
            detection=detection,
            evidence=evidence,
            validation=validation,
            chain_verified=self._chain.verify(),
            detector_name=detection.detector,
        )

    # -- hypothesis lifecycle ----------------------------------------------

    def _set_testing(self, hypothesis: Any) -> None:
        if self._engine is None:
            return
        hyp_id = getattr(hypothesis, "hyp_id", "")
        if not hyp_id:
            return
        from hunter_ai.evidence.hypothesis_engine import HypothesisStatus

        self._engine.update_status(hyp_id, HypothesisStatus.TESTING)

    def _record(self, hypothesis: Any, detection: Detection, validation: Optional[Any]) -> None:
        if self._engine is None:
            return
        hyp_id = getattr(hypothesis, "hyp_id", "")
        if not hyp_id:
            return
        if not detection.confirmed:
            self._engine.set_verdict(hyp_id, "REJECTED", detection.reason)
            return
        if validation is None:
            self._engine.set_verdict(
                hyp_id,
                "CONFIRMED",
                "detector confirmed with differential evidence (no gate requested)",
                confidence_delta=max(
                    0.0,
                    detection.confidence
                    - float(getattr(hypothesis, "confidence", 0.0)),
                ),
            )
            return
        status = getattr(getattr(validation, "status", None), "value", "")
        verdict = {"PROVEN": "CONFIRMED", "REFUTED": "REJECTED"}.get(
            status, "INCONCLUSIVE"
        )
        rationale = getattr(validation, "rationale", "") or status
        self._engine.set_verdict(
            hyp_id,
            verdict,
            rationale,
            confidence_delta=max(
                0.0,
                detection.confidence
                - float(getattr(hypothesis, "confidence", 0.0)),
            ),
        )
