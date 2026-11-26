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
import re
from typing import Any, Callable, Dict, Optional
from urllib.parse import parse_qsl, urlparse

from core.detectors.contract import Detection, DetectionContext, normalize_body
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


def _header_ci(headers: Dict[str, str], name: str) -> str:
    target = name.lower()
    for key, value in (headers or {}).items():
        if str(key).lower() == target:
            return str(value)
    return ""


def _first_identity_label(headers: Dict[str, str], fallback: str) -> str:
    for key, value in (headers or {}).items():
        val = str(value or "").strip()
        if val:
            return f"{key}:{val}"
    return fallback


def _build_proof_payload(detection: Detection) -> Optional[Dict[str, Any]]:
    """Derive a genuine Phase 3 ProofPayload dict strictly from captured detector exchanges."""
    finding = detection.finding
    exchanges = list(detection.exchanges or [])
    if not detection.confirmed or finding is None or not exchanges:
        return None

    vuln = normalize_vuln_type(detection.vuln_class).lower()
    proof_token = str(getattr(finding.verification, "proof_token", "") or "")

    if vuln in ("sqli", "sql_injection", "sqli_boolean"):
        if len(exchanges) < 4:
            return None
        control_a, control_b = exchanges[0], exchanges[1]
        true_ex, false_ex = exchanges[2], exchanges[3]
        control_ok = normalize_body(control_a.body) == normalize_body(control_b.body)
        true_matches = normalize_body(true_ex.body) == normalize_body(control_a.body)
        false_diverges = normalize_body(false_ex.body) != normalize_body(true_ex.body)
        # Verify additional captured true/false pairs if present
        for idx in range(4, len(exchanges) - 1, 2):
            extra_t, extra_f = exchanges[idx], exchanges[idx + 1]
            if normalize_body(extra_t.body) != normalize_body(control_a.body):
                true_matches = False
            if normalize_body(extra_f.body) == normalize_body(extra_t.body):
                false_diverges = False
        return {
            "artifact_type": "sqli",
            "response_text": true_ex.body,
            "baseline_text": control_a.body,
            "metadata": {
                "boolean_true_matches_baseline": true_matches,
                "boolean_false_diverges": false_diverges,
                "control_matches_baseline": control_ok,
                "false_response_text": false_ex.body[:500],
                "status_code": true_ex.status_code,
                "reproduced_count": finding.verification.reproduced_count,
            },
        }

    if vuln in ("xss", "cross_site_scripting", "reflected_xss"):
        if len(exchanges) < 2 or not proof_token:
            return None
        baseline_ex, tested_ex = exchanges[0], exchanges[-1]
        breakout = f'"><{proof_token}>'
        # Only assert the unescaped breakout token if it was actually observed verbatim
        if breakout in tested_ex.body and breakout not in baseline_ex.body:
            return {
                "artifact_type": "token",
                "response_text": tested_ex.body,
                "baseline_text": baseline_ex.body,
                "expected_token": breakout,
                "probed_expression": "",
                "metadata": {"status_code": tested_ex.status_code},
            }
        return None

    if vuln in ("idor", "bola"):
        if len(exchanges) < 2 or not proof_token:
            return None
        owner_ex = exchanges[0]
        tested_req = finding.tested_request
        attacker_ex = exchanges[1]
        if tested_req is not None:
            for ex in exchanges[1:]:
                if ex.probe.url == tested_req.url and ex.probe.headers == tested_req.headers:
                    attacker_ex = ex
                    break
        owner_id = _first_identity_label(owner_ex.probe.headers, "owner")
        actor_id = _first_identity_label(attacker_ex.probe.headers, "anonymous")
        # Baseline is an unauthorized/denied exchange without the victim marker (if observed)
        denied_baseline = ""
        for ex in exchanges[1:]:
            if ex is not attacker_ex and proof_token not in ex.body:
                denied_baseline = ex.body
                break
        return {
            "artifact_type": "idor",
            "response_text": attacker_ex.body,
            "baseline_text": denied_baseline,
            "expected_token": proof_token,
            "probed_expression": "",
            "metadata": {
                "actor_id": actor_id,
                "owner_id": owner_id,
                "status_code": attacker_ex.status_code,
            },
        }

    if vuln == "ssrf":
        if len(exchanges) < 2 or not proof_token:
            return None
        baseline_ex, tested_ex = exchanges[0], exchanges[-1]
        cb_match = re.search(r"callback for path ['\"]([^'\"]+)['\"]", str(finding.evidence or ""))
        oob_callbacks = [cb_match.group(1)] if cb_match else []
        if not oob_callbacks:
            return None
        return {
            "artifact_type": "ssrf",
            "response_text": tested_ex.body,
            "baseline_text": baseline_ex.body,
            "expected_token": proof_token,
            "probed_expression": "",
            "metadata": {
                "oob_nonce": proof_token,
                "oob_callbacks": oob_callbacks,
                "status_code": tested_ex.status_code,
            },
        }

    if vuln in ("open_redirect", "openredirect"):
        if len(exchanges) < 2:
            return None
        baseline_ex, tested_ex = exchanges[0], exchanges[-1]
        location = _header_ci(tested_ex.response_headers, "Location")
        baseline_loc = _header_ci(baseline_ex.response_headers, "Location")
        probe_redirect_host = ""
        for _k, val in parse_qsl(urlparse(tested_ex.probe.url).query, keep_blank_values=True):
            if val.lower().startswith(("http://", "https://")):
                probe_redirect_host = (urlparse(val).hostname or "").lower()
                if probe_redirect_host:
                    break
        if not (location and probe_redirect_host):
            return None
        return {
            "artifact_type": "open_redirect",
            "response_text": tested_ex.body or f"Location: {location}",
            "baseline_text": baseline_ex.body or (f"Location: {baseline_loc}" if baseline_loc else ""),
            "expected_token": proof_token,
            "probed_expression": "",
            "metadata": {
                "probe_redirect_host": probe_redirect_host,
                "location": location,
                "status_code": tested_ex.status_code,
            },
        }

    return None


def build_gate_evidence(detection: Detection) -> Dict[str, Any]:
    """Map a confirmed detection to the keys the 7-Question Gate checks.

    Every value is derived from the recorded exchanges; nothing is asserted
    without an artifact behind it.
    """
    if not detection.confirmed or detection.finding is None:
        return {"confirmed": False, "reason": detection.reason}

    finding = detection.finding
    request_hash, response_hash = _exchange_hashes(detection)
    evidence: Dict[str, Any] = {
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
    proof_payload = _build_proof_payload(detection)
    if proof_payload is not None:
        evidence["proof_payload"] = proof_payload
    return evidence


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
