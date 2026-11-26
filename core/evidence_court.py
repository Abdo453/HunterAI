"""
Evidence Court (محكمة الأدلة) - Authoritative 7-State Epistemic Adjudication
============================================================================
Single authoritative multi-party adjudication engine ensuring no single agent,
tool, or LLM can declare a finding as CONFIRMED without independent,
deterministic verification, causal invariant proof, and metamorphic consistency.

CANONICAL 7 STATES:
  - UNVERIFIED   : Signal tested/observed without deterministic proof
  - CANDIDATE    : Reproducible differential signal pending typed ProofContract / causal proof
  - CONFIRMED    : Deterministic DERIVED proof (ProofContract or CausalInvariant) passed
  - REJECTED     : Refuted, false positive, disproved, blocked by WAF, duplicate, or out-of-scope
  - INCONCLUSIVE : Ambiguous or missing verifier run without explicit tool/runtime failure
  - UNAVAILABLE  : Verification tool/binary missing, target unreachable, or timed out
  - ERROR        : Runtime exception in verifier or proof evaluation

Legacy CourtVerdict members (FALSE_POSITIVE, DISPROVED, OUT_OF_SCOPE, BLOCKED,
DUPLICATE) are preserved as backward-compatible enum values and map cleanly to
the canonical 7 states via ``CourtVerdict.canonical_verdict()``.
"""
from __future__ import annotations

import logging
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union

from core.poe_engine import (
    CANONICAL_PROOF_CATEGORIES,
    PROOF_CONTRACT_REGISTRY,
    ProofContract,
    ProofContractRegistry,
    ProofOfExecutionEngine,
    normalize_vuln_category,
)

logger = logging.getLogger("hunter_ai.evidence_court")


class CourtVerdict(str, Enum):
    # Canonical 7 states
    UNVERIFIED = "UNVERIFIED"
    CANDIDATE = "CANDIDATE"
    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"
    INCONCLUSIVE = "INCONCLUSIVE"
    UNAVAILABLE = "UNAVAILABLE"
    ERROR = "ERROR"

    # Backward-compatible legacy alias members (preserved for existing callers/tests)
    FALSE_POSITIVE = "FALSE_POSITIVE"
    DISPROVED = "DISPROVED"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    BLOCKED = "BLOCKED"
    DUPLICATE = "DUPLICATE"

    def canonical_verdict(self) -> "CourtVerdict":
        """Map any verdict (including legacy alias members) to the canonical 7-state set."""
        if self in _LEGACY_TO_CANONICAL:
            return _LEGACY_TO_CANONICAL[self]
        return self

    @property
    def is_canonical(self) -> bool:
        return self in CANONICAL_COURT_VERDICTS


CANONICAL_COURT_VERDICTS = frozenset({
    CourtVerdict.UNVERIFIED,
    CourtVerdict.CANDIDATE,
    CourtVerdict.CONFIRMED,
    CourtVerdict.REJECTED,
    CourtVerdict.INCONCLUSIVE,
    CourtVerdict.UNAVAILABLE,
    CourtVerdict.ERROR,
})

_LEGACY_TO_CANONICAL: Dict[CourtVerdict, CourtVerdict] = {
    CourtVerdict.FALSE_POSITIVE: CourtVerdict.REJECTED,
    CourtVerdict.DISPROVED: CourtVerdict.REJECTED,
    CourtVerdict.OUT_OF_SCOPE: CourtVerdict.REJECTED,
    CourtVerdict.BLOCKED: CourtVerdict.REJECTED,
    CourtVerdict.DUPLICATE: CourtVerdict.REJECTED,
}


def canonical_verdict(verdict: Union[CourtVerdict, str]) -> CourtVerdict:
    """Normalize any CourtVerdict enum or string into one of the 7 canonical CourtVerdict states."""
    if isinstance(verdict, CourtVerdict):
        return verdict.canonical_verdict()
    raw = str(verdict or "").strip().upper()
    mapping = {
        "CONFIRMED": CourtVerdict.CONFIRMED,
        "PROVEN": CourtVerdict.CONFIRMED,
        "PROVEN_BYPASS": CourtVerdict.CONFIRMED,
        "PROVEN_DIRECT": CourtVerdict.CONFIRMED,
        "UNVERIFIED": CourtVerdict.UNVERIFIED,
        "UNPROVEN": CourtVerdict.UNVERIFIED,
        "CANDIDATE": CourtVerdict.CANDIDATE,
        "LIKELY": CourtVerdict.CANDIDATE,
        "TRIAGED": CourtVerdict.CANDIDATE,
        "REJECTED": CourtVerdict.REJECTED,
        "REFUTED": CourtVerdict.REJECTED,
        "FALSE_POSITIVE": CourtVerdict.REJECTED,
        "DISPROVED": CourtVerdict.REJECTED,
        "OUT_OF_SCOPE": CourtVerdict.REJECTED,
        "BLOCKED": CourtVerdict.REJECTED,
        "DUPLICATE": CourtVerdict.REJECTED,
        "INCONCLUSIVE": CourtVerdict.INCONCLUSIVE,
        "PARTIALLY_VERIFIED": CourtVerdict.INCONCLUSIVE,
        "ESCALATED": CourtVerdict.INCONCLUSIVE,
        "UNAVAILABLE": CourtVerdict.UNAVAILABLE,
        "TIMEOUT": CourtVerdict.UNAVAILABLE,
        "MISSING_BINARY": CourtVerdict.UNAVAILABLE,
        "ERROR": CourtVerdict.ERROR,
    }
    return mapping.get(raw, CourtVerdict.UNVERIFIED)


@dataclass
class CausalEvidence:
    """Class 1: Formal Invariant and Metamorphic Triad Verification Evidence."""
    metamorphic_passed: bool = False
    invariant_passed: bool = False
    invariant_id: str = ""
    causal_strength: float = 0.0
    contradiction_detected: bool = False
    rationale: str = ""
    extracted_observables: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class NegativeEvidence:
    """Class 2: Context-Scoped Defense Boundary Verification Evidence."""
    status_code: Optional[int] = None
    pattern_matched: Optional[str] = None
    boundary_conclusion: str = "BOUNDARY_ENFORCED_FOR_TESTED_CONTEXT"
    unexplored_status: str = "UNKNOWN"
    context_scope: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ExecutionEvidence:
    """Class 3: Physical Execution Telemetry and Proof-of-Execution (PoE)."""
    reproduced: bool = False
    poe_token: Optional[str] = None
    arithmetic_confirmed: bool = False
    status_code: int = 200
    length_delta_only: bool = False
    status_change_only: bool = False
    is_reflection: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ProofStrength(str, Enum):
    """How a claimed deterministic proof was established.

    DERIVED  — an engine re-evaluated the raw observed data and the proof held.
    REFUTED  — an engine re-evaluated the raw observed data and the proof failed.
    DECLARED — the caller asserted a proof flag without supplying checkable data.
    NONE     — no proof was offered at all.
    """
    DERIVED = "DERIVED"
    REFUTED = "REFUTED"
    DECLARED = "DECLARED"
    NONE = "NONE"


@dataclass
class ProofPayload:
    """Raw, engine-checkable evidence backing a claimed deterministic proof.

    This is the difference between "trust me, it executed" and "here is the
    response; verify it yourself".
    """
    response_text: str = ""
    baseline_text: str = ""
    artifact_type: str = ""          # sqli | xss | cmdi | ssrf | idor | lfi | ssti | auth | jwt | deser | race | secret | misconfig | token
    probed_expression: str = "53+19"
    expected_result: str = "72"
    expected_token: str = ""         # nonce/canary that must appear verbatim
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, data: Any) -> Optional["ProofPayload"]:
        if not data:
            return None
        if isinstance(data, ProofPayload):
            return data
        if isinstance(data, dict):
            known = {f for f in cls.__dataclass_fields__}
            payload = cls(**{k: v for k, v in data.items() if k in known})
            if payload.response_text or payload.expected_token or payload.artifact_type or payload.metadata:
                return payload
        return None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_vuln_evidence(cls, vuln_type: str, evidence: str) -> Optional["ProofPayload"]:
        """Builds a re-evaluable payload for classes with a deterministic PoE
        signature. Returns None when no signature applies, so the candidate is
        honestly left UNVERIFIED instead of fabricating a proof.
        """
        text = f"{vuln_type} {evidence or ''}".lower()
        artifact = None
        if any(k in text for k in ("sql", "union select", "sqli")):
            artifact = "sqli"
        elif any(k in text for k in (
            "traversal", "lfi", "etc/passwd", "boot.ini", "[boot loader]",
            "root:x:0:0", "root:/root:", "/bin/bash",
        )):
            artifact = "lfi"
        elif any(k in text for k in ("command injection", "cmd_injection", "cmdi", "rce", "remote code")):
            artifact = "command_injection"
        elif any(k in text for k in ("exposed_secret", "secret", "akia", "ghp_", "private key")):
            artifact = "secret"
        elif any(k in text for k in ("ssrf", "169.254.169.254", "computemetadata")):
            artifact = "ssrf"
        elif any(k in text for k in ("ssti", "template_injection")):
            artifact = "ssti"
        elif any(k in text for k in ("cors", "open_redirect", ".git/head", ".env", "misconfig")):
            artifact = "misconfig"
        if not artifact or not evidence:
            return None
        payload = cls(artifact_type=artifact, response_text=str(evidence)[:4000])
        if artifact == "command_injection":
            payload.expected_result = "72"
            payload.probed_expression = "53+19"
        return payload


class _ProofResolver:
    """Derives proof strength by re-evaluating raw evidence, never by trust."""

    _FLAG_KINDS: Dict[str, str] = {
        "arithmetic_proof_confirmed": "command_injection",
        "canary_confirmed": "token",
        "template_eval_confirmed": "ssti",
        "dom_breakout_confirmed": "token",
        "token_bypass_confirmed": "token",
        "boolean_branch_confirmed": "token",
        "auth_bypass_confirmed": "auth",
        "file_content_confirmed": "lfi",
        "extracted_data": "sqli",
        "deterministic_proof": "token",
    }

    _DECLARED_FLAGS = tuple(_FLAG_KINDS.keys())

    @classmethod
    def declared_flags(cls, verifier_result: Optional[Dict[str, Any]]) -> List[str]:
        if not verifier_result:
            return []
        return [f for f in cls._DECLARED_FLAGS if verifier_result.get(f)]

    @classmethod
    def resolve(
        cls,
        verifier_result: Optional[Dict[str, Any]],
        causal_evidence: Optional["CausalEvidence"] = None,
        proof_payload: Optional[ProofPayload] = None,
        vuln_class: str = "",
    ) -> Tuple[ProofStrength, str, str]:
        """Returns (strength, proof_kind, rationale).

        Order of authority:
        1. Re-evaluable ProofPayload (explicit artifact/category contract or token).
           CRITICAL: When ``expected_token`` is omitted, a bare ``response_text != baseline_text``
           NEVER returns ``ProofStrength.DERIVED`` unless a typed per-category ProofContract
           proves exploitation.
        2. Typed CausalEvidence object with ``invariant_passed=True``.
        3. Declared-only caller booleans -> ``ProofStrength.DECLARED`` (never confirms by default).
        """
        vr = verifier_result or {}

        payload = proof_payload or ProofPayload.from_mapping(vr.get("proof_payload"))
        declared = cls.declared_flags(vr)
        kind_hint = cls._FLAG_KINDS.get(declared[0], "") if declared else ""

        # ── 1. Derive from raw evidence ──────────────────────────────────────
        if payload is not None:
            artifact = (payload.artifact_type or kind_hint or "").lower().strip()
            text = payload.response_text or ""

            # 1a. Classic direct artifact evaluators (keep exact proof_kind labels)
            if artifact == "command_injection" or "command_injection" in artifact or artifact == "cmdi":
                ok, reason = ProofOfExecutionEngine.verify_command_injection(
                    text,
                    expected_arithmetic_result=payload.expected_result or "72",
                    probed_expression=payload.probed_expression or "53+19",
                    baseline_text=payload.baseline_text or "",
                )
                return (
                    (ProofStrength.DERIVED if ok else ProofStrength.REFUTED),
                    "command_injection",
                    reason,
                )

            if artifact == "sqli" or "sqli" in artifact or "sql_injection" in artifact:
                contract_res = PROOF_CONTRACT_REGISTRY.evaluate("sqli", payload.to_dict(), vr)
                if contract_res is not None:
                    return ProofStrength(contract_res.strength), "sqli", contract_res.detail

            if artifact == "lfi" or "lfi" in artifact or "traversal" in artifact:
                ok, reason = ProofOfExecutionEngine.verify_lfi_extraction(
                    text, baseline_text=payload.baseline_text or ""
                )
                return (
                    (ProofStrength.DERIVED if ok else ProofStrength.REFUTED),
                    "lfi",
                    reason,
                )

            # 1b. Typed per-category ProofContract when artifact explicitly names a category
            if artifact and artifact != "token":
                contract_res = PROOF_CONTRACT_REGISTRY.evaluate(artifact, payload.to_dict(), vr)
                if contract_res is not None:
                    return (
                        ProofStrength(contract_res.strength),
                        contract_res.category,
                        contract_res.detail,
                    )

            # 1c. Token / nonce family: expected marker must appear verbatim and
            #     must not be already in baseline or merely echoed from probe expression.
            if payload.expected_token:
                token = payload.expected_token
                if len(text) < len(token):
                    return ProofStrength.REFUTED, "token", "Response shorter than expected token."
                if token not in text:
                    return (
                        ProofStrength.REFUTED,
                        "token",
                        f"Expected token '{token}' absent from observed response.",
                    )
                control = payload.baseline_text or ""
                if control and token in control:
                    return (
                        ProofStrength.REFUTED,
                        "token",
                        "Token already present in the unmutated baseline (not caused by the probe).",
                    )
                if (
                    payload.probed_expression
                    and payload.probed_expression in text
                    and token not in text.replace(payload.probed_expression, "")
                ):
                    return ProofStrength.REFUTED, "token", "Token appears only as part of the reflected payload."
                return (
                    ProofStrength.DERIVED,
                    "token",
                    f"Deterministic token '{token}' observed in the probe response and absent from the baseline.",
                )

            # 1d. Try typed per-category ProofContract derived from vuln_class
            if vuln_class:
                contract_res = PROOF_CONTRACT_REGISTRY.evaluate(vuln_class, payload.to_dict(), vr)
                if contract_res is not None and contract_res.strength in ("DERIVED", "REFUTED"):
                    return (
                        ProofStrength(contract_res.strength),
                        contract_res.category,
                        contract_res.detail,
                    )

            # 1e. CLOSED LOOPHOLE (former L268-273):
            #     When expected_token is omitted and no typed ProofContract proved exploitation,
            #     a bare response_text != baseline_text MUST NEVER return ProofStrength.DERIVED.
            if text and payload.baseline_text and text != payload.baseline_text:
                return (
                    ProofStrength.NONE,
                    "differential_unproven",
                    "Bare response difference from baseline without an expected token or satisfied "
                    "per-category ProofContract is insufficient to prove exploitation (Response Diff != Vulnerability).",
                )

        # ── 2. Causal evidence object ────────────────────────────────────────
        if causal_evidence is not None and causal_evidence.invariant_passed:
            detail = causal_evidence.rationale or "Causal invariant held."
            if causal_evidence.extracted_observables:
                detail = f"{detail} Observables: {sorted(causal_evidence.extracted_observables)[:5]}"
            return ProofStrength.DERIVED, "causal_invariant", detail

        # ── 3. Declared-only ─────────────────────────────────────────────────
        if declared:
            return (
                ProofStrength.DECLARED,
                kind_hint,
                f"Caller declared {', '.join(declared)} without supplying checkable evidence.",
            )

        return ProofStrength.NONE, "", "No deterministic proof offered."


@dataclass
class CausalTriad:
    """The legacy lightweight triad adapter for backward compatibility."""
    baseline_status: int = 200
    baseline_length: int = 1000
    control_status: int = 200
    control_length: int = 1000
    experiment_status: int = 200
    experiment_length: int = 1000
    control_payload_reflected: bool = False
    experiment_payload_reflected: bool = False
    deterministic_execution_token: Optional[str] = None
    metamorphic_relation: Optional[str] = None
    raw_evidence: Dict[str, Any] = field(default_factory=dict)

    def evaluate_causality(self) -> Tuple[bool, str]:
        if (
            self.experiment_status == self.control_status
            and abs(self.experiment_length - self.control_length) < 10
            and not self.deterministic_execution_token
        ):
            return False, "Control mutation produced identical shift as experiment (Dynamic noise or neutral input handling)."

        if (
            self.experiment_status == self.baseline_status
            and abs(self.experiment_length - self.baseline_length) < 5
            and not self.deterministic_execution_token
        ):
            return False, "Experiment produced zero observable differentiation from baseline."

        return True, "Causal differentiation proven: E distinct from both Baseline (B) and Control (C)."


@dataclass
class CourtJudgment:
    judgment_id: str = field(default_factory=lambda: f"judg_{uuid.uuid4().hex[:8]}")
    target_url: str = ""
    parameter: str = ""
    vuln_class: str = ""
    verdict: CourtVerdict = CourtVerdict.UNVERIFIED
    calibrated_severity: str = "Info"
    confidence_score: float = 0.0
    reportable: bool = False
    finder_claim: Dict[str, Any] = field(default_factory=dict)
    verifier_result: Dict[str, Any] = field(default_factory=dict)
    adjudication_rationale: str = ""
    negative_evidence: List[str] = field(default_factory=list)
    provenance_chain: List[Dict[str, Any]] = field(default_factory=list)
    causal_triad_evaluated: bool = False
    causality_rationale: Optional[str] = None
    contradiction_detected: bool = False
    epistemic_state: str = "UNKNOWN"
    proof_strength: str = "NONE"
    proof_kind: str = ""
    proof_detail: str = ""
    timestamp: float = field(default_factory=time.time)

    @property
    def canonical_verdict(self) -> CourtVerdict:
        """Return the normalized canonical 7-state CourtVerdict."""
        return self.verdict.canonical_verdict()

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["verdict"] = self.verdict.value
        d["canonical_verdict"] = self.canonical_verdict.value
        return d


def _classify_verifier_failure(
    finder_claim: Dict[str, Any],
    verifier_result: Optional[Dict[str, Any]],
) -> Optional[Tuple[CourtVerdict, str]]:
    """Distinguish runtime ERROR and timeout/missing-binary UNAVAILABLE from INCONCLUSIVE."""
    sources = [s for s in (verifier_result, finder_claim) if isinstance(s, dict)]

    # 1. Runtime exception / explicit ERROR takes precedence
    for src in sources:
        status_raw = str(src.get("verifier_status") or src.get("status") or "").strip().upper()
        if status_raw == "ERROR" or src.get("exception") or src.get("error"):
            err_msg = str(src.get("exception") or src.get("error") or "Verifier runtime exception.")
            return CourtVerdict.ERROR, f"Verification runtime error: {err_msg}"

    # 2. Timeout / missing binary / unavailable verifier infrastructure
    for src in sources:
        status_raw = str(src.get("verifier_status") or src.get("status") or "").strip().upper()
        if (
            status_raw in ("UNAVAILABLE", "TIMEOUT", "MISSING_BINARY")
            or src.get("timeout")
            or src.get("timed_out")
            or src.get("unavailable")
            or src.get("missing_binary")
            or src.get("tool_missing")
            or src.get("exit_code") == 127
        ):
            reason = str(
                src.get("unavailable_reason")
                or src.get("reason")
                or ("Verifier timed out." if (src.get("timeout") or src.get("timed_out") or status_raw == "TIMEOUT") else "Required verifier tool/binary unavailable.")
            )
            return CourtVerdict.UNAVAILABLE, f"Verification unavailable: {reason}"

    return None


class EvidenceCourt:
    """Authoritative Multi-Party Evidence Court enforcing 7-State Truthfulness & Causal Invariants."""

    PROOF_CONTRACTS: ProofContractRegistry = PROOF_CONTRACT_REGISTRY

    @classmethod
    def adjudicate(
        cls,
        target_url: str,
        parameter: str,
        vuln_class: str,
        finder_claim: Optional[Dict[str, Any]] = None,
        verifier_result: Optional[Dict[str, Any]] = None,
        is_in_scope: bool = True,
        is_blocked_by_waf: bool = False,
        provenance_chain: Optional[List[Dict[str, Any]]] = None,
        causal_triad: Optional[Union[Dict[str, Any], CausalTriad]] = None,
        causal_evidence: Optional[CausalEvidence] = None,
        negative_evidence: Optional[Union[Dict[str, Any], NegativeEvidence]] = None,
        negative_observables: Optional[Dict[str, Any]] = None,
        execution_evidence: Optional[ExecutionEvidence] = None,
        provenance_trace: Optional[Any] = None,
        proof_payload: Optional[Union[Dict[str, Any], ProofPayload]] = None,
        allow_declared_proof: bool = False,
    ) -> CourtJudgment:
        finder_claim = finder_claim or {}
        try:
            proof_payload_obj = ProofPayload.from_mapping(proof_payload)
            if execution_evidence is not None:
                execution_result = execution_evidence.to_dict()
                verifier_result = {**execution_result, **(verifier_result or {})}
            if provenance_trace is not None and provenance_chain is None:
                trace_data = provenance_trace.to_dict() if hasattr(provenance_trace, "to_dict") else provenance_trace
                provenance_chain = trace_data.get("steps", []) if isinstance(trace_data, dict) else []
            judgment = CourtJudgment(
                target_url=target_url,
                parameter=parameter,
                vuln_class=vuln_class,
                finder_claim=finder_claim,
                verifier_result=verifier_result or {},
                provenance_chain=provenance_chain or [],
            )

            # 1. Inviolable Scope Check
            if not is_in_scope:
                judgment.verdict = CourtVerdict.OUT_OF_SCOPE
                judgment.calibrated_severity = "Info"
                judgment.confidence_score = 0.0
                judgment.reportable = False
                judgment.epistemic_state = "BLOCKED"
                judgment.adjudication_rationale = "Target URL is outside authorized scope. Strictly discarded by Scope Firewall."
                judgment.negative_evidence.append("Out of scope target.")
                return judgment

            # 2. WAF Interception Check
            if is_blocked_by_waf or finder_claim.get("waf_blocked") or (verifier_result and verifier_result.get("waf_blocked")):
                judgment.verdict = CourtVerdict.BLOCKED
                judgment.calibrated_severity = "Info"
                judgment.confidence_score = 0.1
                judgment.reportable = False
                judgment.epistemic_state = "BLOCKED"
                judgment.adjudication_rationale = "Probe was intercepted or blocked by Cloudflare/WAF. Does not prove application vulnerability."
                judgment.negative_evidence.append("WAF challenge or block response detected.")
                return judgment

            # 2.5 Verifier Runtime Error / Unavailable Tool or Timeout Check
            failure = _classify_verifier_failure(finder_claim, verifier_result)
            if failure is not None:
                fail_verdict, fail_reason = failure
                judgment.verdict = fail_verdict
                judgment.calibrated_severity = "Info"
                judgment.confidence_score = 0.0
                judgment.reportable = False
                judgment.epistemic_state = fail_verdict.value
                judgment.adjudication_rationale = fail_reason
                judgment.negative_evidence.append(fail_reason)
                return judgment

            # 3. Negative Evidence Evaluation (Scoped Boundary Enforcement)
            observed_status = (verifier_result or {}).get("status_code") or (verifier_result or {}).get("status")
            observed_body = str((verifier_result or {}).get("response_body") or "").lower()

            neg_specs = negative_observables or (verifier_result or {}).get("negative_observables")
            if neg_specs and isinstance(neg_specs, dict):
                neg_statuses = neg_specs.get("status_codes", [])
                neg_patterns = neg_specs.get("response_patterns", [])

                if observed_status in neg_statuses:
                    judgment.verdict = CourtVerdict.DISPROVED
                    judgment.calibrated_severity = "Info"
                    judgment.confidence_score = 0.0
                    judgment.reportable = False
                    judgment.epistemic_state = "REJECTED"
                    judgment.adjudication_rationale = (
                        f"Negative observable triggered: Status code {observed_status} confirms "
                        "BOUNDARY_ENFORCED_FOR_TESTED_CONTEXT. (Unexplored transitions remain UNKNOWN)."
                    )
                    judgment.negative_evidence.append(f"HTTP Status {observed_status} (Tested defense boundary)")
                    return judgment

                for pat in neg_patterns:
                    if pat.lower() in observed_body:
                        judgment.verdict = CourtVerdict.DISPROVED
                        judgment.calibrated_severity = "Info"
                        judgment.confidence_score = 0.0
                        judgment.reportable = False
                        judgment.epistemic_state = "REJECTED"
                        judgment.adjudication_rationale = (
                            f"Negative observable triggered: Pattern '{pat}' found. "
                            "BOUNDARY_ENFORCED_FOR_TESTED_CONTEXT."
                        )
                        judgment.negative_evidence.append(f"Defense pattern: '{pat}'")
                        return judgment

            # 4. Contradictory Evidence Evaluation (CRITICAL EPISTEMIC GATE)
            is_contradictory = (
                (causal_evidence and causal_evidence.contradiction_detected)
                or (verifier_result and verifier_result.get("contradiction_detected"))
                or (verifier_result and verifier_result.get("metamorphic_inconsistent"))
            )

            if is_contradictory:
                judgment.verdict = CourtVerdict.UNVERIFIED
                judgment.calibrated_severity = "Low"
                judgment.confidence_score = 0.40
                judgment.reportable = False
                judgment.contradiction_detected = True
                judgment.epistemic_state = "PARTIALLY_VERIFIED"
                judgment.adjudication_rationale = (
                    "Metamorphic Contradiction: Probe E1 and metamorphic probe E2 produced conflicting results. "
                    "Causal invariant refuted or unconfirmed. State held at PARTIALLY_VERIFIED."
                )
                judgment.negative_evidence.append("Contradictory probe observations detected.")
                return judgment

            # 5. Independent Verification & Reflection Filter
            if not verifier_result or not verifier_result.get("reproduced"):
                if finder_claim.get("is_reflection") or (verifier_result and verifier_result.get("is_reflection")):
                    judgment.verdict = CourtVerdict.FALSE_POSITIVE
                    judgment.calibrated_severity = "Info"
                    judgment.confidence_score = 0.05
                    judgment.reportable = False
                    judgment.epistemic_state = "REJECTED"
                    judgment.adjudication_rationale = "Reflection detected without execution proof (Reflection != Execution)."
                    judgment.negative_evidence.append("Input echoed literally in DOM or script tag.")
                    return judgment

                if not verifier_result:
                    judgment.verdict = CourtVerdict.INCONCLUSIVE
                    judgment.calibrated_severity = "Low"
                    judgment.confidence_score = 0.35
                    judgment.reportable = False
                    judgment.epistemic_state = "UNKNOWN"
                    judgment.adjudication_rationale = "No independent verifier result was supplied. Inconclusive."
                    return judgment

                if str(verifier_result.get("status", "")).upper() == "CANDIDATE":
                    judgment.verdict = CourtVerdict.CANDIDATE
                    judgment.calibrated_severity = "Low"
                    judgment.confidence_score = 0.30
                    judgment.reportable = False
                    judgment.epistemic_state = "CANDIDATE"
                    judgment.adjudication_rationale = "Candidate signal observed; independent deterministic proof not yet established."
                    return judgment

                judgment.verdict = CourtVerdict.UNVERIFIED
                judgment.calibrated_severity = "Low"
                judgment.confidence_score = 0.40
                judgment.reportable = False
                judgment.epistemic_state = "TESTED"
                judgment.adjudication_rationale = "Initial signal detected, but independent verifier could not reproduce effect."
                judgment.negative_evidence.append("Independent re-check failed to reproduce.")
                return judgment

            # 6. Axiom Enforcement: Response Length Delta or Status Alone != Vulnerability
            length_delta_only = verifier_result.get("length_delta_only", False)
            status_change_only = verifier_result.get("status_change_only", False)

            if length_delta_only or status_change_only:
                judgment.verdict = CourtVerdict.FALSE_POSITIVE
                judgment.calibrated_severity = "Info"
                judgment.confidence_score = 0.10
                judgment.reportable = False
                judgment.epistemic_state = "REJECTED"
                judgment.adjudication_rationale = (
                    "Causality Gate Violation: Response length delta or HTTP status code change alone "
                    "does NOT prove vulnerability. Proof of Execution (PoE) != Proof of Vulnerability (PoV)."
                )
                judgment.negative_evidence.append("Length divergence or status change without semantic execution proof.")
                return judgment

            # Evaluate legacy Causal Triad if provided
            if causal_triad:
                triad_obj = causal_triad if isinstance(causal_triad, CausalTriad) else CausalTriad(**causal_triad)
                is_causal, reason = triad_obj.evaluate_causality()
                judgment.causal_triad_evaluated = True
                judgment.causality_rationale = reason

                if not is_causal:
                    judgment.verdict = CourtVerdict.FALSE_POSITIVE
                    judgment.calibrated_severity = "Info"
                    judgment.confidence_score = 0.10
                    judgment.reportable = False
                    judgment.epistemic_state = "REJECTED"
                    judgment.adjudication_rationale = f"Causality Gate Violation: {reason}"
                    judgment.negative_evidence.append(reason)
                    return judgment

            # 7. Deterministic Proof Gate — DERIVED, not declared.
            strength, proof_kind, proof_detail = _ProofResolver.resolve(
                verifier_result=verifier_result,
                causal_evidence=causal_evidence,
                proof_payload=proof_payload_obj,
                vuln_class=vuln_class,
            )
            judgment.proof_strength = strength.value
            judgment.proof_kind = proof_kind
            judgment.proof_detail = proof_detail

            if strength is ProofStrength.REFUTED:
                judgment.verdict = CourtVerdict.FALSE_POSITIVE
                judgment.calibrated_severity = "Info"
                judgment.confidence_score = 0.05
                judgment.reportable = False
                judgment.epistemic_state = "REJECTED"
                judgment.adjudication_rationale = (
                    f"Deterministic proof REFUTED by re-evaluating the supplied evidence: {proof_detail}"
                )
                judgment.negative_evidence.append(proof_detail)
                return judgment

            has_deterministic_proof = strength is ProofStrength.DERIVED

            if strength is ProofStrength.DECLARED:
                if not allow_declared_proof:
                    judgment.verdict = CourtVerdict.UNVERIFIED
                    judgment.calibrated_severity = "Low"
                    judgment.confidence_score = 0.40
                    judgment.reportable = False
                    judgment.epistemic_state = "TESTED"
                    judgment.adjudication_rationale = (
                        f"Proof was asserted but not verifiable: {proof_detail} "
                        "Supply a ProofPayload with the observed response so the engine can re-evaluate it."
                    )
                    judgment.negative_evidence.append("Unverifiable declared proof.")
                    return judgment
                has_deterministic_proof = True

            if has_deterministic_proof:
                judgment.verdict = CourtVerdict.CONFIRMED
                judgment.reportable = True
                judgment.epistemic_state = (
                    "CONFIRMED" if strength is ProofStrength.DERIVED
                    else "CONFIRMED_ON_DECLARED_PROOF"
                )
                judgment.confidence_score = float(
                    (causal_evidence.causal_strength if causal_evidence else 0)
                    or verifier_result.get("confidence", 0.98)
                )
                judgment.adjudication_rationale = (
                    f"Confirmed by {strength.value} proof ({proof_kind}): {proof_detail}"
                )

                v_lower = vuln_class.lower()
                if any(k in v_lower for k in ("rce", "cmd_injection", "command_injection", "cmdi")):
                    judgment.calibrated_severity = "Critical"
                elif any(k in v_lower for k in ("sqli", "sql_injection")):
                    judgment.calibrated_severity = "Critical"
                elif any(k in v_lower for k in ("idor", "bola", "ssrf", "xxe", "isolation_breach", "lfi", "ssti", "deser", "jwt")):
                    judgment.calibrated_severity = "High"
                elif any(k in v_lower for k in ("privilege_escalation", "auth_bypass", "double_execution", "race", "secret")):
                    judgment.calibrated_severity = "High"
                elif "xss" in v_lower:
                    judgment.calibrated_severity = "Medium"
                else:
                    judgment.calibrated_severity = "Medium"

                if not judgment.provenance_chain:
                    try:
                        from core.burp_gateway.provenance import EvidenceProvenanceEngine
                        judgment.provenance_chain = EvidenceProvenanceEngine.synthesize_standard_provenance(
                            target_url=target_url,
                            vuln_class=vuln_class,
                            finder_claim=finder_claim,
                            verifier_result=verifier_result,
                        )
                    except Exception:
                        pass

                return judgment

            if proof_kind == "differential_unproven":
                judgment.verdict = CourtVerdict.CANDIDATE
                judgment.calibrated_severity = "Low"
                judgment.confidence_score = 0.35
                judgment.reportable = False
                judgment.epistemic_state = "CANDIDATE"
                judgment.adjudication_rationale = (
                    f"Differential response observed without deterministic proof ({proof_detail}). "
                    "Held at CANDIDATE until a typed ProofContract or causal invariant is satisfied."
                )
                return judgment

            judgment.verdict = CourtVerdict.UNVERIFIED
            judgment.calibrated_severity = "Medium"
            judgment.confidence_score = 0.50
            judgment.reportable = False
            judgment.epistemic_state = "TESTED"
            judgment.adjudication_rationale = (
                "Verifier observed differential change, but no deterministic proof was established. "
                f"Proof strength: {strength.value}."
            )
            return judgment
        except Exception as exc:
            logger.exception("[EvidenceCourt] Adjudication runtime error for %s: %s", target_url, exc)
            return CourtJudgment(
                target_url=target_url,
                parameter=parameter,
                vuln_class=vuln_class,
                verdict=CourtVerdict.ERROR,
                calibrated_severity="Info",
                confidence_score=0.0,
                reportable=False,
                finder_claim=finder_claim,
                verifier_result=verifier_result if isinstance(verifier_result, dict) else {},
                adjudication_rationale=f"Adjudication runtime error: {exc}",
                negative_evidence=[f"Runtime exception: {exc}"],
                epistemic_state="ERROR",
                proof_strength=ProofStrength.NONE.value,
            )


__all__ = [
    "CANONICAL_COURT_VERDICTS",
    "CANONICAL_PROOF_CATEGORIES",
    "PROOF_CONTRACT_REGISTRY",
    "CausalEvidence",
    "CausalTriad",
    "CourtJudgment",
    "CourtVerdict",
    "EvidenceCourt",
    "ExecutionEvidence",
    "NegativeEvidence",
    "ProofContract",
    "ProofContractRegistry",
    "ProofPayload",
    "ProofStrength",
    "canonical_verdict",
    "normalize_vuln_category",
]
