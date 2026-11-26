"""
HunterAI V27.0 - Extensible Causal Invariants Framework
========================================================
Decouples causal verification from hardcoded payloads or specific test cases.
Provides formal abstractions modeling:
  - input_relation: The semantic input mutation across B, C, E1, E2
  - expected_output_relation: Formal predicted transformation on target state
  - control_constraint: Conditions that harmless control C must satisfy
  - reproducibility_requirement: Number and consistency of metamorphic probe confirmations
  - invalidation_conditions: Exact conditions that conclusively refute the hypothesis

Adapters:
  - CommandExecutionInvariant
  - BooleanDifferentialInvariant
  - AuthorizationInvariant
  - OOBCorrelationInvariant
  - DOMExecutionInvariant
  - StateTransitionInvariant
"""
from __future__ import annotations

import abc
import logging
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from core.reasoning.triad_verifier import TransactionSnapshot, TriadBundle

logger = logging.getLogger("hunter_ai.causal_invariants")

# Volatile content patterns stripped before structural boolean comparison
_VOLATILE_PATTERNS: Tuple[re.Pattern[str], ...] = (
    re.compile(r"<!--.*?-->", re.S),                                        # HTML jitter comments
    re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I),  # UUIDs
    re.compile(r"\b(?:nonce|csrf|token|req|trace|request)[_-]?[0-9a-f]{4,}\b", re.I),
    re.compile(r'name=["\']csrf[-_]?token["\']\s+content=["\'][^"\']+["\']', re.I),
    re.compile(r"\b\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\b"),  # ISO/SQL timestamps
    re.compile(r"\b1[5-9]\d{8}(?:\.\d+)?\b"),                               # Unix epoch seconds
)


def _token_boundary_in(token: str, text: str) -> bool:
    """Return True iff `token` appears in `text` at non-alphanumeric boundaries."""
    if not token or not text:
        return False
    return bool(re.search(rf"(?<![A-Za-z0-9_]){re.escape(token)}(?![A-Za-z0-9_])", text))


def normalize_volatile_content(text: str) -> str:
    """Strip nonces, timestamps, UUIDs, and HTML comments to compare stable structure."""
    if not text:
        return ""
    cleaned = text
    for pat in _VOLATILE_PATTERNS:
        cleaned = pat.sub(" ", cleaned)
    return re.sub(r"\s+", " ", cleaned).strip()


def _structural_tokens(text: str) -> Set[str]:
    """Extract normalized structural + semantic tokens after stripping volatile noise."""
    norm = normalize_volatile_content(text)
    if not norm:
        return set()
    tags = re.findall(r"</?[a-zA-Z][a-zA-Z0-9]*", norm)
    words = re.findall(r"[A-Za-z0-9_]{2,}", re.sub(r"<[^>]+>", " ", norm))
    return {t.lower() for t in tags} | {w.lower() for w in words}


def _jaccard_similarity(a: Set[str], b: Set[str]) -> float:
    if not a and not b:
        return 1.0
    union = a | b
    if not union:
        return 1.0
    return len(a & b) / len(union)


@dataclass
class InvariantEvaluationResult:
    passed: bool
    confidence: float
    reason: str
    extracted_observables: Dict[str, Any] = field(default_factory=dict)
    invalidation_triggered: bool = False
    invalidation_detail: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class CausalInvariant(abc.ABC):
    """Abstract Base Class for formal causal security invariants."""

    def __init__(
        self,
        invariant_id: str,
        name: str,
        description: str,
        input_relation: Optional[Dict[str, Any]] = None,
        expected_output_relation: Optional[Dict[str, Any]] = None,
        control_constraint: Optional[Dict[str, Any]] = None,
        reproducibility_requirement: Optional[Dict[str, Any]] = None,
        invalidation_conditions: Optional[List[str]] = None,
    ):
        self.invariant_id = invariant_id
        self.name = name
        self.description = description
        self.input_relation = input_relation or {}
        self.expected_output_relation = expected_output_relation or {}
        self.control_constraint = control_constraint or {}
        self.reproducibility_requirement = reproducibility_requirement or {"min_metamorphic_reproductions": 1}
        self.invalidation_conditions = invalidation_conditions or []

    @abc.abstractmethod
    def evaluate(self, bundle: TriadBundle) -> InvariantEvaluationResult:
        """Evaluates whether the observed TriadBundle satisfies the formal invariant."""
        pass


class CommandExecutionInvariant(CausalInvariant):
    """
    Evaluates arbitrary command execution / SSTI / arithmetic evaluation.
    Distinguishes algebraic evaluation from literal string reflection, checking
    BOTH Baseline (B) and Control (C) using strict word/token boundaries.
    """

    def __init__(
        self,
        expected_token: str = "72",
        e1_expr: str = "53+19",
        e2_expr: str = "41+31",
        control_expr: str = "53+0",
    ):
        super().__init__(
            invariant_id="INV-CMD-EXEC-01",
            name="Command & Code Execution Invariant",
            description="Evaluates algebraic side-effect vs literal reflection across metamorphic probes.",
            input_relation={"e1": e1_expr, "e2": e2_expr, "control": control_expr},
            expected_output_relation={"evaluated_token": expected_token},
            control_constraint={"must_not_contain": expected_token},
            invalidation_conditions=[
                "literal_reflection_without_evaluation",
                "baseline_contains_token",
                "control_produces_token",
            ],
        )
        self.expected_token = expected_token
        self.e1_expr = e1_expr
        self.e2_expr = e2_expr
        self.control_expr = control_expr

    def evaluate(self, bundle: TriadBundle) -> InvariantEvaluationResult:
        b = bundle.baseline
        c = bundle.control
        e1 = bundle.experiment_1
        e2 = bundle.experiment_2

        # 1a. Check Baseline (B) constraint using strict token boundaries
        if _token_boundary_in(self.expected_token, b.body) or self.expected_token in b.extracted_tokens:
            return InvariantEvaluationResult(
                passed=False,
                confidence=0.0,
                reason="Baseline response B already contained the target token; token is not causally induced.",
                invalidation_triggered=True,
                invalidation_detail="baseline_contains_token",
            )

        # 1b. Check Control (C) constraint using strict token boundaries
        if _token_boundary_in(self.expected_token, c.body) or self.expected_token in c.extracted_tokens:
            return InvariantEvaluationResult(
                passed=False,
                confidence=0.0,
                reason="Control mutation C unexpectedly contained the target token; token is not causal.",
                invalidation_triggered=True,
                invalidation_detail="control_produces_token",
            )

        # 2. Check for Literal Reflection without Execution
        escaped_expr = re.escape(self.e1_expr)
        reflection_detected = (
            self.e1_expr in e1.body
            or f"$({self.e1_expr})" in e1.body
            or f"$(({self.e1_expr}))" in e1.body
            or f"`{self.e1_expr}`" in e1.body
            or bool(re.search(r'["\']' + escaped_expr + r'["\']', e1.body))
        )
        e1_has_token = _token_boundary_in(self.expected_token, e1.body) or (
            self.expected_token in e1.extracted_tokens
        )
        e2_has_token = _token_boundary_in(self.expected_token, e2.body) or (
            self.expected_token in e2.extracted_tokens
        )

        if reflection_detected and not e1_has_token:
            return InvariantEvaluationResult(
                passed=False,
                confidence=0.05,
                reason=f"Literal reflection detected: '{self.e1_expr}' echoed without evaluation.",
                invalidation_triggered=True,
                invalidation_detail="literal_reflection_without_evaluation",
            )

        # 3. Metamorphic Verification across E1 and E2
        if e1_has_token and e2_has_token:
            return InvariantEvaluationResult(
                passed=True,
                confidence=0.99,
                reason=f"Metamorphic Command Execution Invariant satisfied: Both E1 and E2 evaluated to '{self.expected_token}'.",
                extracted_observables={"token": self.expected_token, "e1_verified": True, "e2_verified": True},
            )
        elif e1_has_token and not e2_has_token:
            return InvariantEvaluationResult(
                passed=False,
                confidence=0.40,
                reason="Metamorphic inconsistency: E1 produced token but equivalent probe E2 did not.",
                invalidation_triggered=False,
                invalidation_detail="metamorphic_divergence",
            )
        else:
            return InvariantEvaluationResult(
                passed=False,
                confidence=0.10,
                reason=f"Execution token '{self.expected_token}' absent from probe responses.",
            )


class BooleanDifferentialInvariant(CausalInvariant):
    """
    Evaluates Boolean-based injection (SQLi / LDAP / XPath).
    Strips volatile nonces/timestamps/jitter comments and verifies structural &
    semantic token bifurcation between True (E1, E2) and False (C) predicates.
    """

    def __init__(self, match_threshold: float = 0.85, diverge_threshold: float = 0.75):
        super().__init__(
            invariant_id="INV-BOOLEAN-DIFF-01",
            name="Boolean Differential Invariant",
            description="True condition branches must structurally match baseline after volatile stripping, while False condition diverges.",
            invalidation_conditions=["false_condition_matches_true_condition", "volatile_jitter_only"],
        )
        self.match_threshold = match_threshold
        self.diverge_threshold = diverge_threshold

    def evaluate(self, bundle: TriadBundle) -> InvariantEvaluationResult:
        b = bundle.baseline
        c = bundle.control         # Injected False condition (e.g. ' AND 1=2)
        e1 = bundle.experiment_1   # Injected True condition 1 (e.g. ' AND 1=1)
        e2 = bundle.experiment_2   # Injected True condition 2 (e.g. ' AND 2=2)

        norm_b = normalize_volatile_content(b.body)
        norm_c = normalize_volatile_content(c.body)
        norm_e1 = normalize_volatile_content(e1.body)
        norm_e2 = normalize_volatile_content(e2.body)

        tok_b = _structural_tokens(b.body)
        tok_c = _structural_tokens(c.body)
        tok_e1 = _structural_tokens(e1.body)
        tok_e2 = _structural_tokens(e2.body)

        sim_e1_b = _jaccard_similarity(tok_e1, tok_b)
        sim_e2_b = _jaccard_similarity(tok_e2, tok_b)
        sim_c_b = _jaccard_similarity(tok_c, tok_b)
        sim_c_e1 = _jaccard_similarity(tok_c, tok_e1)

        e1_matches_b = (e1.status_code == b.status_code) and (norm_e1 == norm_b or sim_e1_b >= self.match_threshold)
        e2_matches_b = (e2.status_code == b.status_code) and (norm_e2 == norm_b or sim_e2_b >= self.match_threshold)

        # False condition (C) must diverge structurally/semantically after stripping volatile nonces/timestamps
        c_status_diverges = c.status_code != b.status_code
        c_structure_diverges = (
            norm_c != norm_b
            and sim_c_b < self.diverge_threshold
            and sim_c_e1 < self.diverge_threshold
        )
        c_diverges = c_status_diverges or c_structure_diverges

        observables = {
            "sim_e1_b": round(sim_e1_b, 3),
            "sim_e2_b": round(sim_e2_b, 3),
            "sim_c_b": round(sim_c_b, 3),
            "sim_c_e1": round(sim_c_e1, 3),
            "boolean_split_confirmed": bool(e1_matches_b and e2_matches_b and c_diverges),
        }

        if e1_matches_b and e2_matches_b and c_diverges:
            return InvariantEvaluationResult(
                passed=True,
                confidence=0.98,
                reason=(
                    "Boolean Differential Invariant satisfied: True branches preserve normalized "
                    f"Baseline structure (sim={sim_e1_b:.2f}/{sim_e2_b:.2f}) while False branch "
                    f"diverges structurally (sim={sim_c_b:.2f}, status={c.status_code})."
                ),
                extracted_observables=observables,
            )

        if not c_status_diverges and norm_c == norm_b:
            return InvariantEvaluationResult(
                passed=False,
                confidence=0.05,
                reason="False probe C matched Baseline B after stripping volatile nonces/timestamps (volatile jitter only).",
                extracted_observables=observables,
                invalidation_triggered=True,
                invalidation_detail="volatile_jitter_only",
            )

        return InvariantEvaluationResult(
            passed=False,
            confidence=0.20,
            reason=(
                "Boolean differential failed: Normalized structure did not bifurcate consistently "
                f"(sim_e1_b={sim_e1_b:.2f}, sim_e2_b={sim_e2_b:.2f}, sim_c_b={sim_c_b:.2f})."
            ),
            extracted_observables=observables,
        )


class AuthorizationInvariant(CausalInvariant):
    """
    Evaluates multi-tenant access control and BOLA/IDOR boundaries.
    """

    def __init__(self, resource_id: str, owner_id: str, actor_id: str):
        super().__init__(
            invariant_id=f"INV-AUTHZ-{actor_id}-ON-{resource_id}",
            name="Authorization Boundary Invariant",
            description="Ensures cross-tenant / unprivileged actors cannot read foreign resources.",
            input_relation={"actor": actor_id, "owner": owner_id, "resource": resource_id},
            expected_output_relation={"enforced_status": [401, 403, 404]},
            invalidation_conditions=["foreign_resource_body_exposed", "status_200_with_owner_data"],
        )
        self.resource_id = resource_id
        self.owner_id = owner_id
        self.actor_id = actor_id

    def evaluate(self, bundle: TriadBundle) -> InvariantEvaluationResult:
        e1 = bundle.experiment_1
        e2 = bundle.experiment_2

        e1_denied = e1.status_code in (401, 403) or "unauthorized" in e1.body.lower() or "forbidden" in e1.body.lower()
        e2_denied = e2.status_code in (401, 403) or "unauthorized" in e2.body.lower() or "forbidden" in e2.body.lower()

        if e1_denied and e2_denied:
            return InvariantEvaluationResult(
                passed=True,
                confidence=0.95,
                reason=f"Authorization Invariant enforced: Actor '{self.actor_id}' received 403/401 accessing '{self.resource_id}'.",
                extracted_observables={"boundary_enforced": True, "tested_status": e1.status_code},
            )

        e1_breach = (e1.status_code == 200) and (self.owner_id in e1.body or self.resource_id in e1.body)
        e2_breach = (e2.status_code == 200) and (self.owner_id in e2.body or self.resource_id in e2.body)

        if e1_breach and e2_breach:
            return InvariantEvaluationResult(
                passed=False,
                confidence=0.98,
                reason=f"CRITICAL: Authorization Boundary Breached! Actor '{self.actor_id}' read '{self.resource_id}' owned by '{self.owner_id}'.",
                invalidation_triggered=True,
                invalidation_detail="foreign_resource_body_exposed",
                extracted_observables={"access_control_violation": True},
            )

        return InvariantEvaluationResult(
            passed=False,
            confidence=0.45,
            reason="Inconclusive authorization state: Neither strict denial nor full resource disclosure observed.",
        )


class OOBCorrelationInvariant(CausalInvariant):
    """Evaluates Out-of-Band (OOB) DNS/HTTP callback interactions with unique nonces."""

    def __init__(self, expected_nonce: str):
        super().__init__(
            invariant_id="INV-OOB-CORRELATION-01",
            name="Out-of-Band Callback Invariant",
            description="Validates that external interactions match the unique transaction nonce.",
        )
        self.expected_nonce = expected_nonce

    def evaluate(self, bundle: TriadBundle) -> InvariantEvaluationResult:
        callbacks = bundle.metadata.get("oob_callbacks", [])
        matched = any(self.expected_nonce in str(cb) for cb in callbacks)
        if matched:
            return InvariantEvaluationResult(
                passed=True,
                confidence=0.99,
                reason=f"OOB Callback confirmed with matching nonce '{self.expected_nonce}'.",
                extracted_observables={"oob_nonce_matched": True},
            )
        return InvariantEvaluationResult(
            passed=False,
            confidence=0.10,
            reason=f"No external callback received matching nonce '{self.expected_nonce}'.",
        )


class DOMExecutionInvariant(CausalInvariant):
    """
    Evaluates ACTUAL browser/DOM script execution telemetry.
    Inert regex reflection inside raw HTML (<div data-x="canary">) NEVER passes.
    """

    def __init__(self, canary: str):
        super().__init__(
            invariant_id="INV-DOM-EXECUTION-01",
            name="DOM Script Execution Invariant",
            description="Requires verified runtime DOM/JS execution telemetry (never raw HTML regex match).",
            invalidation_conditions=["inert_html_reflection_only", "baseline_contains_canary", "control_triggers_execution"],
        )
        self.canary = canary

    def evaluate(self, bundle: TriadBundle) -> InvariantEvaluationResult:
        b = bundle.baseline
        c = bundle.control
        e1 = bundle.experiment_1
        e2 = bundle.experiment_2
        meta = bundle.metadata or {}

        # Baseline / control must not trigger the canary
        if meta.get("control_dom_executed") or (self.canary and self.canary in c.extracted_tokens):
            return InvariantEvaluationResult(
                passed=False,
                confidence=0.0,
                reason="Control probe triggered DOM execution signal; not causally attributable to exploit payload.",
                invalidation_triggered=True,
                invalidation_detail="control_triggers_execution",
            )
        if self.canary and self.canary in b.extracted_tokens:
            return InvariantEvaluationResult(
                passed=False,
                confidence=0.0,
                reason="Baseline already emitted DOM canary token.",
                invalidation_triggered=True,
                invalidation_detail="baseline_contains_canary",
            )

        # Require explicit runtime DOM execution evidence (dialog, console canary, JS hook/sink execution)
        runtime_events = meta.get("dom_execution_events") or meta.get("console_logs") or meta.get("dialogs") or []
        runtime_fired = bool(
            meta.get("dom_execution_observed")
            or meta.get("dom_executed")
            or meta.get("dialog_triggered")
            or meta.get("console_canary_fired")
            or meta.get("js_sink_executed")
            or any(self.canary in str(ev) for ev in runtime_events)
        )
        canary_observed_at_runtime = (
            not self.canary
            or any(self.canary in str(ev) for ev in runtime_events)
            or self.canary in e1.extracted_tokens
            or str(meta.get("executed_canary") or "") == self.canary
        )

        if runtime_fired and canary_observed_at_runtime:
            # Check metamorphic consistency if E2 runtime execution was explicitly reported False
            if meta.get("dom_execution_e2_observed") is False:
                return InvariantEvaluationResult(
                    passed=False,
                    confidence=0.35,
                    reason="Metamorphic DOM inconsistency: E1 executed in browser DOM but E2 did not.",
                    invalidation_triggered=False,
                    invalidation_detail="metamorphic_divergence",
                )
            return InvariantEvaluationResult(
                passed=True,
                confidence=0.98,
                reason=f"DOM Execution Invariant satisfied: Runtime JS execution observed for canary '{self.canary}'.",
                extracted_observables={"dom_execution_confirmed": True, "canary": self.canary},
            )

        # Inert raw HTML reflection without browser execution telemetry MUST fail
        if self.canary and self.canary in e1.body:
            return InvariantEvaluationResult(
                passed=False,
                confidence=0.10,
                reason=(
                    f"Inert HTML reflection of '{self.canary}' observed in raw response without "
                    "runtime DOM execution evidence (Reflection != DOM Execution)."
                ),
                invalidation_triggered=True,
                invalidation_detail="inert_html_reflection_only",
            )

        return InvariantEvaluationResult(
            passed=False,
            confidence=0.10,
            reason="No runtime DOM execution evidence observed.",
        )


class StateTransitionInvariant(CausalInvariant):
    """Evaluates business logic workflow transitions and sequence integrity."""

    def __init__(self, prerequisite_step: str, target_step: str):
        super().__init__(
            invariant_id=f"INV-SEQ-{prerequisite_step}-TO-{target_step}",
            name="Workflow Sequence Invariant",
            description="Ensures target state cannot be reached without executing prerequisite.",
        )
        self.prerequisite_step = prerequisite_step
        self.target_step = target_step

    def evaluate(self, bundle: TriadBundle) -> InvariantEvaluationResult:
        e1 = bundle.experiment_1
        if e1.status_code in (400, 409, 412, 422):
            return InvariantEvaluationResult(
                passed=True,
                confidence=0.95,
                reason=f"Workflow Sequence Invariant enforced: Target rejected skipping prerequisite '{self.prerequisite_step}'.",
                extracted_observables={"sequence_enforced": True},
            )
        elif e1.status_code in (200, 201):
            return InvariantEvaluationResult(
                passed=False,
                confidence=0.92,
                reason=f"Sequence Invariant Breached: '{self.target_step}' accepted without '{self.prerequisite_step}'.",
                invalidation_triggered=True,
                invalidation_detail="sequence_violation_permitted",
            )
        return InvariantEvaluationResult(
            passed=False,
            confidence=0.40,
            reason="Inconclusive workflow response status.",
        )


class CausalInvariantRegistry:
    """Registry allowing dynamic lookup and registration of causal invariants."""

    _invariants: Dict[str, CausalInvariant] = {}

    @classmethod
    def register(cls, invariant: CausalInvariant) -> None:
        cls._invariants[invariant.invariant_id] = invariant

    @classmethod
    def get(cls, invariant_id: str) -> Optional[CausalInvariant]:
        return cls._invariants.get(invariant_id)

    @classmethod
    def list_invariants(cls) -> List[Dict[str, Any]]:
        return [
            {"id": inv.invariant_id, "name": inv.name, "description": inv.description}
            for inv in cls._invariants.values()
        ]

    @classmethod
    def register_defaults(cls) -> None:
        """Register all built-in causal invariants by default."""
        defaults: List[CausalInvariant] = [
            CommandExecutionInvariant(),
            BooleanDifferentialInvariant(),
            AuthorizationInvariant(resource_id="default", owner_id="owner", actor_id="actor"),
            OOBCorrelationInvariant(expected_nonce="default"),
            DOMExecutionInvariant(canary="default"),
            StateTransitionInvariant(prerequisite_step="prerequisite", target_step="target"),
        ]
        for inv in defaults:
            cls._invariants.setdefault(inv.invariant_id, inv)


# Ensure built-in causal invariants are registered by default at import time
CausalInvariantRegistry.register_defaults()
