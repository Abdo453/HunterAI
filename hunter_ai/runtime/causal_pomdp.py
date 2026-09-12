"""
HunterAI Causal POMDP & Advanced Cognitive Logic Engine
======================================================
Implements deep cognitive reasoning algorithms for autonomous security research:
1. POMDPBeliefDistribution: Probabilistic belief tracking over unobserved system
   states with Shannon entropy, Bayesian updates, and Expected Information Gain (EIG).
2. CausalInterventionEngine: Pearl's do-calculus counterfactual reasoning, isolating
   minimal causal explanatory sets (MCES) across requests/variables.
3. ApiGrammarInductionEngine: Automatic induction of structured API resource grammars,
   variable types, and parameter semantic categories.
4. TemporalLogicVerifier: Linear Temporal Logic (LTL) trace auditor checking safety,
   precedence, and liveness properties across multi-step execution traces.
5. DeltaDebuggingMinimizer: Zeller's Delta Debugging (ddmin) algorithm minimizing
   complex N-step attack/anomaly traces down to 1-minimal prerequisite steps.
6. SecurityModelChecker: Reachability graph verification discovering violating
   state transitions.
7. CognitiveDiversityCouncil: Multi-agent consensus council (Explorer, Skeptic,
   CausalAnalyst, TemporalAnalyst, Judge) weighting evidence entropy.
8. SelfEvolvingStrategyGenome: Genetic hyperparameter representation of research
   strategies with mutation and crossover operations.
"""
from __future__ import annotations

import math
import re
import uuid
import random
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple


# ─────────────────────────────────────────────────────────────────────────────
# 1. POMDP Belief Distribution Engine
# ─────────────────────────────────────────────────────────────────────────────

class POMDPBeliefDistribution:
    """
    Partially Observable Markov Decision Process (POMDP) Belief Distribution.
    Maintains probability distributions over mutually exclusive system security states.
    Computes Shannon entropy and evaluates Expected Information Gain (EIG) for probe actions.
    """

    def __init__(self, beliefs: Optional[Dict[str, float]] = None):
        if beliefs is None:
            self.beliefs: Dict[str, float] = {}
        else:
            self.beliefs = dict(beliefs)
            self._normalize()

    def _normalize(self) -> None:
        total = sum(self.beliefs.values())
        if total <= 0:
            count = len(self.beliefs)
            if count > 0:
                self.beliefs = {k: 1.0 / count for k in self.beliefs}
            return
        self.beliefs = {k: v / total for k, v in self.beliefs.items()}

    def entropy(self) -> float:
        """
        Shannon entropy in bits: H(b) = -sum(p * log2(p)).
        Maximized when all states are equiprobable (maximum uncertainty).
        Zero when one state has probability 1.0 (complete certainty).
        """
        h = 0.0
        for p in self.beliefs.values():
            if p > 1e-12:
                h -= p * math.log2(p)
        return round(h, 4)

    def update(
        self,
        observation: str,
        observation_likelihoods: Dict[str, Dict[str, float]]
    ) -> "POMDPBeliefDistribution":
        """
        Bayesian observation update:
        P(s | o) = P(o | s) * P(s) / sum_s'(P(o | s') * P(s'))
        
        Args:
            observation: Observed test outcome (e.g. 'STATUS_403', 'TENANT_DATA_RETURNED')
            observation_likelihoods: Dict of {state: {observation: P(o | state)}}
        """
        posterior: Dict[str, float] = {}
        for state, prior in self.beliefs.items():
            likelihoods = observation_likelihoods.get(state, {})
            # Default likelihood for unseen observation is small epsilon
            p_obs_given_state = likelihoods.get(observation, 0.05)
            posterior[state] = prior * p_obs_given_state

        return POMDPBeliefDistribution(posterior)

    def expected_entropy_after_action(
        self,
        possible_observations: List[str],
        observation_likelihoods: Dict[str, Dict[str, float]]
    ) -> float:
        """
        Computes the expected posterior entropy E_o[H(b_o)] if an action is performed.
        """
        expected_h = 0.0

        for obs in possible_observations:
            # Probability of observing obs: P(obs) = sum_s P(obs | s) * b(s)
            p_obs = sum(
                self.beliefs.get(state, 0.0) * observation_likelihoods.get(state, {}).get(obs, 0.05)
                for state in self.beliefs
            )
            if p_obs > 1e-12:
                posterior = self.update(obs, observation_likelihoods)
                expected_h += p_obs * posterior.entropy()

        return round(expected_h, 4)

    def expected_information_gain(
        self,
        possible_observations: List[str],
        observation_likelihoods: Dict[str, Dict[str, float]]
    ) -> float:
        """
        EIG = H(b_current) - E_o[H(b_o)].
        Higher EIG means the experiment has greater discriminatory power.
        """
        prior_h = self.entropy()
        expected_posterior_h = self.expected_entropy_after_action(possible_observations, observation_likelihoods)
        eig = prior_h - expected_posterior_h
        return max(0.0, round(eig, 4))

    def most_likely_state(self) -> Tuple[str, float]:
        """Returns the state with the highest belief probability."""
        if not self.beliefs:
            return ("UNKNOWN", 0.0)
        best_state = max(self.beliefs.items(), key=lambda x: x[1])
        return best_state[0], round(best_state[1], 4)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "beliefs": {k: round(v, 4) for k, v in self.beliefs.items()},
            "entropy": self.entropy(),
            "most_likely": self.most_likely_state()[0],
            "confidence": self.most_likely_state()[1]
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "POMDPBeliefDistribution":
        return cls(data.get("beliefs", {}))


# ─────────────────────────────────────────────────────────────────────────────
# 2. Causal Intervention Engine (Pearl's do(X) Calculus)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class CausalInterventionResult:
    variable: str
    original_val: Any
    intervened_val: Any
    outcome_changed: bool
    average_treatment_effect: float
    is_root_cause: bool
    explanation: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "variable": self.variable,
            "original_val": str(self.original_val),
            "intervened_val": str(self.intervened_val),
            "outcome_changed": self.outcome_changed,
            "average_treatment_effect": round(self.average_treatment_effect, 4),
            "is_root_cause": self.is_root_cause,
            "explanation": self.explanation
        }


class CausalInterventionEngine:
    """
    Pearl's do-calculus intervention engine.
    Applies counterfactual perturbations do(X = v) to isolate genuine causal drivers
    of behavior differences while holding confounding parameters constant.
    """

    @staticmethod
    def evaluate_counterfactual(
        baseline_request: Dict[str, Any],
        interventions: Dict[str, Any],
        oracle_evaluator: Callable[[Dict[str, Any]], bool]
    ) -> List[CausalInterventionResult]:
        """
        For each variable in interventions, holds all other baseline parameters constant
        and performs do(var = intervened_value), querying the oracle evaluator.
        """
        baseline_outcome = oracle_evaluator(baseline_request)
        results: List[CausalInterventionResult] = []

        for var, new_val in interventions.items():
            if var not in baseline_request or baseline_request[var] == new_val:
                continue

            perturbed_request = dict(baseline_request)
            perturbed_request[var] = new_val

            intervened_outcome = oracle_evaluator(perturbed_request)
            outcome_changed = (intervened_outcome != baseline_outcome)

            ate = 1.0 if outcome_changed else 0.0
            explanation = (
                f"Intervening do({var} = {new_val}) altered system outcome from {baseline_outcome} to {intervened_outcome}. "
                f"Variable '{var}' is a verified causal driver."
                if outcome_changed else
                f"Intervening do({var} = {new_val}) produced no state change. Variable '{var}' is non-causal noise."
            )

            results.append(CausalInterventionResult(
                variable=var,
                original_val=baseline_request[var],
                intervened_val=new_val,
                outcome_changed=outcome_changed,
                average_treatment_effect=ate,
                is_root_cause=outcome_changed,
                explanation=explanation
            ))

        return results

    @staticmethod
    def isolate_minimal_causal_set(
        passing_input: Dict[str, Any],
        failing_input: Dict[str, Any],
        oracle_fails: Callable[[Dict[str, Any]], bool]
    ) -> List[str]:
        """
        Isolates the Minimal Causal Explanatory Set (MCES):
        Finds the smallest set of parameter keys in failing_input that must be changed
        to passing_input to eliminate the failure.
        """
        differing_keys = [
            k for k in failing_input
            if k in passing_input and failing_input[k] != passing_input[k]
        ]

        if not oracle_fails(failing_input):
            return []

        # Test each single-variable counterfactual do(k = passing[k])
        causal_keys = []
        for k in differing_keys:
            test_input = dict(failing_input)
            test_input[k] = passing_input[k]
            # If changing k alone fixes the failure (oracle_fails becomes False), k is a direct cause
            if not oracle_fails(test_input):
                causal_keys.append(k)

        # If no single variable was sufficient, all differing keys form an interacting causal set
        if not causal_keys:
            return differing_keys

        return causal_keys


# ─────────────────────────────────────────────────────────────────────────────
# 3. API Grammar Induction Engine
# ─────────────────────────────────────────────────────────────────────────────

class ParamCategory(str, Enum):
    IDENTITY_REF = "IDENTITY_REF"         # user_id, tenant_id, account_id
    STATE_TRANSITION = "STATE_TRANSITION" # status, action, step, event
    FILTER_PAGINATION = "FILTER_PAGINATION" # page, limit, offset, sort
    PAYLOAD_DATA = "PAYLOAD_DATA"         # name, note, bio, title


class ResourceGrammarSegment:
    def __init__(self, value: str, is_param: bool = False, param_type: str = "LITERAL"):
        self.value = value
        self.is_param = is_param
        self.param_type = param_type  # 'UUID', 'INT', 'SLUG', 'LITERAL'

    def to_dict(self) -> Dict[str, Any]:
        return {
            "value": self.value,
            "is_param": self.is_param,
            "param_type": self.param_type
        }


@dataclass
class ApiEndpointGrammar:
    pattern: str
    http_methods: List[str]
    segments: List[ResourceGrammarSegment]
    entity_references: List[str]
    parameter_classifications: Dict[str, ParamCategory]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pattern": self.pattern,
            "http_methods": self.http_methods,
            "segments": [s.to_dict() for s in self.segments],
            "entity_references": self.entity_references,
            "parameter_classifications": {k: v.value for k, v in self.parameter_classifications.items()}
        }


class ApiGrammarInductionEngine:
    """
    Infers structured API resource grammars from observed network traffic.
    Transforms raw paths into generalized parametric templates and categorizes parameters.
    """

    UUID_REGEX = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')
    INT_REGEX = re.compile(r'^\d+$')
    IDENTITY_KEYWORDS = {"user", "tenant", "account", "org", "profile", "customer", "member", "team"}
    STATE_KEYWORDS = {"status", "action", "state", "step", "phase", "stage", "transition"}
    PAGINATION_KEYWORDS = {"page", "limit", "offset", "size", "sort", "order", "cursor", "filter"}

    @classmethod
    def classify_parameter(cls, param_name: str) -> ParamCategory:
        low = param_name.lower()
        if any(kw in low for kw in cls.IDENTITY_KEYWORDS):
            return ParamCategory.IDENTITY_REF
        if any(kw in low for kw in cls.STATE_KEYWORDS):
            return ParamCategory.STATE_TRANSITION
        if any(kw in low for kw in cls.PAGINATION_KEYWORDS):
            return ParamCategory.FILTER_PAGINATION
        return ParamCategory.PAYLOAD_DATA

    @classmethod
    def induce_endpoint_grammar(
        cls,
        path: str,
        method: str = "GET",
        query_params: Optional[List[str]] = None,
        body_params: Optional[List[str]] = None
    ) -> ApiEndpointGrammar:
        """
        Parses an endpoint URL path, induces dynamic segment types (UUID, INT, SLUG),
        and maps parameter roles.
        """
        segments_raw = [s for s in path.strip("/").split("/") if s]
        induced_segments: List[ResourceGrammarSegment] = []
        entity_refs: List[str] = []
        pattern_parts: List[str] = []

        for idx, seg in enumerate(segments_raw):
            prev_seg = segments_raw[idx - 1] if idx > 0 else "item"
            if cls.UUID_REGEX.match(seg):
                param_name = f"{prev_seg}_uuid"
                induced_segments.append(ResourceGrammarSegment(param_name, is_param=True, param_type="UUID"))
                entity_refs.append(param_name)
                pattern_parts.append(f"{{{param_name}}}")
            elif cls.INT_REGEX.match(seg):
                param_name = f"{prev_seg}_id"
                induced_segments.append(ResourceGrammarSegment(param_name, is_param=True, param_type="INT"))
                entity_refs.append(param_name)
                pattern_parts.append(f"{{{param_name}}}")
            else:
                induced_segments.append(ResourceGrammarSegment(seg, is_param=False, param_type="LITERAL"))
                pattern_parts.append(seg)

        pattern = "/" + "/".join(pattern_parts)
        param_classes: Dict[str, ParamCategory] = {}

        for p in (query_params or []):
            param_classes[p] = cls.classify_parameter(p)
            if param_classes[p] == ParamCategory.IDENTITY_REF:
                entity_refs.append(p)

        for p in (body_params or []):
            param_classes[p] = cls.classify_parameter(p)
            if param_classes[p] == ParamCategory.IDENTITY_REF:
                entity_refs.append(p)

        return ApiEndpointGrammar(
            pattern=pattern,
            http_methods=[method],
            segments=induced_segments,
            entity_references=list(set(entity_refs)),
            parameter_classifications=param_classes
        )

    @classmethod
    def generate_grammar_mutations(
        cls,
        grammar: ApiEndpointGrammar,
        substitute_ids: Dict[str, str]
    ) -> str:
        """
        Reconstructs concrete endpoint URLs applying cross-entity substitutions.
        """
        url_parts = []
        for seg in grammar.segments:
            if seg.is_param:
                val = substitute_ids.get(seg.value, "99999")
                url_parts.append(str(val))
            else:
                url_parts.append(seg.value)
        return "/" + "/".join(url_parts)


# ─────────────────────────────────────────────────────────────────────────────
# 4. Temporal Security Logic (LTL Trace Auditor)
# ─────────────────────────────────────────────────────────────────────────────

class TemporalOperator(str, Enum):
    ALWAYS = "ALWAYS"               # [] P (Invariant at all points)
    PRECEDES = "PRECEDES"           # P precedes Q (Q never occurs without earlier P)
    NEVER_AFTER = "NEVER_AFTER"     # After P occurs, Q must never occur
    REQUIRES_STATE = "REQUIRES_STATE" # Action requires prerequisite prior state


@dataclass
class TemporalTraceEvent:
    event_id: str
    action: str
    actor: str
    resource: str
    timestamp: float
    status_code: int = 200
    session_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "action": self.action,
            "actor": self.actor,
            "resource": self.resource,
            "timestamp": self.timestamp,
            "status_code": self.status_code,
            "session_id": self.session_id,
            "metadata": self.metadata
        }


@dataclass
class TemporalSecurityRule:
    rule_id: str
    operator: TemporalOperator
    trigger_action: str
    target_action: Optional[str] = None
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "operator": self.operator.value,
            "trigger_action": self.trigger_action,
            "target_action": self.target_action,
            "description": self.description
        }


@dataclass
class TemporalViolation:
    rule_id: str
    operator: TemporalOperator
    failing_event_index: int
    failing_event: TemporalTraceEvent
    counterexample_trace_indices: List[int]
    explanation: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "operator": self.operator.value,
            "failing_event_index": self.failing_event_index,
            "failing_event": self.failing_event.to_dict(),
            "counterexample_trace_indices": self.counterexample_trace_indices,
            "explanation": self.explanation
        }


class TemporalLogicVerifier:
    """
    Linear Temporal Logic (LTL) trace verifier for multi-step security sequences.
    Evaluates multi-session event histories against safety and precedence properties.
    """

    def __init__(self, rules: Optional[List[TemporalSecurityRule]] = None):
        self.rules: List[TemporalSecurityRule] = list(rules or [])

    def add_rule(self, rule: TemporalSecurityRule) -> None:
        self.rules.append(rule)

    def audit_trace(self, trace: List[TemporalTraceEvent]) -> List[TemporalViolation]:
        violations: List[TemporalViolation] = []

        for rule in self.rules:
            if rule.operator == TemporalOperator.PRECEDES:
                # Target action must be preceded by Trigger action for the same actor/session
                prior_triggers: Set[str] = set()
                for idx, ev in enumerate(trace):
                    if ev.action == rule.trigger_action and ev.status_code < 400:
                        prior_triggers.add(ev.actor)
                    elif ev.action == rule.target_action and ev.status_code < 400:
                        if ev.actor not in prior_triggers:
                            violations.append(TemporalViolation(
                                rule_id=rule.rule_id,
                                operator=rule.operator,
                                failing_event_index=idx,
                                failing_event=ev,
                                counterexample_trace_indices=[idx],
                                explanation=(
                                    f"Security Temporal Violation: '{rule.target_action}' occurred at step {idx} "
                                    f"without required prerequisite '{rule.trigger_action}' for actor '{ev.actor}'."
                                )
                            ))

            elif rule.operator == TemporalOperator.NEVER_AFTER:
                # Once trigger occurs (e.g. LOGOUT/REVOKE), target action (e.g. DATA_EXPORT) must never succeed
                revoked_actors: Dict[str, int] = {}
                for idx, ev in enumerate(trace):
                    if ev.action == rule.trigger_action and ev.status_code < 400:
                        revoked_actors[ev.actor] = idx
                    elif ev.action == rule.target_action and ev.status_code < 400:
                        if ev.actor in revoked_actors:
                            trigger_idx = revoked_actors[ev.actor]
                            violations.append(TemporalViolation(
                                rule_id=rule.rule_id,
                                operator=rule.operator,
                                failing_event_index=idx,
                                failing_event=ev,
                                counterexample_trace_indices=[trigger_idx, idx],
                                explanation=(
                                    f"Security Temporal Violation: '{rule.target_action}' succeeded at step {idx} "
                                    f"after invalidating event '{rule.trigger_action}' at step {trigger_idx} for actor '{ev.actor}'."
                                )
                            ))

            elif rule.operator == TemporalOperator.ALWAYS:
                # Invariant predicate check: status code < 400 for trigger action must satisfy condition
                for idx, ev in enumerate(trace):
                    if ev.action == rule.trigger_action:
                        # If action has an unauthorized role in metadata, it violates ALWAYS
                        if ev.metadata.get("is_authorized") is False and ev.status_code < 400:
                            violations.append(TemporalViolation(
                                rule_id=rule.rule_id,
                                operator=rule.operator,
                                failing_event_index=idx,
                                failing_event=ev,
                                counterexample_trace_indices=[idx],
                                explanation=f"Invariant violated: Unauthorized execution of '{rule.trigger_action}' succeeded with status {ev.status_code}."
                            ))

        return violations


# ─────────────────────────────────────────────────────────────────────────────
# 5. Delta Debugging Minimizer (Trace Reduction ddmin)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class MinimalTraceResult:
    original_trace_length: int
    minimized_trace_length: int
    minimized_trace: List[Any]
    reduction_percentage: float
    total_evaluations: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "original_length": self.original_trace_length,
            "minimized_length": self.minimized_trace_length,
            "minimized_trace": self.minimized_trace,
            "reduction_percentage": round(self.reduction_percentage, 2),
            "evaluations": self.total_evaluations
        }


class DeltaDebuggingMinimizer:
    """
    Zeller's Delta Debugging (ddmin) algorithm adapted for multi-step security traces.
    Reduces complex 15-step exploit sequences down to the 1-minimal subset of prerequisite steps.
    """

    @classmethod
    def minimize(
        cls,
        trace: List[Any],
        oracle_fails: Callable[[List[Any]], bool]
    ) -> MinimalTraceResult:
        """
        Finds a 1-minimal subtrace T' of T such that oracle_fails(T') is True,
        and removing any element from T' causes oracle_fails to return False.
        """
        original_length = len(trace)
        if original_length == 0 or not oracle_fails(trace):
            return MinimalTraceResult(original_length, 0, [], 0.0, 1)

        eval_counter = [1]  # mutable counter

        def run_oracle(subtrace: List[Any]) -> bool:
            eval_counter[0] += 1
            return oracle_fails(subtrace)

        current = list(trace)
        n = 2

        while len(current) >= 2:
            subsets = []
            chunk_size = max(1, math.ceil(len(current) / n))
            for i in range(0, len(current), chunk_size):
                subsets.append(current[i:i + chunk_size])

            # 1. Check if any subset alone triggers the failure
            reduced = False
            for subset in subsets:
                if len(subset) < len(current) and run_oracle(subset):
                    current = subset
                    n = max(n - 1, 2)
                    reduced = True
                    break

            if reduced:
                continue

            # 2. Check if complement of any subset triggers failure
            for subset in subsets:
                complement = [item for item in current if item not in subset]
                if complement and len(complement) < len(current) and run_oracle(complement):
                    current = complement
                    n = max(n - 1, 2)
                    reduced = True
                    break

            if reduced:
                continue

            # 3. Increase granularity if cannot reduce
            if n < len(current):
                n = min(len(current), 2 * n)
            else:
                break

        # Final 1-minimality sweep: remove single elements one by one
        i = 0
        while i < len(current):
            if len(current) <= 1:
                break
            candidate = current[:i] + current[i + 1:]
            if run_oracle(candidate):
                current = candidate
            else:
                i += 1

        min_len = len(current)
        reduction = (1.0 - (min_len / original_length)) * 100.0 if original_length > 0 else 0.0

        return MinimalTraceResult(
            original_trace_length=original_length,
            minimized_trace_length=min_len,
            minimized_trace=current,
            reduction_percentage=reduction,
            total_evaluations=eval_counter[0]
        )


# ─────────────────────────────────────────────────────────────────────────────
# 6. Security Model Checker (Reachability Engine)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ReachabilityViolation:
    initial_state: str
    target_state: str
    action_path: List[str]
    path_length: int
    is_unsafe: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "initial_state": self.initial_state,
            "target_state": self.target_state,
            "action_path": self.action_path,
            "path_length": self.path_length,
            "is_unsafe": self.is_unsafe
        }


class SecurityModelChecker:
    """
    Exhaustive reachability model checker over discrete application security states.
    Discovers counterexample paths leading from unprivileged states to unsafe states.
    """

    def __init__(self):
        # adj[state] = [(action, next_state)]
        self.adj: Dict[str, List[Tuple[str, str]]] = {}
        self.unsafe_states: Set[str] = set()

    def add_transition(self, from_state: str, action: str, to_state: str) -> None:
        if from_state not in self.adj:
            self.adj[from_state] = []
        self.adj[from_state].append((action, to_state))

    def mark_unsafe_state(self, state: str) -> None:
        self.unsafe_states.add(state)

    def find_shortest_unsafe_path(self, start_state: str) -> Optional[ReachabilityViolation]:
        """
        Performs BFS to find the shortest counterexample sequence of actions reaching an unsafe state.
        """
        queue: List[Tuple[str, List[str]]] = [(start_state, [])]
        visited: Set[str] = {start_state}

        while queue:
            curr_state, path = queue.pop(0)

            if curr_state in self.unsafe_states:
                return ReachabilityViolation(
                    initial_state=start_state,
                    target_state=curr_state,
                    action_path=path,
                    path_length=len(path),
                    is_unsafe=True
                )

            for action, next_state in self.adj.get(curr_state, []):
                if next_state not in visited:
                    visited.add(next_state)
                    queue.append((next_state, path + [action]))

        return None


# ─────────────────────────────────────────────────────────────────────────────
# 7. Cognitive Diversity Council
# ─────────────────────────────────────────────────────────────────────────────

class CognitiveRole(str, Enum):
    EXPLORER = "EXPLORER"
    SKEPTIC = "SKEPTIC"
    CAUSAL_ANALYST = "CAUSAL_ANALYST"
    TEMPORAL_ANALYST = "TEMPORAL_ANALYST"
    JUDGE = "JUDGE"


@dataclass
class PersonaOpinion:
    role: CognitiveRole
    verdict: str  # 'CONFIRMED', 'DISMISSED', 'INVESTIGATE_FURTHER'
    confidence: float
    reasoning: str


@dataclass
class CouncilSynthesis:
    consensus_verdict: str
    aggregate_confidence: float
    entropy: float
    persona_opinions: List[PersonaOpinion]
    recommendation: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "consensus_verdict": self.consensus_verdict,
            "aggregate_confidence": round(self.aggregate_confidence, 4),
            "entropy": round(self.entropy, 4),
            "opinions": [
                {
                    "role": o.role.value,
                    "verdict": o.verdict,
                    "confidence": o.confidence,
                    "reasoning": o.reasoning
                }
                for o in self.persona_opinions
            ],
            "recommendation": self.recommendation
        }


class CognitiveDiversityCouncil:
    """
    Ensemble reasoning council combining multiple cognitive perspectives:
    - Explorer: looks for novelty and high entropy.
    - Skeptic: challenges findings with noise and alternative hypotheses.
    - CausalAnalyst: evaluates counterfactual do-calculus causality.
    - TemporalAnalyst: checks trace invariants and sequence rules.
    - Judge: synthesizes beliefs into final actionable assessment.
    """

    ROLE_WEIGHTS = {
        CognitiveRole.EXPLORER: 0.15,
        CognitiveRole.SKEPTIC: 0.25,
        CognitiveRole.CAUSAL_ANALYST: 0.25,
        CognitiveRole.TEMPORAL_ANALYST: 0.20,
        CognitiveRole.JUDGE: 0.15
    }

    @classmethod
    def deliberate(
        cls,
        finding_context: Dict[str, Any],
        has_causal_proof: bool,
        has_temporal_violation: bool,
        reproducibility_rate: float
    ) -> CouncilSynthesis:
        opinions: List[PersonaOpinion] = []

        # 1. Explorer
        opinions.append(PersonaOpinion(
            role=CognitiveRole.EXPLORER,
            verdict="INVESTIGATE_FURTHER" if reproducibility_rate < 0.5 else "CONFIRMED",
            confidence=0.85,
            reasoning="Novel behavior observed; state space exploration warrants priority."
        ))

        # 2. Skeptic
        if reproducibility_rate < 0.8:
            skeptic_verdict = "DISMISSED"
            skeptic_conf = 0.90
            skeptic_reason = f"Low reproducibility ({reproducibility_rate * 100}%). Likely transient network noise."
        else:
            skeptic_verdict = "CONFIRMED"
            skeptic_conf = 0.75
            skeptic_reason = "High reproducibility observed across repeated trials; noise hypothesis refuted."
        opinions.append(PersonaOpinion(
            role=CognitiveRole.SKEPTIC,
            verdict=skeptic_verdict,
            confidence=skeptic_conf,
            reasoning=skeptic_reason
        ))

        # 3. Causal Analyst
        if has_causal_proof:
            causal_verdict = "CONFIRMED"
            causal_conf = 0.95
            causal_reason = "Counterfactual do-calculus verified: target parameter is the sole causal driver."
        else:
            causal_verdict = "DISMISSED"
            causal_conf = 0.80
            causal_reason = "No isolated causal parameter found; changes may be confounded."
        opinions.append(PersonaOpinion(
            role=CognitiveRole.CAUSAL_ANALYST,
            verdict=causal_verdict,
            confidence=causal_conf,
            reasoning=causal_reason
        ))

        # 4. Temporal Analyst
        if has_temporal_violation:
            temp_verdict = "CONFIRMED"
            temp_conf = 0.90
            temp_reason = "Linear temporal logic invariant violated across event trace."
        else:
            temp_verdict = "INVESTIGATE_FURTHER"
            temp_conf = 0.60
            temp_reason = "No explicit temporal ordering violation detected in current trace."
        opinions.append(PersonaOpinion(
            role=CognitiveRole.TEMPORAL_ANALYST,
            verdict=temp_verdict,
            confidence=temp_conf,
            reasoning=temp_reason
        ))

        # 5. Judge synthesis
        vote_scores: Dict[str, float] = {"CONFIRMED": 0.0, "DISMISSED": 0.0, "INVESTIGATE_FURTHER": 0.0}
        for op in opinions:
            weight = cls.ROLE_WEIGHTS.get(op.role, 0.2)
            vote_scores[op.verdict] += weight * op.confidence

        consensus = max(vote_scores.items(), key=lambda x: x[1])[0]
        total_weight = sum(vote_scores.values())
        norm_scores = {k: v / total_weight for k, v in vote_scores.items()} if total_weight > 0 else {}

        # Entropy of council deliberation
        council_entropy = 0.0
        for p in norm_scores.values():
            if p > 1e-12:
                council_entropy -= p * math.log2(p)

        judge_opinion = PersonaOpinion(
            role=CognitiveRole.JUDGE,
            verdict=consensus,
            confidence=norm_scores.get(consensus, 0.5),
            reasoning=f"Synthesis: weighted majority supports {consensus} with confidence {round(norm_scores.get(consensus, 0.5), 2)}."
        )
        opinions.append(judge_opinion)

        recommendation = (
            "Escalate to Verified Finding: Both causal and temporal evidence substantiate vulnerability."
            if consensus == "CONFIRMED" else
            "Prune hypothesis: Lacks causal isolation or reproducibility."
            if consensus == "DISMISSED" else
            "Deploy targeted metamorphic probes to reduce epistemic ambiguity."
        )

        return CouncilSynthesis(
            consensus_verdict=consensus,
            aggregate_confidence=norm_scores.get(consensus, 0.5),
            entropy=council_entropy,
            persona_opinions=opinions,
            recommendation=recommendation
        )


# ─────────────────────────────────────────────────────────────────────────────
# 8. Self-Evolving Strategy Genome
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class StrategyGene:
    name: str
    value: float
    min_val: float
    max_val: float

    def mutate(self, rate: float = 0.15) -> "StrategyGene":
        delta = (self.max_val - self.min_val) * random.uniform(-rate, rate)
        new_val = max(self.min_val, min(self.max_val, self.value + delta))
        return StrategyGene(self.name, round(new_val, 3), self.min_val, self.max_val)


class SelfEvolvingStrategyGenome:
    """
    Evolves autonomous research hyperparameters using genetic optimization.
    Dynamically tunes exploration vs exploitation, skepticism, and causal depth.
    """

    def __init__(self, genes: Optional[Dict[str, StrategyGene]] = None, fitness: float = 0.0):
        if genes is None:
            self.genes = {
                "exploration_bias": StrategyGene("exploration_bias", 0.70, 0.10, 1.0),
                "skepticism_threshold": StrategyGene("skepticism_threshold", 0.80, 0.50, 0.99),
                "causal_intervention_depth": StrategyGene("causal_intervention_depth", 3.0, 1.0, 10.0),
                "temporal_trace_window": StrategyGene("temporal_trace_window", 10.0, 3.0, 50.0),
                "entropy_tolerance": StrategyGene("entropy_tolerance", 0.35, 0.05, 0.80)
            }
        else:
            self.genes = genes
        self.fitness = fitness

    def mutate(self, mutation_rate: float = 0.15) -> "SelfEvolvingStrategyGenome":
        new_genes = {k: gene.mutate(mutation_rate) for k, gene in self.genes.items()}
        return SelfEvolvingStrategyGenome(new_genes, fitness=0.0)

    def crossover(self, partner: "SelfEvolvingStrategyGenome") -> "SelfEvolvingStrategyGenome":
        child_genes: Dict[str, StrategyGene] = {}
        for k in self.genes:
            gene_a = self.genes[k]
            gene_b = partner.genes.get(k, gene_a)
            chosen = gene_a if random.random() > 0.5 else gene_b
            child_genes[k] = StrategyGene(k, chosen.value, chosen.min_val, chosen.max_val)
        return SelfEvolvingStrategyGenome(child_genes, fitness=0.0)

    def evaluate_fitness(
        self,
        unique_vulnerabilities_found: int,
        false_positives_eliminated: int,
        entropy_reduction: float
    ) -> float:
        """
        Fitness function: J = 5 * Vulns + 2 * FalsePositivesEliminated + 3 * EntropyReduction
        """
        self.fitness = round(
            (5.0 * unique_vulnerabilities_found) +
            (2.0 * false_positives_eliminated) +
            (3.0 * entropy_reduction),
            3
        )
        return self.fitness

    def to_dict(self) -> Dict[str, Any]:
        return {
            "fitness": self.fitness,
            "genes": {k: g.value for k, g in self.genes.items()}
        }
