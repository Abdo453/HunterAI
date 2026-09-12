"""
HunterAI Runtime: Unified Cognitive Core
========================================
Implements the core analytical reasoning engines for autonomous security research:
1. Noise & Deception Model: Establishes dynamic baselines and filters out stochastic jitter
   (timestamps, dynamic nonces, CDN variance) from genuine signals.
2. Bayesian Hypothesis Competition: Evaluates competing explanations for observed anomalies
   and calculates posterior probabilities through discriminative probes.
3. Automatic Invariant Discovery: Infers access control and state-machine rules empirically
   from differential observation pairs.
4. Falsification & Anti-Confirmation Engine: Systematically attempts to disprove candidate
   findings using counterfactual and unauthenticated control tests.
5. Deterministic Reproducibility Verifier: Asserts that an anomaly reliably repeats across
   multiple independent trials before formal reporting.
"""
from __future__ import annotations

import math
import time
import logging
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, List, Optional, Any, Set, Tuple

logger = logging.getLogger("hunter_ai.cognitive_core")


# ─── 1. Noise & Deception Model ──────────────────────────────────────────────
@dataclass
class NoiseProfile:
    """Baseline variance profile for an endpoint under identical requests"""
    endpoint: str
    sample_count: int = 0
    mean_length: float = 0.0
    length_variance: float = 0.0
    max_length_delta: int = 0
    observed_statuses: Set[int] = field(default_factory=set)
    dynamic_headers: Set[str] = field(default_factory=set)

    def is_signal_significant(self, observed_length: int, observed_status: int) -> Tuple[bool, str]:
        """Determines if an observed response deviates significantly from the noise floor"""
        if self.sample_count < 2:
            return True, "Insufficient baseline samples; treating change as tentative signal."

        if observed_status not in self.observed_statuses:
            return True, f"Status code {observed_status} differs from baseline statuses {list(self.observed_statuses)}."

        delta = abs(observed_length - self.mean_length)
        threshold = max(25, self.max_length_delta * 1.5)
        if delta > threshold:
            return True, f"Length delta ({delta:.1f} bytes) exceeds noise threshold ({threshold:.1f} bytes)."

        return False, f"Length delta ({delta:.1f} bytes) is within expected noise floor ({threshold:.1f} bytes)."


class NoiseModel:
    """Calculates and maintains baseline noise thresholds across target endpoints"""

    def __init__(self):
        self._profiles: Dict[str, NoiseProfile] = {}

    def calibrate(self, endpoint: str, sample_responses: List[Dict[str, Any]]) -> NoiseProfile:
        """Calibrates noise thresholds from repeated baseline responses"""
        lengths = [len(r.get("text", "")) for r in sample_responses]
        statuses = {r.get("status_code", 200) for r in sample_responses}

        count = len(lengths)
        if count == 0:
            profile = NoiseProfile(endpoint=endpoint)
            self._profiles[endpoint] = profile
            return profile

        mean = sum(lengths) / count
        var = sum((x - mean) ** 2 for x in lengths) / count if count > 1 else 0.0
        max_delta = max(abs(x - mean) for x in lengths) if lengths else 0

        profile = NoiseProfile(
            endpoint=endpoint,
            sample_count=count,
            mean_length=mean,
            length_variance=var,
            max_length_delta=int(max_delta),
            observed_statuses=statuses
        )
        self._profiles[endpoint] = profile
        return profile

    def get_profile(self, endpoint: str) -> Optional[NoiseProfile]:
        return self._profiles.get(endpoint)


# ─── 2. Bayesian Hypothesis Competition ──────────────────────────────────────
@dataclass
class CompetingExplanation:
    """A competing hypothesis explaining a specific response anomaly"""
    explanation_id: str
    category: str
    description: str
    prior_probability: float
    posterior_probability: float
    evidence_points: List[str] = field(default_factory=list)


class BayesianHypothesisCompetition:
    """
    Manages competing hypotheses for an anomaly and applies Bayesian updates
    based on discriminative experimental outcomes.
    """

    def __init__(self, anomaly_description: str):
        self.anomaly_description = anomaly_description
        self.explanations: Dict[str, CompetingExplanation] = {}

    def add_explanation(self, explanation_id: str, category: str, description: str, prior: float):
        self.explanations[explanation_id] = CompetingExplanation(
            explanation_id=explanation_id,
            category=category,
            description=description,
            prior_probability=prior,
            posterior_probability=prior
        )
        self._normalize_probabilities()

    def _normalize_probabilities(self):
        total = sum(e.posterior_probability for e in self.explanations.values())
        if total > 0:
            for e in self.explanations.values():
                e.posterior_probability = round(e.posterior_probability / total, 4)

    def apply_evidence(self, favorable_id: str, likelihood_multiplier: float, evidence_text: str):
        """Updates probability distribution when evidence favors a specific explanation"""
        if favorable_id in self.explanations:
            self.explanations[favorable_id].posterior_probability *= likelihood_multiplier
            self.explanations[favorable_id].evidence_points.append(evidence_text)
            self._normalize_probabilities()

    def get_leading_explanation(self) -> Optional[CompetingExplanation]:
        if not self.explanations:
            return None
        return max(self.explanations.values(), key=lambda e: e.posterior_probability)


# ─── 3. Automatic Invariant Discovery ────────────────────────────────────────
@dataclass
class DiscoveredRule:
    """An empirically deduced security invariant rule"""
    rule_id: str
    resource_type: str
    predicate: str
    description: str
    confidence: float
    supporting_observations: int = 1


class AutomaticInvariantDiscovery:
    """
    Infers operational invariants from contrastive interaction pairs.
    Example: (User A gets 200 on Object 1, User B gets 403 on Object 1)
             => Invariant: Owner(Object) == CallerIdentity
    """

    def __init__(self):
        self._discovered_rules: Dict[str, DiscoveredRule] = {}
        self._rule_counter = 1

    def observe_access_differential(
        self,
        resource_type: str,
        resource_id: str,
        owner_id: str,
        actor_id: str,
        status_code: int
    ) -> Optional[DiscoveredRule]:
        """Infers an ownership or role boundary invariant when differential access is seen"""
        is_owner = (actor_id == owner_id)

        # Pattern: Owner succeeds, non-owner denied -> Strict Ownership Invariant
        if not is_owner and status_code in [401, 403, 404]:
            rule_key = f"OWNERSHIP_{resource_type.upper()}"
            if rule_key in self._discovered_rules:
                rule = self._discovered_rules[rule_key]
                rule.supporting_observations += 1
                rule.confidence = min(0.99, rule.confidence + 0.1)
                return rule
            else:
                rule = DiscoveredRule(
                    rule_id=f"AUTO-INV-{self._rule_counter:03d}",
                    resource_type=resource_type,
                    predicate="Owner(resource) == Actor",
                    description=f"Access to '{resource_type}' objects is strictly restricted to their assigned owner.",
                    confidence=0.85
                )
                self._rule_counter += 1
                self._discovered_rules[rule_key] = rule
                logger.info(f"[InvariantDiscovery] Inferred Invariant: {rule.description}")
                return rule

        return None

    def get_discovered_rules(self) -> List[DiscoveredRule]:
        return list(self._discovered_rules.values())


# ─── 4. Falsification & Anti-Confirmation Engine ─────────────────────────────
class FalsificationEngine:
    """
    Adversarially attempts to disprove candidate findings.
    Only findings that survive rigorous counter-tests are deemed verified.
    """

    @classmethod
    def test_public_resource_falsification(
        cls,
        unauthenticated_response_status: int,
        unauthenticated_response_body: str,
        target_object_id: str
    ) -> Tuple[bool, str]:
        """
        Falsification check: If an unauthenticated request returns the same record,
        the resource is public catalog data and NOT an IDOR/BOLA vulnerability.
        """
        if unauthenticated_response_status == 200 and target_object_id in unauthenticated_response_body:
            return False, "FALSIFIED: Resource is publicly accessible without authentication; no authorization boundary exists."
        return True, "SURVIVED: Resource requires authentication and is not publicly accessible."

    @classmethod
    def test_control_negative_falsification(
        cls,
        probe_status: int,
        control_status: int,
        probe_len: int,
        control_len: int
    ) -> Tuple[bool, str]:
        """
        Falsification check: If a negative control produces identical deviation
        to the probe, the anomaly is caused by noise or input reflection, not vulnerability.
        """
        delta = abs(probe_len - control_len)
        if probe_status == control_status and delta < 20:
            return False, "FALSIFIED: Control negative probe produced identical response; anomaly is not condition-dependent."
        return True, "SURVIVED: Response differs conditionally between affirmative probe and negative control."


# ─── 5. Deterministic Reproducibility Verifier ──────────────────────────────
class ReproducibilityVerifier:
    """
    Ensures an observed security finding reliably reproduces across independent trials.
    """

    @classmethod
    def verify_reproducibility(
        cls,
        trial_results: List[bool],
        required_success_rate: float = 0.8
    ) -> Tuple[bool, float]:
        """Returns True if the anomaly reproduces consistently across trials"""
        if not trial_results:
            return False, 0.0

        successes = sum(1 for r in trial_results if r)
        rate = successes / len(trial_results)
        return (rate >= required_success_rate), round(rate, 2)


# ─── 6. Metamorphic Testing Engine ──────────────────────────────────────────
@dataclass
class MetamorphicRelation:
    """A metamorphic transformation relation that should preserve semantic outcome"""
    name: str
    transform_func: Any
    expected_equivalence: bool = True


class MetamorphicEngine:
    """
    Tests whether semantically equivalent transformations of an input yield consistent
    application responses, or if an unexpected divergence reveals a parser differential or bypass.
    """

    @classmethod
    def generate_metamorphic_variants(cls, base_value: str) -> Dict[str, str]:
        """Generates equivalent encodings/casing/normalization variants"""
        import urllib.parse
        return {
            "identity": base_value,
            "url_encoded": urllib.parse.quote(base_value),
            "uppercase": base_value.upper(),
            "padded_whitespace": f" {base_value} ",
            "double_url_encoded": urllib.parse.quote(urllib.parse.quote(base_value))
        }

    @classmethod
    def evaluate_metamorphic_invariance(
        cls,
        baseline_status: int,
        baseline_body: str,
        variant_status: int,
        variant_body: str
    ) -> Tuple[bool, str]:
        """Checks whether the application maintained semantic invariance across the transformation"""
        status_matches = (baseline_status == variant_status)
        delta_len = abs(len(baseline_body) - len(variant_body))
        if status_matches and delta_len < 30:
            return True, "INVARIANCE_MAINTAINED: Application treated equivalent input consistently."
        return False, f"METAMORPHIC_DIVERGENCE: Input transformation caused unexpected divergence (Status: {baseline_status}->{variant_status}, Delta: {delta_len} bytes)."


# ─── 7. Root-Cause Clustering Engine ────────────────────────────────────────
@dataclass
class ClusteredVulnerability:
    """A consolidated root-cause defect grouping multiple observed symptoms"""
    root_cause_id: str
    defect_class: str
    primary_mechanism: str
    affected_endpoints: List[str] = field(default_factory=list)
    affected_parameters: List[str] = field(default_factory=list)
    confidence: float = 0.9

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class RootCauseClusteringEngine:
    """
    Consolidates raw findings into distinct architectural root causes,
    preventing duplicate reports for the same underlying code defect.
    """

    @classmethod
    def cluster_findings(cls, raw_findings: List[Dict[str, Any]]) -> List[ClusteredVulnerability]:
        clusters: Dict[str, ClusteredVulnerability] = {}

        for fnd in raw_findings:
            v_type = fnd.get("vulnerability", fnd.get("type", "UNKNOWN"))
            param = fnd.get("parameter", fnd.get("param_name", "general"))
            endpoint = fnd.get("endpoint", fnd.get("target", "unknown"))

            # Grouping key based on vulnerability class and parameter family
            cluster_key = f"{v_type.upper()}_{param.lower()}"

            if cluster_key not in clusters:
                clusters[cluster_key] = ClusteredVulnerability(
                    root_cause_id=f"RC_{len(clusters) + 1:02d}_{cluster_key}",
                    defect_class=v_type,
                    primary_mechanism=f"Systemic unvalidated handling of parameter '{param}'",
                    affected_endpoints=[endpoint],
                    affected_parameters=[param],
                    confidence=fnd.get("confidence", 0.85)
                )
            else:
                cluster = clusters[cluster_key]
                if endpoint not in cluster.affected_endpoints:
                    cluster.affected_endpoints.append(endpoint)
                if param not in cluster.affected_parameters:
                    cluster.affected_parameters.append(param)

        return list(clusters.values())


# ─── 8. Epistemic Memory Decay Manager ──────────────────────────────────────
@dataclass
class EphemeralObservation:
    """An observation with temporal decay and recency weighting"""
    key: str
    content: Any
    created_at: float = field(default_factory=time.time)
    ttl_seconds: float = 300.0   # 5 minute default TTL for ephemeral observations
    access_count: int = 1

    def is_expired(self, current_time: Optional[float] = None) -> bool:
        now = current_time or time.time()
        return (now - self.created_at) > self.ttl_seconds


class MemoryDecayManager:
    """
    Prevents context pollution by decaying and pruning short-lived observations
    while preserving permanent architectural facts and verified findings.
    """

    def __init__(self, default_ttl: float = 300.0):
        self.default_ttl = default_ttl
        self._ephemeral_store: Dict[str, EphemeralObservation] = {}
        self._permanent_store: Dict[str, Any] = {}

    def set_ephemeral(self, key: str, value: Any, ttl: Optional[float] = None):
        self._ephemeral_store[key] = EphemeralObservation(
            key=key,
            content=value,
            ttl_seconds=ttl or self.default_ttl
        )

    def get_ephemeral(self, key: str) -> Optional[Any]:
        obs = self._ephemeral_store.get(key)
        if not obs:
            return None
        if obs.is_expired():
            del self._ephemeral_store[key]
            return None
        obs.access_count += 1
        return obs.content

    def prune_expired(self) -> int:
        now = time.time()
        expired_keys = [k for k, obs in self._ephemeral_store.items() if obs.is_expired(now)]
        for k in expired_keys:
            del self._ephemeral_store[k]
        return len(expired_keys)

    def set_permanent(self, key: str, value: Any):
        self._permanent_store[key] = value

    def get_permanent(self, key: str) -> Optional[Any]:
        return self._permanent_store.get(key)
