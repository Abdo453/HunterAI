"""
HunterAI Bayesian Hypothesis Engine
===================================
Models vulnerability discovery as scientific hypothesis testing with formal
Bayesian belief updating:
Prior P(H) -> Observed Evidence -> Likelihood Ratio P(E|H)/P(E|~H) -> Posterior P(H|E)

Replaces naive LLM confidence guessing with evidence-backed probabilities.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class HypothesisState(str, Enum):
    FORMULATED = "FORMULATED"
    UNDER_INVESTIGATION = "UNDER_INVESTIGATION"
    EVIDENCE_CONFIRMED = "EVIDENCE_CONFIRMED"
    FALSIFIED_REFUTED = "FALSIFIED_REFUTED"
    INCONCLUSIVE = "INCONCLUSIVE"


class BayesianBeliefUpdater:
    """Updates subjective probability according to Bayes' rule in odds form"""

    @classmethod
    def update_confidence(cls, prior: float, likelihood_ratio: float) -> float:
        """
        prior: P(H) in (0, 1)
        likelihood_ratio: P(E|H) / P(E|~H)
        Posterior Odds = Prior Odds * Likelihood Ratio
        """
        prior = max(0.01, min(0.99, prior))
        prior_odds = prior / (1.0 - prior)
        posterior_odds = prior_odds * likelihood_ratio
        posterior = posterior_odds / (1.0 + posterior_odds)
        return max(0.01, min(0.99, round(posterior, 4)))


@dataclass
class SecurityHypothesis:
    hypothesis_id: str
    target_endpoint: str
    vulnerability_class: str  # e.g., "SQLI", "BOLA", "SSRF"
    description: str
    prior_probability: float = 0.20
    current_confidence: float = 0.20
    state: HypothesisState = HypothesisState.FORMULATED
    evidence_collected: List[str] = field(default_factory=list)
    pending_experiments: List[str] = field(default_factory=list)

    def apply_evidence(self, evidence_name: str, likelihood_ratio: float):
        self.evidence_collected.append(evidence_name)
        self.current_confidence = BayesianBeliefUpdater.update_confidence(
            self.current_confidence, likelihood_ratio
        )
        if self.current_confidence >= 0.85:
            self.state = HypothesisState.EVIDENCE_CONFIRMED
        elif self.current_confidence <= 0.05:
            self.state = HypothesisState.FALSIFIED_REFUTED
        else:
            self.state = HypothesisState.UNDER_INVESTIGATION


class HypothesisEngine:
    """Generates, tracks, and refines scientific test hypotheses"""

    def __init__(self):
        self._hypotheses: Dict[str, SecurityHypothesis] = {}
        self._counter = 0

    def formulate_hypothesis(
        self,
        endpoint: str,
        vuln_class: str,
        initial_observation: str,
        prior: float = 0.20
    ) -> SecurityHypothesis:
        self._counter += 1
        hyp_id = f"HYP-{vuln_class[:4]}-{self._counter:03d}"
        hyp = SecurityHypothesis(
            hypothesis_id=hyp_id,
            target_endpoint=endpoint,
            vulnerability_class=vuln_class.upper(),
            description=initial_observation,
            prior_probability=prior,
            current_confidence=prior,
            state=HypothesisState.FORMULATED,
            pending_experiments=[
                "Stable Baseline Probe",
                "Computational Nonce Verification",
                "Negative Control Invariance"
            ]
        )
        self._hypotheses[hyp_id] = hyp
        return hyp

    def get_hypothesis(self, hyp_id: str) -> Optional[SecurityHypothesis]:
        return self._hypotheses.get(hyp_id)
