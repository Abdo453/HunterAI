"""
Bayesian Hypothesis Scorer
Mathematically calculates posterior probability P(H|E) using Bayesian belief updates
as concrete evidence items arrive from specialist agents.
"""
import logging
from typing import Dict, Any, Optional

from agents.security_intelligence.schemas import EvidenceItem, EvidenceType
from core.hypotheses.tracker import TrackedHypothesis

log = logging.getLogger("core.hypotheses.scorer")


class BayesianHypothesisScorer:
    """
    المقيّم البايزي للفرضيات الأمنية:
    يطبق مبرهنة بايز لتحديث الاحتمالية اللاحقة P(H|E) بناءً على نوعية الأدلة المرصودة
    """

    # Likelihood table: (P(E | H), P(E | not H))
    _LIKELIHOOD_TABLE = {
        EvidenceType.BEHAVIOR_DIFF: (0.92, 0.05),     # Differential behavior strongly indicates vulnerability
        EvidenceType.AUTH_ANOMALY: (0.88, 0.08),     # Auth anomaly is high indicator
        EvidenceType.ERROR_DISCLOSURE: (0.80, 0.12), # SQL/internal error leak
        EvidenceType.TIMING_LEAK: (0.75, 0.15),      # Consistent time delay
        EvidenceType.CVE_MATCH: (0.70, 0.20),        # Version match
        EvidenceType.STATUS_CODE: (0.55, 0.40),      # Weak indicator
        EvidenceType.REQUEST: (0.50, 0.50),          # Neutral
        EvidenceType.RESPONSE: (0.50, 0.50),         # Neutral
    }

    def update_probability(
        self,
        hypothesis: TrackedHypothesis,
        evidence: EvidenceItem,
        is_refuting: bool = False
    ) -> float:
        """
        حساب الاحتمال البايزي اللاحق P(H | E):
        P(H|E) = [P(E|H) * P(H)] / [P(E|H)*P(H) + P(E|~H)*(1-P(H))]
        """
        prior = hypothesis.posterior_probability

        if is_refuting:
            # Evidence refutes the hypothesis (e.g., standard 404, strict validation)
            p_e_given_h = 0.08
            p_e_given_not_h = 0.85
        else:
            p_e_given_h, p_e_given_not_h = self._LIKELIHOOD_TABLE.get(
                evidence.type, (0.60, 0.35)
            )

        # Scale by evidence confidence / weight if present
        weight = getattr(evidence, "weight", 0.5)
        # Moderate extreme probabilities if evidence weight is low
        effective_p_e_given_h = p_e_given_h * weight + 0.5 * (1 - weight)
        effective_p_e_given_not_h = p_e_given_not_h * weight + 0.5 * (1 - weight)

        numerator = effective_p_e_given_h * prior
        denominator = numerator + (effective_p_e_given_not_h * (1.0 - prior))

        if denominator <= 0.0:
            posterior = prior
        else:
            posterior = numerator / denominator

        posterior = round(max(0.01, min(0.99, posterior)), 3)
        log.debug(f"[BayesianScorer] Hypothesis {hypothesis.id}: Prior={prior:.2f} -> Posterior={posterior:.2f} (Ev: {evidence.type.value})")
        return posterior
