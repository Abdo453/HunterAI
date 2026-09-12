"""
Bayesian Epistemic Engine
Decoupled Bayesian modeling containing:
1. PriorModel: Generates calibrated initial prior distributions
2. LikelihoodModel: Encapsulates conditional likelihoods P(outcome | Hypothesis, Action)
3. PosteriorUpdater: Mathematically updates beliefs via Bayes' theorem with strict normalization.
"""
import logging
from typing import Dict, List, Any, Optional

log = logging.getLogger("core.reasoning.bayesian_engine")


class PriorModel:
    """نموذج الاحتمالات المبدئية (Priors)"""

    @staticmethod
    def uniform(hypothesis_ids: List[str]) -> Dict[str, float]:
        if not hypothesis_ids:
            return {}
        p = round(1.0 / len(hypothesis_ids), 4)
        return {h: p for h in hypothesis_ids}

    @staticmethod
    def create_calibrated_priors(hypotheses_with_weights: Dict[str, float]) -> Dict[str, float]:
        total = sum(hypotheses_with_weights.values())
        if total <= 0.0:
            return PriorModel.uniform(list(hypotheses_with_weights.keys()))
        return {h: round(w / total, 4) for h, w in hypotheses_with_weights.items()}


class LikelihoodModel:
    """
    نموذج الأرجحية الشرطية:
    P(outcome | Hypothesis, Action)
    """

    # Generic lookup: (vuln_type, action_kind, outcome) -> P(outcome | H)
    _DEFAULT_LIKELIHOODS = {
        # BOLA testing
        ("BOLA", "cross_tenant_probe", "200_cross_tenant_data"): 0.92,
        ("BOLA", "cross_tenant_probe", "403_forbidden"): 0.06,
        ("BOLA", "cross_tenant_probe", "404_not_found"): 0.02,
        ("Public_Resource", "cross_tenant_probe", "200_cross_tenant_data"): 0.10,
        ("Public_Resource", "cross_tenant_probe", "200_identical_data"): 0.85,
        ("Strict_AuthZ", "cross_tenant_probe", "403_forbidden"): 0.94,
        ("Strict_AuthZ", "cross_tenant_probe", "200_cross_tenant_data"): 0.02,

        # SQLi testing
        ("SQLi", "injection_probe", "db_error_or_delay"): 0.90,
        ("SQLi", "injection_probe", "generic_200"): 0.08,
        ("Safe_Parameterized", "injection_probe", "db_error_or_delay"): 0.02,
        ("Safe_Parameterized", "injection_probe", "generic_200"): 0.95,

        # Baseline unauthenticated check
        ("BOLA", "unauthenticated_baseline", "401_unauthorized"): 0.85,
        ("Public_Resource", "unauthenticated_baseline", "200_ok"): 0.95,
    }

    @classmethod
    def get_likelihood(
        cls,
        hypothesis_type: str,
        action_kind: str,
        outcome: str
    ) -> float:
        """إرجاع الاحتمال الشرطي P(outcome | H, a)"""
        val = cls._DEFAULT_LIKELIHOODS.get((hypothesis_type, action_kind, outcome))
        if val is not None:
            return val
        # Default fallback
        if "cross_tenant" in outcome or "error" in outcome or "diff" in outcome:
            return 0.80 if hypothesis_type in ["BOLA", "SQLi", "BFLA"] else 0.10
        return 0.50


class PosteriorUpdater:
    """
    محدث المعتقدات البايزي:
    يطبق مبرهنة بايز ويضمن تطبيع الاحتماليات ليكون مجموعها 1.0 بالضبط
    """

    @staticmethod
    def update(
        prior_distribution: Dict[str, float],
        action_kind: str,
        observed_outcome: str,
        hypotheses_types: Optional[Dict[str, str]] = None
    ) -> Dict[str, float]:
        """
        P(H_i | o, a) = [ P(o | H_i, a) * P(H_i) ] / sum_j [ P(o | H_j, a) * P(H_j) ]
        """
        if not prior_distribution:
            return {}

        types = hypotheses_types or {}
        unnormalized: Dict[str, float] = {}

        for h_id, prior in prior_distribution.items():
            h_type = types.get(h_id, h_id)
            likelihood = LikelihoodModel.get_likelihood(h_type, action_kind, observed_outcome)
            unnormalized[h_id] = likelihood * prior

        total_marginal = sum(unnormalized.values())
        if total_marginal <= 1e-12:
            # Degenerate case, preserve prior
            return dict(prior_distribution)

        # Normalize strictly
        posterior = {h: round(prob / total_marginal, 4) for h, prob in unnormalized.items()}

        # Numerical stabilization to ensure sum == 1.0
        diff = 1.0 - sum(posterior.values())
        if abs(diff) > 1e-6 and posterior:
            first_key = list(posterior.keys())[0]
            posterior[first_key] = round(posterior[first_key] + diff, 4)

        return posterior
