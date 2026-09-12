"""
Expected Information Gain (EIG) Engine
Mathematically evaluates the expected entropy reduction for any candidate action:
EIG(a) = H(Belief) - sum_{o in Outcomes} P(o | a) * H(Belief | o, a)
"""
import logging
from typing import Dict, List, Any, Optional

from core.reasoning.action_model import ActionDescriptor, ActionKind
from core.reasoning.uncertainty import UncertaintyModel
from core.reasoning.bayesian_engine import PosteriorUpdater

log = logging.getLogger("core.reasoning.information_gain")


class InformationGainEngine:
    """
    محرك العائد المعلوماتي المتوقع (EIG Engine):
    يحسب كمية المعلومات (بالـ Bits) المتوقع كسبها من أي فحص مقترح
    قبل إرسال أي باكت إلى الشبكة!
    """

    @staticmethod
    def compute_eig(
        prior_distribution: Dict[str, float],
        action: ActionDescriptor,
        hypotheses_types: Optional[Dict[str, str]] = None
    ) -> float:
        """
        حساب العائد المعلوماتي المتوقع:
        EIG(a) = H(B) - E_o[ H(B | o, a) ]
        """
        if not prior_distribution or len(prior_distribution) <= 1:
            return 0.0

        current_entropy = UncertaintyModel.compute_entropy(prior_distribution)
        if current_entropy <= 1e-9:
            return 0.0

        outcomes = action.predicted_outcomes
        if not outcomes:
            # Actions without predicted differential outcomes (e.g. passive recon, baseline ping)
            # have 0 bits of immediate hypothesis entropy reduction, but may have goal/evidence value!
            return 0.0

        total_p = sum(outcomes.values())
        if total_p <= 0.0:
            return 0.0

        expected_posterior_entropy = 0.0

        for outcome, prob in outcomes.items():
            p_outcome = prob / total_p

            # Calculate posterior belief under this hypothetical outcome
            posterior_b = PosteriorUpdater.update(
                prior_distribution=prior_distribution,
                action_kind=action.tool_name,
                observed_outcome=outcome,
                hypotheses_types=hypotheses_types
            )

            h_posterior = UncertaintyModel.compute_entropy(posterior_b)
            expected_posterior_entropy += p_outcome * h_posterior

        eig = round(max(0.0, current_entropy - expected_posterior_entropy), 4)
        log.debug(f"[InformationGain] Action {action.action_id} ({action.tool_name}): Current H={current_entropy:.3f}, E[H]={expected_posterior_entropy:.3f} -> EIG={eig:.4f} bits")
        return eig
