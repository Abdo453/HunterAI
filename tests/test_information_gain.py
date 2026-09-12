"""
Unit & Mathematical Tests for InformationGainEngine
Tests: EIG non-negativity (EIG >= 0), disambiguating vs redundant actions, and zero prior entropy
"""
import pytest

from core.reasoning.information_gain import InformationGainEngine
from core.reasoning.action_model import ActionDescriptor, ActionKind


class TestInformationGain:
    def test_eig_non_negativity(self):
        """Mathematical invariant: Expected Information Gain must be >= 0"""
        prior = {"BOLA": 0.60, "Public_Resource": 0.40}
        action = ActionDescriptor(
            action_kind=ActionKind.DISAMBIGUATION,
            tool_name="cross_tenant_probe",
            target="https://target.local",
            predicted_outcomes={"200_cross_tenant_data": 0.50, "403_forbidden": 0.50}
        )
        eig = InformationGainEngine.compute_eig(prior, action)
        assert eig >= 0.0

    def test_disambiguating_action_has_strictly_higher_eig_than_redundant(self):
        prior = {"BOLA": 0.50, "Public_Resource": 0.50}

        # Action 1: Disambiguating probe separating BOLA from Public
        disambiguating_action = ActionDescriptor(
            action_kind=ActionKind.DISAMBIGUATION,
            tool_name="cross_tenant_probe",
            target="https://target.local/invoices",
            predicted_outcomes={"200_cross_tenant_data": 0.50, "403_forbidden": 0.50}
        )
        eig_useful = InformationGainEngine.compute_eig(prior, disambiguating_action)

        # Action 2: Redundant port scan without differential outcome predictions
        redundant_action = ActionDescriptor(
            action_kind=ActionKind.DISCOVERY,
            tool_name="nmap",
            target="https://target.local",
            predicted_outcomes={}
        )
        eig_redundant = InformationGainEngine.compute_eig(prior, redundant_action)

        assert eig_redundant == 0.0
        assert eig_useful > 0.0
        assert eig_useful > eig_redundant

    def test_zero_prior_entropy_yields_zero_eig(self):
        # When belief is already 100% certain, no action can yield new information
        certain_prior = {"BOLA": 1.0, "Public_Resource": 0.0}
        action = ActionDescriptor(
            action_kind=ActionKind.DISAMBIGUATION,
            tool_name="cross_tenant_probe",
            target="https://target.local",
            predicted_outcomes={"200_cross_tenant_data": 0.50, "403_forbidden": 0.50}
        )
        eig = InformationGainEngine.compute_eig(certain_prior, action)
        assert eig == 0.0
