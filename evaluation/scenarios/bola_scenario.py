"""
BOLA Multi-Tenant Benchmark Scenario
Simulates an enterprise multi-tenant API endpoint (/api/v2/organizations/{org_id}/invoices/{id}).
Ground Truth: BOLA exists (Cross-tenant access succeeds with tenant data).
Optimal path:
1. Disambiguation / Auth Baseline -> 401 proves authenticated
2. Cross-tenant differential probe -> 200 with tenant data proves BOLA
"""
from typing import Dict, List, Any, Optional, Tuple

from evaluation.scenarios.base_scenario import BenchmarkScenario
from core.reasoning.action_model import ActionDescriptor, ActionKind
from core.reasoning.belief_state import BeliefState
from core.attack_graph.graph import CausalAttackGraph
from agents.security_intelligence.schemas import EvidenceItem, EvidenceType


class BOLAMultiTenantScenario(BenchmarkScenario):
    """سيناريو فحص واختبار عزل المستأجرين BOLA"""

    def __init__(self):
        super().__init__(name="BOLA_MultiTenant_Enterprise", category="BOLA", optimal_steps=2)

    def get_initial_hypotheses(self) -> Dict[str, float]:
        return {
            "BOLA": 0.50,
            "Public_Resource": 0.30,
            "Strict_AuthZ": 0.20
        }

    def get_candidate_actions(self) -> List[ActionDescriptor]:
        return [
            ActionDescriptor(
                action_id="act_baseline",
                action_kind=ActionKind.BASELINE,
                tool_name="unauthenticated_baseline",
                target="https://api.corp.local/v2/invoices/100",
                predicted_outcomes={"401_unauthorized": 0.70, "200_ok": 0.30},
                estimated_cost=0.5,
                expected_goal_delta=0.4,
                expected_evidence_value=0.5,
                rationale="Test if endpoint requires authentication to eliminate Public_Resource"
            ),
            ActionDescriptor(
                action_id="act_cross_tenant",
                action_kind=ActionKind.DISAMBIGUATION,
                tool_name="cross_tenant_probe",
                target="https://api.corp.local/v2/invoices/100",
                predicted_outcomes={"200_cross_tenant_data": 0.50, "403_forbidden": 0.50},
                estimated_cost=1.0,
                expected_goal_delta=0.8,
                expected_evidence_value=0.9,
                rationale="Request Alice invoice using Bob token to test authorization boundary"
            ),
            ActionDescriptor(
                action_id="act_redundant_recon",
                action_kind=ActionKind.DISCOVERY,
                tool_name="nmap",
                target="https://api.corp.local",
                predicted_outcomes={},  # EIG will be 0.0
                estimated_cost=2.0,
                expected_goal_delta=0.0,
                expected_evidence_value=0.1,
                rationale="Redundant port scan"
            )
        ]

    def simulate_execution(self, action: ActionDescriptor) -> Tuple[str, Optional[EvidenceItem]]:
        if action.tool_name == "unauthenticated_baseline":
            ev = EvidenceItem(
                type=EvidenceType.AUTH_ANOMALY,
                source="ScenarioSimulator",
                description="Endpoint returned 401 Unauthorized for anonymous request",
                data={"status_code": 401}
            )
            return "401_unauthorized", ev

        elif action.tool_name == "cross_tenant_probe":
            ev = EvidenceItem(
                type=EvidenceType.BEHAVIOR_DIFF,
                source="ScenarioSimulator",
                description="Cross-tenant access succeeded: Bob accessed Alice confidential invoice 100",
                data={"status_code": 200, "tenant_a": "alice_data", "caller": "bob"},
                weight=0.95
            )
            return "200_cross_tenant_data", ev

        return "generic_200", None

    def check_goal(self, belief: BeliefState, graph: CausalAttackGraph) -> Tuple[bool, str]:
        # Goal achieved when BOLA probability >= 0.85 and evidence linked
        p_bola = belief.hypotheses.get("BOLA", 0.0)
        if p_bola >= 0.85 and len(belief.evidence_refs) >= 1:
            return True, f"BOLA confirmed with belief P={p_bola:.2f} and differential proof."
        return False, f"BOLA probability ({p_bola:.2f}) below confidence threshold (0.85)."

    def get_ground_truth(self) -> Dict[str, Any]:
        return {
            "has_vulnerability": True,
            "vulnerability_type": "BOLA",
            "cwe": "CWE-639"
        }
