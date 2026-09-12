"""
Blind SQLi Benchmark Scenario
Simulates a database-backed search route (/products?search=).
Ground Truth: SQLi exists with boolean / syntax error differential.
"""
from typing import Dict, List, Any, Optional, Tuple

from evaluation.scenarios.base_scenario import BenchmarkScenario
from core.reasoning.action_model import ActionDescriptor, ActionKind
from core.reasoning.belief_state import BeliefState
from core.attack_graph.graph import CausalAttackGraph
from agents.security_intelligence.schemas import EvidenceItem, EvidenceType


class BlindSQLiScenario(BenchmarkScenario):
    """سيناريو فحص واختبار حقن قواعد البيانات SQLi"""

    def __init__(self):
        super().__init__(name="Blind_SQLi_Catalog", category="SQLi", optimal_steps=1)

    def get_initial_hypotheses(self) -> Dict[str, float]:
        return {
            "SQLi": 0.50,
            "Safe_Parameterized": 0.50
        }

    def get_candidate_actions(self) -> List[ActionDescriptor]:
        return [
            ActionDescriptor(
                action_id="act_sqli_probe",
                action_kind=ActionKind.DISAMBIGUATION,
                tool_name="injection_probe",
                target="https://shop.corp.local/products?search=test",
                predicted_outcomes={"db_error_or_delay": 0.50, "generic_200": 0.50},
                estimated_cost=1.0,
                expected_goal_delta=0.9,
                expected_evidence_value=0.95,
                rationale="Inject differential quote syntax and measure database error response"
            ),
            ActionDescriptor(
                action_id="act_whois",
                action_kind=ActionKind.DISCOVERY,
                tool_name="whois",
                target="shop.corp.local",
                predicted_outcomes={},  # EIG will be 0.0
                estimated_cost=1.5,
                expected_goal_delta=0.0,
                expected_evidence_value=0.0,
                rationale="Irrelevant domain registrar query"
            )
        ]

    def simulate_execution(self, action: ActionDescriptor) -> Tuple[str, Optional[EvidenceItem]]:
        if action.tool_name == "injection_probe":
            ev = EvidenceItem(
                type=EvidenceType.ERROR_DISCLOSURE,
                source="ScenarioSimulator",
                description="Database syntax error leaked: PostgreSQL 42601 syntax error near quote",
                data={"status_code": 500, "error": "PostgreSQL 42601"},
                weight=0.95
            )
            return "db_error_or_delay", ev
        return "generic_200", None

    def check_goal(self, belief: BeliefState, graph: CausalAttackGraph) -> Tuple[bool, str]:
        p_sqli = belief.hypotheses.get("SQLi", 0.0)
        if p_sqli >= 0.85 and len(belief.evidence_refs) >= 1:
            return True, f"SQLi confirmed with belief P={p_sqli:.2f}."
        return False, f"SQLi probability ({p_sqli:.2f}) below threshold."

    def get_ground_truth(self) -> Dict[str, Any]:
        return {
            "has_vulnerability": True,
            "vulnerability_type": "SQLi",
            "cwe": "CWE-89"
        }
