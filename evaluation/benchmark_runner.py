"""
Automated Benchmark Runner
Executes benchmark scenarios against the AutonomousReasoningLoop and produces quantitative scorecards.
"""
import logging
from typing import Dict, List, Any

from evaluation.scenarios.base_scenario import BenchmarkScenario
from evaluation.scenarios.bola_scenario import BOLAMultiTenantScenario
from evaluation.scenarios.sqli_scenario import BlindSQLiScenario
from evaluation.metrics import ReasoningMetrics, ScenarioScorecard
from core.reasoning.reasoning_loop import AutonomousReasoningLoop, LoopStatus
from core.reasoning.belief_state import BeliefState
from core.reasoning.information_gain import InformationGainEngine
from core.attack_graph.graph import CausalAttackGraph

log = logging.getLogger("evaluation.benchmark_runner")


class BenchmarkRunner:
    """
    مشغّل ومقيّم سيناريوهات الاستدلال المعياري
    """

    def __init__(self):
        self.scenarios: List[BenchmarkScenario] = [
            BOLAMultiTenantScenario(),
            BlindSQLiScenario()
        ]

    def run_scenario(self, scenario: BenchmarkScenario, max_steps: int = 6) -> ScenarioScorecard:
        """
        تشغيل سيناريو واحد وتقييم القرارات وحساب بطاقة الأداء
        """
        belief = BeliefState(investigation_id=f"BENCH-{scenario.category}")
        belief.set_hypotheses(scenario.get_initial_hypotheses(), justification="Scenario Initialization")
        graph = CausalAttackGraph(target=scenario.name)
        loop = AutonomousReasoningLoop(target=scenario.name, belief_state=belief, attack_graph=graph)

        steps_taken = 0
        total_info_gain = 0.0
        decision_regrets: List[float] = []
        goal_achieved = False

        while steps_taken < max_steps and not goal_achieved:
            steps_taken += 1
            candidates = scenario.get_candidate_actions()

            # Calculate EIG for all candidates to determine theoretical optimal action
            eigs = {
                c.action_id: InformationGainEngine.compute_eig(belief.hypotheses, c)
                for c in candidates
            }
            optimal_eig = max(eigs.values()) if eigs else 0.0

            # Execute reasoning step
            step_res = loop.step(
                candidates=candidates,
                executor_callback=scenario.simulate_execution,
                goal_evaluator=scenario.check_goal
            )

            chosen_action_id = step_res.get("action_taken")
            chosen_eig = step_res.get("information_gain_bits", 0.0)
            total_info_gain += max(0.0, chosen_eig)

            # Measure Decision Regret: max(0.0, optimal_eig - chosen_eig)
            regret = max(0.0, round(optimal_eig - chosen_eig, 3))
            decision_regrets.append(regret)

            if step_res.get("status") == LoopStatus.GOAL_ACHIEVED or step_res.get("goal_satisfied"):
                goal_achieved = True
                break

            if step_res.get("status") == LoopStatus.DEADLOCK_DETECTED:
                break

        # Check finding correctness against ground truth
        ground_truth = scenario.get_ground_truth()
        best_hyp = max(belief.hypotheses.items(), key=lambda x: x[1])[0] if belief.hypotheses else None
        predicted_correct = (best_hyp == ground_truth.get("vulnerability_type"))

        scorecard = ReasoningMetrics.calculate_scorecard(
            scenario_name=scenario.name,
            category=scenario.category,
            goal_achieved=goal_achieved,
            actual_steps=steps_taken,
            optimal_steps=scenario.optimal_steps,
            total_information_gain=total_info_gain,
            decision_regrets=decision_regrets,
            ground_truth=ground_truth,
            predicted_finding_correct=predicted_correct
        )
        return scorecard

    def run_all_benchmarks(self) -> List[ScenarioScorecard]:
        scorecards = []
        for sc in self.scenarios:
            card = self.run_scenario(sc)
            scorecards.append(card)
        return scorecards
