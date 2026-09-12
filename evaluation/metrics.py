"""
Reasoning Evaluation Metrics & Scorecard Generator
Calculates Step Efficiency, Decision Regret (EIG_opt - EIG_chosen),
Belief Calibration, False Positive Rate, and Information Yield.
"""
from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field


class ScenarioScorecard(BaseModel):
    """
    بطاقة الأداء المعياري لتقييم عقل الاستدلال
    """
    scenario_name: str
    category: str
    goal_achieved: bool
    actual_steps: int
    optimal_steps: int
    step_efficiency_pct: float
    decision_regret_bits: float
    information_yield_bits: float
    false_positive_rate_pct: float
    overall_reasoning_score: float

    def format_terminal_report(self) -> str:
        sep = "─" * 44
        return f"""
HunterAI Reasoning Benchmark Scorecard
{sep}
Scenario: {self.scenario_name} ({self.category})
Goal Achieved:            {'✅ YES' if self.goal_achieved else '❌ NO'}
Step Efficiency:          {self.step_efficiency_pct:.1f}% ({self.actual_steps} taken vs {self.optimal_steps} optimal)
Decision Regret:          {self.decision_regret_bits:.3f} bits
Information Yield:        {self.information_yield_bits:.3f} bits/step
False Positive Rate:      {self.false_positive_rate_pct:.1f}%
{sep}
Overall Reasoning Score:  {self.overall_reasoning_score:.1f} / 100
"""


class ReasoningMetrics:
    """
    حاسبة مقاييس الاستدلال المعرفي
    """

    @staticmethod
    def calculate_scorecard(
        scenario_name: str,
        category: str,
        goal_achieved: bool,
        actual_steps: int,
        optimal_steps: int,
        total_information_gain: float,
        decision_regrets: List[float],
        ground_truth: Dict[str, Any],
        predicted_finding_correct: bool
    ) -> ScenarioScorecard:
        # Step Efficiency: optimal / actual
        efficiency = min(1.0, optimal_steps / max(1, actual_steps)) * 100.0

        # Mean Decision Regret
        avg_regret = sum(decision_regrets) / max(1, len(decision_regrets)) if decision_regrets else 0.0

        # Information yield per step
        info_yield = total_information_gain / max(1, actual_steps)

        # False positive rate: if no vuln was present but agent confirmed one, or wrong vuln type
        fp_rate = 0.0 if predicted_finding_correct else 100.0

        # Overall weighted composite score (0 to 100)
        score = (
            (0.35 * efficiency)
            + (0.35 * (100.0 if goal_achieved and predicted_finding_correct else 0.0))
            + (0.20 * max(0.0, 100.0 - (avg_regret * 100.0)))
            + (0.10 * min(100.0, info_yield * 100.0))
        )

        return ScenarioScorecard(
            scenario_name=scenario_name,
            category=category,
            goal_achieved=goal_achieved,
            actual_steps=actual_steps,
            optimal_steps=optimal_steps,
            step_efficiency_pct=round(efficiency, 1),
            decision_regret_bits=round(avg_regret, 3),
            information_yield_bits=round(info_yield, 3),
            false_positive_rate_pct=round(fp_rate, 1),
            overall_reasoning_score=round(score, 1)
        )
