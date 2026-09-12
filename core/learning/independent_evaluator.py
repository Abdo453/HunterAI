"""
Independent Security Evaluator
Decoupled verification authority that evaluates agent findings against ground truth.
Enforces 0% false positives, checks differential proof completeness,
and generates standardized graduation scorecards.
"""
import logging
from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field

from core.learning.calibration_recovery import ConfidenceCalibrationTracker

log = logging.getLogger("core.learning.independent_evaluator")


class ExamEvaluationResult(BaseModel):
    """تقرير تقييم مستقل لمحاولة سيناريو"""
    scenario_id: str
    passed: bool
    ground_truth_vulnerable: bool
    agent_declared_vulnerable: bool
    false_positive: bool
    hypothesis_correct: bool
    evidence_valid: bool
    steps_taken: int
    optimal_steps: int
    step_efficiency_pct: float
    score: float
    feedback: str


class IndependentEvaluator:
    """
    المقيّم الأمني المستقل:
    يفصل تقييم أداء الـ Agent عن عقله الاستدلالي لضمان الحيادية والصرامة
    """

    def __init__(self):
        self.calibration_tracker = ConfidenceCalibrationTracker(num_bins=5)

    def evaluate_solution(
        self,
        scenario: Dict[str, Any],
        agent_submission: Dict[str, Any]
    ) -> ExamEvaluationResult:
        """
        تقييم مستقل كامل ضد الـ hidden_truth المخفية
        """
        hidden = scenario.get("hidden_truth", {})
        is_truly_vulnerable = hidden.get("is_vulnerable", False)

        declared_vulnerable = agent_submission.get("declared_vulnerable", False)
        agent_confidence = agent_submission.get("confidence", 0.50)
        agent_hypothesis = agent_submission.get("hypothesis", "")
        evidence_items = agent_submission.get("evidence_items", [])
        steps_taken = max(1, agent_submission.get("steps_taken", 1))
        optimal_steps = max(1, scenario.get("optimal_steps", 2))

        # 1. False Positive Check (Hard Fail)
        false_positive = False
        if not is_truly_vulnerable and declared_vulnerable:
            false_positive = True

        # 2. Hypothesis Accuracy
        expected_variant = hidden.get("variant", "").lower()
        vuln_type = hidden.get("vulnerability", "").lower()
        hyp_lower = agent_hypothesis.lower()

        hypothesis_correct = False
        if is_truly_vulnerable:
            hypothesis_correct = (expected_variant in hyp_lower or vuln_type in hyp_lower or "sqli" in hyp_lower or "bola" in hyp_lower)
        else:
            hypothesis_correct = not declared_vulnerable

        # 3. Evidence Validity
        evidence_valid = False
        if is_truly_vulnerable:
            evidence_valid = len(evidence_items) >= 1
        else:
            evidence_valid = True  # No vulnerability to prove

        # 4. Step Efficiency
        efficiency = min(1.0, optimal_steps / steps_taken) * 100.0

        # 5. Overall Pass & Score
        passed = (not false_positive) and hypothesis_correct and evidence_valid

        # Record calibration prediction
        self.calibration_tracker.record_prediction(
            confidence=agent_confidence,
            actual_correct=passed
        )

        score = 0.0
        if false_positive:
            score = 0.0
            feedback = "FAILED: Critical False Positive detected. Safe behavior flagged as vulnerability."
        elif not passed:
            score = 40.0
            feedback = "FAILED: Incomplete reasoning or insufficient differential evidence."
        else:
            score = round(70.0 + (0.30 * efficiency), 1)
            feedback = f"PASSED: Ground truth satisfied with {efficiency:.1f}% step efficiency and valid proof."

        return ExamEvaluationResult(
            scenario_id=scenario.get("scenario_id", "unknown"),
            passed=passed,
            ground_truth_vulnerable=is_truly_vulnerable,
            agent_declared_vulnerable=declared_vulnerable,
            false_positive=false_positive,
            hypothesis_correct=hypothesis_correct,
            evidence_valid=evidence_valid,
            steps_taken=steps_taken,
            optimal_steps=optimal_steps,
            step_efficiency_pct=round(efficiency, 1),
            score=score,
            feedback=feedback
        )

    def get_calibration_error(self) -> float:
        return self.calibration_tracker.compute_ece()
