"""
HunterAI Experiment Notebook & Failure Intelligence
===================================================
Captures structured investigation traces:
Hypothesis -> Experiment -> Observation -> Verdict -> Lessons Learned.
Retains failure intelligence to prevent redundant exploration loops.
"""
from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("hunter_ai.experiment_notebook")


@dataclass
class ExperimentEntry:
    experiment_id: str
    hypothesis: str
    target_endpoint: str
    technique_applied: str
    probes_sent: int
    outcome: str  # "CONFIRMED", "REFUTED", "INCONCLUSIVE", "BLOCKED_BY_WAF"
    rejected_hypotheses: List[str] = field(default_factory=list)
    lessons_learned: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "experiment_id": self.experiment_id,
            "hypothesis": self.hypothesis,
            "target_endpoint": self.target_endpoint,
            "technique": self.technique_applied,
            "outcome": self.outcome,
            "lessons": self.lessons_learned,
        }


class ExperimentNotebook:
    """
    Epistemic memory maintaining experiment history and failure intelligence.
    """

    def __init__(self):
        self.entries: List[ExperimentEntry] = []
        self._blocked_techniques: Set[str] = set()  # "endpoint:technique"

    def record_experiment(
        self,
        hypothesis: str,
        endpoint: str,
        technique: str,
        probes_sent: int,
        outcome: str,
        lessons: str = ""
    ) -> ExperimentEntry:
        entry = ExperimentEntry(
            experiment_id=f"EXP-{uuid.uuid4().hex[:6].upper()}",
            hypothesis=hypothesis,
            target_endpoint=endpoint,
            technique_applied=technique,
            probes_sent=probes_sent,
            outcome=outcome,
            lessons_learned=lessons
        )
        self.entries.append(entry)

        # Failure intelligence: record techniques that repeatedly fail or get blocked by WAF
        if outcome in ("BLOCKED_BY_WAF", "STRICTLY_REFUTED"):
            self._blocked_techniques.add(f"{endpoint}:{technique}")

        return entry

    def is_technique_suppressed(self, endpoint: str, technique: str) -> bool:
        """Returns True if this technique previously failed and should not be repeated under same conditions"""
        return f"{endpoint}:{technique}" in self._blocked_techniques

    def get_summary(self) -> Dict[str, Any]:
        return {
            "total_experiments": len(self.entries),
            "suppressed_techniques_count": len(self._blocked_techniques),
            "recent_lessons": [e.lessons_learned for e in self.entries[-5:] if e.lessons_learned]
        }
