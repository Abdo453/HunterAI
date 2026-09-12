"""
Pedagogical Modes & Session Management
Enforces three distinct training modes:
1. TRAINING: Full Socratic assistance, conceptual breakdowns, and guidance.
2. PRACTICE: Independent reasoning with limited diagnostic hints upon deadlock.
3. EXAM: Strict zero-hint environment evaluating raw generalization on novel scenarios.
"""
from enum import Enum
from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field


class PedagogicalMode(str, Enum):
    TRAINING = "TRAINING"       # Socratic guidance, explanations on mistake
    PRACTICE = "PRACTICE"       # Independent with limited hints on stall
    EXAM = "EXAM"               # Zero hints, strict benchmark evaluation


class PedagogicalSession(BaseModel):
    """جلسة تدريبية محكومة بوضع بيداغوجي محدد"""
    session_id: str
    mode: PedagogicalMode
    hints_requested: int = 0
    max_hints_allowed: int = 0
    feedback_log: List[str] = Field(default_factory=list)

    def can_provide_hint(self) -> bool:
        if self.mode == PedagogicalMode.EXAM:
            return False
        if self.mode == PedagogicalMode.TRAINING:
            return True
        # PRACTICE mode: limited hints
        return self.hints_requested < self.max_hints_allowed


class PedagogicalSessionManager:
    """
    مدير الأوضاع التعليمية:
    يضبط مستوى المساعدة والتلميحات المسموحة للـ Agent
    """

    @staticmethod
    def create_session(session_id: str, mode: PedagogicalMode) -> PedagogicalSession:
        max_hints = {
            PedagogicalMode.TRAINING: 99,
            PedagogicalMode.PRACTICE: 2,
            PedagogicalMode.EXAM: 0
        }[mode]

        return PedagogicalSession(
            session_id=session_id,
            mode=mode,
            max_hints_allowed=max_hints
        )

    @staticmethod
    def request_hint(session: PedagogicalSession, skill_id: str, context: str = "") -> Dict[str, Any]:
        """طلب تلميح أثناء حل السيناريو"""
        if not session.can_provide_hint():
            return {
                "hint_granted": False,
                "reason": f"Hints are strictly prohibited in {session.mode.value} mode."
            }

        session.hints_requested += 1
        hint_text = f"Hint for {skill_id}: Compare response length and status code between true and false conditions."
        session.feedback_log.append(hint_text)

        return {
            "hint_granted": True,
            "hint": hint_text,
            "hints_remaining": max(0, session.max_hints_allowed - session.hints_requested)
        }
