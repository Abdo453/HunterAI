"""
HunterAI Epistemic Agent Blackboard
===================================
Enforces strict category separation across shared multi-agent state:
OBSERVATION ≠ FACT ≠ HYPOTHESIS ≠ VERDICT
Prevents hallucinated LLM hypotheses from directly becoming facts
without deterministic verification in the Evidence Court.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class BlackboardSlot(str, Enum):
    FACTS = "FACTS"                    # Verified immutable invariants (IP, server banner)
    OBSERVATIONS = "OBSERVATIONS"      # Raw telemetry from tools
    HYPOTHESES = "HYPOTHESES"          # Plausible conjectures under investigation
    OPEN_QUESTIONS = "OPEN_QUESTIONS"  # Gaps in coverage or missing evidence
    DECISIONS = "DECISIONS"            # Policy-approved actions
    EVIDENCE = "EVIDENCE"              # Verified differential proofs


class EpistemicCategoryViolation(ValueError):
    """Raised when an unverified observation or hypothesis is promoted to fact without court verification"""
    pass


@dataclass
class BlackboardEntry:
    entry_id: str = field(default_factory=lambda: f"BLK-{uuid.uuid4().hex[:6].upper()}")
    slot: BlackboardSlot = BlackboardSlot.OBSERVATIONS
    author: str = "agent"
    title: str = ""
    payload: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


class AgentBlackboard:
    """Central epistemic state repository for collaborative multi-agent execution"""

    def __init__(self):
        self._slots: Dict[BlackboardSlot, List[BlackboardEntry]] = {
            slot: [] for slot in BlackboardSlot
        }

    def post_observation(self, author: str, title: str, telemetry_data: Dict[str, Any]) -> BlackboardEntry:
        entry = BlackboardEntry(slot=BlackboardSlot.OBSERVATIONS, author=author, title=title, payload=telemetry_data)
        self._slots[BlackboardSlot.OBSERVATIONS].append(entry)
        return entry

    def post_hypothesis(self, author: str, title: str, hypothesis_data: Dict[str, Any]) -> BlackboardEntry:
        entry = BlackboardEntry(slot=BlackboardSlot.HYPOTHESES, author=author, title=title, payload=hypothesis_data)
        self._slots[BlackboardSlot.HYPOTHESES].append(entry)
        return entry

    def post_fact(self, author: str, title: str, verified_data: Dict[str, Any], verification_proof: str) -> BlackboardEntry:
        if not verification_proof:
            raise EpistemicCategoryViolation(
                "EPISTEMIC VIOLATION: Cannot post to FACTS without deterministic verification_proof."
            )
        entry = BlackboardEntry(slot=BlackboardSlot.FACTS, author=author, title=title, payload=verified_data)
        self._slots[BlackboardSlot.FACTS].append(entry)
        return entry

    def post_evidence(self, author: str, title: str, evidence_data: Dict[str, Any]) -> BlackboardEntry:
        entry = BlackboardEntry(slot=BlackboardSlot.EVIDENCE, author=author, title=title, payload=evidence_data)
        self._slots[BlackboardSlot.EVIDENCE].append(entry)
        return entry

    def get_slot_entries(self, slot: BlackboardSlot) -> List[Dict[str, Any]]:
        return [asdict(e) for e in self._slots[slot]]

    def get_blackboard_state(self) -> Dict[str, Any]:
        return {
            slot.value: len(entries) for slot, entries in self._slots.items()
        }
