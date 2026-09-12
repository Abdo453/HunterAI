"""
Structured Agent Handoff Contract & Investigation Case
======================================================
Standardized investigation case contract for seamless state transfer between
autonomous agents and models:
WebAgent / BurpSensor -> FinderAgent -> VerifierAgent -> EvidenceCourt -> AutonomousBrain

Preserves complete contextual memory across agent boundaries without losing:
- Previous tests executed
- Failed attempts and why they failed
- Unexplored attack hypotheses
- Associated Burp requests and HTTP lineage
"""
from __future__ import annotations

import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class AgentHandoffContract:
    case_id: str = field(default_factory=lambda: f"case_{uuid.uuid4().hex[:8]}")
    target: str = ""
    endpoint: str = ""
    vuln_class: str = ""
    status: str = "OPEN"  # OPEN | IN_PROGRESS | VERIFIED | DISPROVED | INCONCLUSIVE
    confidence: float = 0.0
    source_agent: str = "WebAgent"
    assigned_agent: str = "VerifierAgent"
    next_action: str = "PROBE"  # OBSERVE | HYPOTHESIZE | PROBE | VERIFY | ADJUDICATE | REPORT
    observation: Dict[str, Any] = field(default_factory=dict)
    hypothesis: Dict[str, Any] = field(default_factory=dict)
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    tests_performed: List[Dict[str, Any]] = field(default_factory=list)
    tests_failed: List[Dict[str, Any]] = field(default_factory=list)
    tests_remaining: List[Dict[str, Any]] = field(default_factory=list)
    provenance_trace_id: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def record_test(
        self,
        test_name: str,
        payload: str,
        result: Dict[str, Any],
        succeeded: bool,
        error: Optional[str] = None
    ):
        """Records test execution in history preventing repeating failed experiments"""
        record = {
            "test_name": test_name,
            "payload": payload,
            "result": result,
            "succeeded": succeeded,
            "error": error,
            "timestamp": time.time()
        }
        self.tests_performed.append(record)
        if not succeeded:
            self.tests_failed.append(record)
        self.updated_at = time.time()

    def add_evidence(self, evidence_type: str, raw_data: Any, explanation: str):
        """Appends verified forensic evidence item to case dossier"""
        self.evidence.append({
            "type": evidence_type,
            "data": raw_data,
            "explanation": explanation,
            "timestamp": time.time()
        })
        self.updated_at = time.time()

    def transfer(
        self,
        to_agent: str,
        next_action: str,
        confidence_delta: Optional[float] = None
    ) -> AgentHandoffContract:
        """Transitions custody of case to another agent with action directive"""
        self.source_agent = self.assigned_agent
        self.assigned_agent = to_agent
        self.next_action = next_action
        if confidence_delta is not None:
            self.confidence = max(0.0, min(1.0, self.confidence + confidence_delta))
        self.updated_at = time.time()
        return self

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AgentHandoffContract:
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})

    def save(self, cases_dir: Path) -> Path:
        cases_dir.mkdir(parents=True, exist_ok=True)
        file_path = cases_dir / f"{self.case_id}.json"
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)
        return file_path

    @classmethod
    def load(cls, case_id: str, cases_dir: Path) -> Optional[AgentHandoffContract]:
        file_path = cases_dir / f"{case_id}.json"
        if not file_path.exists():
            return None
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls.from_dict(data)
