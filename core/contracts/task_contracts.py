"""
HunterAI Unified Task & Tool Execution Contracts (P0)
======================================================
Implements strict architectural contracts for all agents and tools:
  1. ToolExecutionResult: Universal contract for any tool execution
     (Task, Target, Action, Raw, Normalized, Errors, Evidence, Coverage Limits, Unknowns, Next Steps)
  2. TaskContract: Lifecycle contract for missions & tasks
     (Ownership, Success Criteria, Dependencies, Status: PENDING->READY->RUNNING->REVIEW->DONE)
  3. EvidenceArtifact: Structured atomic evidence unit linked to Evidence Court & PoE
"""
from __future__ import annotations

import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


class AgentTeam(str, Enum):
    STRATEGIST   = "STRATEGIST"
    RECON        = "RECON"
    WEB          = "WEB"
    NETWORK      = "NETWORK"
    API          = "API"
    JAVASCRIPT   = "JAVASCRIPT"
    HYPOTHESIS   = "HYPOTHESIS"
    VERIFICATION = "VERIFICATION"
    REPORTING    = "REPORTING"


class TaskLifecycleStatus(str, Enum):
    PENDING   = "PENDING"     # Created, waiting for dependencies
    READY     = "READY"       # Dependencies satisfied, ready for pickup
    RUNNING   = "RUNNING"     # Actively being executed by owner agent
    REVIEW    = "REVIEW"      # Execution finished, waiting for independent reviewer
    DONE      = "DONE"        # Review passed & evidence verified
    BLOCKED   = "BLOCKED"     # Blocked by dependency failure or scope violation
    FAILED    = "FAILED"      # Execution failed after retries
    CANCELLED = "CANCELLED"   # Cancelled by Master Brain / Operator


class EvidenceSignificance(str, Enum):
    OBSERVATION = "OBSERVATION"  # Informational surface signal
    ANOMALY     = "ANOMALY"      # Unexpected behavior or parameter sensitivity
    HYPOTHESIS  = "HYPOTHESIS"   # Testable proposition
    PROOF       = "PROOF"        # Causal differential proof or PoE verified payload


@dataclass
class EvidenceArtifact:
    """Atomic evidence record linked into the Evidence Graph."""
    evidence_id: str = field(default_factory=lambda: f"EV-{uuid.uuid4().hex[:6].upper()}")
    significance: EvidenceSignificance = EvidenceSignificance.OBSERVATION
    source_tool: str = ""
    target: str = ""
    description: str = ""
    request_id: Optional[str] = None      # REQ-XXXXXX in CaptureStore
    response_status: Optional[int] = None
    response_hash: Optional[str] = None
    payload_used: Optional[str] = None
    diff_data: Dict[str, Any] = field(default_factory=dict)
    poe_verified: bool = False
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            **asdict(self),
            "significance": self.significance.value,
        }


@dataclass
class ToolExecutionResult:
    """
    Inviolable Universal Tool Contract.
    Every tool adapter (Nmap, Katana, FFuf, Burp, Browser, Subfinder)
    MUST return this standardized schema.
    """
    execution_id: str = field(default_factory=lambda: f"EXEC-{uuid.uuid4().hex[:6].upper()}")
    task_id: str = ""
    tool_name: str = ""
    action: str = ""
    target: str = ""
    parameters: Dict[str, Any] = field(default_factory=dict)
    
    # Execution outcomes
    success: bool = True
    exit_code: int = 0
    duration_ms: float = 0.0
    
    # Data payloads
    raw_output: str = ""
    normalized_data: Dict[str, Any] = field(default_factory=dict)
    
    # Diagnostics & safety
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    # Structured failure category (TOOL_UNAVAILABLE / NONZERO_EXIT / TIMEOUT /
    # EXECUTION_ERROR / POLICY_DENIED / POLICY_ERROR). Empty when not a failure.
    error_category: str = ""
    
    # Generated evidence & intelligence
    evidence_artifacts: List[EvidenceArtifact] = field(default_factory=list)
    
    # Coverage & Gaps
    covered_items: List[str] = field(default_factory=list)      # Endpoints/hosts actually probed
    coverage_limits: List[str] = field(default_factory=list)    # Port range, rate limits, depth
    unresolved_unknowns: List[str] = field(default_factory=list)# What couldn't be determined
    
    # Strategic feedback to Master Brain
    recommended_next_steps: List[Dict[str, Any]] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["evidence_artifacts"] = [e.to_dict() if hasattr(e, "to_dict") else e for e in self.evidence_artifacts]
        return data


@dataclass
class TaskContract:
    """
    Task Entity for the Multi-Agent Investigation System.
    Governed by clear ownership, independent review, and verifiable success conditions.
    """
    task_id: str = field(default_factory=lambda: f"TASK-{uuid.uuid4().hex[:6].upper()}")
    title: str = ""
    team: AgentTeam = AgentTeam.RECON
    owner_agent: str = ""                # Agent responsible for execution
    reviewer_agent: str = ""             # Independent agent validating the result
    
    target: str = ""
    action: str = ""
    parameters: Dict[str, Any] = field(default_factory=dict)
    priority: int = 5                    # 1 (Highest) to 10 (Lowest)
    
    # Dependencies & Invariants
    depends_on: List[str] = field(default_factory=list)
    success_criteria: List[str] = field(default_factory=list)
    scope_verified: bool = False
    
    # State tracking
    status: TaskLifecycleStatus = TaskLifecycleStatus.PENDING
    retry_count: int = 0
    max_retries: int = 2
    
    # Results & Review
    result: Optional[ToolExecutionResult] = None
    review_notes: str = ""
    review_passed: Optional[bool] = None
    
    # Timestamps
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    completed_at: Optional[float] = None

    def mark_ready(self) -> bool:
        if self.status == TaskLifecycleStatus.PENDING:
            self.status = TaskLifecycleStatus.READY
            return True
        return False

    def mark_running(self, owner: str) -> bool:
        if self.status in (TaskLifecycleStatus.READY, TaskLifecycleStatus.PENDING):
            self.status = TaskLifecycleStatus.RUNNING
            self.owner_agent = owner
            self.started_at = time.time()
            return True
        return False

    def submit_for_review(self, result: ToolExecutionResult) -> bool:
        """Called when owner finishes; transfers task to independent review."""
        if self.status == TaskLifecycleStatus.RUNNING:
            self.status = TaskLifecycleStatus.REVIEW
            self.result = result
            return True
        return False

    def approve_review(self, reviewer: str, notes: str = "") -> bool:
        """Called by reviewer agent; seals task as DONE."""
        if self.status == TaskLifecycleStatus.REVIEW:
            self.reviewer_agent = reviewer
            self.review_notes = notes
            self.review_passed = True
            self.status = TaskLifecycleStatus.DONE
            self.completed_at = time.time()
            return True
        return False

    def reject_review(self, reviewer: str, reason: str) -> bool:
        """Called when review fails; flags task or retries."""
        if self.status == TaskLifecycleStatus.REVIEW:
            self.reviewer_agent = reviewer
            self.review_notes = reason
            self.review_passed = False
            if self.retry_count < self.max_retries:
                self.retry_count += 1
                self.status = TaskLifecycleStatus.READY
            else:
                self.status = TaskLifecycleStatus.FAILED
            return True
        return False

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["team"] = self.team.value
        data["status"] = self.status.value
        if self.result and hasattr(self.result, "to_dict"):
            data["result"] = self.result.to_dict()
        return data
