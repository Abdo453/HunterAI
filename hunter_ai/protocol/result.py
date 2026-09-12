"""
Hunter Agent Protocol v1: 5-Question Structured Task Result
============================================================
Every agent MUST answer the 5 core operational questions:
1. What did I do? (action_summary)
2. What did I find? (findings)
3. What is the confidence score? (confidence_score)
4. What is the next logical step? (next_step)
5. What do I need from another Agent? (handoff_request / needed_data)
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any


@dataclass
class StructuredFinding:
    type: str  # SQLi, XSS, SSRF, IDOR, InfoLeak
    title: str
    severity: str  # Critical, High, Medium, Low, Info
    confidence: float  # 0.0 to 1.0
    endpoint: str
    param_name: Optional[str] = None
    evidence_snippet: str = ""
    cwe_id: str = "CWE-Unknown"


@dataclass
class StructuredTaskResult:
    """
    عقد نتيجة المهمة الخماسي (5-Question Task Result Contract):
    يضمن الشفافية والاستدلال الدقيق بدلاً من مجرد القول 'أنا انتهيت'.
    """
    task_id: str
    agent_name: str
    completed: bool

    # 1. ماذا فعلت؟
    action_summary: str

    # 2. ماذا وجدت؟
    findings: List[StructuredFinding] = field(default_factory=list)

    # 3. درجة الثقة الكلية؟
    confidence_score: float = 0.90

    # 4. ما الخطوة القادمة؟
    next_step: str = ""

    # 5. ما الذي أحتاجه من Agent آخر؟
    next_agent: Optional[str] = None
    need: Optional[str] = None
    handoff_envelope: Optional[Dict[str, Any]] = None

    # Meta
    artifacts_created: List[str] = field(default_factory=list)
    latency_ms: float = 0.0
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "agent_name": self.agent_name,
            "completed": self.completed,
            "q1_action_summary": self.action_summary,
            "q2_findings": [asdict(f) for f in self.findings],
            "q3_confidence_score": round(self.confidence_score, 2),
            "q4_next_step": self.next_step,
            "q5_handoff": {
                "next_agent": self.next_agent,
                "need": self.need,
                "envelope": self.handoff_envelope
            },
            "artifacts_created": self.artifacts_created,
            "latency_ms": self.latency_ms,
            "timestamp": self.timestamp
        }
