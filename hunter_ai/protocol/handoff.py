"""
Hunter Agent Protocol v1: Structured Handoff Envelope
=====================================================
Defines the official protocol envelope for passing work between agents:
- Handoff validation
- Priority levels (low, medium, high, critical)
- Context pointers (Level 1 Summary, Level 2 Evidence Ref, Level 3 Raw Path)
"""
from __future__ import annotations

import time
import uuid
from enum import Enum
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any


class HandoffPriority(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class HandoffEnvelope:
    """
    مظروف التسليم بين الوكلاء (Handoff Envelope):
    يُرسل من الوكيل المنتهي إلى العقل (Brain) لإعادة توجيه المهمة للوكيل التالي مع الذاكرة المناسبة.
    """
    handoff_id: str = field(default_factory=lambda: f"hnd_{uuid.uuid4().hex[:8]}")
    handoff: bool = True
    from_agent: str = ""
    to_agent: str = ""
    task: str = ""
    context_id: str = ""  # job_id
    priority: HandoffPriority = HandoffPriority.MEDIUM
    summary: Dict[str, Any] = field(default_factory=dict)  # Level 1 summary context
    evidence_ref: Optional[str] = None                    # Level 2 pointer
    raw_data_path: Optional[str] = None                   # Level 3 pointer
    required_skill: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    accepted_by: Optional[str] = None
    completed: bool = False

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["priority"] = self.priority.value
        return d
