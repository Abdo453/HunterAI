"""
Multi-Agent Specialist Contracts (SickHackShark-Inspired)
Defines standardized contracts for task delegation and reporting between the Lead Analyst and specialists.
"""
import uuid
import time
from enum import Enum
from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field

from agents.security_intelligence.schemas import EvidenceItem


class SpecialistRole(str, Enum):
    RECON = "RECON"                     # Infrastructure, DNS, ports, CDN/WAF
    WEB = "WEB"                         # DOM, forms, HTML crawling, JS endpoints
    API = "API"                         # REST/GraphQL endpoints, parameter schemas
    AUTH = "AUTH"                       # JWT, OAuth, session management, RBAC/ABAC
    VULNERABILITY = "VULNERABILITY"     # Controlled probing, injection differential tests
    CRITIC = "CRITIC"                   # Adversarial auditor, false-positive filter
    LEAD_ANALYST = "LEAD_ANALYST"       # Master coordinator & synthesizer


class SpecialistTask(BaseModel):
    """
    عقد تكليف المهمة للوكيل المتخصص (SickHackShark Contract: WHO, WHAT, WHY, WHEN, TOOL)
    """
    id: str = Field(default_factory=lambda: f"TASK-{uuid.uuid4().hex[:8]}")
    role: SpecialistRole
    target: str
    objective: str
    context_node_ids: List[str] = Field(default_factory=list)
    authorized_tools: List[str] = Field(default_factory=list)
    expected_evidence: str = ""
    timeout: int = 60
    created_at: float = Field(default_factory=time.time)


class SpecialistReport(BaseModel):
    """
    تقرير الوكيل المتخصص الناتج عن تنفيذ المهمة
    """
    task_id: str
    role: SpecialistRole
    target: str
    success: bool
    observations: List[str] = Field(default_factory=list)
    discovered_nodes: List[Dict[str, Any]] = Field(default_factory=list)
    discovered_edges: List[Dict[str, Any]] = Field(default_factory=list)
    evidence_items: List[EvidenceItem] = Field(default_factory=list)
    hypotheses_suggested: List[str] = Field(default_factory=list)
    critic_approval: bool = True
    critic_notes: Optional[str] = None
    execution_time: float = 0.0
    completed_at: float = Field(default_factory=time.time)
