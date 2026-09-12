"""
Attack Graph Edges (LuaN1ao-Inspired)
Defines semantic causal relationships connecting nodes in the Attack Graph.
"""
import uuid
import time
from enum import Enum
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field


class EdgeType(str, Enum):
    EXPOSES = "EXPOSES"                     # Asset exposes Service, Service exposes Endpoint
    RUNS_ON = "RUNS_ON"                     # Service runs on Asset
    ACCEPTS_INPUT = "ACCEPTS_INPUT"         # Endpoint accepts Parameter
    AUTHENTICATED_AS = "AUTHENTICATED_AS"   # Session/Token is authenticated as Identity
    HAS_VULNERABILITY = "HAS_VULNERABILITY" # Asset/Endpoint has a Vulnerability
    EXPLOITS = "EXPLOITS"                   # Action or finding exploits a node
    TRANSITIONS_TO = "TRANSITIONS_TO"       # Sequential state transition
    ESCALATES_TO = "ESCALATES_TO"           # Low privilege escalates to High privilege
    LEADS_TO_IMPACT = "LEADS_TO_IMPACT"     # Vulnerability execution leads to specific Impact


class AttackEdge(BaseModel):
    """
    رابط سببي بين عقدتين في الرسم البياني للهجوم
    """
    id: str = Field(default_factory=lambda: f"EDGE-{uuid.uuid4().hex[:8]}")
    source_id: str
    target_id: str
    edge_type: EdgeType
    weight: float = 1.0
    confidence: float = 1.0
    properties: Dict[str, Any] = Field(default_factory=dict)
    provenance: Optional[str] = None
    created_at: float = Field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()
