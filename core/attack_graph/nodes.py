"""
Attack Graph Nodes (LuaN1ao & Cairn-Inspired)
Defines semantic entity nodes in the Causal Attack Graph:
Assets, Services, Endpoints, Parameters, Identities, Sessions, Credentials, Vulnerabilities, and Impacts.
"""
import time
import uuid
from enum import Enum
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field


class NodeType(str, Enum):
    OBSERVATION = "OBSERVATION"         # Raw perceptual output (status, length, headers)
    FACT = "FACT"                       # Verified empirical reality
    ASSET = "ASSET"                     # Host, IP, domain, container
    SERVICE = "SERVICE"                 # Network service (e.g., HTTP, SSH, PostgreSQL)
    ENDPOINT = "ENDPOINT"               # Web / API route (e.g., /api/v1/orders/{id})
    PARAMETER = "PARAMETER"             # Input parameter (query, body, header, cookie)
    IDENTITY = "IDENTITY"               # User account, role, service account
    SESSION = "SESSION"                 # Active authenticated session / token
    CREDENTIAL = "CREDENTIAL"           # Secret, API key, password, private key
    VULNERABILITY = "VULNERABILITY"     # Candidate or confirmed security flaw
    IMPACT = "IMPACT"                   # Security / business consequence (e.g., Data Exfiltration, RCE)


class AttackNode(BaseModel):
    """
    عقدة في الرسم البياني السببي للهجوم
    """
    id: str = Field(default_factory=lambda: f"NODE-{uuid.uuid4().hex[:8]}")
    node_type: NodeType
    label: str
    properties: Dict[str, Any] = Field(default_factory=dict)
    risk_score: float = Field(default=0.0, ge=0.0, le=10.0)
    compromised: bool = False
    verified: bool = False
    discovered_at: float = Field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()
