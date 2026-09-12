"""
Governed Tool Gateway Schemas & Risk Tiers (CyberStrikeAI-Inspired)
Enforces controlled execution contracts, risk classification, policy verdicts, and evidence generation.
"""
import time
import uuid
from enum import Enum
from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field

from agents.security_intelligence.schemas import EvidenceItem


class RiskTier(str, Enum):
    TIER_0_PASSIVE = "TIER_0_PASSIVE"               # Zero risk: Passive inspection, DNS, WHOIS, read-only logs
    TIER_1_RECON_ACTIVE = "TIER_1_RECON_ACTIVE"     # Low risk: Port scanning, tech discovery, non-intrusive crawling
    TIER_2_PROBE = "TIER_2_PROBE"                   # Medium risk: Parameter probing, auth differential checks, harmless fuzzing
    TIER_3_EXPLOIT_POC = "TIER_3_EXPLOIT_POC"       # High risk: Controlled PoC verification, privilege escalation test
    TIER_4_PROHIBITED_DESTRUCTIVE = "TIER_4_PROHIBITED_DESTRUCTIVE" # Extreme risk: Database drops, disk wipes, DoS, forbidden


class ActionProposal(BaseModel):
    """
    مقترح الأكشن الصادر من الوكيل الذكي (LLM / Agent):
    لا يُنفذ مباشرة أبداً بل يخضع لفحص السياسات ومصنف المخاطر
    """
    id: str = Field(default_factory=lambda: f"PROP-{uuid.uuid4().hex[:8]}")
    proposing_agent: str = "AutonomousBrain"
    target: str
    tool_name: str
    command_args: str = ""
    action_type: str = "CLI_TOOL"  # "HTTP_REQUEST", "CLI_TOOL", "SMART_POC", "PORT_SCAN"
    rationale: str = ""
    expected_evidence: str = ""
    is_destructive: bool = False
    timeout: int = 120
    created_at: float = Field(default_factory=time.time)


class PolicyVerdict(BaseModel):
    """
    قرار محرك السياسات حول الموافقة على المقترح أو حظره
    """
    allowed: bool
    risk_tier: RiskTier
    status: str  # "APPROVED", "BLOCKED_SCOPE", "BLOCKED_RISK", "BLOCKED_DESTRUCTIVE", "BLOCKED_ACTIVE_DISALLOWED"
    reason: str
    sanitized_args: Optional[str] = None
    evaluated_at: float = Field(default_factory=time.time)


class GovernedExecutionResult(BaseModel):
    """
    نتيجة التنفيذ المحكوم بما فيها المخرجات الخام والأدلة المولدة آلياً
    """
    proposal_id: str
    tool_name: str
    target: str
    success: bool
    blocked: bool = False
    risk_tier: RiskTier
    raw_stdout: str = ""
    raw_stderr: str = ""
    returncode: int = 0
    duration: float = 0.0
    evidence_item: Optional[EvidenceItem] = None
    error: Optional[str] = None
    executed_at: float = Field(default_factory=time.time)
