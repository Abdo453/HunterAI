"""
HunterAI Pipeline Schemas
Pydantic v2 Models for every stage of the Autonomous Bug-Bounty Pipeline
"""
from __future__ import annotations

import time
import uuid
from enum import Enum
from typing import Any, Dict, List, Optional, Set
from pydantic import BaseModel, Field


class AssetCategory(str, Enum):
    API = "API"
    ADMIN = "ADMIN"
    DEVELOPMENT = "DEVELOPMENT"
    UPLOAD = "UPLOAD"
    AUTHENTICATION = "AUTHENTICATION"
    CDN = "CDN"
    WEB = "WEB"
    DATABASE = "DATABASE"
    OTHER = "OTHER"


class FindingStatus(str, Enum):
    CONFIRMED = "CONFIRMED"
    LIKELY = "LIKELY"
    UNVERIFIED = "UNVERIFIED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class FindingTier(str, Enum):
    OBSERVATION = "observation"
    HYPOTHESIS = "hypothesis"
    NEEDS_REVIEW = "needs_review"
    VERIFIED_FINDING = "verified_finding"


class ProfileMode(str, Enum):
    SAFE = "safe"
    PASSIVE = "passive"
    ACTIVE_SAFE = "active-safe"


class ProgramType(str, Enum):
    BBP = "BBP"                         # Bug Bounty Program (Monetary rewards, HoF, Swag)
    VDP = "VDP"                         # Vulnerability Disclosure Program (HoF, Swag, No cash)
    SELF_HOSTED_BBP = "SELF_HOSTED_BBP" # Direct company program with monetary rewards
    SELF_HOSTED_VDP = "SELF_HOSTED_VDP" # Direct company program with HoF/Responsible disclosure


class ProgramPlatform(str, Enum):
    HACKERONE = "HackerOne"
    BUGCROWD = "Bugcrowd"
    INTIGRITI = "Intigriti"
    YESWEHACK = "YesWeHack"
    SELF_HOSTED = "Self-Hosted"
    UNKNOWN = "Unknown"


class ProgramVisibility(str, Enum):
    PUBLIC = "PUBLIC"   # Open to all researchers
    PRIVATE = "PRIVATE" # Invitation-only (Strict NDA mode)


class ProgramMetadata(BaseModel):
    """Metadata regarding Bug Bounty / Vulnerability Disclosure Program"""
    program_type: ProgramType = ProgramType.VDP
    platform: ProgramPlatform = ProgramPlatform.UNKNOWN
    visibility: ProgramVisibility = ProgramVisibility.PUBLIC
    policy_url: Optional[str] = None
    contact_email: Optional[str] = None
    security_txt_found: bool = False
    security_txt_url: Optional[str] = None
    pgp_key_url: Optional[str] = None
    acknowledgments_url: Optional[str] = None  # Hall of Fame
    safe_harbor_terms: Optional[str] = None
    bounty_eligible: bool = False
    nda_required: bool = False


class EvidenceType(str, Enum):
    BEHAVIORAL = "behavioral"
    CONTROLLED_EXECUTION = "controlled_execution"
    ARITHMETIC_PROOF = "arithmetic_proof"
    TIME_DELAY = "time_delay"
    OOB_CANARY = "oob_canary"
    REFLECTION = "reflection"


class ScopeConfig(BaseModel):
    """Scope & Safety boundary contract"""
    target: str
    domain: str
    program_name: str = "default_scope"
    program_type: ProgramType = ProgramType.VDP
    program_platform: ProgramPlatform = ProgramPlatform.UNKNOWN
    program_visibility: ProgramVisibility = ProgramVisibility.PUBLIC
    program_metadata: Optional[ProgramMetadata] = None
    in_scope: List[str] = Field(default_factory=list)
    out_of_scope: List[str] = Field(default_factory=list)
    rate_limit: int = 15
    authenticated: bool = False
    auth_data: Dict[str, Any] = Field(default_factory=dict)
    is_authorized: bool = True
    rejection_reason: Optional[str] = None


class SubdomainRecord(BaseModel):
    """Normalized asset record with origin tracking"""
    asset: str
    domain: str
    type: str = "subdomain"
    sources: List[str] = Field(default_factory=list)
    confidence: float = 1.0
    discovered_at: float = Field(default_factory=time.time)


class LiveAssetRecord(BaseModel):
    """Alive host record gathered from httpx/probing"""
    url: str
    host: str
    port: int = 443
    scheme: str = "https"
    status_code: int = 200
    title: str = ""
    server: str = ""
    content_length: int = 0
    technologies: List[str] = Field(default_factory=list)
    redirect_url: Optional[str] = None
    response_time: float = 0.0
    asset_class: AssetCategory = AssetCategory.WEB


class EndpointRecord(BaseModel):
    """Discovered URL/Route endpoint record"""
    url: str
    path: str
    method: str = "GET"
    category: str = "OTHER"
    source: str = "crawler"
    status_code: Optional[int] = None
    headers: Dict[str, str] = Field(default_factory=dict)
    parameters: List[str] = Field(default_factory=list)


class ParameterRecord(BaseModel):
    """Context-aware parameter record mapped to candidate vuln classes"""
    parameter: str
    endpoint: str
    method: str = "GET"
    source: str = "query"
    potential_classes: List[str] = Field(default_factory=list)
    sample_value: Optional[str] = None
    context: Dict[str, Any] = Field(default_factory=dict)
    tested_skills: List[str] = Field(default_factory=list)
    status: str = "DISCOVERED"


class SecretFindingRecord(BaseModel):
    """Leaked credentials / secret discovered in code or JS"""
    file_url: str
    secret_type: str
    matched_string: str
    line_number: Optional[int] = None
    confidence: float = 0.90
    severity: str = "High"


class VerificationEvidence(BaseModel):
    """Evidence layer verifying an exploit or differential anomaly"""
    type: str = "behavioral"
    description: str
    proof_snippet: str
    verified: bool = True
    request_hash: Optional[str] = None
    response_hash: Optional[str] = None
    request_raw: Optional[str] = None
    response_raw: Optional[str] = None


class ReproductionArtifact(BaseModel):
    """Step-by-step reproduction curl request and server response"""
    curl_command: str
    http_request: str = ""
    http_response_snippet: str = ""
    payload_used: str = ""


class HunterFinding(BaseModel):
    """Structured, verified finding contract"""
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    finding: str
    asset: str
    endpoint: str
    parameter: Optional[str] = None
    vuln_type: str
    status: FindingStatus = FindingStatus.CONFIRMED
    tier: FindingTier = FindingTier.VERIFIED_FINDING
    severity: str = "Medium"
    confidence: float = 0.90
    cvss_score: float = 5.0
    cvss_vector: Optional[str] = None
    cwe: str = "CWE-20"
    owasp_top10: str = "A03:2021-Injection"
    evidence: List[VerificationEvidence] = Field(default_factory=list)
    reproduction: Optional[ReproductionArtifact] = None
    false_positive_checks: Dict[str, Any] = Field(default_factory=dict)
    remediation: str = "Validate and sanitize all user input."
    tool: str = "HunterAI"
    request_hash: Optional[str] = None
    response_hash: Optional[str] = None
    reproducible: bool = True
    execution_timestamp_utc: Optional[str] = None
    created_at: float = Field(default_factory=time.time)


class ToolExecutionMeta(BaseModel):
    """Metadata tracking every single tool execution (The Metadata part of Triple Artifacts)"""
    tool: str
    target: str
    stage: str
    command: str
    started_at: str
    finished_at: str
    duration_seconds: float
    status: str = "success"  # success, failure, fallback
    raw_output_file: str
    parsed_output_file: str
    metadata_file: Optional[str] = None
    item_count: int = 0
    input_source: Optional[str] = None
    next_stage: Optional[str] = None
    error: Optional[str] = None

    @property
    def tool_name(self) -> str:
        return self.tool

    @property
    def parsed_data_file(self) -> str:
        return self.parsed_output_file


class DataLineageRecord(BaseModel):
    """Lineage tracking tracing the origin/ancestry of every asset or finding"""
    asset_id: str
    asset_value: str
    asset_type: str  # domain, ip, url, parameter, secret, finding
    discovered_by_tool: str
    stage: str
    parent_asset_id: Optional[str] = None
    timestamp: float = Field(default_factory=time.time)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class StageExecutionRecord(BaseModel):
    """Status and file outputs for an individual recon/scanning stage"""
    stage_name: str
    status: str = "pending"  # pending, running, completed, skipped, failed
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    input_files: List[str] = Field(default_factory=list)
    output_files: List[str] = Field(default_factory=list)
    item_count: int = 0
    tools_used: List[str] = Field(default_factory=list)


class ScanManifest(BaseModel):
    """Authoritative manifest for the entire engagement run"""
    target: str
    domain: str
    session_id: str
    started_at: str
    finished_at: Optional[str] = None
    workflow: str = "full"
    profile: str = "safe"
    scope_file: Optional[str] = None
    status: str = "running"  # running, completed, aborted, failed
    engagement_dir: str
    stages: Dict[str, StageExecutionRecord] = Field(default_factory=dict)
    summary: Dict[str, int] = Field(default_factory=dict)

