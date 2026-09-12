"""
Comprehensive Pydantic Data Schemas for HunterAI Security Intelligence Layer
Enforces strict typing, provenance tracking, security contexts, contradictions, scope modes, and learning profiles.
"""
import time
import uuid
from enum import Enum
from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field


# -------------------------------------------------------------------------
# 1. Observation Schemas
# -------------------------------------------------------------------------
class ObservationType(str, Enum):
    HTTP_REQUEST = "http_request"
    HTTP_RESPONSE = "http_response"
    PARAMETER = "parameter"
    ENDPOINT = "endpoint"
    AUTH_HEADER = "auth_header"
    BEHAVIOR_DIFF = "behavior_difference"
    TECH_STACK = "technology_stack"
    FILE_UPLOAD = "file_upload"
    WEBSOCKET = "websocket"
    ERROR_PATTERN = "error_pattern"


class SecurityObservation(BaseModel):
    id: str = Field(default_factory=lambda: f"OBS-{uuid.uuid4().hex[:8]}")
    project_id: str = "default_project"
    target: str
    source: str = "burp_agent"  # "burp_agent", "recon_agent", "web_agent", "manual"
    obs_type: ObservationType
    data: Dict[str, Any]
    tags: List[str] = Field(default_factory=list)
    timestamp: float = Field(default_factory=time.time)
    operation_id: Optional[str] = None
    correlation_id: Optional[str] = None


# -------------------------------------------------------------------------
# 2. Provenance & Attribution Schema
# -------------------------------------------------------------------------
class ProvenanceRecord(BaseModel):
    id: str = Field(default_factory=lambda: f"PRV-{uuid.uuid4().hex[:8]}")
    source_component: str  # e.g., "burp_agent.listener", "vulnerability_analyst", "gpt-4o", "qwen2.5"
    model_name: Optional[str] = None
    evidence_ids: List[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0, default=1.0)
    created_at: float = Field(default_factory=time.time)
    notes: Optional[str] = None


# -------------------------------------------------------------------------
# 3. Security Context Schema
# -------------------------------------------------------------------------
class SecurityContext(BaseModel):
    target: str
    project_id: str = "default_project"
    endpoint_path: str = "/"
    http_method: str = "GET"
    is_authenticated: bool = False
    auth_type: Optional[str] = None  # "jwt", "session_cookie", "api_key", "basic", "none"
    user_role: Optional[str] = None
    known_technologies: List[str] = Field(default_factory=list)
    historical_findings_count: int = 0
    is_state_changing: bool = False
    parameters_observed: List[str] = Field(default_factory=list)
    context_notes: List[str] = Field(default_factory=list)


# -------------------------------------------------------------------------
# 4. Evidence Schemas
# -------------------------------------------------------------------------
class EvidenceType(str, Enum):
    REQUEST = "request"
    RESPONSE = "response"
    BEHAVIOR_DIFF = "behavior_difference"
    STATUS_CODE = "status_code"
    AUTH_ANOMALY = "auth_anomaly"
    CVE_MATCH = "cve_match"
    PARAMETER_CONTROL = "parameter_control"
    TIMING_LEAK = "timing_leak"
    ERROR_DISCLOSURE = "error_disclosure"
    CONTRADICTORY_PROOF = "contradictory_proof"


class EvidenceItem(BaseModel):
    id: str = Field(default_factory=lambda: f"EVD-{uuid.uuid4().hex[:8]}")
    type: EvidenceType
    source: str
    data: Dict[str, Any] = Field(default_factory=dict)
    description: str
    weight: float = Field(ge=0.0, le=1.0, default=0.5)
    verified: bool = True
    timestamp: float = Field(default_factory=time.time)
    provenance: Optional[ProvenanceRecord] = None


# -------------------------------------------------------------------------
# 5. Hypothesis & Contradiction Schemas
# -------------------------------------------------------------------------
class HypothesisStatus(str, Enum):
    OPEN = "open"
    CONFIRMED = "confirmed"
    REJECTED_FALSE_POSITIVE = "rejected_false_positive"
    DISPROVED_BY_CONTRADICTION = "disproved_by_contradiction"
    NEEDS_MORE_DATA = "needs_more_data"


class ContradictionResult(BaseModel):
    has_contradiction: bool
    contradictory_evidence: List[str] = Field(default_factory=list)
    penalty_score: float = 0.0
    explanation: str = ""


class SecurityHypothesis(BaseModel):
    id: str = Field(default_factory=lambda: f"HYP-{uuid.uuid4().hex[:8]}")
    title: str
    vulnerability_type: str  # e.g., "BOLA", "SQLi", "SSRF", "IDOR", "Auth_Bypass", "BFLA"
    cwe_id: Optional[str] = None
    target_endpoint: str
    parameters: List[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)
    evidence_ids: List[str] = Field(default_factory=list)
    evidence_required: List[str] = Field(default_factory=list)
    reasoning_steps: List[str] = Field(default_factory=list)
    counter_arguments: List[str] = Field(default_factory=list)
    contradictions: Optional[ContradictionResult] = None
    status: HypothesisStatus = HypothesisStatus.OPEN
    created_at: float = Field(default_factory=time.time)


# -------------------------------------------------------------------------
# 6. Finding & Decision Schemas
# -------------------------------------------------------------------------
class SeverityLevel(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ConfidenceLevel(str, Enum):
    UNKNOWN = "UNKNOWN"         # 0.00 - 0.20
    WEAK = "WEAK"               # 0.20 - 0.40
    POSSIBLE = "POSSIBLE"       # 0.40 - 0.60
    STRONG = "STRONG"           # 0.60 - 0.80
    HIGH = "HIGH"               # 0.80 - 0.95
    CONFIRMED = "CONFIRMED"     # 0.95 - 1.00


class FindingStatus(str, Enum):
    OBSERVED = "OBSERVED"               # Heuristic observation / passive anomaly detected
    SUSPECTED = "SUSPECTED"             # Contextualized with hypothesis and required evidence defined
    CONFIRMED = "CONFIRMED"             # Reproducible differential behavior confirmed (Shannon/Dark-Moon principle)
    EXPLOITED = "EXPLOITED"             # Controlled non-destructive execution demonstrated
    IMPACT_VERIFIED = "IMPACT_VERIFIED" # Business/security impact established, full PoC ready


class IntelligenceFinding(BaseModel):
    id: str = Field(default_factory=lambda: f"FND-{uuid.uuid4().hex[:8]}")
    project_id: str = "default_project"
    target: str
    title: str
    vulnerability_type: str
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    severity: SeverityLevel = SeverityLevel.MEDIUM
    confidence_score: float = Field(ge=0.0, le=1.0)
    confidence_level: ConfidenceLevel
    status: FindingStatus = FindingStatus.OBSERVED
    hypotheses_validated: List[str] = Field(default_factory=list)
    evidence: List[EvidenceItem] = Field(default_factory=list)
    reasoning_chain: List[str] = Field(default_factory=list)
    critic_notes: Optional[str] = None
    contradiction_notes: Optional[str] = None
    attack_path_summary: Optional[str] = None
    remediation_advice: Optional[str] = None
    provenance: Optional[ProvenanceRecord] = None
    poc_steps: List[str] = Field(default_factory=list)
    reproduction_curl: Optional[str] = None
    impact_description: Optional[str] = None
    lifecycle_history: List[Dict[str, Any]] = Field(default_factory=list)
    created_at: float = Field(default_factory=time.time)


class ActionPriority(str, Enum):
    IMMEDIATE = "immediate"
    HIGH = "high"
    NORMAL = "normal"
    DEFERRED = "deferred"
    NO_ACTION = "no_action"


class SecurityDecision(BaseModel):
    id: str = Field(default_factory=lambda: f"DEC-{uuid.uuid4().hex[:8]}")
    target: str
    finding_id: Optional[str] = None
    recommended_action: str
    action_priority: ActionPriority
    rationale: str
    required_evidence_to_confirm: List[str] = Field(default_factory=list)
    safe_active_check_suggested: Optional[str] = None
    is_safe_to_automate: bool = True
    operation_id: Optional[str] = None
    correlation_id: Optional[str] = None
    created_at: float = Field(default_factory=time.time)


# -------------------------------------------------------------------------
# 7. Education, Learning Profile & Lesson Schemas
# -------------------------------------------------------------------------
class ExplanationLevel(str, Enum):
    SIMPLE = "simple"           # Level 1: اشرحلي ببساطة
    TECHNICAL = "technical"     # Level 2: اشرح تقني
    PENTESTER = "pentester"     # Level 3: اشرح كـ Pentester
    RESEARCHER = "researcher"   # Level 4: اشرح كـ Security Researcher


class SecurityLesson(BaseModel):
    id: str = Field(default_factory=lambda: f"LSN-{uuid.uuid4().hex[:8]}")
    topic: str
    vuln_class: str
    cwe: Optional[str] = None
    related_finding_id: Optional[str] = None
    explanations: Dict[str, str] = Field(default_factory=dict)  # level -> text
    real_world_scenario: str = ""
    detection_methodology: List[str] = Field(default_factory=list)
    remediation_guide: str = ""
    interactive_quiz_id: Optional[str] = None
    created_at: float = Field(default_factory=time.time)


class QuizQuestion(BaseModel):
    id: str = Field(default_factory=lambda: f"QZ-{uuid.uuid4().hex[:8]}")
    topic: str
    scenario: str
    options: List[str]
    correct_option_index: int
    explanation_on_correct: str
    explanation_on_wrong: str
    concept_tested: str


class QuizEvaluation(BaseModel):
    quiz_id: str
    user_answer_index: Optional[int] = None
    user_answer_text: Optional[str] = None
    is_correct: bool
    understanding_score: float = Field(ge=0.0, le=1.0)
    strong_points: List[str] = Field(default_factory=list)
    weak_points: List[str] = Field(default_factory=list)
    feedback_ar: str
    next_recommendation: str


class LearningProfileData(BaseModel):
    user_id: str = "default_student"
    mastery_scores: Dict[str, float] = Field(default_factory=dict)  # concept -> score (0.0 to 1.0)
    recurring_mistakes: Dict[str, int] = Field(default_factory=dict)  # concept -> count
    preferred_level: ExplanationLevel = ExplanationLevel.TECHNICAL
    total_quizzes_taken: int = 0
    total_correct_quizzes: int = 0
    last_active: float = Field(default_factory=time.time)


# -------------------------------------------------------------------------
# 8. Scope Modes & Scope Decision Schemas
# -------------------------------------------------------------------------
class ScopeMode(str, Enum):
    PASSIVE = "PASSIVE"           # Monitoring & Passive Analysis
    ACTIVE = "ACTIVE"             # Active Verification & Probing
    THEORETICAL = "THEORETICAL"   # Educational, Conceptual & Offline Theory
    BLOCKED = "BLOCKED"           # Out-of-Scope / Prohibited Action


class ScopeRule(BaseModel):
    target: str
    allowed_domains: List[str] = Field(default_factory=list)
    allowed_ips: List[str] = Field(default_factory=list)
    allowed_ports: List[int] = Field(default_factory=lambda: [80, 443, 8080, 8443])
    excluded_paths: List[str] = Field(default_factory=lambda: ["/logout", "/delete", "/reset"])
    allow_active_tests: bool = True
    authorized_by: str = "Self-Authorized Testing"


class ScopeDecision(BaseModel):
    allowed: bool
    mode: ScopeMode
    target: str
    action: str
    reason: str
    safe_alternative: Optional[str] = None


class ScopeCheckResult(BaseModel):
    is_in_scope: bool
    is_action_permitted: bool
    reason: str
    safe_alternative_suggested: Optional[str] = None


# -------------------------------------------------------------------------
# 9. Research Schemas
# -------------------------------------------------------------------------
class ResearchSource(BaseModel):
    source_name: str
    url: Optional[str] = None
    confidence: float = Field(ge=0.0, le=1.0, default=0.8)
    retrieved_at: float = Field(default_factory=time.time)


class ResearchReport(BaseModel):
    id: str = Field(default_factory=lambda: f"RES-{uuid.uuid4().hex[:8]}")
    query: str
    topic: str
    cve_id: Optional[str] = None
    summary: str
    affected_components: List[str] = Field(default_factory=list)
    root_cause_analysis: str = ""
    detection_heuristics: List[str] = Field(default_factory=list)
    mitigation: str = ""
    sources: List[ResearchSource] = Field(default_factory=list)
    arabic_summary: str = ""
    cached: bool = False
