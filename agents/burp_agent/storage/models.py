"""
Storage Models for BurpAgent
Pydantic & Dataclass schemas for all 13 database entities and runtime objects.
"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field


class TriagePriority(str, Enum):
    LOW = "LOW"
    NORMAL = "NORMAL"
    INTERESTING = "INTERESTING"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class HTTPMethod(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    OPTIONS = "OPTIONS"
    HEAD = "HEAD"
    CONNECT = "CONNECT"
    TRACE = "TRACE"


class ParameterLocation(str, Enum):
    QUERY = "query"
    BODY = "body"
    JSON = "json"
    HEADER = "header"
    COOKIE = "cookie"
    PATH = "path"
    MULTIPART = "multipart"


class TrafficSession(BaseModel):
    id: str
    target_host: str
    created_at: float = Field(default_factory=lambda: datetime.now().timestamp())
    description: Optional[str] = None
    is_active: bool = True
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ParameterModel(BaseModel):
    id: Optional[int] = None
    request_id: Optional[str] = None
    endpoint_id: Optional[str] = None
    name: str
    value: Optional[str] = None
    location: ParameterLocation = ParameterLocation.QUERY
    param_type: Optional[str] = None  # int, string, uuid, jwt, etc.
    is_sensitive: bool = False
    is_user_controlled_id: bool = False
    is_role_indicator: bool = False
    sample_values: List[str] = Field(default_factory=list)


class HTTPRequestModel(BaseModel):
    id: str
    session_id: Optional[str] = None
    timestamp: float = Field(default_factory=lambda: datetime.now().timestamp())
    host: str
    port: int = 80
    protocol: str = "http"
    method: str = "GET"
    url: str
    path: str
    query_string: str = ""
    headers: Dict[str, str] = Field(default_factory=dict)
    cookies: Dict[str, str] = Field(default_factory=dict)
    body: Optional[str] = None
    body_length: int = 0
    content_type: Optional[str] = None
    parameters: List[ParameterModel] = Field(default_factory=list)
    client_ip: Optional[str] = None
    triage_priority: TriagePriority = TriagePriority.NORMAL
    triage_reasons: List[str] = Field(default_factory=list)
    raw_request: Optional[str] = None


class HTTPResponseModel(BaseModel):
    id: str
    request_id: str
    timestamp: float = Field(default_factory=lambda: datetime.now().timestamp())
    status_code: int = 200
    status_message: Optional[str] = None
    headers: Dict[str, str] = Field(default_factory=dict)
    body: Optional[str] = None
    body_length: int = 0
    content_type: Optional[str] = None
    response_time_ms: float = 0.0
    server_banner: Optional[str] = None
    technologies: List[str] = Field(default_factory=list)
    raw_response: Optional[str] = None


class EndpointModel(BaseModel):
    id: str  # e.g., "GET /api/users/{id}"
    host: str
    method: str
    normalized_path: str  # /api/users/{id}
    raw_paths: List[str] = Field(default_factory=list)
    parameters: List[str] = Field(default_factory=list)
    auth_required: bool = False
    auth_types: List[str] = Field(default_factory=list)
    roles_observed: List[str] = Field(default_factory=list)
    status_codes_seen: List[int] = Field(default_factory=list)
    first_seen: float = Field(default_factory=lambda: datetime.now().timestamp())
    last_seen: float = Field(default_factory=lambda: datetime.now().timestamp())
    request_count: int = 1
    is_api: bool = False
    is_admin: bool = False
    is_sensitive: bool = False
    tags: List[str] = Field(default_factory=list)


class FileModel(BaseModel):
    id: Optional[int] = None
    request_id: str
    filename: str
    extension: str
    declared_mime: Optional[str] = None
    detected_mime: Optional[str] = None
    file_size: int = 0
    magic_bytes: Optional[str] = None
    sha256: Optional[str] = None
    potential_risk: Optional[str] = None  # e.g. "Double extension", "Executable in upload"
    timestamp: float = Field(default_factory=lambda: datetime.now().timestamp())


class WebSocketFrameModel(BaseModel):
    id: Optional[int] = None
    connection_id: str
    timestamp: float = Field(default_factory=lambda: datetime.now().timestamp())
    direction: str = "outgoing"  # outgoing (client->server) or incoming (server->client)
    opcode: int = 1  # 1: text, 2: binary, 8: close, 9: ping, 10: pong
    payload: str = ""
    payload_size: int = 0
    is_json: bool = False
    parsed_json: Optional[Dict[str, Any]] = None


class TechnologyModel(BaseModel):
    id: Optional[int] = None
    host: str
    name: str
    category: str  # Server, Framework, Language, CDN, Analytics
    version: Optional[str] = None
    confidence: float = 1.0
    evidence_request_id: Optional[str] = None
    discovered_at: float = Field(default_factory=lambda: datetime.now().timestamp())


class FindingModel(BaseModel):
    id: Optional[int] = None
    title: str
    vuln_type: str
    severity: str  # Critical, High, Medium, Low, Info
    confidence: float = 0.8
    endpoint: Optional[str] = None
    parameter: Optional[str] = None
    request_id: Optional[str] = None
    response_id: Optional[str] = None
    description: str
    evidence: str
    remediation: Optional[str] = None
    created_at: float = Field(default_factory=lambda: datetime.now().timestamp())
    cvss_score: Optional[float] = None
    status: str = "OPEN"


class EvidenceModel(BaseModel):
    id: Optional[int] = None
    finding_id: Optional[int] = None
    request_id: str
    response_id: Optional[str] = None
    endpoint_id: Optional[str] = None
    parameter_name: Optional[str] = None
    highlight_offset: Optional[int] = None
    evidence_snippet: str
    timestamp: float = Field(default_factory=lambda: datetime.now().timestamp())


class GraphNodeModel(BaseModel):
    id: str  # node identifier
    label: str
    node_type: str  # endpoint, auth_state, role, parameter, finding, credential
    metadata: Dict[str, Any] = Field(default_factory=dict)
    weight: float = 1.0


class GraphEdgeModel(BaseModel):
    id: Optional[int] = None
    source_node: str
    target_node: str
    relationship: str  # TRANSITIONS_TO, REQUIRES_AUTH, EXPOSES_PARAM, LEADS_TO_FINDING
    evidence_id: Optional[int] = None
    confidence: float = 1.0
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AIAnalysisModel(BaseModel):
    id: Optional[int] = None
    request_id: str
    model_name: str
    prompt_summary: str
    analysis_text: str
    suggested_vulns: List[str] = Field(default_factory=list)
    confidence_score: float = 0.0
    attack_path_suggested: Optional[str] = None
    duration_ms: float = 0.0
    created_at: float = Field(default_factory=lambda: datetime.now().timestamp())
