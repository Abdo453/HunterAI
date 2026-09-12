"""
HunterAI Code Intelligence Pipeline — Data Models
=================================================
Defines strict schemas for page asset bundling, JS inventory, code chunking,
application code mapping, endpoint/secret hunting, source-to-sink flows,
and analysis manifests.
"""
from __future__ import annotations

import hashlib
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set


class SecretStatus(str, Enum):
    CANDIDATE = "CANDIDATE"
    CLASSIFIED = "CLASSIFIED"
    CONTEXT_CHECKED = "CONTEXT_CHECKED"
    VALIDATED = "VALIDATED"
    REJECTED = "REJECTED"


class SinkCategory(str, Enum):
    DOM = "DOM"                      # innerHTML, outerHTML, document.write
    EXEC = "EXEC"                    # eval, Function, setTimeout/setInterval strings
    NAV = "NAV"                      # location.href, window.open
    STORAGE = "STORAGE"              # localStorage, sessionStorage, document.cookie
    NETWORK = "NETWORK"              # fetch, axios, XMLHttpRequest, WebSocket
    SERIALIZATION = "SERIALIZATION"  # JSON.parse untrusted, postMessage
    CRYPTO = "CRYPTO"                # weak hashing, hardcoded seeds


@dataclass
class PageAssetBundle:
    target_url: str
    raw_html: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    inline_scripts: List[str] = field(default_factory=list)
    external_js_urls: List[str] = field(default_factory=list)
    json_blocks: List[Dict[str, Any]] = field(default_factory=list)
    next_data: Optional[Dict[str, Any]] = None
    forms: List[Dict[str, Any]] = field(default_factory=list)
    links: List[str] = field(default_factory=list)
    iframes: List[str] = field(default_factory=list)
    network_requests: List[Dict[str, Any]] = field(default_factory=list)
    captured_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class JSInventoryItem:
    url: str
    local_path: str = ""
    sha256: str = ""
    size_bytes: int = 0
    framework: str = "vanilla"  # next.js, react, vue, angular, etc.
    minified: bool = False
    has_source_map: bool = False
    source_map_url: Optional[str] = None
    status: str = "discovered"  # discovered, downloaded, analyzed, error
    discovered_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CodeChunk:
    chunk_id: str = field(default_factory=lambda: f"chk_{uuid.uuid4().hex[:8]}")
    file_path: str = ""
    chunk_type: str = "function"  # function, class, route, config, sink
    name: str = ""
    start_line: int = 1
    end_line: int = 1
    code: str = ""
    calls: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DiscoveredEndpoint:
    url_or_path: str
    method: str = "GET"
    source_file: str = ""
    line_number: int = 0
    function_name: str = ""
    parameters: List[str] = field(default_factory=list)
    auth_hint: Optional[str] = None  # bearer, basic, cookie, public
    is_in_scope: bool = True
    discovery_type: str = "fetch"  # fetch, axios, xhr, websocket, graphql, route_def

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SecretCandidate:
    secret_id: str = field(default_factory=lambda: f"sec_{uuid.uuid4().hex[:8]}")
    secret_type: str = "api_key"  # jwt, api_key, private_key, cloud_cred, token
    raw_match: str = ""
    redacted_preview: str = ""
    source_file: str = ""
    line_number: int = 0
    entropy: float = 0.0
    status: SecretStatus = SecretStatus.CANDIDATE
    validation_notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        return d


@dataclass
class SourceSinkFlow:
    flow_id: str = field(default_factory=lambda: f"flow_{uuid.uuid4().hex[:8]}")
    source: str = ""
    source_type: str = "url_param"  # url_param, hash, postMessage, storage, window_name
    sink: str = ""
    sink_category: SinkCategory = SinkCategory.DOM
    source_file: str = ""
    line_number: int = 0
    data_path: List[str] = field(default_factory=list)
    sanitized: bool = False
    is_exploitable: bool = False
    confidence: float = 0.0
    evidence: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["sink_category"] = self.sink_category.value
        return d


@dataclass
class CodeFinding:
    id: str = field(default_factory=lambda: f"JS-{uuid.uuid4().hex[:6].upper()}")
    type: str = "potential_issue"
    severity: str = "Medium"
    confidence: float = 0.5
    file: str = ""
    line: int = 0
    function: str = ""
    source: str = ""
    sink: str = ""
    data_flow: List[str] = field(default_factory=list)
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    reasoning: str = ""
    verification: Dict[str, Any] = field(default_factory=lambda: {
        "status": "unverified",
        "required_next_step": "Active differential probe needed."
    })

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ApplicationCodeMap:
    target: str
    pages: List[str] = field(default_factory=list)
    functions: Dict[str, List[str]] = field(default_factory=dict)
    api_routes: List[Dict[str, Any]] = field(default_factory=list)
    technology_stack: List[str] = field(default_factory=list)
    generated_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AnalysisManifest:
    target: str
    scope: List[str] = field(default_factory=list)
    files_analyzed: int = 0
    js_analyzed: int = 0
    endpoints_discovered: int = 0
    secrets_discovered: int = 0
    technologies: List[str] = field(default_factory=list)
    observations: List[str] = field(default_factory=list)
    tests_performed: List[str] = field(default_factory=list)
    tests_failed: List[str] = field(default_factory=list)
    potential_findings: List[Dict[str, Any]] = field(default_factory=list)
    confirmed_findings: List[Dict[str, Any]] = field(default_factory=list)
    false_positives: List[Dict[str, Any]] = field(default_factory=list)
    unverified_findings: List[Dict[str, Any]] = field(default_factory=list)
    next_recommended_analysis: List[str] = field(default_factory=list)
    do_not_repeat: List[str] = field(default_factory=list)
    completed_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)