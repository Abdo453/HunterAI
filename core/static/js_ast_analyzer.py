"""
JavaScript AST & Static Route Extraction Engine
Extracts API routes, REST endpoints, GraphQL queries, hidden parameters, and exposed tokens
from bundled/minified JavaScript files using AST-like parsing and pattern recognition.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)

# Common REST & API route patterns in JavaScript source
ROUTE_PATTERNS = [
    # fetch('/api/v1/...') or axios.get('/api/v1/...')
    re.compile(r"""(?:fetch|axios(?:\.(?:get|post|put|delete|patch))?)\s*\(\s*['"`]([^'"`\s\?#]+(?:\?[^'"`\s]*)?)['"`]""", re.IGNORECASE),
    # Path strings: '/api/v1/users', '/v2/auth/login'
    re.compile(r"""['"`](/(?:api|v[0-9]|graphql|auth|admin|user|users|account|orders|checkout|service)[a-zA-Z0-9_\-\./]*)['"`]""", re.IGNORECASE),
    # Angular/React Route definitions: path: '/dashboard/:id'
    re.compile(r"""path\s*:\s*['"`](/[a-zA-Z0-9_\-/:.]+)['"`]""", re.IGNORECASE),
]

# Sensitive keys and token patterns in JavaScript
SECRET_PATTERNS = [
    ("api_key", re.compile(r"""(?i)(?:api_?key|apikey|api_secret)\s*[:=]\s*['"`]([a-zA-Z0-9_\-]{16,})['"`]""")),
    ("jwt_token", re.compile(r"""(?i)eyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}""")),
    ("aws_access_key", re.compile(r"""\b(AKIA[0-9A-Z]{16})\b""")),
    ("bearer_token", re.compile(r"""(?i)['"`]Bearer\s+([a-zA-Z0-9_\-\.]{20,})['"`]""")),
]

# Parameter name patterns extracted from JS object literals
PARAM_PATTERNS = [
    re.compile(r"""params\s*:\s*\{\s*([^}]+)\}""", re.IGNORECASE),
    re.compile(r"""(?:data|body)\s*:\s*\{\s*([^}]+)\}""", re.IGNORECASE),
]


@dataclass
class JSAnalysisResult:
    js_url_or_path: str
    discovered_endpoints: List[str] = field(default_factory=list)
    graphql_queries: List[str] = field(default_factory=list)
    extracted_parameters: List[str] = field(default_factory=list)
    potential_secrets: List[Dict[str, str]] = field(default_factory=list)
    framework_hints: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.js_url_or_path,
            "endpoints": sorted(list(set(self.discovered_endpoints))),
            "graphql_queries": self.graphql_queries,
            "parameters": sorted(list(set(self.extracted_parameters))),
            "secrets_found_count": len(self.potential_secrets),
            "frameworks": self.framework_hints,
        }


class JavaScriptASTAnalyzer:
    """
    محلل كود الـ JavaScript ومسارات الـ API (JS AST & Route Analyzer):
    - يستخرج المسارات ونقاط نهاية الـ REST/GraphQL المخفية داخل كود الـ Front-end.
    - يستخرج الـ Parameters والمتغيرات المرسلة في الـ Payloads.
    - يرصد الـ Secrets والـ API Keys المكشوفة بالخطأ.
    """

    @classmethod
    def analyze_source(cls, js_content: str, source_identifier: str = "bundle.js") -> JSAnalysisResult:
        if not js_content:
            return JSAnalysisResult(js_url_or_path=source_identifier)

        endpoints: Set[str] = set()
        graphql: List[str] = []
        parameters: Set[str] = set()
        secrets: List[Dict[str, str]] = []
        frameworks: Set[str] = set()

        # 1. Framework detection hints
        if "react" in js_content.lower() or "_jsx" in js_content or "useState" in js_content:
            frameworks.add("React")
        if "vue" in js_content.lower() or "__vue__" in js_content or "createApp" in js_content:
            frameworks.add("Vue.js")
        if "angular" in js_content.lower() or "ng-version" in js_content:
            frameworks.add("Angular")
        if "apollo" in js_content.lower() or "gql`" in js_content:
            frameworks.add("Apollo/GraphQL")

        # 2. Extract endpoints via regex rules
        for pattern in ROUTE_PATTERNS:
            for match in pattern.finditer(js_content):
                route = match.group(1).strip()
                # Exclude static assets or CSS
                if not re.search(r"\.(css|png|jpg|jpeg|gif|svg|woff2?|ico)$", route, re.IGNORECASE):
                    endpoints.add(route)

        # 3. Extract GraphQL Queries
        gql_pattern = re.compile(r"""(?:gql|graphql)\s*`([^`]+)`""", re.IGNORECASE)
        for match in gql_pattern.finditer(js_content):
            query_clean = match.group(1).strip()
            if query_clean:
                graphql.append(query_clean[:300])

        # 4. Extract parameters from params/body object literals
        for pattern in PARAM_PATTERNS:
            for match in pattern.finditer(js_content):
                block = match.group(1)
                # find keys: 'user_id': ... or userId: ...
                keys = re.findall(r"""([a-zA-Z0-9_\-]+)\s*:""", block)
                for k in keys:
                    if len(k) > 1 and k not in ("true", "false", "null", "undefined", "function"):
                        parameters.add(k)

        # Also extract parameters from URL queries inside endpoints
        for ep in endpoints:
            if "?" in ep:
                q_part = ep.split("?")[1]
                for param_pair in q_part.split("&"):
                    p_name = param_pair.split("=")[0]
                    if p_name:
                        parameters.add(p_name)

        # 5. Extract secrets
        for secret_name, sec_pat in SECRET_PATTERNS:
            for match in sec_pat.finditer(js_content):
                val = match.group(1) if match.groups() else match.group(0)
                # Redact partially for security report
                masked = val[:4] + "*" * (len(val) - 8) + val[-4:] if len(val) > 8 else "[REDACTED]"
                secrets.append({"type": secret_name, "preview": masked})

        return JSAnalysisResult(
            js_url_or_path=source_identifier,
            discovered_endpoints=sorted(list(endpoints)),
            graphql_queries=graphql,
            extracted_parameters=sorted(list(parameters)),
            potential_secrets=secrets,
            framework_hints=sorted(list(frameworks))
        )
