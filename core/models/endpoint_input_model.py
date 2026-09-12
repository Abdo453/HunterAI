"""
HunterAI Endpoint & Input Model (Phase 2 Core)
==============================================
Normalized attack surface representation produced by Passive Discovery:
- Endpoints (URL paths, HTTP methods, content types)
- Parameters (query, form, JSON, header, cookie)
- Technology markers and security flags
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set
from urllib.parse import parse_qs, urlparse


class ParameterLocation(str, Enum):
    QUERY = "query"
    BODY_FORM = "body_form"
    BODY_JSON = "body_json"
    HEADER = "header"
    COOKIE = "cookie"
    PATH = "path"


@dataclass
class InputParameter:
    name: str
    location: ParameterLocation
    sample_value: str = ""
    inferred_type: str = "string"  # "string", "int", "boolean", "json"
    is_reflected: bool = False
    reflection_context: Optional[str] = None  # "html_body", "html_attribute", "script_block"


@dataclass
class EndpointModel:
    target: str
    path: str
    method: str = "GET"
    parameters: Dict[str, InputParameter] = field(default_factory=dict)
    content_type: str = "text/html"
    requires_auth: bool = False
    discovered_from: str = "passive_traffic"  # "burp", "browser", "crawler", "js_parser"
    discovered_at: float = field(default_factory=time.time)

    def add_parameter(self, name: str, location: ParameterLocation, sample_val: str = "") -> InputParameter:
        if name not in self.parameters:
            self.parameters[name] = InputParameter(name=name, location=location, sample_value=sample_val)
        return self.parameters[name]

    @property
    def url(self) -> str:
        protocol = "https" if "https" in self.target else "http"
        clean_target = self.target.replace("http://", "").replace("https://", "")
        return f"{protocol}://{clean_target}{self.path}"


class AttackSurfaceCatalog:
    """Catalog of all discovered endpoints, parameters, and technologies"""

    def __init__(self, target_domain: str):
        self.target_domain = target_domain
        self.endpoints: Dict[str, EndpointModel] = {}
        self.js_files: Set[str] = set()
        self.api_routes: Set[str] = set()

    def record_exchange(
        self,
        method: str,
        url: str,
        request_headers: Optional[Dict[str, str]] = None,
        request_body: str = "",
        response_status: int = 200,
        response_headers: Optional[Dict[str, str]] = None,
        response_body: str = ""
    ) -> EndpointModel:
        parsed = urlparse(url)
        path = parsed.path or "/"
        key = f"{method.upper()}:{path}"

        if key not in self.endpoints:
            self.endpoints[key] = EndpointModel(
                target=parsed.netloc or self.target_domain,
                path=path,
                method=method.upper()
            )
        ep = self.endpoints[key]

        # Extract Query Parameters
        query_dict = parse_qs(parsed.query)
        for k, vals in query_dict.items():
            ep.add_parameter(k, ParameterLocation.QUERY, vals[0] if vals else "")

        # Check for API Route marker
        if "/api/" in path or "/v1/" in path or "/v2/" in path or "application/json" in str(response_headers):
            self.api_routes.add(path)

        # Check for JS file
        if path.endswith(".js"):
            self.js_files.add(path)

        return ep

    @property
    def total_endpoints(self) -> int:
        return len(self.endpoints)

    @property
    def total_parameters(self) -> int:
        return sum(len(ep.parameters) for ep in self.endpoints.values())
