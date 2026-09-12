"""
Network Observer
================
Passively intercepts HTTP/S traffic, classifies resource types, extracts hidden
API endpoints, parameters, cookies, and tokens during browser exploration.
"""
from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set
from urllib.parse import parse_qs, urlparse

logger = logging.getLogger("hunter_ai.network_observer")


@dataclass
class ObservedTrafficItem:
    url: str
    method: str
    resource_type: str
    status: Optional[int] = None
    headers: Dict[str, str] = field(default_factory=dict)
    query_params: Dict[str, List[str]] = field(default_factory=dict)
    is_api: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class NetworkObserver:
    """Collects and categorizes in-scope network events from the browser session"""

    def __init__(self, base_host: str):
        self.base_host = base_host.lower()
        self.traffic_log: List[ObservedTrafficItem] = []
        self.discovered_api_endpoints: Set[str] = set()
        self.discovered_parameters: Set[str] = set()
        self.auth_tokens: Set[str] = set()

    def observe_request(
        self,
        url: str,
        method: str,
        resource_type: str = "xhr",
        status: Optional[int] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> ObservedTrafficItem:
        headers = headers or {}
        parsed = urlparse(url)
        qparams = parse_qs(parsed.query)

        # Detect if it is an API route
        is_api = any(kw in parsed.path.lower() for kw in ("/api/", "/v1/", "/v2/", "/graphql", "/auth", "/rest/"))
        if is_api:
            self.discovered_api_endpoints.add(url)

        # Collect query params
        for p in qparams.keys():
            self.discovered_parameters.add(p)

        # Detect Bearer tokens in headers
        auth_hdr = headers.get("authorization", "")
        if auth_hdr.startswith("Bearer "):
            self.auth_tokens.add(auth_hdr[7:].strip())

        item = ObservedTrafficItem(
            url=url,
            method=method.upper(),
            resource_type=resource_type.lower(),
            status=status,
            headers=headers,
            query_params=qparams,
            is_api=is_api,
        )
        self.traffic_log.append(item)
        return item

    def get_summary(self) -> Dict[str, Any]:
        return {
            "total_requests": len(self.traffic_log),
            "api_endpoints_count": len(self.discovered_api_endpoints),
            "parameters_count": len(self.discovered_parameters),
            "auth_tokens_found": len(self.auth_tokens),
            "discovered_api_endpoints": sorted(list(self.discovered_api_endpoints)),
            "discovered_parameters": sorted(list(self.discovered_parameters)),
        }
