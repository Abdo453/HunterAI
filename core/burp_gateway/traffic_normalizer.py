"""
HunterAI Burp Canonical Traffic Normalizer
==========================================
Converts diverse, heterogenous traffic observations (from Burp Proxy, Repeater,
Burp Scanner, Context Menu Extension, and Browser) into a uniform, canonical
epistemic representation:
- CanonicalRequest: Method, URL, Host, Path, Query Params, Headers, Body, Content-Type
- CanonicalResponse: Status Code, Headers, Body, Content-Type, Latency
- CanonicalIdentity: Identity ID, Role Tier, Token Fingerprints
- TargetStateContext: Stateful session tags, cookies, workflow step
- CanonicalTransaction: The unified transaction with BurpCorrelationContext & Provenance
"""
from __future__ import annotations

import hashlib
import json
import re
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from core.burp_gateway.correlation import BurpCorrelationContext


class TrafficSource(str, Enum):
    PROXY = "PROXY"
    REPEATER = "REPEATER"
    SCANNER = "SCANNER"
    EXTENSION = "EXTENSION"
    BROWSER = "BROWSER"
    AGENT_PROBE = "AGENT_PROBE"


@dataclass
class CanonicalRequest:
    method: str = "GET"
    url: str = ""
    host: str = ""
    path: str = "/"
    query_params: Dict[str, List[str]] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    content_type: str = "application/octet-stream"

    def __post_init__(self):
        self.method = self.method.upper()
        if self.url and (not self.host or self.path == "/"):
            parsed = urlparse(self.url)
            self.host = parsed.netloc or self.host
            self.path = parsed.path or "/"
            if parsed.query and not self.query_params:
                self.query_params = parse_qs(parsed.query)

        # Detect content type
        for k, v in self.headers.items():
            if k.lower() == "content-type":
                self.content_type = v.split(";")[0].strip().lower()
                break

    def get_all_parameter_names(self) -> List[str]:
        """Extracts parameter names across URL query, form body, and JSON keys."""
        names = set(self.query_params.keys())
        if self.body:
            if "application/x-www-form-urlencoded" in self.content_type:
                names.update(parse_qs(self.body).keys())
            elif "application/json" in self.content_type:
                try:
                    parsed_json = json.loads(self.body)
                    if isinstance(parsed_json, dict):
                        names.update(parsed_json.keys())
                except Exception:
                    pass
        return sorted(list(names))

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CanonicalResponse:
    status_code: int = 200
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    content_type: str = "text/html"
    round_trip_ms: float = 0.0

    def __post_init__(self):
        for k, v in self.headers.items():
            if k.lower() == "content-type":
                self.content_type = v.split(";")[0].strip().lower()
                break

    @property
    def body_len(self) -> int:
        return len(self.body)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CanonicalIdentity:
    identity_id: str = "ANONYMOUS"
    role: str = "ANONYMOUS"
    bearer_token_hash: Optional[str] = None
    session_cookie_hash: Optional[str] = None
    csrf_token_hash: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TargetStateContext:
    workflow_step: Optional[str] = None
    cookies: Dict[str, str] = field(default_factory=dict)
    observed_state_tag: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CanonicalTransaction:
    """The canonical epistemic currency for all HTTP interactions in HunterAI."""
    tx_id: str
    source: TrafficSource
    correlation: BurpCorrelationContext
    request: CanonicalRequest
    response: CanonicalResponse
    identity: CanonicalIdentity
    state: TargetStateContext
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tx_id": self.tx_id,
            "source": self.source.value,
            "correlation": self.correlation.to_dict(),
            "request": self.request.to_dict(),
            "response": self.response.to_dict(),
            "identity": self.identity.to_dict(),
            "state": self.state.to_dict(),
            "timestamp": self.timestamp,
        }


class BurpTrafficNormalizer:
    """
    Transforms any raw input into a CanonicalTransaction.
    Supports raw HTTP wire string, gateway JSON dictionary, BurpSessionContext,
    or scanner issue payloads.
    """

    @classmethod
    def normalize_raw_http(
        cls,
        raw_request: str,
        raw_response: str,
        host: str = "target.local",
        port: int = 80,
        protocol: str = "http",
        source: TrafficSource = TrafficSource.PROXY,
        correlation: Optional[BurpCorrelationContext] = None,
        round_trip_ms: float = 0.0,
    ) -> CanonicalTransaction:
        """Parses raw HTTP request/response strings into a CanonicalTransaction."""
        # 1. Parse Request
        sep = "\r\n\r\n" if "\r\n\r\n" in raw_request else ("\r\n" if "\r\n" in raw_request else "\n")
        clean_req = raw_request.replace("\r\n", "\n")
        if "\n\n" in clean_req:
            req_hdr_part, req_body = clean_req.split("\n\n", 1)
        else:
            req_hdr_part, req_body = clean_req, ""

        req_lines = req_hdr_part.splitlines() if req_hdr_part else []
        first_req_line = req_lines[0] if req_lines else "GET / HTTP/1.1"
        parts = first_req_line.split()
        method = parts[0] if len(parts) > 0 else "GET"
        path = parts[1] if len(parts) > 1 else "/"

        req_headers = {}
        for hline in req_lines[1:]:
            if ":" in hline:
                k, v = hline.split(":", 1)
                req_headers[k.strip()] = v.strip()

        full_url = f"{protocol}://{host}:{port}{path}" if port not in (80, 443) else f"{protocol}://{host}{path}"
        parsed_url = urlparse(full_url)
        query_params = parse_qs(parsed_url.query) if parsed_url.query else {}

        req_obj = CanonicalRequest(
            method=method,
            url=full_url,
            host=host,
            path=parsed_url.path or "/",
            query_params=query_params,
            headers=req_headers,
            body=req_body,
        )

        # 2. Parse Response
        clean_resp = raw_response.replace("\r\n", "\n")
        if "\n\n" in clean_resp:
            resp_hdr_part, resp_body = clean_resp.split("\n\n", 1)
        else:
            resp_hdr_part, resp_body = clean_resp, ""

        resp_lines = resp_hdr_part.splitlines() if resp_hdr_part else []
        first_resp_line = resp_lines[0] if resp_lines else "HTTP/1.1 200 OK"
        rparts = first_resp_line.split()
        status_code = int(rparts[1]) if len(rparts) > 1 and rparts[1].isdigit() else 200

        resp_headers = {}
        for hline in resp_lines[1:]:
            if ":" in hline:
                k, v = hline.split(":", 1)
                resp_headers[k.strip()] = v.strip()

        resp_obj = CanonicalResponse(
            status_code=status_code,
            headers=resp_headers,
            body=resp_body,
            round_trip_ms=round_trip_ms,
        )

        # 3. Extract Correlation Context
        if correlation is None:
            correlation = BurpCorrelationContext.from_headers(req_headers)

        # 4. Extract Identity & State
        identity = cls._extract_identity(req_headers, correlation)
        state = cls._extract_state(req_headers, resp_headers)

        return CanonicalTransaction(
            tx_id=correlation.transaction_id,
            source=source,
            correlation=correlation,
            request=req_obj,
            response=resp_obj,
            identity=identity,
            state=state,
            timestamp=time.time(),
        )

    @classmethod
    def normalize_dict(cls, data: Dict[str, Any]) -> CanonicalTransaction:
        """Normalizes gateway json dictionary into CanonicalTransaction."""
        if "request" in data and isinstance(data["request"], str):
            source_map = {
                "proxy": TrafficSource.PROXY,
                "repeater": TrafficSource.REPEATER,
                "scanner": TrafficSource.SCANNER,
                "extension": TrafficSource.EXTENSION,
                "context_menu": TrafficSource.EXTENSION,
                "browser": TrafficSource.BROWSER,
                "agent": TrafficSource.AGENT_PROBE,
            }
            src = source_map.get(str(data.get("tool", "")).lower(), TrafficSource.PROXY)
            return cls.normalize_raw_http(
                raw_request=data.get("request", ""),
                raw_response=data.get("response", ""),
                host=data.get("host", "target.local"),
                port=int(data.get("port", 80)),
                protocol=data.get("protocol", "http"),
                source=src,
            )

        # Structured dict format
        req_d = data.get("request", {})
        resp_d = data.get("response", {})
        corr_d = data.get("correlation", {})
        corr = BurpCorrelationContext.from_dict(corr_d) if corr_d else BurpCorrelationContext(
            transaction_id=data.get("tx_id") or data.get("request_id") or f"tx_{uuid.uuid4().hex[:10]}"
        )

        req_obj = CanonicalRequest(
            method=req_d.get("method", "GET"),
            url=req_d.get("url", ""),
            host=req_d.get("host", ""),
            path=req_d.get("path", "/"),
            query_params=req_d.get("query_params", {}),
            headers=req_d.get("headers", {}),
            body=req_d.get("body", ""),
            content_type=req_d.get("content_type", "application/octet-stream"),
        )
        resp_obj = CanonicalResponse(
            status_code=int(resp_d.get("status_code", 200)),
            headers=resp_d.get("headers", {}),
            body=resp_d.get("body", ""),
            content_type=resp_d.get("content_type", "text/html"),
            round_trip_ms=float(resp_d.get("round_trip_ms", 0.0)),
        )

        source_map = {
            "proxy": TrafficSource.PROXY,
            "repeater": TrafficSource.REPEATER,
            "scanner": TrafficSource.SCANNER,
            "extension": TrafficSource.EXTENSION,
            "context_menu": TrafficSource.EXTENSION,
            "browser": TrafficSource.BROWSER,
            "agent": TrafficSource.AGENT_PROBE,
        }
        raw_source = str(data.get("source") or data.get("tool", "PROXY")).lower()
        src = source_map.get(raw_source, TrafficSource.PROXY)

        identity = cls._extract_identity(req_obj.headers, corr)
        state = cls._extract_state(req_obj.headers, resp_obj.headers)

        return CanonicalTransaction(
            tx_id=corr.transaction_id,
            source=src,
            correlation=corr,
            request=req_obj,
            response=resp_obj,
            identity=identity,
            state=state,
            timestamp=float(data.get("timestamp", time.time())),
        )

    @classmethod
    def _extract_identity(cls, req_headers: Dict[str, str], corr: BurpCorrelationContext) -> CanonicalIdentity:
        bearer_hash = None
        cookie_hash = None
        csrf_hash = None

        for k, v in req_headers.items():
            kl = k.lower()
            if kl == "authorization" and v.startswith("Bearer "):
                bearer_hash = hashlib.sha256(v[7:].encode()).hexdigest()[:12]
            elif kl == "cookie":
                cookie_hash = hashlib.sha256(v.encode()).hexdigest()[:12]
            elif "csrf" in kl or "xsrf" in kl:
                csrf_hash = hashlib.sha256(v.encode()).hexdigest()[:12]

        return CanonicalIdentity(
            identity_id=corr.identity_id or "ANONYMOUS",
            role=corr.identity_id or "ANONYMOUS",
            bearer_token_hash=bearer_hash,
            session_cookie_hash=cookie_hash,
            csrf_token_hash=csrf_hash,
        )

    @classmethod
    def _extract_state(cls, req_headers: Dict[str, str], resp_headers: Dict[str, str]) -> TargetStateContext:
        cookies = {}
        for k, v in req_headers.items():
            if k.lower() == "cookie":
                for part in v.split(";"):
                    if "=" in part:
                        ck, cv = part.split("=", 1)
                        cookies[ck.strip()] = cv.strip()
        for k, v in resp_headers.items():
            if k.lower() == "set-cookie":
                part = v.split(";")[0]
                if "=" in part:
                    ck, cv = part.split("=", 1)
                    cookies[ck.strip()] = cv.strip()

        return TargetStateContext(cookies=cookies)
