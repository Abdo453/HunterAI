"""
Request Normalizer & Parameter Extractor for BurpAgent
Strips protocol bloat, extracts query and body parameters, and generates
compact summaries to preserve the LLM context window.
"""
import re
import json
import hashlib
import urllib.parse
from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field


class NormalizedRequest(BaseModel):
    """ملخص مضغوط ودلالي لطلب الـ HTTP يحمي نافذة سياق الـ LLM"""
    method: str
    url: str
    path: str
    query_params: Dict[str, str] = Field(default_factory=dict)
    body_params: Dict[str, Any] = Field(default_factory=dict)
    auth_headers: Dict[str, str] = Field(default_factory=dict)
    signals: List[str] = Field(default_factory=list)
    summary: str = ""
    body_length: int = 0
    sha256: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


class RequestNormalizer:
    """
    محول ومطبع طلبات الـ HTTP:
    يستخرج الإشارات والباراميترات مع إخفاء التفاصيل غير الضرورية عن الموديل
    """

    @classmethod
    def normalize(
        cls,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None
    ) -> NormalizedRequest:
        method = method.upper().strip()
        headers = headers or {}
        body = body or ""

        parsed = urllib.parse.urlparse(url)
        path = parsed.path or "/"

        # 1. Parse Query Parameters
        query_params: Dict[str, str] = {}
        if parsed.query:
            qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            query_params = {k: v[0] if len(v) == 1 else ",".join(v) for k, v in qs.items()}

        # 2. Parse Body Parameters (JSON or URL-encoded)
        body_params: Dict[str, Any] = {}
        content_type = ""
        for h, v in headers.items():
            if h.lower() == "content-type":
                content_type = v.lower()
                break

        if body.strip():
            if "application/json" in content_type:
                try:
                    body_params = json.loads(body)
                except Exception:
                    body_params = {"raw_unparsed": body[:200]}
            elif "application/x-www-form-urlencoded" in content_type:
                try:
                    qs_body = urllib.parse.parse_qs(body, keep_blank_values=True)
                    body_params = {k: v[0] if len(v) == 1 else ",".join(v) for k, v in qs_body.items()}
                except Exception:
                    body_params = {}

        # 3. Extract Authentication & Identity Headers
        auth_headers: Dict[str, str] = {}
        signals: List[str] = []

        for h, v in headers.items():
            h_lower = h.lower()
            if h_lower in ["authorization", "x-api-key", "token"]:
                auth_headers[h] = v
                signals.append("authenticated_request")
                if "bearer" in v.lower():
                    signals.append("bearer_token")
                if "eyj" in v.lower():
                    signals.append("jwt_structure")
            elif h_lower == "cookie":
                auth_headers[h] = v
                signals.append("session_cookies")

        # 4. Extract Path & Parameter Signals
        if re.search(r"/\d+(?:/|$)", path) or any(k.lower().endswith("id") for k in query_params):
            signals.append("numeric_id")
            signals.append("resource_identifier")
        if re.search(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", path):
            signals.append("uuid_in_path")
        if any(w in path.lower() for w in ["/admin", "/manage", "/dashboard"]):
            signals.append("admin_path")

        # 5. Compute SHA256 and Summary
        req_sig = f"{method} {url} {body}".encode("utf-8")
        sha256 = hashlib.sha256(req_sig).hexdigest()

        all_params = list(query_params.keys()) + list(body_params.keys())
        params_str = f"Params: [{', '.join(all_params)}]" if all_params else "No params"
        summary = f"{method} {path} ({params_str}, Signals: [{', '.join(set(signals))}])"

        return NormalizedRequest(
            method=method,
            url=url,
            path=path,
            query_params=query_params,
            body_params=body_params,
            auth_headers=auth_headers,
            signals=list(set(signals)),
            summary=summary,
            body_length=len(body),
            sha256=sha256
        )
