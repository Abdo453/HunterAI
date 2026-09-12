"""
Response Normalizer & Telemetry Extractor for BurpAgent
Summarizes HTTP responses, classifies content types, computes cryptographic hashes,
and detects error signatures without overwhelming the LLM context window.
"""
import re
import hashlib
from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field


class NormalizedResponse(BaseModel):
    """ملخص مضغوط ودلالي لاستجابة الـ HTTP"""
    status_code: int
    content_type: str = "text/plain"
    content_length: int = 0
    is_error: bool = False
    error_signature: Optional[str] = None
    signals: List[str] = Field(default_factory=list)
    summary: str = ""
    sha256: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


class ResponseNormalizer:
    """
    محول ومطبع استجابات الـ HTTP
    """

    ERROR_SIGNATURES = {
        "postgresql": r"syntax error at or near|PostgreSQL error|pg_sleep",
        "mysql": r"You have an error in your SQL syntax|Warning: mysql_|MySqlException",
        "sqlite": r"unrecognized token|near \".*\": syntax error|SQLite3::SQLException",
        "waf": r"Access Denied|Request Blocked|Cloudflare|WAF|403 Forbidden"
    }

    @classmethod
    def normalize(
        cls,
        status_code: int,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None
    ) -> NormalizedResponse:
        headers = headers or {}
        body = body or ""

        content_type = "text/plain"
        for h, v in headers.items():
            if h.lower() == "content-type":
                content_type = v.split(";")[0].strip().lower()
                break

        body_len = len(body)
        signals: List[str] = []

        if status_code >= 400:
            signals.append("http_error")
        if status_code in [401, 403]:
            signals.append("auth_denied")
        if "application/json" in content_type:
            signals.append("json_response")

        # Detect error signature in body
        error_signature = None
        for engine, pattern in cls.ERROR_SIGNATURES.items():
            if re.search(pattern, body, re.IGNORECASE):
                error_signature = engine
                signals.append(f"{engine}_detected")
                break

        sha256 = hashlib.sha256(body.encode("utf-8")).hexdigest()
        summary = f"Status {status_code} ({content_type}, {body_len} bytes, Signals: [{', '.join(set(signals))}])"

        return NormalizedResponse(
            status_code=status_code,
            content_type=content_type,
            content_length=body_len,
            is_error=(status_code >= 400 or error_signature is not None),
            error_signature=error_signature,
            signals=list(set(signals)),
            summary=summary,
            sha256=sha256
        )
