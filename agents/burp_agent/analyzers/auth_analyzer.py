"""
Authentication & JWT Context Analyzer for BurpAgent
"""
import base64
import json
import logging
from typing import Optional
from agents.burp_agent.storage.models import HTTPRequestModel, HTTPResponseModel, FindingModel
from agents.burp_agent.evidence.evidence_manager import EvidenceManager

log = logging.getLogger("burp_agent.auth_analyzer")


class AuthAnalyzer:
    """تدقيق آليات المصادقة وتوكنات الـ JWT والكوكيز في الترافيك المباشر"""

    def __init__(self, evidence_mgr: EvidenceManager):
        self.evidence_mgr = evidence_mgr

    async def analyze(self, req: HTTPRequestModel, resp: Optional[HTTPResponseModel] = None):
        auth_hdr = req.headers.get("Authorization") or req.headers.get("authorization")
        if auth_hdr and auth_hdr.startswith("Bearer "):
            token = auth_hdr.split("Bearer ", 1)[1].strip()
            self._inspect_jwt(token, req, resp)

        if resp and resp.headers:
            for k, v in resp.headers.items():
                if k.lower() == "set-cookie":
                    self._inspect_cookie_security(v, req, resp)

    def _inspect_jwt(self, token: str, req: HTTPRequestModel, resp: Optional[HTTPResponseModel]):
        parts = token.split(".")
        if len(parts) >= 2:
            try:
                # Decode Header
                header_raw = parts[0] + "=" * ((4 - len(parts[0]) % 4) % 4)
                header = json.loads(base64.urlsafe_b64decode(header_raw.encode("ascii")))

                # Check None Algorithm
                if header.get("alg", "").lower() == "none":
                    finding = FindingModel(
                        title="Critical JWT Algorithm Confusion (alg: none)",
                        vuln_type="jwt_none_algorithm",
                        severity="Critical",
                        confidence=0.99,
                        endpoint=req.url,
                        request_id=req.id,
                        response_id=resp.id if resp else None,
                        description="JWT header specifies 'alg: none', allowing signature bypass.",
                        evidence=f"Authorization: Bearer {token[:40]}... (Header: {json.dumps(header)})",
                        remediation="Reject tokens with 'none' algorithm and enforce strict RS256/HS256 verification."
                    )
                    self.evidence_mgr.link_finding_to_traffic(finding, req.id, resp.id if resp else None)
            except Exception:
                pass

    def _inspect_cookie_security(self, cookie_hdr: str, req: HTTPRequestModel, resp: Optional[HTTPResponseModel]):
        c_low = cookie_hdr.lower()
        if "httponly" not in c_low and any(s in c_low for s in ("session", "token", "auth", "jwt")):
            finding = FindingModel(
                title="Sensitive Cookie Missing HttpOnly Flag",
                vuln_type="cookie_missing_httponly",
                severity="Medium",
                confidence=0.95,
                endpoint=req.url,
                request_id=req.id,
                response_id=resp.id if resp else None,
                description="Session/Auth cookie does not set the HttpOnly flag, exposing it to XSS theft.",
                evidence=f"Set-Cookie: {cookie_hdr[:120]}",
                remediation="Add HttpOnly and Secure flags to all authentication cookies."
            )
            self.evidence_mgr.link_finding_to_traffic(finding, req.id, resp.id if resp else None)
