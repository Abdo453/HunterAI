"""
HunterAI WAF & Rate-Limit Backoff Protocol
==========================================
Strict Policy:
- NEVER attempt stealth bypasses, WAF tampering, or adversarial evasion.
- Detect WAF block signatures (Cloudflare, AWS WAF, ModSecurity, 429, 403 challenge).
- Halt automated testing immediately on the blocked route.
- Queue a structured intervention request for the human operator.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class WAFProvider(str, Enum):
    CLOUDFLARE = "Cloudflare"
    AWS_WAF = "AWS WAF"
    MODSECURITY = "ModSecurity"
    AKAMAI = "Akamai"
    GENERIC_RATE_LIMIT = "Rate Limiter (HTTP 429)"
    UNKNOWN_WAF = "Generic WAF / Firewall"


class InterventionStatus(str, Enum):
    PENDING = "PENDING_OPERATOR_DECISION"
    APPLY_RATE_LIMIT = "RATE_LIMIT_REDUCED"
    PROVIDE_BYPASS_HEADER = "BYPASS_HEADER_ATTACHED"
    EXCLUDE_ROUTE = "ROUTE_EXCLUDED_FROM_SCOPE"
    ABORT_MISSION = "MISSION_ABORTED"


@dataclass
class WAFInterventionRequest:
    request_id: str
    target_host: str
    endpoint: str
    detected_waf: WAFProvider
    trigger_status: int
    trigger_reason: str
    created_at: float = field(default_factory=time.time)
    status: InterventionStatus = InterventionStatus.PENDING
    resolution_notes: str = ""


class WAFBackoffEngine:
    """Manages WAF detection, non-evasion policy enforcement, and operator intervention queue"""

    WAF_HEADER_SIGNATURES = {
        "cf-ray": WAFProvider.CLOUDFLARE,
        "cf-cache-status": WAFProvider.CLOUDFLARE,
        "x-amzn-waf-action": WAFProvider.AWS_WAF,
        "x-amzn-requestid": WAFProvider.AWS_WAF,
        "x-akamai-transformed": WAFProvider.AKAMAI,
        "server": {
            "cloudflare": WAFProvider.CLOUDFLARE,
            "mod_security": WAFProvider.MODSECURITY,
            "modsecurity": WAFProvider.MODSECURITY,
        }
    }

    def __init__(self):
        self.intervention_queue: List[WAFInterventionRequest] = []
        self.active_blocks: Dict[str, WAFProvider] = {}

    def inspect_response(
        self,
        status_code: int,
        headers: Dict[str, str],
        body: str,
        endpoint: str,
        host: str
    ) -> Optional[WAFInterventionRequest]:
        """Inspects HTTP response for WAF block or rate limiting"""
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        detected: Optional[WAFProvider] = None
        reason = ""

        # 1. Check HTTP 429
        if status_code == 429:
            detected = WAFProvider.GENERIC_RATE_LIMIT
            reason = "HTTP 429 Too Many Requests received. Automatic throttling active."

        # 2. Check WAF Headers
        if not detected:
            for h_key, provider in self.WAF_HEADER_SIGNATURES.items():
                if h_key == "server":
                    srv = headers_lower.get("server", "")
                    for name, srv_provider in provider.items():
                        if name in srv:
                            detected = srv_provider
                            reason = f"Detected {srv_provider.value} via Server header: '{srv}'"
                            break
                elif h_key in headers_lower:
                    detected = provider
                    reason = f"Detected {provider.value} via header '{h_key}'"
                    break

        # 3. Check 403 Forbidden with WAF block body signatures
        if not detected and status_code == 403:
            body_l = body.lower()
            if "access denied" in body_l or "blocked by security policy" in body_l or "captcha" in body_l or "attention required" in body_l:
                detected = WAFProvider.UNKNOWN_WAF
                reason = "HTTP 403 WAF Block / Challenge signature observed in response body."

        if detected:
            req_id = f"WAF-INT-{len(self.intervention_queue)+1:03d}"
            req = WAFInterventionRequest(
                request_id=req_id,
                target_host=host,
                endpoint=endpoint,
                detected_waf=detected,
                trigger_status=status_code,
                trigger_reason=reason
            )
            self.intervention_queue.append(req)
            self.active_blocks[f"{host}:{endpoint}"] = detected
            return req

        return None

    def resolve_intervention(
        self,
        request_id: str,
        resolution: InterventionStatus,
        notes: str = ""
    ) -> bool:
        for req in self.intervention_queue:
            if req.request_id == request_id:
                req.status = resolution
                req.resolution_notes = notes
                return True
        return False

    def is_endpoint_blocked(self, host: str, endpoint: str) -> bool:
        return f"{host}:{endpoint}" in self.active_blocks
