"""
Multi-Dimensional Response Fingerprinter
========================================
Extracts rich fingerprints (status, hashes, DOM structure, headers, timing)
to discern whether changes between HTTP responses are caused by injected payloads
or normal dynamic page variations (Next.js hydration, CSRF tokens, rotating banners).
"""
import hashlib
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Optional, Tuple


@dataclass
class ResponseFingerprint:
    status_code: int
    headers_hash: str
    body_hash: str
    body_length: int
    title: str
    dom_skeleton_hash: str
    timing_ms: float = 0.0
    redirect_url: Optional[str] = None
    cookies_hash: str = ""
    content_type: str = ""
    has_waf_challenge: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ResponseFingerprinter:
    """Generates normalized fingerprints from HTTP responses"""

    @classmethod
    def fingerprint(
        cls,
        status_code: int,
        body: str,
        headers: Optional[Dict[str, str]] = None,
        timing_ms: float = 0.0
    ) -> ResponseFingerprint:
        headers = headers or {}
        norm_body = body or ""

        # Check for Cloudflare / WAF challenges
        b_lower = norm_body.lower()
        has_waf = status_code in (403, 429) and any(
            sig in b_lower for sig in ("cloudflare", "attention required", "just a moment", "cf-browser-verification")
        )

        # Body hash
        body_h = hashlib.sha256(norm_body.encode("utf-8", errors="ignore")).hexdigest()

        # Extract title
        m_title = re.search(r"<title[^>]*>([^<]+)</title>", norm_body, re.I)
        title = m_title.group(1).strip() if m_title else ""

        # DOM Skeleton: Strip dynamic text, numbers, timestamps to measure pure structural delta
        dom_skeleton = re.sub(r">[^<]+<", "><", norm_body)
        dom_skeleton = re.sub(r'="[^"]*"', '=""', dom_skeleton)
        dom_h = hashlib.sha256(dom_skeleton.encode("utf-8", errors="ignore")).hexdigest()

        # Headers hash (ignoring Date, Server, Set-Cookie)
        stable_headers = {
            k.lower(): v for k, v in headers.items()
            if k.lower() not in ("date", "set-cookie", "cf-ray", "x-request-id", "age", "cf-cache-status")
        }
        h_str = "&".join(f"{k}={v}" for k, v in sorted(stable_headers.items()))
        h_hash = hashlib.sha256(h_str.encode("utf-8", errors="ignore")).hexdigest()

        # Cookies hash
        cookie_str = headers.get("set-cookie", "")
        c_hash = hashlib.sha256(cookie_str.encode("utf-8", errors="ignore")).hexdigest() if cookie_str else ""

        return ResponseFingerprint(
            status_code=status_code,
            headers_hash=h_hash,
            body_hash=body_h,
            body_length=len(norm_body),
            title=title,
            dom_skeleton_hash=dom_h,
            timing_ms=timing_ms,
            redirect_url=headers.get("location"),
            cookies_hash=c_hash,
            content_type=headers.get("content-type", ""),
            has_waf_challenge=has_waf
        )

    @classmethod
    def is_meaningful_deviation(
        cls,
        baseline: ResponseFingerprint,
        test: ResponseFingerprint
    ) -> Tuple[bool, str]:
        """
        Determines if difference between baseline and test response is statistically meaningful
        rather than dynamic page noise.
        """
        if baseline.has_waf_challenge or test.has_waf_challenge:
            return False, "Deviation caused by WAF/Cloudflare challenge."

        # Status change (e.g. 200 -> 500, or 403 -> 200)
        if baseline.status_code != test.status_code:
            return True, f"Status code shifted from {baseline.status_code} to {test.status_code}."

        # DOM structure change
        if baseline.dom_skeleton_hash != test.dom_skeleton_hash:
            len_delta = abs(baseline.body_length - test.body_length)
            if len_delta > 100:
                return True, f"Structural DOM divergence detected ({len_delta} bytes length delta)."

        return False, "Response difference is within normal dynamic variation limits."