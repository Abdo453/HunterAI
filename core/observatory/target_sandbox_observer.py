"""
╔══════════════════════════════════════════════════════════════════════════╗
║     TARGET OBSERVATORY SANDBOX — صندوق مرصد الأهداف الذكي للمعرفة العميقة  ║
║                                                                          ║
║  فكرة المنظومة:                                                          ║
║  صندوق مراقبة معزول تضع فيه أي موقع (URL)، ليقوم الإيجنت بالآتي:        ║
║  1. التشريح السلوكي وحركة المرور (Behavioral & Traffic Profiling)       ║
║  2. استكشاف الترسانة التقنية (Tech Stack, WAF, Frameworks, Servers)     ║
║  3. تفكيك كود الـ JavaScript واستخراج الـ Endpoints والمفاتيح الخفية     ║
║  4. رسم خريطة الروابط ونظام المصادقة والتفاعل (State & Behavior Mapping) ║
║  5. تقييم مؤشر التعرض والسطح الأمني (Attack Surface & Exposure Index)   ║
╚══════════════════════════════════════════════════════════════════════════╝
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

logger = logging.getLogger("hunter_ai.target_observatory")


@dataclass
class TechSignature:
    category: str
    name: str
    version: Optional[str] = None
    confidence: float = 1.0
    evidence: str = ""


@dataclass
class DiscoveredEndpoint:
    url: str
    method: str = "GET"
    source: str = "html"  # html, javascript, header, form
    parameters: List[str] = field(default_factory=list)
    is_sensitive: bool = False


@dataclass
class TargetObservationReport:
    target_url: str
    canonical_host: str
    observation_timestamp: float
    duration_ms: float
    status_code: int
    title: str
    
    # 1. Tech Stack
    technologies: List[Dict[str, Any]] = field(default_factory=list)
    waf_detected: Optional[str] = None
    server_banner: Optional[str] = None
    
    # 2. Defensive Posture
    security_headers: Dict[str, Any] = field(default_factory=dict)
    missing_headers: List[str] = field(default_factory=list)
    cookies_analysis: List[Dict[str, Any]] = field(default_factory=list)
    
    # 3. Behavioral Features
    has_authentication: bool = False
    has_file_upload: bool = False
    has_payment_gateway: bool = False
    forms_count: int = 0
    external_scripts_count: int = 0
    trackers_detected: List[str] = field(default_factory=list)
    
    # 4. Discovered Assets & Endpoints
    discovered_endpoints: List[Dict[str, Any]] = field(default_factory=list)
    extracted_secrets: List[Dict[str, str]] = field(default_factory=list)
    js_files: List[str] = field(default_factory=list)
    
    # 5. Synthesis & Risk Rating
    exposure_score: float = 0.0  # 0 to 100
    risk_level: str = "LOW"
    key_observations: List[str] = field(default_factory=list)
    recommended_audit_focus: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)


class TargetSandboxObserver:
    """
    محرك الصندوق الذكي لمراقبة وفحص سلوك المواقع.
    """

    KNOWN_WAF_SIGNATURES = {
        "Cloudflare": ["cf-ray", "__cfduid", "cf-cache-status", "cloudflare"],
        "AWS CloudFront/WAF": ["x-amz-cf-id", "cloudfront", "awselb"],
        "Akamai": ["x-akamai-transformed", "akamai"],
        "Imperva / Incapsula": ["x-iinfo", "incap_ses", "_incap_"],
        "Fastly": ["x-fastly-request-id", "fastly"],
        "Sucuri": ["x-sucuri-id", "sucuri"],
        "F5 BIG-IP": ["bigipserver", "x-cnection"],
    }

    SENSITIVE_PARAM_PATTERNS = [
        r"(?i)\b(api[_-]?key|token|auth|secret|password|pwd|admin|bearer|jwt)\b",
        r"(?i)\b(redirect_uri|next|callback|return_url|url)\b",
        r"(?i)\b(id|uid|account_id|user_id|role)\b",
    ]

    SECRET_REGEXES = {
        "Generic API Key": r"(?i)(api[_-]?key|apikey)['\"]?\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{16,64})['\"]",
        "JWT Token": r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",
        "AWS Access Key": r"AKIA[0-9A-Z]{16}",
        "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
        "Firebase URL": r"https://[a-zA-Z0-9_-]+\.firebaseio\.com",
    }

    def __init__(self, timeout_s: float = 15.0, user_agent: Optional[str] = None):
        self.timeout_s = timeout_s
        self.user_agent = user_agent or (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36 (HunterObservatory/2.0)"
        )

    async def observe_target(self, target_url: str) -> TargetObservationReport:
        """
        إجراء الفحص المعزول للموقع وتفكيك سلوكه بالكامل.
        """
        t0 = time.perf_counter()
        if not target_url.startswith(("http://", "https://")):
            target_url = f"https://{target_url}"

        parsed = urlparse(target_url)
        canonical_host = parsed.netloc or parsed.path

        import httpx

        headers = {
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }

        transport_err = None
        resp = None
        html_content = ""
        final_url = target_url
        status_code = 0
        response_headers: Dict[str, str] = {}
        cookies_list: List[Dict[str, Any]] = []

        try:
            async with httpx.AsyncClient(
                verify=False,
                follow_redirects=True,
                timeout=self.timeout_s,
                headers=headers,
            ) as client:
                resp = await client.get(target_url)
                final_url = str(resp.url)
                status_code = resp.status_code
                response_headers = {k.lower(): v for k, v in resp.headers.items()}
                html_content = resp.text

                for cookie in client.cookies.jar:
                    cookies_list.append({
                        "name": cookie.name,
                        "value": cookie.value[:10] + "..." if len(cookie.value) > 10 else cookie.value,
                        "domain": cookie.domain,
                        "path": cookie.path,
                        "secure": cookie.secure,
                        "httponly": cookie.has_nonstandard_attr("httponly") or "httponly" in str(cookie._rest).lower(),
                    })
        except Exception as exc:
            transport_err = str(exc)
            logger.debug("Observation HTTP probe failed for %s: %s", target_url, exc)

        duration_ms = (time.perf_counter() - t0) * 1000

        # Title extraction
        title_match = re.search(r"<title[^>]*>(.*?)</title>", html_content, re.IGNORECASE | re.DOTALL)
        title = title_match.group(1).strip() if title_match else f"Host: {canonical_host}"

        # 1. Tech Stack Detection
        techs: List[TechSignature] = []
        server_banner = response_headers.get("server")
        if server_banner:
            techs.append(TechSignature(category="Web Server", name=server_banner, evidence="Server header"))

        powered_by = response_headers.get("x-powered-by")
        if powered_by:
            techs.append(TechSignature(category="Runtime / Framework", name=powered_by, evidence="X-Powered-By header"))

        # DOM Signatures
        dom_patterns = {
            "WordPress": r"wp-(content|includes)",
            "React": r"(react\.development\.js|react\.production\.min\.js|__NEXT_DATA__|data-reactroot)",
            "Next.js": r"/_next/static/",
            "Vue.js": r"(vue\.runtime|data-v-[a-f0-9]+)",
            "Angular": r"(ng-version|ng-app)",
            "Bootstrap": r"(bootstrap(?:\.min)?\.(?:css|js))",
            "Tailwind CSS": r"(tailwind|font-sans|antialiased)",
            "Laravel": r"(laravel_session|csrf-token|XSRF-TOKEN)",
            "Django": r"(csrfmiddlewaretoken)",
            "jQuery": r"jquery[.-]([0-9.]+)?(?:\.min)?\.js",
            "Shopify": r"cdn\.shopify\.com",
        }
        for name, pattern in dom_patterns.items():
            if re.search(pattern, html_content, re.IGNORECASE):
                techs.append(TechSignature(category="Frontend / CMS", name=name, evidence=f"Matched regex pattern: {pattern}"))

        # WAF Detection
        waf_found = None
        for waf_name, indicators in self.KNOWN_WAF_SIGNATURES.items():
            for ind in indicators:
                header_match = any(ind in k or ind in v for k, v in response_headers.items())
                body_match = ind in html_content[:3000].lower()
                if header_match or body_match:
                    waf_found = waf_name
                    techs.append(TechSignature(category="Security / WAF", name=waf_name, evidence=f"Indicator: {ind}"))
                    break
            if waf_found:
                break

        # 2. Defensive Posture & Missing Security Headers
        recommended_headers = [
            ("content-security-policy", "CSP restricts resource loading and blocks XSS"),
            ("strict-transport-security", "HSTS forces encrypted HTTPS communication"),
            ("x-frame-options", "Prevents UI redressing / Clickjacking"),
            ("x-content-type-options", "Blocks MIME-sniffing exploits"),
            ("referrer-policy", "Controls referral information leakage"),
            ("permissions-policy", "Restricts browser API access (camera, geo, etc.)"),
        ]
        present_sec_headers = {}
        missing_sec_headers = []
        for hdr, reason in recommended_headers:
            if hdr in response_headers:
                present_sec_headers[hdr] = response_headers[hdr]
            else:
                missing_sec_headers.append(f"{hdr} ({reason})")

        # 3. Behavioral Features
        has_auth = bool(re.search(r"(?i)(login|signin|password|username|auth|register|signup|oauth)", html_content))
        has_file_upload = bool(re.search(r'<input[^>]+type=["\']file["\']', html_content, re.IGNORECASE))
        has_payment = bool(re.search(r"(?i)(stripe|paypal|checkout|card[_-]?number|cvv|billing)", html_content))
        forms_count = len(re.findall(r"<form\b", html_content, re.IGNORECASE))

        # Extract JS files
        script_srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html_content, re.IGNORECASE)
        js_urls = [urljoin(final_url, s) for s in script_srcs if s.endswith(".js") or ".js?" in s]
        external_scripts_count = len(script_srcs)

        # Trackers
        tracker_patterns = {
            "Google Analytics": r"(googletagmanager\.com|google-analytics\.com)",
            "Meta / Facebook Pixel": r"connect\.facebook\.net",
            "Hotjar": r"static\.hotjar\.com",
            "Cloudflare Analytics": r"static\.cloudflareinsights\.com",
            "Segment": r"cdn\.segment\.com",
        }
        trackers = []
        for tr_name, pat in tracker_patterns.items():
            if re.search(pat, html_content, re.IGNORECASE):
                trackers.append(tr_name)

        # 4. Discovered Endpoints from HTML & Forms
        endpoints: List[DiscoveredEndpoint] = []
        # Links
        hrefs = re.findall(r'<a[^>]+href=["\']([^"\'#][^"\']*)["\']', html_content, re.IGNORECASE)
        for h in hrefs[:30]:
            full = urljoin(final_url, h)
            if canonical_host in full:
                endpoints.append(DiscoveredEndpoint(url=full, source="href"))

        # Forms
        form_actions = re.findall(r'<form[^>]+action=["\']([^"\']*)["\']', html_content, re.IGNORECASE)
        for act in form_actions:
            endpoints.append(DiscoveredEndpoint(
                url=urljoin(final_url, act),
                method="POST",
                source="form_action",
                is_sensitive=True,
            ))

        # 5. Extract Secrets / Tokens Regex
        secrets_found: List[Dict[str, str]] = []
        for sec_name, rx in self.SECRET_REGEXES.items():
            matches = re.findall(rx, html_content)
            for m in matches:
                val = m[1] if isinstance(m, tuple) else m
                secrets_found.append({
                    "type": sec_name,
                    "preview": f"{val[:6]}...{val[-4:]}" if len(val) > 10 else val,
                })

        # 6. Calculate Exposure Index (0-100)
        exposure_score = 15.0  # baseline for live web surface
        if has_auth:
            exposure_score += 15.0
        if has_file_upload:
            exposure_score += 20.0
        if has_payment:
            exposure_score += 15.0
        if forms_count > 3:
            exposure_score += 10.0
        if len(missing_sec_headers) >= 4:
            exposure_score += 15.0
        if server_banner:
            exposure_score += 5.0
        if secrets_found:
            exposure_score += 20.0

        exposure_score = min(100.0, exposure_score)
        risk_level = "CRITICAL" if exposure_score >= 80 else ("HIGH" if exposure_score >= 60 else ("MEDIUM" if exposure_score >= 40 else "LOW"))

        # Observations & Recommended Audit Focus
        observations = [
            f"Target resolved with status code HTTP {status_code} ({duration_ms:.1f}ms).",
            f"Detected {len(techs)} technical layers/signatures.",
            f"Security headers evaluation: {len(present_sec_headers)} present, {len(missing_sec_headers)} recommended missing.",
        ]
        if waf_found:
            observations.append(f"Fronting Web Application Firewall identified: {waf_found}.")
        if has_auth:
            observations.append("Authentication portals and credential login handlers detected.")
        if has_file_upload:
            observations.append("Multi-part file upload endpoints detected in DOM.")

        recommendations = []
        if has_auth:
            recommendations.append("Audit Authentication mechanisms (OAuth state validation, Rate limiting, Brute-force resilience).")
        if has_file_upload:
            recommendations.append("Audit File Upload handler (MIME-type validation, extension sanitization, storage isolation).")
        if missing_sec_headers:
            recommendations.append("Enforce missing baseline security headers (Content-Security-Policy & Strict-Transport-Security).")
        if endpoints:
            recommendations.append("Map discovered internal API routes for Broken Object Level Authorization (BOLA/IDOR).")

        return TargetObservationReport(
            target_url=target_url,
            canonical_host=canonical_host,
            observation_timestamp=time.time(),
            duration_ms=round(duration_ms, 2),
            status_code=status_code,
            title=title,
            technologies=[asdict(t) for t in techs],
            waf_detected=waf_found,
            server_banner=server_banner,
            security_headers=present_sec_headers,
            missing_headers=missing_sec_headers,
            cookies_analysis=cookies_list,
            has_authentication=has_auth,
            has_file_upload=has_file_upload,
            has_payment_gateway=has_payment,
            forms_count=forms_count,
            external_scripts_count=external_scripts_count,
            trackers_detected=trackers,
            discovered_endpoints=[asdict(e) for e in endpoints[:20]],
            extracted_secrets=secrets_found,
            js_files=js_urls[:10],
            exposure_score=round(exposure_score, 1),
            risk_level=risk_level,
            key_observations=observations,
            recommended_audit_focus=recommendations,
        )
