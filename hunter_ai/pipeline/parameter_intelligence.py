"""
HunterAI Parameter Intelligence Engine
=====================================
Analyzes endpoints, paths, parameter names, and sample values to:
1. Determine the semantic role of the parameter (Image transformation, search, auth, ID, redirect, file, command, tracking).
2. Filter out non-injectable media optimization & tracking noise.
3. Gate hypothesis generation so active testing is only directed at meaningful attack surfaces.
"""
from __future__ import annotations

import re
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, urlparse, urlsplit, urlunsplit, urlencode


class ParameterRole(str, Enum):
    IMAGE_TRANSFORMATION = "IMAGE_TRANSFORMATION"
    SEARCH_QUERY = "SEARCH_QUERY"
    RESOURCE_IDENTIFIER = "RESOURCE_IDENTIFIER"
    AUTH_CREDENTIAL = "AUTH_CREDENTIAL"
    REDIRECT_TARGET = "REDIRECT_TARGET"
    FILE_PATH = "FILE_PATH"
    COMMAND_EXECUTION = "COMMAND_EXECUTION"
    TRACKING_METRIC = "TRACKING_METRIC"
    PAGINATION_STATE = "PAGINATION_STATE"
    GENERIC_INPUT = "GENERIC_INPUT"


class ParameterClassification:
    def __init__(
        self,
        parameter: str,
        role: ParameterRole,
        risk_level: str,
        potential_vulns: List[str],
        is_active_candidate: bool,
        rationale: str,
    ):
        self.parameter = parameter
        self.role = role
        self.risk_level = risk_level  # CRITICAL, HIGH, MEDIUM, LOW, NOISE
        self.potential_vulns = potential_vulns
        self.is_active_candidate = is_active_candidate
        self.rationale = rationale

    def to_dict(self) -> Dict[str, Any]:
        return {
            "parameter": self.parameter,
            "role": self.role.value,
            "risk_level": self.risk_level,
            "potential_vulns": self.potential_vulns,
            "is_active_candidate": self.is_active_candidate,
            "rationale": self.rationale,
        }


class ParameterIntelligenceEngine:
    """
    Intelligent classifier for HTTP request parameters.
    Prevents false positives and hypothesis bloat on static assets and tracking noise.
    """

    STATIC_EXTENSIONS: Set[str] = {
        ".webp", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".bmp", ".tiff",
        ".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp4", ".mp3", ".avi", ".mov",
        ".css", ".map", ".js", ".mjs"
    }

    IMAGE_OPTIMIZATION_PARAMS: Set[str] = {
        "q", "w", "h", "f", "fit", "quality", "width", "height", "format",
        "resize", "crop", "auto", "dpr", "blur", "sharp", "bg-color", "output"
    }

    TRACKING_PARAMS: Set[str] = {
        "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
        "fbclid", "gclid", "dclid", "msclkid", "_ga", "_gl", "_hsenc", "_hsmi",
        "mc_cid", "mc_eid", "ref", "v", "ver", "version", "ts", "timestamp", "nonce", "_"
    }

    PAGINATION_PARAMS: Set[str] = {
        "page", "p", "offset", "limit", "size", "count", "per_page", "page_size", "cursor", "start"
    }

    ID_PARAMS: Set[str] = {
        "id", "user_id", "uid", "account_id", "item_id", "order_id", "profile_id",
        "doc_id", "uuid", "guid", "post_id", "customer_id", "org_id", "member_id"
    }

    AUTH_PARAMS: Set[str] = {
        "token", "auth", "jwt", "api_key", "secret", "password", "pass", "pwd",
        "code", "session", "bearer", "access_token", "refresh_token", "auth_token", "key"
    }

    REDIRECT_PARAMS: Set[str] = {
        "url", "redirect", "redirect_url", "redirect_to", "dest", "destination",
        "return_to", "next", "forward", "target_url", "callback", "oauth_callback", "src", "link"
    }

    FILE_PARAMS: Set[str] = {
        "file", "path", "folder", "doc", "page", "template", "include", "view",
        "layout", "load_file", "filename", "filepath", "document", "report_path"
    }

    COMMAND_PARAMS: Set[str] = {
        "cmd", "exec", "command", "ping", "host", "ip", "run", "eval", "script", "cli", "query_exec"
    }

    SEARCH_PARAMS: Set[str] = {
        "q", "search", "query", "s", "keyword", "term", "filter", "find", "search_term", "lookup"
    }

    @classmethod
    def classify(
        cls,
        endpoint_url: str,
        param_name: str,
        sample_value: Optional[str] = None,
        content_type: Optional[str] = None
    ) -> ParameterClassification:
        p_clean = param_name.strip()
        p_low = p_clean.lower()
        url_parsed = urlparse(endpoint_url)
        path_low = url_parsed.path.lower()

        is_static_path = any(path_low.endswith(ext) for ext in cls.STATIC_EXTENSIONS)
        is_image_endpoint = is_static_path or any(sub in path_low for sub in ("/images/", "/image/", "/_next/image", "/assets/img/", "/media/"))

        # 1. Image Transformation Filter (q, w, f on image paths)
        if is_image_endpoint and (p_low in cls.IMAGE_OPTIMIZATION_PARAMS or is_static_path):
            return ParameterClassification(
                parameter=p_clean,
                role=ParameterRole.IMAGE_TRANSFORMATION,
                risk_level="NOISE",
                potential_vulns=[],
                is_active_candidate=False,
                rationale=f"Image transformation parameter '{p_clean}' on static/media endpoint '{path_low}'",
            )

        # 2. Tracking / Telemetry Parameters
        if p_low in cls.TRACKING_PARAMS:
            return ParameterClassification(
                parameter=p_clean,
                role=ParameterRole.TRACKING_METRIC,
                risk_level="NOISE",
                potential_vulns=[],
                is_active_candidate=False,
                rationale=f"Tracking/telemetry parameter '{p_clean}' — non-functional for vulnerability testing",
            )

        # 3. Command Execution
        if p_low in cls.COMMAND_PARAMS:
            return ParameterClassification(
                parameter=p_clean,
                role=ParameterRole.COMMAND_EXECUTION,
                risk_level="CRITICAL",
                potential_vulns=["CmdInjection"],
                is_active_candidate=True,
                rationale=f"High-risk command parameter '{p_clean}' mapped to OS Command Injection",
            )

        # 4. Resource Identifiers (IDOR / SQLi)
        if p_low in cls.ID_PARAMS or re.match(r"^.*_?(id|uid|uuid|guid)$", p_low):
            return ParameterClassification(
                parameter=p_clean,
                role=ParameterRole.RESOURCE_IDENTIFIER,
                risk_level="HIGH",
                potential_vulns=["IDOR", "SQLi"],
                is_active_candidate=True,
                rationale=f"Resource identifier '{p_clean}' mapped to IDOR and SQL Injection",
            )

        # 5. Redirect / SSRF
        if p_low in cls.REDIRECT_PARAMS:
            return ParameterClassification(
                parameter=p_clean,
                role=ParameterRole.REDIRECT_TARGET,
                risk_level="HIGH",
                potential_vulns=["SSRF", "OpenRedirect"],
                is_active_candidate=True,
                rationale=f"Redirect/URL parameter '{p_clean}' mapped to SSRF and Open Redirect",
            )

        # 6. File Path / Inclusion
        if p_low in cls.FILE_PARAMS:
            return ParameterClassification(
                parameter=p_clean,
                role=ParameterRole.FILE_PATH,
                risk_level="HIGH",
                potential_vulns=["LFI", "PathTraversal"],
                is_active_candidate=True,
                rationale=f"File parameter '{p_clean}' mapped to Local File Inclusion and Path Traversal",
            )

        # 7. Search / Text Input (XSS / SSTI)
        if p_low in cls.SEARCH_PARAMS and not is_static_path:
            return ParameterClassification(
                parameter=p_clean,
                role=ParameterRole.SEARCH_QUERY,
                risk_level="MEDIUM",
                potential_vulns=["XSS", "SSTI"],
                is_active_candidate=True,
                rationale=f"Search/text input parameter '{p_clean}' mapped to XSS and SSTI",
            )

        # 8. Authentication / Secrets
        if p_low in cls.AUTH_PARAMS:
            return ParameterClassification(
                parameter=p_clean,
                role=ParameterRole.AUTH_CREDENTIAL,
                risk_level="HIGH",
                potential_vulns=["IDOR"],
                is_active_candidate=True,
                rationale=f"Auth/token parameter '{p_clean}' mapped to Access Control & Authorization",
            )

        # 9. Pagination
        if p_low in cls.PAGINATION_PARAMS:
            return ParameterClassification(
                parameter=p_clean,
                role=ParameterRole.PAGINATION_STATE,
                risk_level="LOW",
                potential_vulns=["SQLi"],
                is_active_candidate=True,
                rationale=f"Pagination parameter '{p_clean}' mapped to SQL Injection (Offset/Limit fuzzing)",
            )

        # 10. Generic Input on dynamic endpoints
        if not is_static_path:
            return ParameterClassification(
                parameter=p_clean,
                role=ParameterRole.GENERIC_INPUT,
                risk_level="MEDIUM",
                potential_vulns=["XSS", "SQLi"],
                is_active_candidate=True,
                rationale=f"Generic input parameter '{p_clean}' on dynamic endpoint",
            )

        # Fallback for static assets
        return ParameterClassification(
            parameter=p_clean,
            role=ParameterRole.GENERIC_INPUT,
            risk_level="NOISE",
            potential_vulns=[],
            is_active_candidate=False,
            rationale=f"Parameter '{p_clean}' on static asset — skipped",
        )


def inject_url_parameter(url: str, param_name: str, payload: str) -> str:
    """
    Safely injects or replaces a query parameter in a target URL.
    Never causes double query marks (??) or string concatenation errors.
    """
    parts = urlsplit(url)
    params = parse_qsl(parts.query, keep_blank_values=True)
    found = False
    new_params = []
    for k, v in params:
        if k == param_name:
            new_params.append((k, payload))
            found = True
        else:
            new_params.append((k, v))
    if not found:
        new_params.append((param_name, payload))

    return urlunsplit((
        parts.scheme,
        parts.netloc,
        parts.path,
        urlencode(new_params),
        parts.fragment
    ))
