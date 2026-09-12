"""
HunterAI Validation Arena - Target Lab Model & Transport
=========================================================
Provides realistic mock web application environments with deterministic ground-truth:
- Simulates server-side logic, session validation, parameter parsing, and error differentials
- Encapsulates ground truth: vulnerability classification, proof nonce, and expected court verdict
"""
from __future__ import annotations

import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple


@dataclass
class TargetGroundTruth:
    has_vulnerability: bool
    vulnerability_class: Optional[str]  # e.g., "cmd_injection", "sqli", "idor", "ssrf", "ssti", "xss", "jwt", None
    parameter: Optional[str]
    cwe_id: Optional[str]
    safe_verification_proof: Optional[str]
    expected_verdict: str  # "CONFIRMED" or "REFUTED"
    rationale: str


@dataclass
class ArenaTarget:
    """A benchmark lab target representing a specific vulnerability or safe negative control"""
    target_id: str
    name: str
    category: str
    description: str
    host: str
    path: str
    method: str = "GET"
    parameters: List[str] = field(default_factory=list)
    ground_truth: TargetGroundTruth = field(default_factory=lambda: TargetGroundTruth(
        has_vulnerability=False,
        vulnerability_class=None,
        parameter=None,
        cwe_id=None,
        safe_verification_proof=None,
        expected_verdict="REFUTED",
        rationale="Safe endpoint"
    ))
    handler: Optional[Callable[[str, str, Dict[str, str], Dict[str, str], str], Tuple[int, Dict[str, str], str]]] = None

    def execute_http(
        self,
        method: str,
        path: str,
        headers: Optional[Dict[str, str]] = None,
        query: str = "",
        body: str = ""
    ) -> Tuple[int, Dict[str, str], str]:
        """Executes simulated HTTP request against the lab target handler"""
        headers = headers or {}
        parsed_query = urllib.parse.parse_qs(query, keep_blank_values=True)
        # Flatten query dict
        query_params = {k: v[0] if v else "" for k, v in parsed_query.items()}

        # Parse body if form encoded
        body_params: Dict[str, str] = {}
        if headers.get("Content-Type", "").startswith("application/x-www-form-urlencoded") and body:
            parsed_body = urllib.parse.parse_qs(body, keep_blank_values=True)
            body_params = {k: v[0] if v else "" for k, v in parsed_body.items()}

        merged_params = {**query_params, **body_params}

        if self.handler:
            return self.handler(method.upper(), path, headers, merged_params, body)

        return 200, {"Content-Type": "text/plain"}, "OK"
