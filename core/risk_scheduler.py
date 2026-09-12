"""
Risk-Based Scheduler
====================
Calculates multidimensional Risk Priority Score for testing targets:
Risk Score = Param Context + Endpoint Type + Auth State + Technology - WAF Penalty
Prioritizes API / auth endpoints and de-prioritizes / skips UI navigation parameters.
"""
from typing import Dict, Any


class RiskScheduler:
    """Ranks and filters parameters and endpoints for active testing"""

    UI_PARAMS = {"modal", "slide", "ampslide", "tab", "page", "step", "view", "theme", "lang", "layout", "nav"}

    @classmethod
    def calculate_priority(
        cls,
        endpoint_url: str,
        param_name: str,
        skill_name: str,
        auth_state: str = "unauthenticated",
        waf_detected: bool = False
    ) -> float:
        p_lower = param_name.lower()
        score = 0.50

        # 1. Parameter Context Filter
        if p_lower in cls.UI_PARAMS:
            # UI navigation parameters should almost NEVER be tested with heavy skills
            if skill_name in ("cmd_injection", "sqli", "ssrf"):
                return 0.10  # Automatically below the 0.35 execution threshold
            score -= 0.30

        if any(k in p_lower for k in ("id", "user", "uid", "account", "order")):
            score += 0.30
        elif any(k in p_lower for k in ("cmd", "exec", "query", "q", "search", "ip")):
            score += 0.25

        # 2. Endpoint Type
        ep_lower = endpoint_url.lower()
        if "/api/" in ep_lower or "/v1/" in ep_lower or "/graphql" in ep_lower:
            score += 0.20
        elif any(t in ep_lower for t in ("/terms", "/privacy", "/about", "/help")):
            score -= 0.20

        # 3. WAF Penalty
        if waf_detected and skill_name in ("sqli", "cmd_injection"):
            score -= 0.15

        return round(max(0.0, min(1.0, score)), 2)

    @classmethod
    def should_execute_skill(cls, priority_score: float, min_threshold: float = 0.35) -> bool:
        return priority_score >= min_threshold