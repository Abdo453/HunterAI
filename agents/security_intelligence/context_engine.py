"""
Context Engine for Security Intelligence
Synthesizes project architecture, target history, authentication states, and endpoint parameters into an enriched SecurityContext.
"""
import logging
from typing import Dict, Any, Optional
from agents.security_intelligence.schemas import SecurityObservation, SecurityContext
from agents.security_intelligence.memory_manager import MemoryManager

log = logging.getLogger("security_intelligence.context")


class ContextEngine:
    """محرك بناء السياق الأمني: تزويد الاستدلال بخلفية المشروع والهدف والتوثيق والتقنيات"""

    def __init__(self, memory_manager: Optional[MemoryManager] = None):
        self.memory = memory_manager or MemoryManager()

    def build_context(self, observation: SecurityObservation) -> SecurityContext:
        """
        بناء السياق الأمني المتكامل للملاحظة الحالية
        """
        data = observation.data
        path = data.get("path", "") or data.get("url", "")
        method = data.get("method", "GET").upper()
        headers = data.get("headers", {})

        # Extract Authentication state
        is_auth = False
        auth_type = "none"
        auth_header = headers.get("authorization", "") or headers.get("Authorization", "")
        cookie_header = headers.get("cookie", "") or headers.get("Cookie", "")

        if auth_header:
            is_auth = True
            if "bearer" in auth_header.lower():
                auth_type = "jwt" if "eyj" in auth_header.lower() else "bearer_token"
            elif "basic" in auth_header.lower():
                auth_type = "basic"
            else:
                auth_type = "api_key"
        elif cookie_header:
            is_auth = True
            auth_type = "session_cookie"

        # Parameters
        params = data.get("parameters", [])
        if isinstance(params, dict):
            param_list = list(params.keys())
        elif isinstance(params, list):
            param_list = [str(p) for p in params]
        else:
            param_list = []

        # Target history
        target_host = observation.target
        hist_count = self.memory.target.get_findings_count(target_host)
        proj_summary = self.memory.project.get_summary()

        context_notes = []
        if is_auth:
            context_notes.append(f"Authenticated session ({auth_type})")
        if method in ["POST", "PUT", "PATCH", "DELETE"]:
            context_notes.append(f"State-changing HTTP {method}")
        if proj_summary["technologies"]:
            context_notes.append(f"Known tech: {', '.join(proj_summary['technologies'][:3])}")

        return SecurityContext(
            target=target_host,
            project_id=observation.project_id,
            endpoint_path=path,
            http_method=method,
            is_authenticated=is_auth,
            auth_type=auth_type,
            known_technologies=proj_summary.get("technologies", []),
            historical_findings_count=hist_count,
            is_state_changing=method in ["POST", "PUT", "PATCH", "DELETE"],
            parameters_observed=param_list,
            context_notes=context_notes
        )
