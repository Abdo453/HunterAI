"""
HunterAI Dynamic Decision Core & Track Dispatcher
=================================================
Implements the signal-driven decision cycle:
  Discovery -> Evidence -> Decision -> Next Tool -> New Evidence -> Decision

Specialized Tracks:
1. WordPress Track (wpscan, /wp-json/, plugins)
2. GraphQL Track (introspection queries, batching)
3. OpenAPI / Swagger Track (schema parsing, endpoint fuzzing)
4. File Upload Track (multipart forms, content-type checks)
5. JWT / Auth Track (token inspection, algorithm checks)
6. Redirect / SSRF Track (redirect=, url=, dest= parameters)
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set

from core.evidence_graph import EvidenceGraph, ParameterNode
from core.memory.failure_memory import FailureMemory
from core.tool_registry import ToolRegistry

logger = logging.getLogger("hunter_ai.decision_core")


class AttackTrack(str, Enum):
    WORDPRESS = "wordpress"
    GRAPHQL = "graphql"
    OPENAPI_SWAGGER = "openapi_swagger"
    FILE_UPLOAD = "file_upload"
    JWT_AUTH = "jwt_auth"
    REDIRECT_SSRF = "redirect_ssrf"
    IDOR_ACCESS_CONTROL = "idor_access_control"
    STANDARD_RECON = "standard_recon"


@dataclass
class TrackRecommendation:
    track: AttackTrack
    target_url: str
    target_path: str
    trigger_signal: str
    recommended_tools: List[str]
    suggested_hypothesis: str
    test_plan: str
    confidence_in_signal: float = 0.9


class DecisionCore:
    """
    Analyzes live discoveries and evidence to dynamically route testing into specialized tracks.
    """

    def __init__(
        self,
        tool_registry: ToolRegistry,
        failure_memory: Optional[FailureMemory] = None,
    ):
        self.tool_registry = tool_registry
        self.failure_memory = failure_memory or FailureMemory()

    def evaluate_signals(
        self,
        target_host: str,
        endpoints: List[str],
        parameters: List[str],
        technologies: List[str],
        raw_observations: List[str] = None,
    ) -> List[TrackRecommendation]:
        """
        Scans all incoming discoveries and generates prioritized track recommendations.
        """
        recommendations: List[TrackRecommendation] = []
        obs_text = " ".join(raw_observations or []).lower()
        tech_text = " ".join(technologies).lower()
        joined_endpoints = " ".join(endpoints).lower()

        # 1. WordPress Track
        if "wordpress" in tech_text or "wp-content" in joined_endpoints or "wp-json" in joined_endpoints:
            can_run, _ = self.failure_memory.should_execute("wordpress_track", target_host)
            if can_run:
                recommendations.append(
                    TrackRecommendation(
                        track=AttackTrack.WORDPRESS,
                        target_url=f"https://{target_host}",
                        target_path="/wp-json/",
                        trigger_signal="WordPress signatures detected in technologies or paths",
                        recommended_tools=["wpscan"],
                        suggested_hypothesis="Exposed WordPress REST API user enumeration or outdated plugin vulnerability",
                        test_plan="Probe /wp-json/wp/v2/users and enumerate installed plugins against vulnerability database",
                    )
                )

        # 2. GraphQL Track
        if any(ep for ep in endpoints if ep.lower().rstrip("/").endswith("graphql")):
            can_run, _ = self.failure_memory.should_execute("graphql_track", target_host)
            if can_run:
                recommendations.append(
                    TrackRecommendation(
                        track=AttackTrack.GRAPHQL,
                        target_url=f"https://{target_host}",
                        target_path="/graphql",
                        trigger_signal="GraphQL endpoint discovered",
                        recommended_tools=["custom_graphql_client", "ffuf"],
                        suggested_hypothesis="GraphQL Schema Introspection enabled allowing sensitive field disclosure",
                        test_plan="POST /graphql with __schema query to test introspection authorization",
                    )
                )

        # 3. OpenAPI / Swagger Track
        swagger_match = [ep for ep in endpoints if any(s in ep.lower() for s in ["swagger", "api-docs", "openapi.json"])]
        if swagger_match:
            can_run, _ = self.failure_memory.should_execute("swagger_track", target_host)
            if can_run:
                target_swag = swagger_match[0]
                recommendations.append(
                    TrackRecommendation(
                        track=AttackTrack.OPENAPI_SWAGGER,
                        target_url=f"https://{target_host}{target_swag}",
                        target_path=target_swag,
                        trigger_signal="Interactive API documentation discovered",
                        recommended_tools=["httpx", "custom_schema_parser"],
                        suggested_hypothesis="Publicly accessible API documentation reveals hidden administrative endpoints",
                        test_plan="Parse schema paths and test undocumented parameters with differential auth headers",
                    )
                )

        # 4. Redirect / SSRF Track
        ssrf_params = {"redirect", "url", "next", "dest", "destination", "return", "callback", "target", "uri"}
        found_ssrf = [p for p in parameters if p.lower() in ssrf_params]
        if found_ssrf:
            for p in found_ssrf:
                can_run, _ = self.failure_memory.should_execute(f"ssrf_{p}", target_host)
                if can_run:
                    recommendations.append(
                        TrackRecommendation(
                            track=AttackTrack.REDIRECT_SSRF,
                            target_url=f"https://{target_host}",
                            target_path="",
                            trigger_signal=f"Potentially vulnerable redirect/URL parameter detected: '{p}'",
                            recommended_tools=["httpx"],
                            suggested_hypothesis=f"Parameter '{p}' lacks domain validation, allowing Open Redirect or SSRF",
                            test_plan=f"Provide controlled test canary domain and verify HTTP 30x Location header",
                        )
                    )

        # 5. File Upload Track
        if "upload" in joined_endpoints or "multipart" in obs_text:
            can_run, _ = self.failure_memory.should_execute("upload_track", target_host)
            if can_run:
                recommendations.append(
                    TrackRecommendation(
                        track=AttackTrack.FILE_UPLOAD,
                        target_url=f"https://{target_host}",
                        target_path="/upload",
                        trigger_signal="File upload endpoint or multipart form observed",
                        recommended_tools=["browser_automation"],
                        suggested_hypothesis="File upload mechanism lacks strict MIME/extension validation",
                        test_plan="Upload non-executable benign test file and verify response path reflection",
                    )
                )

        # 6. IDOR / Access Control Track
        id_params = {"id", "user_id", "account_id", "org_id", "profile_id", "doc_id"}
        found_ids = [p for p in parameters if p.lower() in id_params]
        if found_ids:
            for p in found_ids:
                recommendations.append(
                    TrackRecommendation(
                        track=AttackTrack.IDOR_ACCESS_CONTROL,
                        target_url=f"https://{target_host}",
                        target_path="",
                        trigger_signal=f"Direct object identifier parameter detected: '{p}'",
                        recommended_tools=["browser_automation", "traffic_bridge"],
                        suggested_hypothesis=f"Parameter '{p}' can be enumerated across user tenants (IDOR)",
                        test_plan=f"Replay request with alternate tenant session and check for differential response",
                    )
                )

        logger.info(f"DECISION CORE: Generated {len(recommendations)} active track recommendations for '{target_host}'")
        return recommendations
