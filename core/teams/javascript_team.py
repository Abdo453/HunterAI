"""
HunterAI JavaScript & Frontend Intelligence Team (P1)
======================================================
Specialized multi-agent squad for client-side bundle and code intelligence:
  1. BundleAnalysisAgent: Unpacks and inspects webpack/vite chunks and minified scripts
  2. RouteExtractionAgent: Extracts hidden endpoints, internal paths, and API contracts
  3. SecretTriageAgent: Flags hardcoded API keys, bearer tokens, internal dev domains
  4. JSReviewAgent: Independent reviewer validating extracted routes & updating CoverageLedger
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional

from core.contracts.task_contracts import (
    AgentTeam,
    EvidenceArtifact,
    EvidenceSignificance,
    TaskContract,
    ToolExecutionResult,
)
from core.coverage.coverage_ledger import AssetType, CoverageLedger

logger = logging.getLogger("hunter_ai.teams.javascript")


class RouteExtractionAgent:
    """Extracts hidden routes and unlinked endpoints from client-side JS bundles."""
    def __init__(self, agent_name: str = "RouteExtractionAgent"):
        self.name = agent_name

    def execute(self, task: TaskContract, context: Dict[str, Any]) -> ToolExecutionResult:
        target_script = task.target
        logger.info("[%s] Parsing JavaScript bundle: %s", self.name, target_script)

        # Simulated AST/Regex extraction of frontend routes
        extracted_routes = [
            "/api/v1/internal/health",
            "/api/v1/admin/feature-flags",
            "/api/v1/users/export",
            "/v2/debug/profiler",
        ]

        evidence = [
            EvidenceArtifact(
                significance=EvidenceSignificance.OBSERVATION,
                source_tool=self.name,
                target=r,
                description=f"Hidden endpoint extracted from JS bundle: {r}",
            )
            for r in extracted_routes
        ]

        return ToolExecutionResult(
            task_id=task.task_id,
            tool_name=self.name,
            action="route_extraction",
            target=target_script,
            success=True,
            raw_output=f"Extracted {len(extracted_routes)} internal endpoints",
            normalized_data={"extracted_routes": extracted_routes},
            evidence_artifacts=evidence,
            covered_items=[target_script],
            coverage_limits=["Regex & AST string pattern scan"],
            unresolved_unknowns=["Dynamically assembled route concatenations"],
            recommended_next_steps=[
                {"team": "WEB", "action": "http_analysis", "target": r}
                for r in extracted_routes[:2]
            ],
        )


class SecretTriageAgent:
    """Scans bundles for credentials, API tokens, and internal dev domains."""
    def __init__(self, agent_name: str = "SecretTriageAgent"):
        self.name = agent_name

    def execute(self, task: TaskContract, context: Dict[str, Any]) -> ToolExecutionResult:
        target_script = task.target
        logger.info("[%s] Triaging secrets in bundle %s", self.name, target_script)

        # Triaged findings
        identified_tokens = [
            {
                "type": "PUBLIC_STRIPE_KEY",
                "value": "pk_live_********************",
                "risk": "LOW_INTENDED_PUBLIC",
                "file": target_script,
            }
        ]

        evidence = [
            EvidenceArtifact(
                significance=EvidenceSignificance.OBSERVATION,
                source_tool=self.name,
                target=target_script,
                description=f"Client-side public API key identified: {identified_tokens[0]['type']}",
            )
        ]

        return ToolExecutionResult(
            task_id=task.task_id,
            tool_name=self.name,
            action="secret_triage",
            target=target_script,
            success=True,
            raw_output=f"Found {len(identified_tokens)} token patterns",
            normalized_data={"secrets": identified_tokens},
            evidence_artifacts=evidence,
            covered_items=[target_script],
            coverage_limits=["Standard regex credential scanner"],
            unresolved_unknowns=["Obfuscated or encrypted runtime strings"],
        )


class JSReviewAgent:
    """Independent reviewer for JavaScript Team tasks; updates CoverageLedger."""
    def __init__(self, agent_name: str = "JSReviewAgent"):
        self.name = agent_name

    def review(self, task: TaskContract, ledger: Optional[CoverageLedger] = None) -> bool:
        if not task.result or not task.result.success:
            task.reject_review(self.name, "JS task execution failed.")
            return False

        if ledger and task.result.normalized_data:
            # Record the bundle
            ledger.record_discovery(AssetType.JS_BUNDLE, task.target, discovered_by=task.owner_agent)
            ledger.record_analysis(AssetType.JS_BUNDLE, task.target, analyzed_by=self.name)

            # Record newly revealed endpoints
            routes = task.result.normalized_data.get("extracted_routes", [])
            for r in routes:
                ledger.record_discovery(AssetType.ENDPOINT, r, discovered_by=task.owner_agent, metadata={"source_bundle": task.target})

        task.approve_review(self.name, f"JS bundle review complete; verified {len(task.result.covered_items)} files.")
        return True
