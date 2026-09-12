"""
HunterAI Correlation, Deduplication, and Priority Engines
Correlates signals across tools, merges duplicate findings with Bayesian confidence,
and sorts into strict Bug Bounty priority tiers (P0 - P5).
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Set, Tuple
from hunter_ai.pipeline.schemas import (
    HunterFinding,
    FindingStatus,
    EndpointRecord,
    ParameterRecord,
    SecretFindingRecord,
    LiveAssetRecord,
)

logger = logging.getLogger("hunter_ai.correlation")


class CorrelationEngine:
    """
    Correlates intelligence signals across stages:
    - Links JS secrets and API tokens to active API endpoints.
    - Links historical parameters (Wayback) to current alive endpoints.
    - Identifies high-value attack surfaces by correlating multi-stage signals.
    """

    @staticmethod
    def correlate_attack_surface(
        endpoints: List[EndpointRecord],
        parameters: List[ParameterRecord],
        secrets: List[SecretFindingRecord],
        live_assets: List[LiveAssetRecord]
    ) -> List[Dict[str, Any]]:
        correlated_targets = []
        live_urls = {a.url.rstrip("/") for a in live_assets}

        # Index secrets by domain/asset
        secret_keys = [s.secret_type for s in secrets]

        for p in parameters:
            base_ep = p.endpoint.split("?")[0].rstrip("/")
            is_live = any(base_ep.startswith(lu) for lu in live_urls)

            relevance_score = 1.0
            reasons = []

            if is_live:
                relevance_score += 0.5
                reasons.append("Endpoint is verified alive (HTTP 200)")

            if p.potential_classes:
                relevance_score += 0.3 * len(p.potential_classes)
                reasons.append(f"Mapped to high-risk classes: {', '.join(p.potential_classes)}")

            if any("api" in p.endpoint.lower() for _ in [1]):
                relevance_score += 0.4
                reasons.append("REST / API Endpoint")
                if secret_keys:
                    relevance_score += 0.5
                    reasons.append(f"Associated with exposed client secrets ({len(secrets)})")

            correlated_targets.append({
                "endpoint": p.endpoint,
                "parameter": p.parameter,
                "potential_classes": p.potential_classes,
                "relevance_score": round(relevance_score, 2),
                "reasons": reasons,
                "is_live": is_live
            })

        correlated_targets.sort(key=lambda x: x["relevance_score"], reverse=True)
        return correlated_targets


class DeduplicationEngine:
    """
    Merges duplicate findings across multiple tools and models.
    Combines evidence, prevents duplicate report entries, and increases confidence.
    """

    @staticmethod
    def deduplicate(findings: List[HunterFinding]) -> List[HunterFinding]:
        seen: Dict[Tuple[str, Optional[str], str], HunterFinding] = {}

        for f in findings:
            # Key: (endpoint, parameter, normalized_vuln_type)
            norm_type = f.vuln_type.lower().replace("-", "_").replace(" ", "_")
            if "sql" in norm_type:
                norm_type = "sqli"
            elif "xss" in norm_type or "cross" in norm_type:
                norm_type = "xss"
            elif "cmd" in norm_type or "rce" in norm_type or "command" in norm_type:
                norm_type = "cmd_injection"
            elif "ssrf" in norm_type:
                norm_type = "ssrf"
            elif "idor" in norm_type or "bola" in norm_type:
                norm_type = "idor"

            key = (f.endpoint.split("?")[0], f.parameter, norm_type)

            if key not in seen:
                seen[key] = f
            else:
                existing = seen[key]
                # Merge evidence
                existing.evidence.extend(f.evidence)
                # Bayesian Confidence Combination: C = 1 - (1 - C1)*(1 - C2)
                combined_conf = 1.0 - (1.0 - existing.confidence) * (1.0 - f.confidence)
                existing.confidence = round(min(0.99, max(existing.confidence, combined_conf)), 2)
                # Promote status if newly confirmed
                if f.status == FindingStatus.CONFIRMED:
                    existing.status = FindingStatus.CONFIRMED
                # Retain highest CVSS score
                existing.cvss_score = max(existing.cvss_score, f.cvss_score)
                # Append tool source
                if f.tool not in existing.tool:
                    existing.tool = f"{existing.tool}, {f.tool}"

        return list(seen.values())


class PriorityEngine:
    """
    Ranks findings into standard Bug Bounty priority tiers (P0 to P5):
    - P0: Critical confirmed (RCE, SQLi with extraction, account takeover)
    - P1: High confirmed (SSRF internal, severe IDOR, stored XSS)
    - P2: Medium confirmed (Reflected XSS, CSRF, info leakage)
    - P3: Low confirmed (Weak headers, open redirect)
    - P4: Interesting / Information (Open ports, tech stack, directory listing)
    - P5: Unverified / Candidate hypothesis
    """

    @staticmethod
    def assign_priority(finding: HunterFinding) -> str:
        if finding.status != FindingStatus.CONFIRMED:
            return "P5"

        score = finding.cvss_score
        if score >= 9.0:
            return "P0"
        elif score >= 7.0:
            return "P1"
        elif score >= 4.0:
            return "P2"
        elif score > 0.0:
            return "P3"
        return "P4"

    @classmethod
    def rank_findings(cls, findings: List[HunterFinding]) -> List[Tuple[str, HunterFinding]]:
        ranked = [(cls.assign_priority(f), f) for f in findings]
        tier_order = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "P4": 4, "P5": 5}
        ranked.sort(key=lambda x: (tier_order.get(x[0], 9), -x[1].cvss_score))
        return ranked
