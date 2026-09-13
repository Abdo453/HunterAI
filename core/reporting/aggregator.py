"""
HunterAI Finding Aggregator & Root-Cause Clustering
===================================================
Groups findings that stem from the exact same underlying vulnerability
(e.g., identical missing security header, shared vulnerable ORM model across 20 endpoints)
into a single Consolidated Finding with an attached list of affected assets.
Eliminates report fatigue and alert noise.
"""
from __future__ import annotations

import hashlib
from typing import Any, Dict, List
from core.finding_model import Finding


class FindingAggregator:
    """Consolidates findings by Root Cause signature"""

    @classmethod
    def _compute_root_cause_hash(cls, finding: Finding) -> str:
        # Group by: vulnerability_type + title + cwe
        seed = f"{finding.vulnerability_type}:{finding.title}:{finding.cwe}"
        return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:12]

    @classmethod
    def aggregate(cls, findings: List[Finding]) -> List[Dict[str, Any]]:
        """Groups findings by root-cause signature, collecting all affected endpoints"""
        clusters: Dict[str, Dict[str, Any]] = {}

        for f in findings:
            rc_hash = cls._compute_root_cause_hash(f)
            if rc_hash not in clusters:
                clusters[rc_hash] = {
                    "root_cause_id": f"RC-{rc_hash.upper()}",
                    "primary_finding": f,
                    "vulnerability_type": f.vulnerability_type,
                    "title": f.title,
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "cwe": f.cwe,
                    "owasp": f.owasp,
                    "impact": f.impact,
                    "remediation": f.remediation,
                    "affected_endpoints": []
                }
            clusters[rc_hash]["affected_endpoints"].append({
                "endpoint": f.endpoint,
                "parameter": f.parameter,
                "target": f.target,
                "proof_token": f.verification.proof_token
            })

        return list(clusters.values())
