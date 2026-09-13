"""
HunterAI Evidence Quality Score (EQS) & Expiration Engine
=========================================================
Computes a rigorous quality rating (0 - 100) across 5 empirical pillars:
1. Completeness (20%): Full baseline, control, request, response data
2. Reproducibility (25%): Independent replay success rate (e.g. 3/3)
3. Cryptographic Integrity (20%): SHA-256 hash match against report signature
4. Differential Signal (20%): Statistical distinctness of anomaly
5. Freshness / Expiration (15%): Evidence decay over time (default TTL: 7 days)
"""
from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, Optional


class EvidenceFreshnessStatus(str, Enum):
    FRESH = "FRESH"
    AGING = "AGING"
    STALE_REQUIRES_RETEST = "STALE_REQUIRES_RETEST"


@dataclass
class EvidenceQualityMetrics:
    completeness: float = 1.0          # 0.0 to 1.0
    reproducibility: float = 1.0       # 0.0 to 1.0 (e.g. 3/3 = 1.0)
    integrity_verified: bool = True    # Cryptographic hash verification
    differential_signal: float = 1.0   # 0.0 to 1.0
    age_days: float = 0.0              # Days elapsed since initial observation
    ttl_days: float = 7.0              # Configured evidence validity lifespan


@dataclass
class EvidenceQualityReport:
    overall_score: float               # 0.0 to 100.0
    grade: str                         # A+, A, B, C, F
    freshness_status: EvidenceFreshnessStatus
    is_audit_grade: bool
    breakdown: Dict[str, float]
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["freshness_status"] = self.freshness_status.value
        return d


class EvidenceQualityEngine:
    """Evaluates the mathematical and temporal rigor of security findings"""

    @classmethod
    def evaluate(cls, metrics: EvidenceQualityMetrics) -> EvidenceQualityReport:
        # Determine Freshness Status
        if metrics.age_days > metrics.ttl_days:
            freshness_status = EvidenceFreshnessStatus.STALE_REQUIRES_RETEST
            freshness_score = 0.0
        elif metrics.age_days > (metrics.ttl_days * 0.5):
            freshness_status = EvidenceFreshnessStatus.AGING
            decay = (metrics.age_days - (metrics.ttl_days * 0.5)) / (metrics.ttl_days * 0.5)
            freshness_score = round(15.0 * (1.0 - decay), 1)
        else:
            freshness_status = EvidenceFreshnessStatus.FRESH
            freshness_score = 15.0

        # Pillar calculations
        completeness_pts = round(20.0 * min(1.0, max(0.0, metrics.completeness)), 1)
        reproducibility_pts = round(25.0 * min(1.0, max(0.0, metrics.reproducibility)), 1)
        integrity_pts = 20.0 if metrics.integrity_verified else 0.0
        differential_pts = round(20.0 * min(1.0, max(0.0, metrics.differential_signal)), 1)

        raw_total = completeness_pts + reproducibility_pts + integrity_pts + differential_pts + freshness_score

        # Fatal Cap: If cryptographic integrity fails, evidence is compromised
        if not metrics.integrity_verified:
            raw_total = min(raw_total, 25.0)

        overall_score = round(raw_total, 1)

        # Assign Grade
        if overall_score >= 95.0:
            grade = "A+"
        elif overall_score >= 85.0:
            grade = "A"
        elif overall_score >= 70.0:
            grade = "B"
        elif overall_score >= 50.0:
            grade = "C"
        else:
            grade = "F"

        is_audit_grade = (overall_score >= 80.0) and (freshness_status != EvidenceFreshnessStatus.STALE_REQUIRES_RETEST)

        breakdown = {
            "completeness_score": completeness_pts,
            "reproducibility_score": reproducibility_pts,
            "integrity_score": integrity_pts,
            "differential_score": differential_pts,
            "freshness_score": freshness_score
        }

        return EvidenceQualityReport(
            overall_score=overall_score,
            grade=grade,
            freshness_status=freshness_status,
            is_audit_grade=is_audit_grade,
            breakdown=breakdown
        )
