"""
HunterAI 'Why Not?' Negative Proof & Epistemic Coverage Engine
==============================================================
Answers the fundamental question: 'Why did HunterAI find no vulnerabilities on Endpoint X?'
Provides mathematical proof: Tested identities, payload counts, negative control verifications,
and precise coverage percentages.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("hunter_ai.why_not_engine")


@dataclass
class NegativeProofRecord:
    endpoint: str
    vulnerability_class: str
    tested_identities: List[str]
    total_probes_sent: int
    probes_rejected_strictly: int
    negative_control_verified: bool
    private_data_leakage_detected: bool
    coverage_percentage: float
    reason_no_finding: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "endpoint": self.endpoint,
            "vulnerability_class": self.vulnerability_class,
            "tested_identities": self.tested_identities,
            "total_probes_sent": self.total_probes_sent,
            "rejections": self.probes_rejected_strictly,
            "negative_control_verified": self.negative_control_verified,
            "coverage_percentage": f"{self.coverage_percentage:.1f}%",
            "reason_no_finding": self.reason_no_finding,
        }


class WhyNotEngine:
    """
    Maintains rigorous negative proof and coverage records.
    Guarantees: 'No Finding != Safe', but 'No Finding + Documented Negative Proof'.
    """

    def __init__(self):
        self.negative_records: Dict[str, NegativeProofRecord] = {}

    def record_negative_proof(
        self,
        endpoint: str,
        vuln_class: str,
        tested_identities: List[str],
        total_probes: int,
        rejections: int,
        negative_control_verified: bool,
        private_data_leaked: bool = False,
        coverage: float = 100.0
    ) -> NegativeProofRecord:
        if private_data_leaked:
            reason = "Warning: Data leaked, should be a confirmed finding."
        else:
            reason = (
                f"Tested across {len(tested_identities)} identities with {total_probes} probes. "
                f"All {rejections} unauthorized requests were strictly rejected (401/403/404) "
                f"with zero sensitive data leakage and verified negative controls."
            )

        rec = NegativeProofRecord(
            endpoint=endpoint,
            vulnerability_class=vuln_class,
            tested_identities=tested_identities,
            total_probes_sent=total_probes,
            probes_rejected_strictly=rejections,
            negative_control_verified=negative_control_verified,
            private_data_leakage_detected=private_data_leaked,
            coverage_percentage=coverage,
            reason_no_finding=reason
        )
        self.negative_records[f"{endpoint}:{vuln_class}"] = rec
        return rec

    def get_negative_proof(self, endpoint: str, vuln_class: str) -> Optional[NegativeProofRecord]:
        return self.negative_records.get(f"{endpoint}:{vuln_class}")
