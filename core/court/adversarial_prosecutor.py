"""
HunterAI Adversarial Evidence Prosecutor
========================================
Acts as the skeptical prosecutor in EvidenceCourtV2.
Its sole mandate: Prove the candidate finding is NOT a true vulnerability.
Pits counter-theories (WAF, Cache, Jitter, Generic 200) against the finding,
demanding verifiable counter-evidence before conceding.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger("hunter_ai.adversarial_prosecutor")


class CounterTheoryType(str, Enum):
    WAF_PERIMETER_INTERFERENCE = "WAF_PERIMETER_INTERFERENCE"
    CDN_CACHE_REFLECTION = "CDN_CACHE_REFLECTION"
    SERVER_TIMING_JITTER = "SERVER_TIMING_JITTER"
    GENERIC_ERROR_200_MASK = "GENERIC_ERROR_200_MASK"
    PUBLIC_STATIC_PAGE = "PUBLIC_STATIC_PAGE"
    BASELINE_INSTABILITY = "BASELINE_INSTABILITY"


@dataclass
class ProsecutionChallenge:
    """A formal counter-argument raised against a finding by the Prosecutor."""
    theory_type: CounterTheoryType
    prosecutor_argument: str
    rebuttal_requirement: str
    is_rebutted: bool = False
    rebuttal_evidence: str = ""


@dataclass
class ProsecutionRuling:
    """The final disposition of the prosecutor after cross-examining evidence."""
    finding_family: str
    target_endpoint: str
    challenges_raised: List[ProsecutionChallenge]
    all_rebutted: bool
    prosecutor_disposition: str  # "CONCEDED", "OBJECTION_SUSTAINED"
    justification: str
    canonical_verdict: str = "UNVERIFIED"  # Canonical 7-state mapping

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_family": self.finding_family,
            "target_endpoint": self.target_endpoint,
            "prosecutor_disposition": self.prosecutor_disposition,
            "canonical_verdict": self.canonical_verdict,
            "all_rebutted": self.all_rebutted,
            "justification": self.justification,
            "challenges": [
                {
                    "theory": c.theory_type.value,
                    "arg": c.prosecutor_argument,
                    "requirement": c.rebuttal_requirement,
                    "rebutted": c.is_rebutted,
                }
                for c in self.challenges_raised
            ],
        }


class AdversarialEvidenceProsecutor:
    """
    Adversarial cross-examiner for EvidenceCourtV2.
    Actively attempts to refute claims before they reach final adjudication.
    """

    @classmethod
    def cross_examine_finding(
        cls,
        vuln_family: str,
        endpoint: str,
        evidence_payload: Dict[str, Any],
    ) -> ProsecutionRuling:
        """Cross-examines a submitted finding against the top noise hypotheses."""
        challenges: List[ProsecutionChallenge] = []
        family_upper = (vuln_family or "").upper()
        ep_payload = evidence_payload or {}

        # 0. Universal Challenge: Baseline Stability & WAF Perimeter Cleanliness
        if ep_payload.get("baseline_stable") is False:
            challenges.append(ProsecutionChallenge(
                theory_type=CounterTheoryType.BASELINE_INSTABILITY,
                prosecutor_argument="Baseline responses are unstable; dynamic server jitter can mimic exploit signals.",
                rebuttal_requirement="Establish a stable normalized baseline before claiming causal divergence.",
                is_rebutted=False,
                rebuttal_evidence="",
            ))

        if ep_payload.get("waf_clean") is False or ep_payload.get("waf_block_detected") is True:
            challenges.append(ProsecutionChallenge(
                theory_type=CounterTheoryType.WAF_PERIMETER_INTERFERENCE,
                prosecutor_argument=(
                    "Active perimeter defense (WAF block/challenge) interfered with the probe; "
                    "observed behavior reflects perimeter defense rather than an application flaw."
                ),
                rebuttal_requirement="Provide clean non-WAF responses showing backend execution.",
                is_rebutted=False,
                rebuttal_evidence="",
            ))

        # 1. Challenge: Generic 200 OK / Public Page (Auth Bypass & BOLA/IDOR)
        if any(term in family_upper for term in ("AUTH", "BOLA", "IDOR", "PRIVILEGE")):
            leaked_private_data = bool(
                ep_payload.get("sensitive_data_leaked", False)
                or ep_payload.get("private_data_matched", False)
            )
            challenges.append(ProsecutionChallenge(
                theory_type=CounterTheoryType.GENERIC_ERROR_200_MASK,
                prosecutor_argument=(
                    "The HTTP 200 OK response could be a generic public view or error landing page, "
                    "not an authentication/authorization bypass."
                ),
                rebuttal_requirement="Demonstrate that private tenant or user data leaked into the response.",
                is_rebutted=leaked_private_data,
                rebuttal_evidence="Verified private data leaked in unauth/cross-tenant response." if leaked_private_data else "",
            ))

        # 2. Challenge: WAF Rate Limit / Perimeter Trap (All active injections)
        if any(term in family_upper for term in ("SQL", "COMMAND", "CMDI", "INJECTION", "SSRF", "XSS")):
            waf_clean = bool(ep_payload.get("waf_clean", True)) and not bool(ep_payload.get("waf_block_detected", False))
            if not any(c.theory_type == CounterTheoryType.WAF_PERIMETER_INTERFERENCE for c in challenges):
                challenges.append(ProsecutionChallenge(
                    theory_type=CounterTheoryType.WAF_PERIMETER_INTERFERENCE,
                    prosecutor_argument=(
                        "The response anomaly may be an active perimeter defense (Cloudflare / AWS WAF captcha/block) "
                        "rather than a true backend execution sink."
                    ),
                    rebuttal_requirement="Provide clean baseline probe showing non-WAF response headers and normal status.",
                    is_rebutted=waf_clean,
                    rebuttal_evidence="Baseline response clean of WAF signatures and captcha cookies." if waf_clean else "",
                ))

        # 3. Challenge: CDN Caching / Reflected Stored Trap (XSS & Cache)
        if "XSS" in family_upper or "CACHE" in family_upper:
            cache_busting_used = bool(
                ep_payload.get("cache_busting_verified", False)
                or ep_payload.get("dynamic_nonce_verified", False)
            )
            challenges.append(ProsecutionChallenge(
                theory_type=CounterTheoryType.CDN_CACHE_REFLECTION,
                prosecutor_argument=(
                    "The reflected string may be an edge cache hit from an earlier request rather than a "
                    "dynamically rendered vulnerability."
                ),
                rebuttal_requirement="Provide unique dynamic nonce or runtime DOM execution proving live origin impact.",
                is_rebutted=cache_busting_used,
                rebuttal_evidence="Cache-busting dynamic nonce verified against origin." if cache_busting_used else "",
            ))

        # 4. Challenge: Server Timing Jitter (Time-based Blind SQLi / CMDi)
        if "TIME" in family_upper or "BLIND" in family_upper:
            timing_reproduced = int(ep_payload.get("timing_reproduced_n_times", 0) or 0) >= 2
            challenges.append(ProsecutionChallenge(
                theory_type=CounterTheoryType.SERVER_TIMING_JITTER,
                prosecutor_argument=(
                    "The latency spike could be caused by temporary server load, garbage collection, "
                    "or transient network jitter."
                ),
                rebuttal_requirement="Must reproduce time delta strictly correlating with sleep payload at least 2 times.",
                is_rebutted=timing_reproduced,
                rebuttal_evidence="Timing delay reproduced consistently across independent runs." if timing_reproduced else "",
            ))

        # Evaluate overall outcome + map to canonical 7-state verdict
        all_rebutted = all(c.is_rebutted for c in challenges) if challenges else True
        if all_rebutted:
            disposition = "CONCEDED"
            canon = "CONFIRMED"
            justification = (
                "Prosecution Concession: All adversarial challenges (WAF, Cache, Jitter, Generic 200) "
                "successfully refuted by physical proof."
            )
        else:
            disposition = "OBJECTION_SUSTAINED"
            unmet_types = [c.theory_type for c in challenges if not c.is_rebutted]
            unmet = [t.value for t in unmet_types]
            if all(t in (CounterTheoryType.BASELINE_INSTABILITY, CounterTheoryType.SERVER_TIMING_JITTER) for t in unmet_types):
                canon = "INCONCLUSIVE"
            else:
                canon = "REJECTED"
            justification = (
                "Prosecution Objection Sustained: Finding fails to eliminate plausible alternative "
                f"explanations: {', '.join(unmet)}."
            )

        return ProsecutionRuling(
            finding_family=vuln_family,
            target_endpoint=endpoint,
            challenges_raised=challenges,
            all_rebutted=all_rebutted,
            prosecutor_disposition=disposition,
            justification=justification,
            canonical_verdict=canon,
        )
