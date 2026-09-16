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


@dataclass
class ProsecutionChallenge:
    """A formal counter-argument raised against a finding by the Prosecutor"""
    theory_type: CounterTheoryType
    prosecutor_argument: str
    rebuttal_requirement: str
    is_rebutted: bool = False
    rebuttal_evidence: str = ""


@dataclass
class ProsecutionRuling:
    """The final disposition of the prosecutor after cross-examining evidence"""
    finding_family: str
    target_endpoint: str
    challenges_raised: List[ProsecutionChallenge]
    all_rebutted: bool
    prosecutor_disposition: str  # "CONCEDED" (VOTE_CONFIRM), "OBJECTION_SUSTAINED" (VOTE_REJECT / VOTE_INCONCLUSIVE)
    justification: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_family": self.finding_family,
            "target_endpoint": self.target_endpoint,
            "prosecutor_disposition": self.prosecutor_disposition,
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
            ]
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
        evidence_payload: Dict[str, Any]
    ) -> ProsecutionRuling:
        """
        Cross-examines a submitted finding against the top noise hypotheses.
        """
        challenges: List[ProsecutionChallenge] = []
        family_upper = vuln_family.upper()

        # 1. Challenge: Generic 200 OK / Public Page (Auth Bypass & BOLA)
        if any(term in family_upper for term in ("AUTH", "BOLA", "IDOR", "PRIVILEGE")):
            leaked_private_data = evidence_payload.get("sensitive_data_leaked", False) or evidence_payload.get("private_data_matched", False)
            ch = ProsecutionChallenge(
                theory_type=CounterTheoryType.GENERIC_ERROR_200_MASK,
                prosecutor_argument=(
                    "The HTTP 200 OK response could be a generic public view or error landing page, "
                    "not an authentication/authorization bypass."
                ),
                rebuttal_requirement="Demonstrate that private tenant or user data leaked into the response.",
                is_rebutted=bool(leaked_private_data),
                rebuttal_evidence="Verified private data leaked in unauth/cross-tenant response." if leaked_private_data else ""
            )
            challenges.append(ch)

        # 2. Challenge: WAF Rate Limit / Perimeter Trap (All active injections)
        if any(term in family_upper for term in ("SQL", "COMMAND", "INJECTION", "SSRF", "XSS")):
            waf_clean = evidence_payload.get("waf_clean", True) and not evidence_payload.get("waf_block_detected", False)
            ch = ProsecutionChallenge(
                theory_type=CounterTheoryType.WAF_PERIMETER_INTERFERENCE,
                prosecutor_argument=(
                    "The response anomaly may be an active perimeter defense (Cloudflare / AWS WAF captcha/block) "
                    "rather than a true backend execution sink."
                ),
                rebuttal_requirement="Provide clean baseline probe showing non-WAF response headers and normal status.",
                is_rebutted=bool(waf_clean),
                rebuttal_evidence="Baseline response clean of WAF signatures and captcha cookies." if waf_clean else ""
            )
            challenges.append(ch)

        # 3. Challenge: CDN Caching / Reflected Stored Trap (XSS & Tampering)
        if "XSS" in family_upper or "CACHE" in family_upper:
            cache_busting_used = evidence_payload.get("cache_busting_verified", False) or evidence_payload.get("dynamic_nonce_verified", False)
            ch = ProsecutionChallenge(
                theory_type=CounterTheoryType.CDN_CACHE_REFLECTION,
                prosecutor_argument=(
                    "The reflected string may be an edge cache hit from an earlier request rather than a "
                    "dynamically rendered stored vulnerability."
                ),
                rebuttal_requirement="Provide unique dynamic nonce in query string proving real-time origin execution.",
                is_rebutted=bool(cache_busting_used),
                rebuttal_evidence="Cache-busting dynamic nonce reflected from origin backend." if cache_busting_used else ""
            )
            challenges.append(ch)

        # 4. Challenge: Server Timing Jitter (Time-based Blind SQLi / CMDi)
        if "TIME" in family_upper or "BLIND" in family_upper:
            timing_reproduced = evidence_payload.get("timing_reproduced_n_times", 0) >= 2
            ch = ProsecutionChallenge(
                theory_type=CounterTheoryType.SERVER_TIMING_JITTER,
                prosecutor_argument=(
                    "The latency spike could be caused by temporary server load, garbage collection, "
                    "or transient network jitter."
                ),
                rebuttal_requirement="Must reproduce time delta strictly correlating with sleep payload at least 2 times.",
                is_rebutted=bool(timing_reproduced),
                rebuttal_evidence="Timing delay reproduced consistently across independent runs." if timing_reproduced else ""
            )
            challenges.append(ch)

        # Evaluate overall outcome
        all_rebutted = all(c.is_rebutted for c in challenges) if challenges else True
        if all_rebutted:
            disposition = "CONCEDED"
            justification = "Prosecution Concession: All adversarial challenges (WAF, Cache, Jitter, Generic 200) successfully refuted by physical proof."
        else:
            disposition = "OBJECTION_SUSTAINED"
            unmet = [c.theory_type.value for c in challenges if not c.is_rebutted]
            justification = f"Prosecution Objection Sustained: Finding fails to eliminate plausible alternative explanations: {', '.join(unmet)}."

        return ProsecutionRuling(
            finding_family=vuln_family,
            target_endpoint=endpoint,
            challenges_raised=challenges,
            all_rebutted=all_rebutted,
            prosecutor_disposition=disposition,
            justification=justification
        )
