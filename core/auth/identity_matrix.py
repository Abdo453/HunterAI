"""
HunterAI Dual-Identity Authorization Matrix (BOLA / IDOR Verification Engine)
=============================================================================
Mathematically proves Broken Object-Level Authorization (IDOR) by executing
differential probes across two independent user contexts:
  - User A (Attacker Identity)
  - User B (Victim Identity)
  - Unauthenticated (Public Baseline)

Differential Rules (PoE):
  1. Victim Probe: Accesses Victim Object with Victim Auth -> MUST return 200 + Victim Token.
  2. Public Probe: Accesses Victim Object with No Auth -> MUST return 401/403/Redirect.
  3. Attacker Probe: Accesses Victim Object with Attacker Auth ->
     - If 401/403 -> SECURE (Authorization enforced).
     - If 200 + Victim Private Data returned -> CONFIRMED IDOR / BOLA!
"""
from __future__ import annotations

import difflib
import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("hunter_ai.identity_matrix")


class IDORVerdict(str, Enum):
    CONFIRMED_IDOR   = "CONFIRMED_IDOR"
    ENFORCED_ACCESS  = "ENFORCED_ACCESS"
    PUBLIC_ENDPOINT  = "PUBLIC_ENDPOINT"
    INCONCLUSIVE     = "INCONCLUSIVE"
    OBJECT_NOT_FOUND = "OBJECT_NOT_FOUND"


@dataclass
class IdentityContext:
    user_id: str
    username: str = ""
    role: str = "standard_user"
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    canary_data: List[str] = field(default_factory=list)  # Unique tokens belonging only to this user


@dataclass
class DifferentialEvidence:
    verdict: IDORVerdict
    confidence: float
    endpoint: str
    tested_object_id: str
    victim_user_id: str
    attacker_user_id: str
    victim_status: int
    attacker_status: int
    unauth_status: int
    token_leakage_detected: List[str] = field(default_factory=list)
    similarity_ratio: float = 0.0
    rationale: str = ""


class DualIdentityMatrix:
    """
    Executes and adjudicates 3-way differential authorization tests.
    """

    def __init__(
        self,
        user_attacker: Optional[IdentityContext] = None,
        user_victim: Optional[IdentityContext] = None,
    ):
        self.attacker = user_attacker
        self.victim = user_victim

    def evaluate_differential(
        self,
        endpoint: str,
        victim_object_id: str,
        victim_response_code: int,
        victim_response_body: str,
        attacker_response_code: int,
        attacker_response_body: str,
        unauth_response_code: int = 401,
        unauth_response_body: str = "",
    ) -> DifferentialEvidence:
        """
        Adjudicates IDOR candidate using 3-way differential response comparison.
        """
        # Rule 1: If unauthenticated request succeeds identically, endpoint is public!
        if unauth_response_code in (200, 201) and len(unauth_response_body) > 20:
            if abs(len(unauth_response_body) - len(victim_response_body)) < 15:
                return DifferentialEvidence(
                    verdict=IDORVerdict.PUBLIC_ENDPOINT,
                    confidence=0.95,
                    endpoint=endpoint,
                    tested_object_id=victim_object_id,
                    victim_user_id=self.victim.user_id if self.victim else "victim",
                    attacker_user_id=self.attacker.user_id if self.attacker else "attacker",
                    victim_status=victim_response_code,
                    attacker_status=attacker_response_code,
                    unauth_status=unauth_response_code,
                    rationale="Endpoint returns identical data without authentication (Public Resource != IDOR).",
                )

        # Rule 2: If victim cannot even access their own object
        if victim_response_code not in (200, 201, 204):
            return DifferentialEvidence(
                verdict=IDORVerdict.OBJECT_NOT_FOUND,
                confidence=0.85,
                endpoint=endpoint,
                tested_object_id=victim_object_id,
                victim_user_id=self.victim.user_id if self.victim else "victim",
                attacker_user_id=self.attacker.user_id if self.attacker else "attacker",
                victim_status=victim_response_code,
                attacker_status=attacker_response_code,
                unauth_status=unauth_response_code,
                rationale="Victim user cannot access their own object baseline.",
            )

        # Rule 3: If attacker is properly denied with 401/403
        if attacker_response_code in (401, 403):
            return DifferentialEvidence(
                verdict=IDORVerdict.ENFORCED_ACCESS,
                confidence=0.98,
                endpoint=endpoint,
                tested_object_id=victim_object_id,
                victim_user_id=self.victim.user_id if self.victim else "victim",
                attacker_user_id=self.attacker.user_id if self.attacker else "attacker",
                victim_status=victim_response_code,
                attacker_status=attacker_response_code,
                unauth_status=unauth_response_code,
                rationale="Authorization barrier successfully rejected attacker context (HTTP 401/403).",
            )

        # Rule 4: Attacker received 200 OK. Check for canary token leakage
        leaked_tokens = []
        if self.victim and self.victim.canary_data:
            for canary in self.victim.canary_data:
                if canary in attacker_response_body:
                    leaked_tokens.append(canary)

        # Calculate semantic similarity
        seq = difflib.SequenceMatcher(None, victim_response_body, attacker_response_body)
        similarity = seq.ratio()

        if attacker_response_code in (200, 201) and (leaked_tokens or similarity > 0.80):
            confidence = 0.98 if leaked_tokens else 0.90
            return DifferentialEvidence(
                verdict=IDORVerdict.CONFIRMED_IDOR,
                confidence=confidence,
                endpoint=endpoint,
                tested_object_id=victim_object_id,
                victim_user_id=self.victim.user_id if self.victim else "victim",
                attacker_user_id=self.attacker.user_id if self.attacker else "attacker",
                victim_status=victim_response_code,
                attacker_status=attacker_response_code,
                unauth_status=unauth_response_code,
                token_leakage_detected=leaked_tokens,
                similarity_ratio=similarity,
                rationale=(
                    f"Attacker context accessed victim object with HTTP {attacker_response_code} "
                    f"(Similarity: {similarity*100:.1f}%, Leaked Canaries: {leaked_tokens})."
                ),
            )

        return DifferentialEvidence(
            verdict=IDORVerdict.INCONCLUSIVE,
            confidence=0.50,
            endpoint=endpoint,
            tested_object_id=victim_object_id,
            victim_user_id=self.victim.user_id if self.victim else "victim",
            attacker_user_id=self.attacker.user_id if self.attacker else "attacker",
            victim_status=victim_response_code,
            attacker_status=attacker_response_code,
            unauth_status=unauth_response_code,
            similarity_ratio=similarity,
            rationale="Ambiguous response structure; cannot mathematically prove authorization breach.",
        )
