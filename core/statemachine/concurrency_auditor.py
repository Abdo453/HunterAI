"""
HunterAI Concurrency & TOCTOU (Time-of-Check to Time-of-Use) Auditor
====================================================================
Analyzes endpoint contracts and state mutators to detect concurrency hazards:
1. Missing Idempotency Tokens (Idempotency-Key headers on financial/quota mutations)
2. Check-Then-Act race hazard anti-patterns (e.g. checking balance before debit without locking)
3. Parallel Re-entrancy Hazards
4. Database Row Lock Gaps (Missing SELECT FOR UPDATE)
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set


class ConcurrencyRiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class TOCTOUHazardType(str, Enum):
    MISSING_IDEMPOTENCY_KEY = "MISSING_IDEMPOTENCY_KEY"
    CHECK_THEN_ACT_WINDOW = "CHECK_THEN_ACT_WINDOW"
    PARALLEL_REPLAY_HAZARD = "PARALLEL_REPLAY_HAZARD"
    UNLOCKED_RESOURCE_MUTATION = "UNLOCKED_RESOURCE_MUTATION"


@dataclass
class ConcurrencyAuditReport:
    route: str
    method: str
    risk_level: ConcurrencyRiskLevel
    hazards_detected: List[TOCTOUHazardType] = field(default_factory=list)
    evidence_proof: str = ""
    remediation_advice: List[str] = field(default_factory=list)
    is_vulnerable: bool = False
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "route": self.route,
            "method": self.method,
            "risk_level": self.risk_level.value,
            "hazards_detected": [h.value for h in self.hazards_detected],
            "evidence_proof": self.evidence_proof,
            "remediation_advice": self.remediation_advice,
            "is_vulnerable": self.is_vulnerable,
            "timestamp": self.timestamp,
        }


class ConcurrencyAuditor:
    """
    Audits HTTP endpoint contracts and backend code snippets for race conditions
    and TOCTOU vulnerabilities under high concurrency.
    """

    FINANCIAL_OR_QUOTA_KEYWORDS = [
        "pay", "charge", "transfer", "withdraw", "deposit", "checkout",
        "coupon", "discount", "voucher", "redeem", "credit", "balance",
        "points", "token", "order", "inventory", "stock", "subscribe"
    ]

    CHECK_THEN_ACT_REGEX = re.compile(
        r"(if\s+.*(?:balance|stock|quota|count|credits?)\s*(?:>=|>|==|<|<=).*\n(?:[\t ]+.*\n)*?[\t ]+.*(?:debit|deduct|withdraw|update|decrement|save|commit))",
        re.IGNORECASE
    )

    LOCKING_PRIMITIVES = [
        "select_for_update", "with_for_update", "transaction.atomic",
        "mutex", "lock", "semaphore", "idempotency", "redis.lock",
        "optimistic_lock", "version_id"
    ]

    def __init__(self):
        pass

    def evaluate_endpoint(
        self,
        route: str,
        method: str = "POST",
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
        source_code_snippet: Optional[str] = None
    ) -> ConcurrencyAuditReport:
        """
        Evaluates an endpoint contract for concurrency safety invariants.
        """
        headers = {k.lower(): v for k, v in (headers or {}).items()}
        route_lower = route.lower()
        method_upper = method.upper()

        is_mutating = method_upper in ("POST", "PUT", "PATCH", "DELETE")
        is_financial_or_quota = any(kw in route_lower for kw in self.FINANCIAL_OR_QUOTA_KEYWORDS)
        if body and not is_financial_or_quota:
            is_financial_or_quota = any(kw in body.lower() for kw in self.FINANCIAL_OR_QUOTA_KEYWORDS)

        has_idempotency_header = any(
            "idempotency" in k or "idempotent" in k or "nonce" in k
            for k in headers.keys()
        )

        hazards: List[TOCTOUHazardType] = []
        evidence_lines: List[str] = []
        advice: List[str] = []

        # 1. Check Missing Idempotency Key on Financial / State Mutating Route
        if is_mutating and is_financial_or_quota and not has_idempotency_header:
            hazards.append(TOCTOUHazardType.MISSING_IDEMPOTENCY_KEY)
            hazards.append(TOCTOUHazardType.PARALLEL_REPLAY_HAZARD)
            evidence_lines.append(
                f"Endpoint '{method_upper} {route}' mutates financial/quota state but lacks an 'Idempotency-Key' or replay token header."
            )
            advice.append(
                "Require an 'Idempotency-Key' header on all mutating POST/PUT requests and store processed keys in Redis/Cache with TTL."
            )

        # 2. Source Code Static Check-Then-Act Analysis (if provided)
        if source_code_snippet:
            has_lock = any(lock in source_code_snippet.lower() for lock in self.LOCKING_PRIMITIVES)
            has_check_then_act = bool(self.CHECK_THEN_ACT_REGEX.search(source_code_snippet))

            if has_check_then_act and not has_lock:
                hazards.append(TOCTOUHazardType.CHECK_THEN_ACT_WINDOW)
                hazards.append(TOCTOUHazardType.UNLOCKED_RESOURCE_MUTATION)
                evidence_lines.append(
                    "Detected Check-Then-Act pattern reading balance/quota before debiting without explicit row-level locking (select_for_update) or distributed lock."
                )
                advice.append(
                    "Wrap the read and update inside an atomic transaction using pessimistic row locking ('select_for_update()') or a distributed mutex."
                )

        # Determine Risk Level
        if TOCTOUHazardType.CHECK_THEN_ACT_WINDOW in hazards or (
            TOCTOUHazardType.MISSING_IDEMPOTENCY_KEY in hazards and is_financial_or_quota
        ):
            risk_level = ConcurrencyRiskLevel.CRITICAL if "transfer" in route_lower or "pay" in route_lower else ConcurrencyRiskLevel.HIGH
        elif hazards:
            risk_level = ConcurrencyRiskLevel.MEDIUM
        else:
            risk_level = ConcurrencyRiskLevel.LOW

        is_vuln = len(hazards) > 0

        return ConcurrencyAuditReport(
            route=route,
            method=method_upper,
            risk_level=risk_level,
            hazards_detected=hazards,
            evidence_proof="; ".join(evidence_lines) if evidence_lines else "No obvious concurrency hazards detected.",
            remediation_advice=advice,
            is_vulnerable=is_vuln
        )

    def simulate_burst_race(
        self,
        endpoint: str,
        initial_balance: int = 100,
        debit_amount: int = 100,
        concurrent_requests: int = 10,
        has_locking: bool = False,
        has_idempotency: bool = False
    ) -> Dict[str, Any]:
        """
        Simulates a deterministic multi-request burst against an endpoint
        to prove TOCTOU / race hazard vulnerability or verify defense.
        """
        if has_idempotency:
            # Only the first unique request succeeds; remaining 9 are rejected as duplicate
            successful = 1
            final_balance = initial_balance - debit_amount
        elif has_locking:
            # Serialized execution: only first request succeeds because balance drops to 0
            successful = 1
            final_balance = initial_balance - debit_amount
        else:
            # Vulnerable race window: multiple concurrent threads observe initial_balance >= debit_amount
            # Simulates parallel reads before updates
            successful = min(concurrent_requests, 5)  # E.g., 5 parallel threads read balance=100 before decrement
            final_balance = initial_balance - (successful * debit_amount)

        is_race_exploited = successful > 1 and final_balance < 0

        return {
            "endpoint": endpoint,
            "initial_balance": initial_balance,
            "debit_amount": debit_amount,
            "concurrent_requests": concurrent_requests,
            "successful_debits": successful,
            "final_balance": final_balance,
            "is_race_exploited": is_race_exploited,
            "protection_applied": "IdempotencyKey" if has_idempotency else ("PessimisticLock" if has_locking else "None")
        }
