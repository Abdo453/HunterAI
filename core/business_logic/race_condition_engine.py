"""
HunterAI Race Condition & High-Concurrency State Engine
=======================================================
Synchronized multi-packet request engine designed to detect:
1. Double-spend & multi-redemption (coupons, gift cards, credits)
2. Negative balance & financial limit bypass
3. 2FA / OTP brute-force bypass via concurrent race windows
4. Duplicate resource allocation (likes, votes, orders, seats)
"""
from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

import httpx

from core.business_logic.schemas import (
    BusinessActionType,
    BusinessInvariant,
    BusinessLogicViolationReport,
    BusinessResourceState,
)

logger = logging.getLogger("hunter_ai.race_condition")


class _AsyncBarrierCompat:
    """Python 3.10-compatible asyncio barrier fallback (native asyncio.Barrier added in 3.11)."""

    def __init__(self, parties: int) -> None:
        if parties < 1:
            raise ValueError("parties must be >= 1")
        self._parties = parties
        self._count = 0
        self._generation = 0
        self._cond = asyncio.Condition()

    async def wait(self) -> int:
        async with self._cond:
            gen = self._generation
            index = self._count
            self._count += 1
            if self._count >= self._parties:
                self._count = 0
                self._generation += 1
                self._cond.notify_all()
                return index
            while gen == self._generation:
                await self._cond.wait()
            return index


_AsyncBarrier = getattr(asyncio, "Barrier", _AsyncBarrierCompat)


@dataclass
class ConcurrentRequestResult:
    request_index: int
    status_code: int
    latency_ms: float
    response_body: str
    headers: Dict[str, str] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


@dataclass
class RaceConditionAnalysis:
    is_vulnerable: bool
    total_dispatched: int
    successful_count: int
    status_distribution: Dict[int, int]
    min_delta_ms: float
    evidence: str
    violation_report: Optional[BusinessLogicViolationReport] = None


class RaceConditionEngine:
    """
    High-precision synchronized concurrent request engine.
    Uses asyncio barriers and connection pre-warming to ensure all N requests
    hit the server's application thread within the smallest possible race window (<10ms).
    """

    def __init__(self, timeout_secs: float = 12.0):
        self.timeout_secs = timeout_secs

    async def run_synchronized_race(
        self,
        url: str,
        method: str = "POST",
        headers: Optional[Dict[str, str]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        concurrency: int = 20,
        success_status_codes: Optional[List[int]] = None,
        max_permitted_success: int = 1,
    ) -> RaceConditionAnalysis:
        """
        Dispatches `concurrency` requests simultaneously using a synchronization barrier.
        Flags a race condition if more than `max_permitted_success` requests succeed.
        """
        success_codes = success_status_codes or [200, 201, 204]
        headers = headers or {}
        barrier = _AsyncBarrier(concurrency)
        results: List[ConcurrentRequestResult] = []

        limits = httpx.Limits(max_keepalive_connections=concurrency, max_connections=concurrency)
        async with httpx.AsyncClient(limits=limits, timeout=self.timeout_secs, verify=False) as client:
            # Pre-warm connection if possible
            try:
                head_resp = await client.head(url, headers=headers)
            except Exception:
                pass

            async def _worker(idx: int):
                # Wait for all workers to be fully primed and ready
                await barrier.wait()
                start_t = time.perf_counter()
                try:
                    if method.upper() == "POST":
                        resp = await client.post(url, headers=headers, json=json_body)
                    elif method.upper() == "PUT":
                        resp = await client.put(url, headers=headers, json=json_body)
                    elif method.upper() == "DELETE":
                        resp = await client.delete(url, headers=headers)
                    else:
                        resp = await client.get(url, headers=headers)
                    elapsed = (time.perf_counter() - start_t) * 1000.0
                    body_sample = resp.text[:1000] if resp.text else ""
                    results.append(
                        ConcurrentRequestResult(
                            request_index=idx,
                            status_code=resp.status_code,
                            latency_ms=elapsed,
                            response_body=body_sample,
                            headers=dict(resp.headers),
                        )
                    )
                except Exception as exc:
                    elapsed = (time.perf_counter() - start_t) * 1000.0
                    results.append(
                        ConcurrentRequestResult(
                            request_index=idx,
                            status_code=0,
                            latency_ms=elapsed,
                            response_body=f"Client Exception: {exc}",
                        )
                    )

            tasks = [_worker(i) for i in range(concurrency)]
            await asyncio.gather(*tasks, return_exceptions=True)

        return self._evaluate_results(
            url=url,
            results=results,
            max_permitted=max_permitted_success,
            success_codes=success_codes,
            concurrency=concurrency,
        )

    def _evaluate_results(
        self,
        url: str,
        results: List[ConcurrentRequestResult],
        max_permitted: int,
        success_codes: List[int],
        concurrency: int,
    ) -> RaceConditionAnalysis:
        status_dist: Dict[int, int] = {}
        successful_reqs: List[ConcurrentRequestResult] = []

        for r in results:
            status_dist[r.status_code] = status_dist.get(r.status_code, 0) + 1
            if r.status_code in success_codes:
                successful_reqs.append(r)

        success_count = len(successful_reqs)
        is_vuln = success_count > max_permitted

        # Calculate time clustering
        timestamps = [r.timestamp for r in results if r.status_code > 0]
        min_delta = (max(timestamps) - min(timestamps)) * 1000.0 if len(timestamps) > 1 else 0.0

        violation = None
        if is_vuln:
            evidence = (
                f"Synchronized Race Condition Verified on {url}: Dispatched {concurrency} requests, "
                f"expected at most {max_permitted} success, but {success_count} succeeded. "
                f"Status Distribution: {status_dist}. Completed within {min_delta:.2f}ms."
            )
            violation = BusinessLogicViolationReport(
                finding_id=f"RACE-{uuid.uuid4().hex[:6].upper()}",
                invariant_id="INV-06-CONCURRENCY-LIMIT",
                invariant_name="Race Condition / Limit Overwrite",
                violating_action="CONCURRENT_BURST_DISPATCH",
                initial_state="UNCOMMITTED",
                resulting_state="OVER_ALLOCATED",
                payload_mutation={
                    "concurrency": concurrency,
                    "successful_count": success_count,
                    "max_allowed": max_permitted,
                },
                security_impact=(
                    f"State inconsistency / duplicate fulfillment: {success_count} concurrent operations succeeded "
                    f"where only {max_permitted} was allowed (Double-Spend / Limit Bypass)."
                ),
                evidence_proof=evidence,
            )
        else:
            evidence = (
                f"No race condition detected on {url}. Success count: {success_count}/{concurrency} "
                f"(Permitted: <= {max_permitted}). Server properly locked transaction."
            )

        return RaceConditionAnalysis(
            is_vulnerable=is_vuln,
            total_dispatched=concurrency,
            successful_count=success_count,
            status_distribution=status_dist,
            min_delta_ms=min_delta,
            evidence=evidence,
            violation_report=violation,
        )
