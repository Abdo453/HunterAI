"""
Adaptive Rate Limiter & Circuit Breaker
Protects target infrastructure, enforces per-domain rate limits, and dynamically
backs off on HTTP 429 / 503 / WAF throttling and respects Retry-After headers.
"""
from __future__ import annotations

import asyncio
import email.utils
import logging
import time
from enum import Enum
from typing import Any, Dict, Optional

logger = logging.getLogger("hunter_ai.rate_limiter")


class CircuitState(str, Enum):
    CLOSED = "CLOSED"        # Normal operation: requests permitted
    OPEN = "OPEN"            # Tripped: server is throttling or degraded, requests paused
    HALF_OPEN = "HALF_OPEN"  # Recovery testing: probe cautiously


class DomainState:
    """Tracks rate limiting and circuit health for an individual target host"""
    def __init__(self, host: str, rate_limit_rps: float = 2.0, failure_threshold: int = 5, cooldown_seconds: float = 15.0):
        self.host = host
        self.rate_limit_rps = max(0.1, rate_limit_rps)
        self.min_delay = 1.0 / self.rate_limit_rps
        self.last_request_time: float = 0.0

        # Backoff & Retry
        self.consecutive_errors: int = 0
        self.backoff_until: float = 0.0
        self.current_backoff_seconds: float = 0.0

        # Circuit Breaker
        self.failure_threshold = failure_threshold
        self.cooldown_seconds = cooldown_seconds
        self.circuit_state = CircuitState.CLOSED
        self.circuit_tripped_at: float = 0.0

        self.lock = asyncio.Lock()


class AdaptiveRateLimiter:
    """
    Adaptive Rate Limiter with per-domain Token Bucket & Circuit Breaker.
    Guarantees non-destructive request spacing and intelligent throttle management.
    """

    def __init__(
        self,
        default_rate_limit_rps: float = 2.0,
        failure_threshold: int = 5,
        cooldown_seconds: float = 15.0,
        enabled: bool = True
    ):
        self.default_rate_limit_rps = default_rate_limit_rps
        self.failure_threshold = failure_threshold
        self.cooldown_seconds = cooldown_seconds
        self.enabled = enabled
        self._domains: Dict[str, DomainState] = {}
        self._global_lock = asyncio.Lock()

    def _get_domain_state(self, host: str) -> DomainState:
        clean_host = host.lower().strip()
        if clean_host not in self._domains:
            self._domains[clean_host] = DomainState(
                clean_host,
                rate_limit_rps=self.default_rate_limit_rps,
                failure_threshold=self.failure_threshold,
                cooldown_seconds=self.cooldown_seconds
            )
        return self._domains[clean_host]

    def get_state(self, host: str) -> DomainState:
        """Returns the domain rate limit & circuit state tracker"""
        return self._get_domain_state(host)

    async def acquire(self, host: str) -> bool:
        """
        Enforces rate limiting delay and checks circuit breaker before issuing request.
        Returns True when it is safe to proceed.
        """
        if not self.enabled:
            return True

        dom = self._get_domain_state(host)

        async with dom.lock:
            now = time.time()

            # 1. Circuit Breaker Check
            if dom.circuit_state == CircuitState.OPEN:
                if now - dom.circuit_tripped_at > dom.cooldown_seconds:
                    logger.info(f"Circuit Breaker for {host} entering HALF_OPEN recovery test")
                    dom.circuit_state = CircuitState.HALF_OPEN
                else:
                    sleep_needed = dom.cooldown_seconds - (now - dom.circuit_tripped_at)
                    logger.warning(f"Circuit Breaker OPEN for {host}. Pausing requests for {sleep_needed:.1f}s")
                    await asyncio.sleep(sleep_needed)
                    dom.circuit_state = CircuitState.HALF_OPEN

            # 2. Dynamic Backoff Check (from Retry-After or 429/503)
            now = time.time()
            if dom.backoff_until > now:
                sleep_needed = dom.backoff_until - now
                logger.info(f"Rate Limiter backoff active for {host}. Sleeping {sleep_needed:.2f}s")
                await asyncio.sleep(sleep_needed)

            # 3. Minimum Interval Enforcement (Token Spacing)
            now = time.time()
            time_since_last = now - dom.last_request_time
            if time_since_last < dom.min_delay:
                wait_time = dom.min_delay - time_since_last
                await asyncio.sleep(wait_time)

            dom.last_request_time = time.time()
            return True

    def record_response(
        self,
        host: str,
        status_code: int,
        headers: Optional[Dict[str, str]] = None,
        duration: float = 0.0
    ):
        """
        Updates circuit state and throttles based on server response status and headers.
        """
        if not self.enabled:
            return

        dom = self._get_domain_state(host)
        headers = headers or {}
        now = time.time()

        # Handle Throttling & Server Stress
        if status_code in (429, 503):
            dom.consecutive_errors += 1
            retry_after_seconds = self._parse_retry_after(headers)

            if retry_after_seconds is not None:
                backoff = retry_after_seconds
                logger.warning(f"Received HTTP {status_code} from {host}. Respecting Retry-After: {backoff:.1f}s")
            else:
                # Exponential backoff: 2s, 4s, 8s, up to max 60s
                backoff = min(60.0, 2.0 * (2 ** (dom.consecutive_errors - 1)))
                logger.warning(f"Received HTTP {status_code} from {host}. Applying exponential backoff: {backoff:.1f}s")

            dom.current_backoff_seconds = backoff
            dom.backoff_until = now + backoff

            # Trip Circuit Breaker if failure threshold exceeded
            if dom.consecutive_errors >= dom.failure_threshold:
                if dom.circuit_state != CircuitState.OPEN:
                    dom.circuit_state = CircuitState.OPEN
                    dom.circuit_tripped_at = now
                    logger.error(
                        f"CIRCUIT BREAKER TRIPPED for {host}! {dom.consecutive_errors} consecutive throttle errors. "
                        f"Pausing all traffic for {dom.cooldown_seconds}s to protect target."
                    )
        elif 200 <= status_code < 400:
            # Successful response
            if dom.circuit_state == CircuitState.HALF_OPEN:
                logger.info(f"Target {host} recovered. Circuit Breaker CLOSED.")
                dom.circuit_state = CircuitState.CLOSED

            dom.consecutive_errors = max(0, dom.consecutive_errors - 1)
            dom.backoff_until = 0.0

    def _parse_retry_after(self, headers: Dict[str, str]) -> Optional[float]:
        """Parses standard HTTP Retry-After header (either delta-seconds or HTTP-date)"""
        # Case-insensitive header lookup
        val = None
        for k, v in headers.items():
            if k.lower() == "retry-after":
                val = v.strip()
                break

        if not val:
            return None

        # Check integer seconds
        try:
            sec = float(val)
            return max(0.0, sec)
        except ValueError:
            pass

        # Check HTTP date format (e.g. Wed, 21 Oct 2026 07:28:00 GMT)
        try:
            parsed_time = email.utils.parsedate_to_datetime(val)
            delta = (parsed_time.timestamp() - time.time())
            return max(0.0, delta)
        except Exception:
            return None

    def get_stats(self, host: str) -> Dict[str, Any]:
        """Returns diagnostic statistics for host"""
        dom = self._get_domain_state(host)
        return {
            "host": dom.host,
            "rate_limit_rps": dom.rate_limit_rps,
            "circuit_state": dom.circuit_state.value,
            "consecutive_errors": dom.consecutive_errors,
            "backoff_active": dom.backoff_until > time.time(),
            "backoff_remaining": max(0.0, round(dom.backoff_until - time.time(), 2))
        }
