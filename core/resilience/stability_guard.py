"""
HunterAI Stability & Circuit Breaker Guard
==========================================
Protects the platform against target instability:
- Huge response body truncation (stream byte cap, default 5 MB)
- Redirect Loop Breaker (max 5 hops)
- Malformed HTML/JSON resilient parsing
- Circuit Breaker on slow / unresponsive endpoints (halts after 3 timeouts)
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("hunter_ai.stability_guard")


class CircuitOpenError(RuntimeError):
    """Raised when an endpoint is temporarily bypassed due to consecutive timeouts"""
    pass


class RedirectLoopError(RuntimeError):
    """Raised when an endpoint triggers a circular redirect loop"""
    pass


@dataclass
class CircuitState:
    consecutive_failures: int = 0
    is_open: bool = False
    cooldown_until: float = 0.0


class StabilityGuard:
    """Guarantees process stability under adversarial or degraded network conditions"""

    def __init__(
        self,
        max_response_bytes: int = 5 * 1024 * 1024,  # 5 MB
        max_redirect_hops: int = 5,
        consecutive_failure_threshold: int = 3,
        circuit_cooldown_sec: float = 60.0
    ):
        self.max_response_bytes = max_response_bytes
        self.max_redirect_hops = max_redirect_hops
        self.consecutive_failure_threshold = consecutive_failure_threshold
        self.circuit_cooldown_sec = circuit_cooldown_sec
        self.endpoint_circuits: Dict[str, CircuitState] = {}

    def truncate_payload(self, raw_bytes: bytes) -> Tuple[bytes, bool]:
        """Safely truncates abnormally large response bodies"""
        if len(raw_bytes) > self.max_response_bytes:
            logger.warning(f"⚠️ Response exceeded size cap ({len(raw_bytes)} bytes); truncating to {self.max_response_bytes} bytes.")
            return raw_bytes[:self.max_response_bytes], True
        return raw_bytes, False

    def validate_redirect_chain(self, hops: List[str]):
        """Detects redirect loops and excessive hops"""
        if len(hops) > self.max_redirect_hops:
            raise RedirectLoopError(f"Redirect limit exceeded: {len(hops)} hops observed.")
        if len(hops) != len(set(hops)):
            raise RedirectLoopError(f"Circular redirect loop detected: {hops}")

    def pre_request_check(self, endpoint_key: str):
        """Inspects circuit breaker state before executing network socket probe"""
        circuit = self.endpoint_circuits.get(endpoint_key)
        if circuit and circuit.is_open:
            if time.time() < circuit.cooldown_until:
                raise CircuitOpenError(
                    f"CIRCUIT BREAKER OPEN: Endpoint '{endpoint_key}' temporarily suspended due to consecutive timeouts."
                )
            else:
                # Cooldown expired, half-open test
                circuit.is_open = False
                circuit.consecutive_failures = 0

    def record_outcome(self, endpoint_key: str, is_success: bool, is_timeout: bool = False):
        """Updates circuit breaker state based on socket response"""
        if endpoint_key not in self.endpoint_circuits:
            self.endpoint_circuits[endpoint_key] = CircuitState()

        circuit = self.endpoint_circuits[endpoint_key]
        if is_success:
            circuit.consecutive_failures = 0
            circuit.is_open = False
        elif is_timeout:
            circuit.consecutive_failures += 1
            if circuit.consecutive_failures >= self.consecutive_failure_threshold:
                circuit.is_open = True
                circuit.cooldown_until = time.time() + self.circuit_cooldown_sec
                logger.error(f"🛑 Circuit breaker tripped for '{endpoint_key}' ({circuit.consecutive_failures} timeouts).")
