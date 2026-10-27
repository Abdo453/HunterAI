"""Read-only HTTP transport used by the safe verification lab.

The transport is deliberately narrow:

* only ``GET`` and ``HEAD``;
* no proxy environment variables (so loopback tests never leave the machine);
* redirects are not followed (the 3xx response is the evidence);
* a hard request budget and response-size cap;
* an optional signed-grant policy check before every request.

There is no generic ``request(method, ...)`` entry point, so a detector cannot
accidentally send ``POST``/``PUT``/``DELETE``.
"""
from __future__ import annotations

import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse

from core.detectors.contract import (
    Probe,
    ProbeExchange,
    sha256_json,
    sha256_text,
)

DEFAULT_USER_AGENT = "HunterAI-SafeDetector/1.0 (+read-only)"


class PolicyViolation(RuntimeError):
    """Raised when the signed grant does not authorize a probe."""


class TransportError(RuntimeError):
    """Raised when a probe cannot be executed safely."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        # Returning None makes urllib surface the 3xx as an HTTPError, which the
        # transport records as the response instead of silently following it.
        return None


@dataclass
class TransportConfig:
    timeout_s: float = 5.0
    max_body_bytes: int = 512_000
    max_requests: int = 80
    allowed_hosts: Optional[Set[str]] = None


class HttpTransport:
    """Small, auditable HTTP client for detectors."""

    def __init__(
        self,
        config: Optional[TransportConfig] = None,
        *,
        policy_engine=None,
    ):
        self.config = config or TransportConfig()
        self._policy_engine = policy_engine
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            _NoRedirect(),
        )
        self._exchanges: List[ProbeExchange] = []
        self._requests_sent = 0

    @property
    def exchanges(self) -> List[ProbeExchange]:
        return list(self._exchanges)

    # -- public, read-only verbs -------------------------------------------

    def get(self, url: str, headers: Optional[Dict[str, str]] = None) -> ProbeExchange:
        return self._send("GET", url, headers)

    def head(self, url: str, headers: Optional[Dict[str, str]] = None) -> ProbeExchange:
        return self._send("HEAD", url, headers)

    # -- internals ----------------------------------------------------------

    def _send(self, method: str, url: str, headers: Optional[Dict[str, str]]) -> ProbeExchange:
        probe = Probe(method=method, url=url, headers=headers or {})
        self._check_target(probe)
        self._check_policy(probe)

        if self._requests_sent >= self.config.max_requests:
            raise TransportError(
                f"request budget exhausted ({self.config.max_requests} probes)"
            )

        request = urllib.request.Request(
            probe.url,
            method=probe.method,
            headers={"User-Agent": DEFAULT_USER_AGENT, **probe.headers},
        )
        self._requests_sent += 1
        start = time.perf_counter()
        status = 0
        response_headers: Dict[str, str] = {}
        body_bytes = b""
        truncated = False
        try:
            with self._opener.open(request, timeout=self.config.timeout_s) as response:
                status = int(getattr(response, "status", 0) or 0)
                response_headers = dict(response.headers.items())
                body_bytes = response.read(self.config.max_body_bytes + 1)
        except urllib.error.HTTPError as exc:
            status = int(exc.code)
            response_headers = dict(exc.headers.items()) if exc.headers else {}
            body_bytes = exc.read(self.config.max_body_bytes + 1)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise TransportError(f"probe failed for {probe.url}: {exc}") from exc

        if len(body_bytes) > self.config.max_body_bytes:
            body_bytes = body_bytes[: self.config.max_body_bytes]
            truncated = True

        body = body_bytes.decode("utf-8", errors="replace")
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        exchange = ProbeExchange(
            probe=probe,
            status_code=status,
            response_headers=response_headers,
            body=body,
            elapsed_ms=elapsed_ms,
            request_hash=sha256_text(probe.canonical()),
            response_hash=sha256_json(
                {
                    "status": status,
                    "headers": {
                        key.lower(): value for key, value in response_headers.items()
                    },
                    "body": body,
                    "truncated": truncated,
                }
            ),
            truncated=truncated,
        )
        self._exchanges.append(exchange)
        return exchange

    def _check_target(self, probe: Probe) -> None:
        parsed = urlparse(probe.url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise TransportError(f"unsupported probe URL: {probe.url!r}")
        if self.config.allowed_hosts is not None:
            if parsed.hostname.lower() not in {
                host.lower() for host in self.config.allowed_hosts
            }:
                raise PolicyViolation(
                    f"host {parsed.hostname!r} is not in the transport allowlist"
                )

    def _check_policy(self, probe: Probe) -> None:
        engine = self._policy_engine
        if engine is None:
            return
        from core.policy.red_team import ActionClass, ActionRequest

        decision = engine.evaluate(
            ActionRequest(
                target=probe.url,
                action_class=ActionClass.ACTIVE_TEST,
                tool_id="detector.http",
                risk_level="medium",
                operation=f"{probe.method} {probe.url}",
            )
        )
        if not decision.allowed:
            raise PolicyViolation(decision.reason)
