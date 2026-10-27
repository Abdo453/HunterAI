"""Connector foundations: metadata, rate limiting, retries, cursors, HTTP.

Every connector must be polite and deterministic.  The HTTP client:

* spaces requests according to the source's documented rate;
* retries 429/5xx with exponential backoff (honouring ``Retry-After``);
* enforces a response-size cap;
* rejects redirects to hosts outside the source allowlist;
* never disables TLS verification;
* never logs credentials.
"""
from __future__ import annotations

import asyncio
import logging
import random
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple
from urllib.parse import urlparse

import httpx

from ..models import VulnerabilityRecord

logger = logging.getLogger("core.vuln_intel.sources")


class SourceError(Exception):
    """Base class for connector failures."""


class RetryableSourceError(SourceError):
    def __init__(self, message: str, *, status: Optional[int] = None, retry_after: Optional[float] = None):
        super().__init__(message)
        self.status = status
        self.retry_after = retry_after


class SourceHTTPError(SourceError):
    def __init__(self, message: str, *, status: int):
        super().__init__(message)
        self.status = status


class SourceParseError(SourceError):
    pass


class ResponseTooLargeError(SourceError):
    pass


class SourceUnavailableError(SourceError):
    pass


@dataclass(frozen=True)
class SourceMetadata:
    source_id: str
    name: str
    base_url: str
    license: str = "unknown"
    terms_url: str = ""
    historical_start: str = "unknown"
    max_window_days: int = 120
    rate_limit_requests: int = 5
    rate_limit_period_seconds: float = 30.0
    allowed_hosts: Tuple[str, ...] = ()
    supports_incremental: bool = True
    notes: str = ""

    def __post_init__(self) -> None:
        if not self.allowed_hosts:
            host = urlparse(self.base_url).hostname
            if host:
                object.__setattr__(self, "allowed_hosts", (host,))


@dataclass
class Cursor:
    start_index: int = 0
    page: int = 0
    token: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {"start_index": self.start_index, "page": self.page, "token": self.token}

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> "Cursor":
        data = data or {}
        return cls(
            start_index=int(data.get("start_index", 0) or 0),
            page=int(data.get("page", 0) or 0),
            token=data.get("token"),
        )


@dataclass
class Page:
    records: List[Dict[str, Any]]
    next_cursor: Optional[Cursor] = None
    total_results: Optional[int] = None
    raw_count: int = 0


class RateLimiter:
    """Evenly spaced async rate limiter (average rate per period)."""

    def __init__(
        self,
        requests: int,
        period_seconds: float,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Any] = asyncio.sleep,
    ):
        self.requests = max(1, int(requests))
        self.period_seconds = max(0.0, float(period_seconds))
        self._interval = self.period_seconds / self.requests
        self._clock = clock
        self._sleep = sleep
        self._last: Optional[float] = None
        self._lock = asyncio.Lock()
        self.sleeps: List[float] = []

    async def acquire(self) -> None:
        async with self._lock:
            now = self._clock()
            if self._last is not None and self._interval > 0:
                wait = self._interval - (now - self._last)
                if wait > 0:
                    self.sleeps.append(wait)
                    await self._sleep(wait)
                    now = self._clock()
            self._last = now


@dataclass
class RetryPolicy:
    max_attempts: int = 4
    base_delay: float = 1.0
    max_delay: float = 30.0
    jitter: float = 0.1
    retry_statuses: Tuple[int, ...] = (429, 500, 502, 503, 504)
    rng: random.Random = field(default_factory=random.Random)

    def should_retry_status(self, status: int) -> bool:
        return status in self.retry_statuses

    def delay_for(self, attempt: int, retry_after: Optional[float] = None) -> float:
        if retry_after is not None:
            return max(0.0, min(float(retry_after), self.max_delay))
        delay = min(self.max_delay, self.base_delay * (2 ** max(0, attempt - 1)))
        if self.jitter > 0:
            delay *= 1.0 + self.rng.uniform(-self.jitter, self.jitter)
        return max(0.0, delay)


class HttpClient:
    """Small async JSON client with rate limiting and retries."""

    DEFAULT_HEADERS = {
        "User-Agent": "HunterAI-VulnIntel/0.1 (+https://github.com/Abdo453/HunterAI)",
        "Accept": "application/json",
    }

    def __init__(
        self,
        metadata: SourceMetadata,
        *,
        client: Optional[httpx.AsyncClient] = None,
        timeout: float = 30.0,
        max_bytes: int = 50 * 1024 * 1024,
        rate_limiter: Optional[RateLimiter] = None,
        retry_policy: Optional[RetryPolicy] = None,
        sleep: Callable[[float], Any] = asyncio.sleep,
        headers: Optional[Dict[str, str]] = None,
    ):
        self.metadata = metadata
        self._client = client
        self._owns_client = client is None
        self.timeout = timeout
        self.max_bytes = max(1, int(max_bytes))
        self.rate_limiter = rate_limiter or RateLimiter(
            metadata.rate_limit_requests, metadata.rate_limit_period_seconds
        )
        self.retry_policy = retry_policy or RetryPolicy()
        self._sleep = sleep
        self.headers = dict(self.DEFAULT_HEADERS)
        if headers:
            self.headers.update(headers)

    async def __aenter__(self) -> "HttpClient":
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=True,
                verify=True,
                headers=self.headers,
            )
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    async def get_json(
        self,
        url: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Any:
        return await self._request("GET", url, params=params, headers=headers)

    async def post_json(
        self,
        url: str,
        payload: Any,
        *,
        headers: Optional[Dict[str, str]] = None,
    ) -> Any:
        """POST a JSON body and return the parsed JSON response.

        The same safety envelope as :meth:`get_json` applies: retries, the
        redirect allowlist, and the response-size cap.
        """
        return await self._request("POST", url, json_body=payload, headers=headers)

    async def _request(
        self,
        method: str,
        url: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json_body: Any = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Any:
        if self._client is None:
            await self.__aenter__()
        assert self._client is not None

        last_error: Optional[Exception] = None
        for attempt in range(1, self.retry_policy.max_attempts + 1):
            await self.rate_limiter.acquire()
            try:
                response = await self._client.request(
                    method,
                    url,
                    params=params,
                    json=json_body,
                    headers=headers,
                )
            except httpx.RequestError as exc:
                last_error = exc
                if attempt >= self.retry_policy.max_attempts:
                    raise SourceUnavailableError(f"{self.metadata.source_id}: request failed: {exc}") from exc
                await self._sleep(self.retry_policy.delay_for(attempt))
                continue

            self._validate_redirect_host(response)

            if self.retry_policy.should_retry_status(response.status_code):
                retry_after = _retry_after_seconds(response.headers.get("Retry-After"))
                last_error = RetryableSourceError(
                    f"{self.metadata.source_id}: HTTP {response.status_code}",
                    status=response.status_code,
                    retry_after=retry_after,
                )
                if attempt >= self.retry_policy.max_attempts:
                    raise SourceUnavailableError(str(last_error)) from last_error
                await self._sleep(self.retry_policy.delay_for(attempt, retry_after))
                continue

            if response.status_code >= 400:
                raise SourceHTTPError(
                    f"{self.metadata.source_id}: HTTP {response.status_code} for {url}",
                    status=response.status_code,
                )

            content = response.content
            if len(content) > self.max_bytes:
                raise ResponseTooLargeError(
                    f"{self.metadata.source_id}: response {len(content)} bytes exceeds {self.max_bytes}"
                )
            try:
                return response.json()
            except ValueError as exc:
                raise SourceParseError(
                    f"{self.metadata.source_id}: invalid JSON from {url}"
                ) from exc

        raise SourceUnavailableError(str(last_error or "request failed"))

    def _validate_redirect_host(self, response: httpx.Response) -> None:
        host = response.url.host
        allowed = {h.lower() for h in self.metadata.allowed_hosts if h}
        if not allowed or not host:
            return
        if host.lower() not in allowed:
            raise SourceHTTPError(
                f"{self.metadata.source_id}: redirect to disallowed host {host!r}",
                status=403,
            )


class SourceConnector(ABC):
    """A read-only advisory source."""

    metadata: SourceMetadata

    @abstractmethod
    async def fetch_page(
        self,
        *,
        start: Any,
        end: Any,
        cursor: Cursor,
        page_size: int,
    ) -> Page:
        raise NotImplementedError

    @abstractmethod
    def normalize(self, raw: Dict[str, Any]) -> VulnerabilityRecord:
        raise NotImplementedError


def _retry_after_seconds(value: Optional[str]) -> Optional[float]:
    if not value:
        return None
    try:
        return float(value)
    except ValueError:
        return None


__all__ = [
    "Cursor",
    "HttpClient",
    "Page",
    "RateLimiter",
    "ResponseTooLargeError",
    "RetryPolicy",
    "RetryableSourceError",
    "SourceConnector",
    "SourceError",
    "SourceHTTPError",
    "SourceMetadata",
    "SourceParseError",
    "SourceUnavailableError",
]
