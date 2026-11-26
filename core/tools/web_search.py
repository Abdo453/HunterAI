"""
Intent-Routed Web Search Orchestrator
=====================================
Adapted from PentAGI ``backend/pkg/tools/web_search.go`` (commit ``cffed94``, MIT License).

Agents express search INTENT (``links``, ``answer``, ``research``, ``exploit``)
rather than hardcoding a single search vendor. ``WebSearchOrchestrator`` walks
the mode's ordered fallback chain, skips unconfigured engines, retries only
transient errors (429/5xx/transport) with linear backoff, enforces
``StrictScopeEngine`` egress boundaries, and scrubs queries/outputs with
``SecretSanitizer``.
"""
from __future__ import annotations

import asyncio
import logging
from enum import Enum
from typing import Dict, List, Optional, Protocol, Tuple
from urllib.parse import urlparse

from core.scope_engine import ScopePolicy, StrictScopeEngine
from core.secret_sanitizer import SecretSanitizer
from core.tools.sploitus import (
    FatalSearchError,
    RetryableSearchError,
    SearchRequest,
    SploitusSearcher,
)

logger = logging.getLogger(__name__)


class EngineID(str, Enum):
    GOOGLE = "google"
    DUCKDUCKGO = "duckduckgo"
    TAVILY = "tavily"
    FIRECRAWL = "firecrawl"
    TRAVERSAAL = "traversaal"
    PERPLEXITY = "perplexity"
    SEARXNG = "searxng"
    SPLOITUS = "sploitus"
    INTERNAL = "browser"


class SearchMode(str, Enum):
    LINKS = "links"
    ANSWER = "answer"
    RESEARCH = "research"
    EXPLOIT = "exploit"


DEFAULT_MODE = SearchMode.ANSWER
MAX_ENGINE_ATTEMPTS = 2
RETRY_BACKOFF_BASE_S = 0.3
WEB_SEARCH_DEFAULT_RESULTS = 5
WEB_SEARCH_MAX_RESULTS = 25

# Single source of truth for intent -> ordered fallback engine chain
FALLBACK_STRATEGY: Dict[SearchMode, Tuple[EngineID, ...]] = {
    SearchMode.LINKS: (
        EngineID.GOOGLE,
        EngineID.DUCKDUCKGO,
        EngineID.SEARXNG,
        EngineID.FIRECRAWL,
        EngineID.TAVILY,
        EngineID.PERPLEXITY,
        EngineID.TRAVERSAAL,
    ),
    SearchMode.ANSWER: (
        EngineID.TAVILY,
        EngineID.FIRECRAWL,
        EngineID.PERPLEXITY,
        EngineID.INTERNAL,
        EngineID.TRAVERSAAL,
        EngineID.GOOGLE,
        EngineID.DUCKDUCKGO,
        EngineID.SEARXNG,
    ),
    SearchMode.RESEARCH: (
        EngineID.PERPLEXITY,
        EngineID.TAVILY,
        EngineID.FIRECRAWL,
        EngineID.INTERNAL,
        EngineID.TRAVERSAAL,
        EngineID.GOOGLE,
        EngineID.DUCKDUCKGO,
        EngineID.SEARXNG,
    ),
    SearchMode.EXPLOIT: (
        EngineID.SPLOITUS,
        EngineID.TAVILY,
        EngineID.FIRECRAWL,
        EngineID.PERPLEXITY,
        EngineID.INTERNAL,
        EngineID.TRAVERSAAL,
        EngineID.GOOGLE,
        EngineID.DUCKDUCKGO,
        EngineID.SEARXNG,
    ),
}

_ENGINE_DEFAULT_HOSTS: Dict[EngineID, str] = {
    EngineID.GOOGLE: "www.googleapis.com",
    EngineID.DUCKDUCKGO: "html.duckduckgo.com",
    EngineID.TAVILY: "api.tavily.com",
    EngineID.FIRECRAWL: "api.firecrawl.dev",
    EngineID.TRAVERSAAL: "api-ares.traversaal.ai",
    EngineID.PERPLEXITY: "api.perplexity.ai",
    EngineID.SPLOITUS: "sploitus.com",
}


class SearchEngine(Protocol):
    """Protocol satisfied by any search engine backend."""

    def is_available(self) -> bool: ...

    async def search(self, req: SearchRequest) -> str: ...


def normalize_mode(mode: Optional[str]) -> SearchMode:
    if not mode:
        return DEFAULT_MODE
    cleaned = str(mode).strip().lower()
    for m in SearchMode:
        if m.value == cleaned:
            return m
    return DEFAULT_MODE


def clamp_results(n: Optional[int]) -> int:
    if n is None or n < 1:
        return WEB_SEARCH_DEFAULT_RESULTS
    return min(int(n), WEB_SEARCH_MAX_RESULTS)


class WebSearchOrchestrator:
    """Intent-routed web search tool gated by ``StrictScopeEngine``."""

    def __init__(
        self,
        *,
        engines: Optional[Dict[EngineID, SearchEngine]] = None,
        scope_engine: Optional[StrictScopeEngine] = None,
        local_only: bool = False,
        max_attempts: int = MAX_ENGINE_ATTEMPTS,
        retry_backoff_s: float = RETRY_BACKOFF_BASE_S,
    ) -> None:
        self.scope_engine = scope_engine
        self.local_only = bool(local_only)
        self.max_attempts = max(1, int(max_attempts))
        self.retry_backoff_s = max(0.0, float(retry_backoff_s))
        self.engines: Dict[EngineID, SearchEngine] = dict(engines or {})
        if EngineID.SPLOITUS not in self.engines:
            self.engines[EngineID.SPLOITUS] = SploitusSearcher(
                scope_engine=scope_engine
            )
        self.search_log: List[Dict[str, str]] = []

    def is_available(self) -> bool:
        if self.local_only:
            return False
        return any(e is not None and e.is_available() for e in self.engines.values())

    def _check_engine_egress(self, engine_id: EngineID, engine: SearchEngine) -> Tuple[bool, str]:
        """Fail closed when ``local_only`` is active or ``StrictScopeEngine`` denies the engine host."""
        if self.local_only:
            return False, "local_only mode forbids external web_search egress"

        endpoint = getattr(engine, "api_url", "") or getattr(engine, "base_url", "")
        if endpoint:
            parsed = urlparse(str(endpoint))
            host = parsed.hostname or ""
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            path = parsed.path or "/"
        else:
            host = _ENGINE_DEFAULT_HOSTS.get(engine_id, "")
            port = 443
            path = "/"

        if not host:
            return True, "internal/in-process engine"

        # Always run inviolable check (blocks loopback/IMDS/reserved metadata)
        inviolable = self.scope_engine or StrictScopeEngine(ScopePolicy(allowed_domains=[host]))
        inv_ok, inv_reason = inviolable.check_inviolable(host)
        if not inv_ok:
            return False, inv_reason

        if self.scope_engine is not None:
            allowed, reason = self.scope_engine.is_allowed(
                target=host,
                path=path,
                port=port,
                method="GET",
            )
            if not allowed:
                return False, reason
        return True, "allowed"

    async def _run_with_retry(self, engine: SearchEngine, req: SearchRequest) -> str:
        last_exc: Optional[Exception] = None
        for attempt in range(1, self.max_attempts + 1):
            try:
                return await engine.search(req)
            except RetryableSearchError as exc:
                last_exc = exc
                if attempt >= self.max_attempts:
                    raise
                delay = exc.retry_after if exc.retry_after > 0 else self.retry_backoff_s * attempt
                if delay > 0:
                    await asyncio.sleep(delay)
            except Exception:
                raise
        assert last_exc is not None
        raise last_exc

    async def search(
        self,
        query: str,
        *,
        mode: Optional[str] = None,
        max_results: Optional[int] = None,
        exploit_type: str = "",
        sort: str = "",
    ) -> Dict[str, object]:
        cleaned_query = SecretSanitizer.sanitize_text((query or "").strip())
        if not cleaned_query:
            raise ValueError("web_search: 'query' is required and cannot be empty")

        resolved_mode = normalize_mode(mode)
        if self.local_only:
            return {
                "ok": False,
                "mode": resolved_mode.value,
                "engine": None,
                "attempts": 0,
                "blocked_by_scope": True,
                "content": "web_search blocked: local_only mode forbids external search egress.",
            }

        req = SearchRequest(
            query=cleaned_query,
            max_results=clamp_results(max_results),
            exploit_type=(exploit_type or "").strip(),
            sort=(sort or "").strip(),
        )

        chain = FALLBACK_STRATEGY[resolved_mode]
        attempted = 0
        blocked_reasons: List[str] = []
        last_err: Optional[Exception] = None
        last_engine: Optional[EngineID] = None

        for engine_id in chain:
            engine = self.engines.get(engine_id)
            if engine is None or not engine.is_available():
                continue

            egress_ok, egress_reason = self._check_engine_egress(engine_id, engine)
            if not egress_ok:
                blocked_reasons.append(f"{engine_id.value}: {egress_reason}")
                continue

            attempted += 1
            try:
                raw_result = await self._run_with_retry(engine, req)
                sanitized = SecretSanitizer.sanitize_text(raw_result)
                self.search_log.append(
                    {
                        "mode": resolved_mode.value,
                        "engine": engine_id.value,
                        "query": cleaned_query[:500],
                        "status": "ok",
                    }
                )
                return {
                    "ok": True,
                    "mode": resolved_mode.value,
                    "engine": engine_id.value,
                    "attempts": attempted,
                    "blocked_by_scope": False,
                    "content": sanitized,
                }
            except (RetryableSearchError, FatalSearchError, Exception) as exc:
                last_err = exc
                last_engine = engine_id
                logger.warning(
                    "web_search engine %s failed for mode=%s: %s",
                    engine_id.value,
                    resolved_mode.value,
                    exc,
                )

        if attempted == 0 and blocked_reasons:
            return {
                "ok": False,
                "mode": resolved_mode.value,
                "engine": None,
                "attempts": 0,
                "blocked_by_scope": True,
                "content": (
                    f"web_search denied by StrictScopeEngine for mode '{resolved_mode.value}': "
                    + "; ".join(blocked_reasons)
                ),
            }

        if attempted == 0:
            return {
                "ok": False,
                "mode": resolved_mode.value,
                "engine": None,
                "attempts": 0,
                "blocked_by_scope": False,
                "content": (
                    f"web_search: no search engine is configured for mode '{resolved_mode.value}'."
                ),
            }

        self.search_log.append(
            {
                "mode": resolved_mode.value,
                "engine": last_engine.value if last_engine else "none",
                "query": cleaned_query[:500],
                "status": "exhausted",
            }
        )
        return {
            "ok": False,
            "mode": resolved_mode.value,
            "engine": last_engine.value if last_engine else None,
            "attempts": attempted,
            "blocked_by_scope": False,
            "content": (
                f"web_search: all {attempted} configured engine(s) failed for mode "
                f"'{resolved_mode.value}'. Last error ({last_engine.value if last_engine else 'unknown'}): {last_err}."
            ),
        }
