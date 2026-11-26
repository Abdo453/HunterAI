"""
Sploitus Exploit & Security Tool Searcher
=========================================
Adapted from PentAGI ``backend/pkg/tools/searchers/sploitus.go`` (commit ``cffed94``, MIT License).

Queries the Sploitus exploit/tool search API with bounded response formatting
(50 KB per source preview, 80 KB total output cap), transient error
classification (HTTP 499/422/429/5xx -> retryable), and mandatory
``StrictScopeEngine`` egress validation so local-only or scoped engagements
never leak queries to external hosts without authorization.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import quote_plus, urlparse

import httpx

from core.scope_engine import ScopePolicy, StrictScopeEngine, validate_http_url_target
from core.secret_sanitizer import SecretSanitizer

logger = logging.getLogger(__name__)

SPLOITUS_API_URL = "https://sploitus.com/search"
SPLOITUS_DEFAULT_SORT = "default"
DEFAULT_SPLOITUS_LIMIT = 10
MAX_SPLOITUS_LIMIT = 25
DEFAULT_SPLOITUS_TYPE = "exploits"
SPLOITUS_REQUEST_TIMEOUT = 30.0

MAX_SOURCE_SIZE = 50 * 1024        # 50 KB per source field
MAX_TOTAL_RESULT_SIZE = 80 * 1024  # 80 KB total output limit
TRUNCATION_MSG_BUFFER = 500


class RetryableSearchError(RuntimeError):
    """Transient search failure eligible for bounded retry."""

    def __init__(self, message: str, retry_after: float = 0.0) -> None:
        super().__init__(message)
        self.retry_after = float(retry_after or 0.0)


class FatalSearchError(RuntimeError):
    """Non-retryable search failure (policy denial, malformed response, 4xx)."""


@dataclass
class SearchRequest:
    query: str
    max_results: int = 5
    exploit_type: str = ""
    sort: str = ""


@dataclass
class SploitusExploit:
    id: str = ""
    title: str = ""
    type: str = ""
    href: str = ""
    download: str = ""
    score: float = 0.0
    published: str = ""
    source: str = ""
    language: str = ""


@dataclass
class SploitusResponse:
    exploits: List[SploitusExploit] = field(default_factory=list)
    exploits_total: int = 0

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SploitusResponse":
        raw_items = data.get("exploits") or []
        exploits: List[SploitusExploit] = []
        for item in raw_items:
            if not isinstance(item, dict):
                continue
            try:
                score = float(item.get("score") or 0.0)
            except (TypeError, ValueError):
                score = 0.0
            exploits.append(
                SploitusExploit(
                    id=str(item.get("id") or ""),
                    title=str(item.get("title") or ""),
                    type=str(item.get("type") or ""),
                    href=str(item.get("href") or ""),
                    download=str(item.get("download") or ""),
                    score=score,
                    published=str(item.get("published") or ""),
                    source=str(item.get("source") or ""),
                    language=str(item.get("language") or ""),
                )
            )
        return cls(
            exploits=exploits,
            exploits_total=int(data.get("exploits_total") or len(exploits)),
        )


def format_sploitus_results(
    query: str,
    exploit_type: str,
    limit: int,
    resp: SploitusResponse,
) -> str:
    """Format a ``SploitusResponse`` into bounded, secret-scrubbed Markdown."""
    lines: List[str] = [
        "# Sploitus Search Results\n\n",
        f"**Query:** `{query}`  \n",
        f"**Type:** {exploit_type}  \n",
        f"**Total matches on Sploitus:** {resp.exploits_total}\n\n",
        "---\n\n",
    ]
    if limit < 1:
        limit = DEFAULT_SPLOITUS_LIMIT

    results = resp.exploits[:limit]
    etype = exploit_type.lower()

    if not results:
        if etype == "tools":
            lines.append("No security tools were found for the given query.\n")
        else:
            lines.append("No exploits were found for the given query.\n")
        return SecretSanitizer.sanitize_text("".join(lines))

    header = (
        f"## Security Tools (showing up to {len(results)})\n\n"
        if etype == "tools"
        else f"## Exploits (showing up to {len(results)})\n\n"
    )
    lines.append(header)
    current_size = sum(len(x) for x in lines)
    actual_shown = 0
    truncated_by_size = False

    for idx, item in enumerate(results, start=1):
        if current_size >= MAX_TOTAL_RESULT_SIZE - TRUNCATION_MSG_BUFFER:
            truncated_by_size = True
            break

        item_parts: List[str] = [f"### {idx}. {item.title}\n\n"]
        if item.href:
            item_parts.append(f"**URL:** {item.href}  \n")
        if etype == "tools":
            if item.download:
                item_parts.append(f"**Download:** {item.download}  \n")
            if item.type:
                item_parts.append(f"**Source Type:** {item.type}  \n")
            if item.id:
                item_parts.append(f"**ID:** {item.id}  \n")
        else:
            if item.score > 0:
                item_parts.append(f"**CVSS Score:** {item.score:.1f}  \n")
            if item.type:
                item_parts.append(f"**Type:** {item.type}  \n")
            if item.published:
                item_parts.append(f"**Published:** {item.published}  \n")
            if item.id:
                item_parts.append(f"**ID:** {item.id}  \n")
            if item.language:
                item_parts.append(f"**Language:** {item.language}  \n")
            if item.source:
                preview = item.source
                if len(preview) > MAX_SOURCE_SIZE:
                    preview = preview[:MAX_SOURCE_SIZE] + "\n... [source truncated, exceeded 50 KB limit]"
                item_parts.append(f"\n**Source Preview:**\n```\n{preview}\n```\n")
        item_parts.append("\n---\n\n")
        item_content = "".join(item_parts)

        if current_size + len(item_content) > MAX_TOTAL_RESULT_SIZE - TRUNCATION_MSG_BUFFER:
            truncated_by_size = True
            break

        lines.append(item_content)
        current_size += len(item_content)
        actual_shown += 1

    if truncated_by_size:
        lines.append(
            f"\n\n**Note:** Results truncated after {actual_shown} items due to "
            f"{MAX_TOTAL_RESULT_SIZE} bytes size limit. Total shown: {actual_shown} of {len(results)} available.\n"
        )

    return SecretSanitizer.sanitize_text("".join(lines))


class SploitusSearcher:
    """Sploitus exploit/tool search primitive gated by ``StrictScopeEngine``."""

    engine_id: str = "sploitus"

    def __init__(
        self,
        *,
        enabled: Optional[bool] = None,
        scope_engine: Optional[StrictScopeEngine] = None,
        api_url: str = SPLOITUS_API_URL,
        timeout_s: float = SPLOITUS_REQUEST_TIMEOUT,
        transport: Optional[httpx.AsyncBaseTransport] = None,
    ) -> None:
        if enabled is None:
            env_val = os.getenv("SPLOITUS_ENABLED", "true").strip().lower()
            enabled = env_val not in ("0", "false", "no", "off")
        self._enabled = bool(enabled)
        self.scope_engine = scope_engine
        self.api_url = api_url
        self.timeout_s = timeout_s
        self._transport = transport

    def is_available(self) -> bool:
        return self._enabled

    def _enforce_scope(self) -> None:
        """Validate Sploitus egress through ``validate_http_url_target`` and
        ``StrictScopeEngine`` (fail closed, non-overridable SSRF/scheme invariants)."""
        in_scope = list(self.scope_engine.in_scope) if self.scope_engine is not None else None
        out_of_scope = list(self.scope_engine.out_of_scope) if self.scope_engine is not None else None
        fail_closed = bool(
            self.scope_engine is not None
            and getattr(self.scope_engine.policy, "fail_closed", False)
        )
        ok_url, url_reason = validate_http_url_target(
            self.api_url,
            in_scope=in_scope,
            out_of_scope=out_of_scope,
            allow_loopback=False,
            resolve_dns=False,
            fail_closed=fail_closed,
        )
        if not ok_url:
            raise FatalSearchError(f"Sploitus egress denied for '{self.api_url}': {url_reason}")

        parsed = urlparse(self.api_url)
        host = parsed.hostname or ""
        if not host:
            raise FatalSearchError("Sploitus API URL has no hostname")

        # Always run inviolable check even when no scope_engine was supplied
        inviolable_engine = self.scope_engine or StrictScopeEngine(
            ScopePolicy(allowed_domains=[host])
        )
        inv_ok, inv_reason = inviolable_engine.check_inviolable(host)
        if not inv_ok:
            raise FatalSearchError(f"ScopeEngine denied Sploitus host '{host}': {inv_reason}")

        if self.scope_engine is not None:
            allowed, reason = self.scope_engine.is_allowed(
                target=host,
                path=parsed.path or "/",
                port=parsed.port or (443 if parsed.scheme == "https" else 80),
                method="POST",
            )
            if not allowed:
                raise FatalSearchError(f"StrictScopeEngine denied Sploitus egress: {reason}")

    async def search(self, req: SearchRequest) -> str:
        if not self.is_available():
            raise FatalSearchError("sploitus search engine is not configured/enabled")

        query = req.query.strip()
        if not query:
            raise FatalSearchError("sploitus query cannot be empty")

        self._enforce_scope()

        exploit_type = (req.exploit_type or DEFAULT_SPLOITUS_TYPE).strip().lower()
        sort = (req.sort or SPLOITUS_DEFAULT_SORT).strip().lower()
        limit = req.max_results
        if limit < 1 or limit > MAX_SPLOITUS_LIMIT:
            limit = DEFAULT_SPLOITUS_LIMIT

        payload = {
            "query": query,
            "type": exploit_type,
            "sort": sort,
            "title": False,
            "offset": 0,
        }
        headers = {
            "Accept": "application/json",
            "Accept-Language": "en-US,en;q=0.9",
            "Content-Type": "application/json",
            "Origin": "https://sploitus.com",
            "Referer": f"https://sploitus.com/?query={quote_plus(query)}",
            "DNT": "1",
        }

        client_kwargs: Dict[str, Any] = {
            "timeout": self.timeout_s,
            "follow_redirects": False,
            "trust_env": False,
        }
        if self._transport is not None:
            client_kwargs["transport"] = self._transport

        try:
            async with httpx.AsyncClient(**client_kwargs) as client:
                resp = await client.post(self.api_url, json=payload, headers=headers)
        except Exception as exc:
            raise RetryableSearchError(f"request to Sploitus failed: {exc}") from exc

        if resp.status_code in (499, 422, 429) or resp.status_code >= 500:
            retry_after = 0.0
            try:
                retry_after = float(resp.headers.get("Retry-After", "0") or 0.0)
            except ValueError:
                retry_after = 0.0
            raise RetryableSearchError(
                f"Sploitus transient HTTP {resp.status_code}",
                retry_after=retry_after,
            )

        if resp.status_code != 200:
            raise FatalSearchError(f"the Sploitus API returned HTTP {resp.status_code}")

        try:
            api_resp = SploitusResponse.from_dict(resp.json())
        except Exception as exc:
            raise FatalSearchError(f"failed to decode Sploitus response: {exc}") from exc

        return format_sploitus_results(query, exploit_type, limit, api_resp)
