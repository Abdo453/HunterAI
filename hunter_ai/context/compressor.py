"""HunterAI Context Compressor (Thin Delegation Shim to ``core.context``).

Delegates header filtering, endpoint deduplication, control-sequence scrubbing,
and rune-safe head+tail response compression to ``core.context.manager``.
"""
from __future__ import annotations

from typing import Dict, List, Optional

from core.context.manager import (
    HEADERS_TO_STRIP,
    compress_http_headers,
    compress_response_body,
    deduplicate_endpoints,
)


class ContextCompressor:
    """Backwards-compatible compressor delegating to ``core.context.manager``."""

    @classmethod
    def compress_http_headers(cls, headers: Dict[str, str]) -> Dict[str, str]:
        return compress_http_headers(headers)

    @classmethod
    def deduplicate_endpoints(cls, endpoints: List[str]) -> List[str]:
        return deduplicate_endpoints(endpoints)

    @classmethod
    def compress_response_body(
        cls,
        body: str,
        max_chars: int = 2000,
        reflection_marker: Optional[str] = None,
    ) -> str:
        return compress_response_body(
            body,
            max_chars=max_chars,
            reflection_marker=reflection_marker,
        )


__all__ = ["ContextCompressor", "HEADERS_TO_STRIP"]
