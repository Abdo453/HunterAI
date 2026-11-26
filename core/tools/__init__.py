"""
HunterAI Core Agent Tools
=========================
Canonical Python tool primitives adapted from PentAGI (commit ``cffed94``, MIT License):
- ``state_guard``: ``ErrFlowStateGuard`` sentinel for non-retryable flow-state refusals
- ``file_diff``: context-anchored unified diff parser & in-memory / workspace applier
- ``sploitus``: Sploitus exploit/tool searcher gated by ``StrictScopeEngine``
- ``web_search``: intent-routed multi-engine search orchestrator gated by ``StrictScopeEngine``
"""
from __future__ import annotations

from core.tools.file_diff import (
    DiffApplyError,
    DiffHunk,
    DiffHunkLine,
    apply_unified_diff,
    apply_unified_diff_to_file,
    parse_unified_diff,
)
from core.tools.sploitus import (
    FatalSearchError,
    RetryableSearchError,
    SearchRequest,
    SploitusExploit,
    SploitusResponse,
    SploitusSearcher,
    format_sploitus_results,
)
from core.tools.state_guard import (
    ErrFlowStateGuard,
    FlowStateGuardError,
    is_state_guard,
    state_guard,
    unwrap_state_guard,
)
from core.tools.web_search import (
    EngineID,
    FALLBACK_STRATEGY,
    SearchEngine,
    SearchMode,
    WebSearchOrchestrator,
    clamp_results,
    normalize_mode,
)

__all__ = [
    "DiffApplyError",
    "DiffHunk",
    "DiffHunkLine",
    "EngineID",
    "ErrFlowStateGuard",
    "FALLBACK_STRATEGY",
    "FatalSearchError",
    "FlowStateGuardError",
    "RetryableSearchError",
    "SearchEngine",
    "SearchMode",
    "SearchRequest",
    "SploitusExploit",
    "SploitusResponse",
    "SploitusSearcher",
    "WebSearchOrchestrator",
    "apply_unified_diff",
    "apply_unified_diff_to_file",
    "clamp_results",
    "format_sploitus_results",
    "is_state_guard",
    "normalize_mode",
    "parse_unified_diff",
    "state_guard",
    "unwrap_state_guard",
]
