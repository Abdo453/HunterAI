"""Canonical HunterAI LLM Infrastructure Package (Phase 6).

Exports structured backend diagnostics, bounded retries, non-deterministic
failover, SSRF-gated wire/tool/context probes, thinking-tag stream filtering,
PolicyGate-enforced content tool-call parsing, canonical model manifest &
hardware profiles, process-wide GPU/VRAM scheduling, and hardware telemetry.
"""
from __future__ import annotations

from core.llm.content_tool_calls import (
    MAX_NORMALIZE_DEPTH,
    RejectedToolCall,
    ValidatedToolCall,
    parse_and_gate_content_tool_calls,
    parse_content_tool_calls,
)
from core.llm.errors import (
    BackendError,
    ErrorCategory,
    StructuredDiagnostic,
    classify_backend,
    diagnose_error,
    format_user_error,
    is_deterministic_error,
    is_refusal_error,
    is_transient,
    parse_retry_after,
)
from core.llm.failover import FailoverResult, should_failover, with_failover
from core.llm.gpu_scheduler import (
    GPULease,
    GPUScheduler,
    PRIORITY_BACKGROUND,
    PRIORITY_INTERACTIVE,
    PRIORITY_NORMAL,
    get_gpu_scheduler,
)
from core.llm.hardware_monitor import (
    HardwareMonitor,
    get_hardware_monitor,
    get_vram_manager_loaded_model,
    register_vram_manager,
)
from core.llm.manifest import (
    DEFAULT_GEMINI_MODEL,
    GEMINI_MODELS,
    HardwareProfileConfig,
    ModelManifest,
    RoleAssignment,
    canonical_gemini_model,
    get_model_manifest,
)
from core.llm.probe import (
    OllamaContextInfo,
    ToolProbeResult,
    WireProbeResult,
    detect_ollama_context_window,
    detect_wire_kind,
    parse_ollama_context_info,
    probe_tool_support,
    validate_probe_base_url,
)
from core.llm.retry import MAX_RETRY_AFTER_S, RetryInfo, RetryOptions, with_retry
from core.llm.stream_filter import ThinkingStreamFilter, strip_thinking_tags

__all__ = [
    "BackendError",
    "DEFAULT_GEMINI_MODEL",
    "ErrorCategory",
    "FailoverResult",
    "GEMINI_MODELS",
    "GPULease",
    "GPUScheduler",
    "HardwareMonitor",
    "HardwareProfileConfig",
    "MAX_NORMALIZE_DEPTH",
    "MAX_RETRY_AFTER_S",
    "ModelManifest",
    "OllamaContextInfo",
    "PRIORITY_BACKGROUND",
    "PRIORITY_INTERACTIVE",
    "PRIORITY_NORMAL",
    "RejectedToolCall",
    "RetryInfo",
    "RetryOptions",
    "RoleAssignment",
    "StructuredDiagnostic",
    "ThinkingStreamFilter",
    "ToolProbeResult",
    "ValidatedToolCall",
    "WireProbeResult",
    "canonical_gemini_model",
    "classify_backend",
    "detect_ollama_context_window",
    "detect_wire_kind",
    "diagnose_error",
    "format_user_error",
    "get_gpu_scheduler",
    "get_hardware_monitor",
    "get_model_manifest",
    "get_vram_manager_loaded_model",
    "is_deterministic_error",
    "is_refusal_error",
    "is_transient",
    "parse_and_gate_content_tool_calls",
    "parse_content_tool_calls",
    "parse_ollama_context_info",
    "parse_retry_after",
    "probe_tool_support",
    "register_vram_manager",
    "should_failover",
    "strip_thinking_tags",
    "validate_probe_base_url",
    "with_failover",
    "with_retry",
]
