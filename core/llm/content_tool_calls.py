"""Content-embedded tool-call extraction with depth limits, Pydantic validation, and PolicyGate gating.

Adapted from PentesterFlow/agent ``src/llm/contentToolCalls.ts``
(commit ``0759d873a07350a70283c9751f7d136905f777c7``, licensed under Apache-2.0;
see ``THIRD_PARTY_LICENSES/PENTESTERFLOW_APACHE2.txt`` and ``NOTICE``).

Security hardening for HunterAI:
- Enforces ``MAX_NORMALIZE_DEPTH = 20`` to prevent recursion crashes from
  degraded/looping local-model JSON output.
- Validates every extracted tool call through strict Pydantic schemas
  (``ValidatedToolCall``).
- Enforces ``PolicyGate.evaluate(...)`` before returning any tool call for
  dispatch (fail-closed when a target/command violates scope or invariants).
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import logging
import re
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from core.control_plane.policy_gate import ActionCategory, ActionRequest, PolicyDecision, PolicyGate
from core.scope_engine import ScopePolicy

logger = logging.getLogger("hunter_ai.llm.content_tool_calls")

MAX_NORMALIZE_DEPTH: int = 20
_FENCED_JSON_RE = re.compile(r"^```(?:json)?\s*([\s\S]*?)\s*```$", re.IGNORECASE)
_TOOL_NAME_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")

_COMMAND_ARG_KEYS = ("command", "cmd", "shell_command", "args", "command_args")
_TARGET_ARG_KEYS = ("target", "url", "host", "endpoint", "target_url", "domain")
_PATH_ARG_KEYS = ("path", "file_path", "filepath")


class ValidatedToolCall(BaseModel):
    """Pydantic-validated tool invocation extracted from model text."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=1, max_length=128)
    arguments: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("name")
    @classmethod
    def _validate_name(cls, value: str) -> str:
        clean = value.strip()
        if not _TOOL_NAME_RE.fullmatch(clean):
            raise ValueError(f"Invalid tool name format: {value!r}")
        return clean

    @field_validator("arguments")
    @classmethod
    def _validate_arguments(cls, value: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(value, dict):
            raise ValueError("arguments must be a JSON object")
        for key in value:
            if not isinstance(key, str) or len(key) > 128:
                raise ValueError(f"Invalid argument key: {key!r}")
        return value


@dataclass(frozen=True)
class RejectedToolCall:
    """Record of a parsed or malformed tool call blocked by validation or PolicyGate."""

    name: str
    arguments: Dict[str, Any]
    reason: str
    stage: str  # "pydantic" | "policy_gate"


def _normalize_named_call(
    name_value: Any,
    args_value: Any,
    known_tools: Set[str],
) -> Optional[Tuple[str, Dict[str, Any]]]:
    if not isinstance(name_value, str):
        return None
    name_clean = name_value.strip()
    if name_clean not in known_tools:
        return None

    args: Any = args_value
    if isinstance(args, str):
        try:
            args = json.loads(args)
        except (ValueError, TypeError):
            args = {}
    args_dict = args if isinstance(args, dict) else {}
    return name_clean, args_dict


def _normalize_tool_calls(
    value: Any,
    known_tools: Set[str],
    depth: int = 0,
) -> List[Tuple[str, Dict[str, Any]]]:
    if depth > MAX_NORMALIZE_DEPTH:
        return []
    if isinstance(value, list):
        out: List[Tuple[str, Dict[str, Any]]] = []
        for item in value:
            out.extend(_normalize_tool_calls(item, known_tools, depth + 1))
        return out
    if not isinstance(value, dict):
        return []

    for container_key in (
        "tool_calls",
        "toolCalls",
        "tool_call",
        "toolCall",
        "function_call",
        "functionCall",
    ):
        nested = value.get(container_key)
        if isinstance(nested, dict):
            return _normalize_tool_calls(nested, known_tools, depth + 1)
        if isinstance(nested, list):
            out_list: List[Tuple[str, Dict[str, Any]]] = []
            for item in nested:
                out_list.extend(_normalize_tool_calls(item, known_tools, depth + 1))
            return out_list

    fn_val = value.get("function")
    if isinstance(fn_val, dict):
        call = _normalize_named_call(fn_val.get("name"), fn_val.get("arguments"), known_tools)
        return [call] if call else []
    if isinstance(fn_val, str):
        args = (
            value.get("arguments")
            or value.get("args")
            or value.get("parameters")
            or value.get("input")
            or {}
        )
        call = _normalize_named_call(fn_val, args, known_tools)
        return [call] if call else []

    name = None
    for k in ("name", "tool", "tool_name", "toolName", "action", "action_name", "actionName"):
        if value.get(k) is not None:
            name = value.get(k)
            break

    args = {}
    for k in ("arguments", "args", "parameters", "input", "action_input", "actionInput"):
        if value.get(k) is not None:
            args = value.get(k)
            break

    call = _normalize_named_call(name, args, known_tools)
    return [call] if call else []


def _parse_json_from_content(content: str) -> Any:
    trimmed = (content or "").strip()
    if not trimmed:
        return None
    fenced = _FENCED_JSON_RE.match(trimmed)
    candidate = fenced.group(1).strip() if fenced else trimmed
    try:
        return json.loads(candidate)
    except (ValueError, TypeError):
        return None


def _infer_action_request(
    call: ValidatedToolCall,
    *,
    default_category: ActionCategory,
    requested_by_model: str,
) -> ActionRequest:
    args = call.arguments
    target = ""
    url: Optional[str] = None
    command: Optional[str] = None
    path: Optional[str] = None

    for key in _TARGET_ARG_KEYS:
        val = args.get(key)
        if isinstance(val, str) and val.strip():
            if not target:
                target = val.strip()
            if key in ("url", "target_url", "endpoint") and val.strip().startswith(("http://", "https://")):
                url = val.strip()

    for key in _COMMAND_ARG_KEYS:
        val = args.get(key)
        if isinstance(val, str) and val.strip():
            command = val.strip()
            break

    for key in _PATH_ARG_KEYS:
        val = args.get(key)
        if isinstance(val, str) and val.strip():
            path = val.strip()
            break

    low_name = call.name.lower()
    category = default_category
    if command is not None or any(tok in low_name for tok in ("shell", "bash", "exec", "terminal", "command", "run_tool")):
        category = ActionCategory.TERMINAL_COMMAND
    elif any(tok in low_name for tok in ("fuzz", "sqlmap", "ffuf", "nuclei", "exploit", "attack")):
        category = ActionCategory.ACTIVE_FUZZING
    elif any(tok in low_name for tok in ("browser", "navigate", "click")):
        category = ActionCategory.BROWSER_NAVIGATE
    elif any(tok in low_name for tok in ("file_write", "write_file", "edit")):
        category = ActionCategory.FILE_WRITE
    elif any(tok in low_name for tok in ("file_read", "read_file")):
        category = ActionCategory.FILE_READ
    elif url is not None or target:
        category = ActionCategory.HTTP_REQUEST

    method = str(args.get("method") or "GET").upper()
    return ActionRequest(
        category=category,
        target=target or ("local_terminal" if category in (ActionCategory.TERMINAL_COMMAND, ActionCategory.FILE_READ, ActionCategory.FILE_WRITE) else ""),
        command=command,
        url=url,
        path=path,
        method=method,
        reason=f"Content-embedded tool call: {call.name}",
        requested_by_model=requested_by_model,
        metadata={"tool_name": call.name, "arg_keys": sorted(args.keys())},
    )


def _default_fail_closed_gate() -> PolicyGate:
    return PolicyGate(
        scope_policy=ScopePolicy(allowed_targets=[], fail_closed=True),
        authorized=False,
        allow_destructive=False,
    )


def parse_and_gate_content_tool_calls(
    content: str,
    known_tools: Iterable[str],
    *,
    policy_gate: Optional[PolicyGate] = None,
    default_category: ActionCategory = ActionCategory.HTTP_REQUEST,
    requested_by_model: str = "unknown",
) -> Tuple[List[ValidatedToolCall], List[RejectedToolCall]]:
    """Extract, Pydantic-validate, and PolicyGate-check content-embedded tool calls.

    Every candidate call MUST pass both Pydantic validation AND ``PolicyGate.evaluate``
    before appearing in the returned ``allowed`` list.
    """
    known_set = {str(t).strip() for t in known_tools if str(t).strip()}
    if not known_set:
        return [], []

    parsed = _parse_json_from_content(content)
    if parsed is None:
        return [], []

    try:
        raw_calls = _normalize_tool_calls(parsed, known_set, depth=0)
    except RecursionError:
        return [], []

    gate = policy_gate if policy_gate is not None else _default_fail_closed_gate()
    allowed: List[ValidatedToolCall] = []
    rejected: List[RejectedToolCall] = []

    for raw_name, raw_args in raw_calls:
        try:
            validated = ValidatedToolCall(name=raw_name, arguments=raw_args)
        except ValidationError as exc:
            rejected.append(
                RejectedToolCall(
                    name=str(raw_name),
                    arguments=raw_args if isinstance(raw_args, dict) else {},
                    reason=f"Pydantic validation failed: {exc}",
                    stage="pydantic",
                )
            )
            continue

        req = _infer_action_request(
            validated,
            default_category=default_category,
            requested_by_model=requested_by_model,
        )
        try:
            decision: PolicyDecision = gate.evaluate(req)
        except Exception as exc:  # noqa: BLE001 - fail closed on policy error
            logger.warning("[ContentToolCalls] PolicyGate evaluation error for %s: %s", validated.name, exc)
            rejected.append(
                RejectedToolCall(
                    name=validated.name,
                    arguments=validated.arguments,
                    reason=f"PolicyGate error (fail-closed): {exc}",
                    stage="policy_gate",
                )
            )
            continue

        if not decision.allowed:
            logger.warning(
                "[ContentToolCalls] PolicyGate blocked tool '%s': %s",
                validated.name,
                decision.reason,
            )
            rejected.append(
                RejectedToolCall(
                    name=validated.name,
                    arguments=validated.arguments,
                    reason=decision.reason,
                    stage="policy_gate",
                )
            )
            continue

        allowed.append(validated)

    return allowed, rejected


def parse_content_tool_calls(
    content: str,
    known_tools: Iterable[str],
    *,
    policy_gate: Optional[PolicyGate] = None,
    default_category: ActionCategory = ActionCategory.HTTP_REQUEST,
    requested_by_model: str = "unknown",
) -> List[ValidatedToolCall]:
    """Return ONLY Pydantic-validated and PolicyGate-approved content tool calls."""
    allowed, _rejected = parse_and_gate_content_tool_calls(
        content,
        known_tools,
        policy_gate=policy_gate,
        default_category=default_category,
        requested_by_model=requested_by_model,
    )
    return allowed


__all__ = [
    "MAX_NORMALIZE_DEPTH",
    "RejectedToolCall",
    "ValidatedToolCall",
    "parse_and_gate_content_tool_calls",
    "parse_content_tool_calls",
]
