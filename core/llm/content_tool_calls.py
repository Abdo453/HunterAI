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
_TARGET_ARG_KEYS = ("target", "url", "host", "endpoint", "target_url", "domain", "uri", "href")
_URL_ARG_KEYS = frozenset({"url", "target_url", "endpoint", "uri", "href"})
_PATH_ARG_KEYS = ("path", "file_path", "filepath")
_URI_SCHEME_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*):")
_HOST_PORT_RE = re.compile(r"^[A-Za-z0-9._-]+:\d{1,5}(?:/.*)?$")
_DISALLOWED_CMD_SCHEME_RE = re.compile(
    r"(?i)(?:^|[\s'\"=])(?:file|gopher|dict|ftp|ftps|ldap|ldaps|jar|php|expect|ssh|telnet|data)://"
)


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


def _coerce_command_parts(args: Dict[str, Any]) -> Optional[str]:
    """Coerce string OR list/tuple command & argument fields into a single command string."""
    parts: List[str] = []
    for key in _COMMAND_ARG_KEYS:
        val = args.get(key)
        if isinstance(val, str):
            clean = val.strip()
            if clean:
                parts.append(clean)
        elif isinstance(val, (list, tuple)):
            tokens = [str(item).strip() for item in val if item is not None and str(item).strip()]
            if tokens:
                parts.append(" ".join(tokens))
    return " ".join(parts).strip() if parts else None


def _check_disallowed_scheme(candidate: str) -> Optional[str]:
    """Reject non-HTTP(S) URI schemes such as file://, gopher://, dict://, ftp://."""
    clean = (candidate or "").strip()
    if not clean:
        return None
    if _HOST_PORT_RE.match(clean):
        return None
    m = _URI_SCHEME_RE.match(clean)
    if m:
        scheme = m.group(1).lower()
        if scheme not in ("http", "https"):
            return f"SECURITY INVARIANT: Disallowed URI scheme '{scheme}:' in tool argument"
    return None


def _extract_candidate_targets_and_urls(args: Dict[str, Any]) -> List[Tuple[str, Optional[str]]]:
    """Collect every distinct (target, url) pair present across all target/URL argument keys."""
    pairs: List[Tuple[str, Optional[str]]] = []
    seen: Set[Tuple[str, Optional[str]]] = set()

    def _add(key: str, raw_val: str) -> None:
        clean = raw_val.strip()
        if not clean:
            return
        is_url_key = key in _URL_ARG_KEYS or "://" in clean or bool(_URI_SCHEME_RE.match(clean) and not _HOST_PORT_RE.match(clean))
        pair = (clean, clean if is_url_key else None)
        if pair not in seen:
            seen.add(pair)
            pairs.append(pair)

    for key in _TARGET_ARG_KEYS:
        val = args.get(key)
        if isinstance(val, str):
            _add(key, val)
        elif isinstance(val, (list, tuple)):
            for item in val:
                if isinstance(item, str):
                    _add(key, item)

    return pairs


def _infer_action_requests(
    call: ValidatedToolCall,
    *,
    default_category: ActionCategory,
    requested_by_model: str,
) -> Tuple[List[ActionRequest], Optional[str]]:
    """Build PolicyGate ``ActionRequest``s covering ALL candidate targets/URLs and commands.

    Returns ``(requests, immediate_rejection_reason)``. If any argument carries a
    disallowed non-HTTP(S) scheme (e.g. ``file://``, ``gopher://``), returns an
    immediate fail-closed rejection reason before dispatch.
    """
    args = call.arguments
    command = _coerce_command_parts(args)
    if command and _DISALLOWED_CMD_SCHEME_RE.search(command):
        return [], "SECURITY INVARIANT: Disallowed non-HTTP(S) URI scheme in command arguments"

    candidate_pairs = _extract_candidate_targets_and_urls(args)
    for cand_target, cand_url in candidate_pairs:
        scheme_err = _check_disallowed_scheme(cand_url or cand_target)
        if scheme_err:
            return [], scheme_err

    path: Optional[str] = None
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
    elif candidate_pairs:
        category = ActionCategory.HTTP_REQUEST

    method = str(args.get("method") or "GET").upper()
    requests: List[ActionRequest] = []

    if not candidate_pairs:
        fallback_target = (
            "local_terminal"
            if category in (ActionCategory.TERMINAL_COMMAND, ActionCategory.FILE_READ, ActionCategory.FILE_WRITE)
            else ""
        )
        requests.append(
            ActionRequest(
                category=category,
                target=fallback_target,
                command=command,
                url=None,
                path=path,
                method=method,
                reason=f"Content-embedded tool call: {call.name}",
                requested_by_model=requested_by_model,
                metadata={"tool_name": call.name, "arg_keys": sorted(args.keys())},
            )
        )
        return requests, None

    for cand_target, cand_url in candidate_pairs:
        requests.append(
            ActionRequest(
                category=category,
                target=cand_target,
                command=command,
                url=cand_url,
                path=path,
                method=method,
                reason=f"Content-embedded tool call: {call.name}",
                requested_by_model=requested_by_model,
                metadata={"tool_name": call.name, "arg_keys": sorted(args.keys())},
            )
        )
    return requests, None


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

    Every candidate call MUST pass Pydantic validation, URI-scheme invariants,
    and ``PolicyGate.evaluate`` across ALL distinct candidate targets/URLs and
    coerced command arguments before appearing in the returned ``allowed`` list.
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

        requests, immediate_reject = _infer_action_requests(
            validated,
            default_category=default_category,
            requested_by_model=requested_by_model,
        )
        if immediate_reject:
            logger.warning(
                "[ContentToolCalls] Blocked tool '%s': %s",
                validated.name,
                immediate_reject,
            )
            rejected.append(
                RejectedToolCall(
                    name=validated.name,
                    arguments=validated.arguments,
                    reason=immediate_reject,
                    stage="policy_gate",
                )
            )
            continue

        blocked_reason: Optional[str] = None
        for req in requests:
            try:
                decision: PolicyDecision = gate.evaluate(req)
            except Exception as exc:  # noqa: BLE001 - fail closed on policy error
                logger.warning("[ContentToolCalls] PolicyGate evaluation error for %s: %s", validated.name, exc)
                blocked_reason = f"PolicyGate error (fail-closed): {exc}"
                break

            if not decision.allowed:
                logger.warning(
                    "[ContentToolCalls] PolicyGate blocked tool '%s': %s",
                    validated.name,
                    decision.reason,
                )
                blocked_reason = decision.reason
                break

        if blocked_reason is not None:
            rejected.append(
                RejectedToolCall(
                    name=validated.name,
                    arguments=validated.arguments,
                    reason=blocked_reason,
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
