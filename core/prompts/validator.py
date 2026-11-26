"""
CI Prompt Template Variable Validator & Reflector Loop Guard
============================================================
Adapted from PentAGI ``backend/pkg/templates/validator/validator.go`` and
``backend/pkg/templates/prompts/reflector.tmpl`` (commit ``cffed94``, MIT License).

1. **Template Validator**:
   - Parses every ``{{...}}`` directive and extracts referenced ``{{.Var}}`` names.
   - Rejects unbalanced braces, unclosed ``if``/``range`` blocks, empty templates,
     undeclared/dangling ``{{.Var}}`` placeholders, and channel violations
     (``TECHNICAL_TOOL`` must NEVER embed ``{{.Lang}}``; ``OPERATOR_UI`` MUST declare ``{{.Lang}}``).
   - Smoke-renders each template with synthetic dummy data to prove rendering succeeds.

2. **ReflectorLoopGuard (``max_repeats=3``)**:
   - Tracks canonical tool-call signatures ``(tool_name, sorted_args_json)``.
   - Detects both direct repetition (``A -> A -> A``) and alternating 2-step
     oscillation loops (``A -> B -> A -> B -> A -> B``).
   - Injects structured English reflection guidance rendered from ``PromptType.REFLECTOR``
     when the loop threshold is reached.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import re
from collections import Counter, deque
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, List, Mapping, Optional, Sequence, Set, Tuple

from core.prompts.templates import (
    PROMPT_TEMPLATES,
    PROMPT_VARIABLES,
    PromptChannel,
    PromptTemplate,
    PromptType,
    render_prompt,
    render_template_string,
)

_TAG_RE = re.compile(r"\{\{(.*?)\}\}", re.DOTALL)
_FIELD_RE = re.compile(r"(?<![A-Za-z0-9_])\.([A-Za-z_][A-Za-z0-9_]*)")
_BUILTINS: Set[str] = {
    "and", "or", "not", "eq", "ne", "lt", "le", "gt", "ge",
    "len", "index", "slice", "print", "printf", "println",
    "if", "else", "end", "range", "with", "template", "block",
}


@dataclass(frozen=True)
class TemplateValidationError:
    error_type: str
    message: str
    prompt_type: str = ""
    details: str = ""

    def __str__(self) -> str:
        prefix = f"[{self.prompt_type}] " if self.prompt_type else ""
        return f"{prefix}{self.error_type}: {self.message}"


def extract_template_variables(template_text: str) -> List[str]:
    """Parse a Go-style ``{{.Var}}`` template and return sorted top-level variable names.

    Raises ``ValueError`` on empty template, unbalanced ``{{`` / ``}}`` braces,
    unbalanced ``if``/``range``/``end`` blocks, or malformed directives.
    """
    if not template_text or not template_text.strip():
        raise ValueError("Template content cannot be empty")

    if template_text.count("{{") != template_text.count("}}"):
        raise ValueError("Unbalanced '{{' and '}}' template delimiters")

    # Ensure no unclosed '{{' or stray '}}' remains after removing matched tags
    remainder = _TAG_RE.sub("", template_text)
    if "{{" in remainder or "}}" in remainder:
        raise ValueError("Malformed or nested template braces detected")

    variables: Set[str] = set()
    block_stack: List[str] = []

    for match in _TAG_RE.finditer(template_text):
        expr = match.group(1).strip()
        if not expr:
            raise ValueError("Empty '{{}}' template directive")

        if expr.startswith("if "):
            block_stack.append("if")
            in_range = "range" in block_stack
            for var in _FIELD_RE.findall(expr[3:]):
                if var not in _BUILTINS and not in_range:
                    variables.add(var)
        elif expr.startswith("range "):
            for var in _FIELD_RE.findall(expr[6:]):
                if var not in _BUILTINS:
                    variables.add(var)
            block_stack.append("range")
        elif expr == "else":
            if not block_stack:
                raise ValueError("Unexpected '{{else}}' without open block")
        elif expr == "end":
            if not block_stack:
                raise ValueError("Unexpected '{{end}}' without open block")
            block_stack.pop()
        elif expr == ".":
            if "range" not in block_stack:
                raise ValueError("Bare '{{.}}' is only valid inside a '{{range}}' block")
        else:
            # Must be a clean .Var reference
            if not re.fullmatch(r"\.[A-Za-z_][A-Za-z0-9_]*", expr):
                raise ValueError(f"Unsupported or malformed template expression: '{{{{{expr}}}}}'")
            var = expr[1:]
            if var not in _BUILTINS and "range" not in block_stack:
                variables.add(var)

    if block_stack:
        raise ValueError(f"Unclosed template block(s): {', '.join(block_stack)}")

    return sorted(variables)


def create_dummy_template_data(variables: Optional[Sequence[str]] = None) -> Dict[str, Any]:
    """Build deterministic mock values for CI smoke-rendering of templates."""
    defaults: Dict[str, Any] = {
        "Lang": "English",
        "Target": "https://example.com",
        "ScopeSummary": "*.example.com",
        "CurrentTime": "2026-01-01T00:00:00Z",
        "ExecutionContext": "Task #1: Baseline recon complete.",
        "ToolsSummary": "subfinder, httpx, nuclei",
        "Platform": "hackerone",
        "FindingsSummary": "1 candidate finding pending EvidenceCourt review.",
        "Question": "What is the next highest-value test?",
        "ToolName": "httpx",
        "Objective": "Probe live web services",
        "Constraints": "In-scope only, no destructive verbs",
        "Schema": '{"type":"object","properties":{"target":{"type":"string"}}}',
        "Query": "CVE-2025-0001 example",
        "SearchMode": "exploit",
        "Task": "Parse HTTP headers safely",
        "Language": "python",
        "BarrierTools": "- report_blocker\n- switch_strategy",
        "Request": "Verify authentication boundary on /api/v1/admin",
        "RepeatedCall": "httpx({'target': 'https://example.com'})",
        "RepeatCount": 3,
        "MaxRepeats": 3,
        "HistoryText": "GET /api/v1/health -> 200 OK",
        "MaxChars": 2000,
    }
    if variables:
        for v in variables:
            defaults.setdefault(v, f"mock_{v.lower()}")
    return defaults


def validate_template(
    prompt_type: PromptType | str,
    template_text: str,
    *,
    declared_vars: Optional[Sequence[str]] = None,
    channel: Optional[PromptChannel] = None,
) -> List[TemplateValidationError]:
    """Validate a prompt template against declared variables, channel rules, and rendering."""
    errors: List[TemplateValidationError] = []
    ptype_name = prompt_type.value if isinstance(prompt_type, PromptType) else str(prompt_type)

    resolved_type: Optional[PromptType] = None
    if isinstance(prompt_type, PromptType):
        resolved_type = prompt_type
    else:
        try:
            resolved_type = PromptType(prompt_type)
        except ValueError:
            resolved_type = None

    if declared_vars is None:
        if resolved_type is None or resolved_type not in PROMPT_VARIABLES:
            return [
                TemplateValidationError(
                    error_type="UnknownPromptType",
                    message=f"Unknown prompt type: {ptype_name!r}",
                    prompt_type=ptype_name,
                )
            ]
        declared_set = set(PROMPT_VARIABLES[resolved_type])
    else:
        declared_set = set(declared_vars)

    if channel is None and resolved_type is not None and resolved_type in PROMPT_TEMPLATES:
        channel = PROMPT_TEMPLATES[resolved_type].channel

    if not template_text or not template_text.strip():
        return [
            TemplateValidationError(
                error_type="EmptyTemplate",
                message="Template content cannot be empty",
                prompt_type=ptype_name,
            )
        ]

    try:
        actual_vars = extract_template_variables(template_text)
    except ValueError as exc:
        return [
            TemplateValidationError(
                error_type="SyntaxError",
                message=str(exc),
                prompt_type=ptype_name,
            )
        ]

    # 1. Check undeclared / dangling variables
    unauthorized = sorted(v for v in actual_vars if v not in declared_set)
    if unauthorized:
        errors.append(
            TemplateValidationError(
                error_type="UnauthorizedVariable",
                message=f"Template references undeclared variable(s): {unauthorized}",
                prompt_type=ptype_name,
                details=f"Declared variables: {sorted(declared_set)}",
            )
        )

    # 2. Enforce dual-channel language boundary
    if channel == PromptChannel.TECHNICAL_TOOL and "Lang" in actual_vars:
        errors.append(
            TemplateValidationError(
                error_type="ChannelViolation",
                message="Technical tool/query templates must stay strict English and must not use {{.Lang}}",
                prompt_type=ptype_name,
            )
        )
    if channel == PromptChannel.OPERATOR_UI and "Lang" not in actual_vars:
        errors.append(
            TemplateValidationError(
                error_type="ChannelViolation",
                message="Operator UI templates must reference {{.Lang}} for dual-channel localization",
                prompt_type=ptype_name,
            )
        )

    # 3. Smoke-render with mock data
    if not errors:
        mock_data = create_dummy_template_data(sorted(declared_set))
        try:
            rendered = render_template_string(template_text, mock_data, strict=True)
            if re.search(r"\{\{\s*(?:\.[A-Za-z_]|if\b|range\b|else\b|end\b)", rendered):
                errors.append(
                    TemplateValidationError(
                        error_type="RenderingFailed",
                        message="Rendered template still contains unexpanded template directive markers",
                        prompt_type=ptype_name,
                    )
                )
        except Exception as exc:
            errors.append(
                TemplateValidationError(
                    error_type="RenderingFailed",
                    message=f"Template rendering failed: {exc}",
                    prompt_type=ptype_name,
                )
            )

    return errors


def validate_all_templates(
    templates_map: Optional[Mapping[PromptType, PromptTemplate]] = None,
) -> Dict[str, List[TemplateValidationError]]:
    """CI entry point: validate every registered prompt template.

    Returns a dict mapping failing prompt_type -> list of errors (empty dict == all valid).
    """
    source = templates_map if templates_map is not None else PROMPT_TEMPLATES
    failures: Dict[str, List[TemplateValidationError]] = {}
    for ptype, tmpl in source.items():
        errs = validate_template(
            ptype,
            tmpl.content,
            declared_vars=tmpl.variables,
            channel=tmpl.channel,
        )
        if errs:
            failures[ptype.value] = errs
    return failures


def assert_all_templates_valid() -> None:
    """Raise ``AssertionError`` if any registered prompt template fails CI validation."""
    failures = validate_all_templates()
    if failures:
        lines = [str(err) for errs in failures.values() for err in errs]
        raise AssertionError("Prompt template CI validation failed:\n" + "\n".join(lines))


# ---------------------------------------------------------------------------
# ReflectorLoopGuard (max_repeats=3) — PentAGI-adapted stalled-loop breaker
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class LoopGuardDecision:
    stalled: bool
    repeat_count: int
    max_repeats: int
    signature: str
    loop_kind: str = "none"  # "none" | "identical_consecutive" | "identical_window" | "oscillation"
    guidance: str = ""
    should_halt: bool = False


class ReflectorLoopGuard:
    """Detects stalled/identical or oscillating tool-call loops and emits
    structured English reflection guidance rendered from ``PromptType.REFLECTOR``.

    Default ``max_repeats=3`` triggers on the 3rd identical invocation (or 3rd
    full cycle of an ``A -> B -> A -> B -> A -> B`` oscillation).
    """

    def __init__(
        self,
        *,
        max_repeats: int = 3,
        window_size: int = 12,
        halt_multiplier: int = 2,
    ) -> None:
        self.max_repeats = max(2, int(max_repeats))
        self.window_size = max(self.max_repeats * 2, int(window_size))
        self.halt_multiplier = max(2, int(halt_multiplier))
        self._history: Deque[Tuple[str, str]] = deque(maxlen=self.window_size)
        self._total_calls: int = 0
        self._triggers: int = 0

    @staticmethod
    def canonical_signature(tool_name: str, arguments: Mapping[str, Any] | Any) -> Tuple[str, str]:
        """Return ``(digest, human_label)`` stably normalizing argument key order."""
        name = str(tool_name or "").strip().lower()
        try:
            norm_args = json.dumps(arguments if arguments is not None else {}, sort_keys=True, default=str, ensure_ascii=False)
        except Exception:
            norm_args = str(arguments)
        raw = f"{name}::{norm_args}"
        digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
        label = f"{name}({norm_args[:180]})"
        return digest, label

    def record_call(
        self,
        tool_name: str,
        arguments: Optional[Mapping[str, Any]] = None,
        *,
        execution_context: str = "",
        request: str = "",
        barrier_tools: Optional[Sequence[str]] = None,
        outcome: str = "",
    ) -> LoopGuardDecision:
        """Record a tool call and evaluate whether the agent is stuck in a loop."""
        digest, label = self.canonical_signature(tool_name, arguments or {})
        self._history.append((digest, label))
        self._total_calls += 1

        # 1. Consecutive identical count
        consecutive = 0
        for d, _ in reversed(self._history):
            if d == digest:
                consecutive += 1
            else:
                break

        # 2. Total identical occurrences inside sliding window
        window_counts = Counter(d for d, _ in self._history)
        window_count = window_counts[digest]

        # 3. 2-call oscillation (A, B, A, B, A, B)
        oscillation_cycles = 0
        if len(self._history) >= 2 * self.max_repeats:
            tail = [d for d, _ in list(self._history)[-(2 * self.max_repeats):]]
            if tail[0] != tail[1] and all(tail[i] == tail[i % 2] for i in range(len(tail))):
                oscillation_cycles = self.max_repeats

        loop_kind = "none"
        effective_count = max(consecutive, window_count, oscillation_cycles)
        if consecutive >= self.max_repeats:
            loop_kind = "identical_consecutive"
            effective_count = consecutive
        elif oscillation_cycles >= self.max_repeats:
            loop_kind = "oscillation"
            effective_count = oscillation_cycles
        elif window_count >= self.max_repeats:
            loop_kind = "identical_window"
            effective_count = window_count

        if loop_kind == "none":
            return LoopGuardDecision(
                stalled=False,
                repeat_count=effective_count,
                max_repeats=self.max_repeats,
                signature=digest,
                loop_kind="none",
                guidance="",
                should_halt=False,
            )

        self._triggers += 1
        tools_text = "\n".join(f"- {t}" for t in (barrier_tools or ["switch_strategy", "report_blocker", "finish_subtask"]))
        ctx_text = execution_context or (f"Last observed outcome: {outcome}" if outcome else "Repeated call produced no new state transition.")
        guidance = render_prompt(
            PromptType.REFLECTOR,
            {
                "BarrierTools": tools_text,
                "CurrentTime": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "ExecutionContext": ctx_text,
                "Request": request,
                "RepeatedCall": label,
                "RepeatCount": effective_count,
                "MaxRepeats": self.max_repeats,
            },
        )
        should_halt = effective_count >= self.max_repeats * self.halt_multiplier
        return LoopGuardDecision(
            stalled=True,
            repeat_count=effective_count,
            max_repeats=self.max_repeats,
            signature=digest,
            loop_kind=loop_kind,
            guidance=guidance,
            should_halt=should_halt,
        )

    def reset(self) -> None:
        self._history.clear()

    def stats(self) -> Dict[str, int]:
        return {
            "total_calls": self._total_calls,
            "triggers": self._triggers,
            "window_len": len(self._history),
            "max_repeats": self.max_repeats,
        }
