"""Phase 4 Dual-Channel Prompt Templates, CI Variable Validator & ReflectorLoopGuard Tests."""
from __future__ import annotations

import pytest

from core.prompts import (
    PROMPT_TEMPLATES,
    PromptChannel,
    PromptType,
    ReflectorLoopGuard,
    assert_all_templates_valid,
    create_dummy_template_data,
    extract_template_variables,
    render_prompt,
    validate_all_templates,
    validate_template,
)


def test_ci_all_registered_prompt_templates_valid():
    failures = validate_all_templates()
    assert failures == {}, f"Template CI validation failed: {failures}"
    assert_all_templates_valid()


def test_dual_channel_operator_ui_vs_strict_english_technical_tool():
    # Operator UI template accepts {{.Lang}} and localizes cleanly
    ui_data = create_dummy_template_data()
    ui_data["Lang"] = "Arabic"
    rendered_ar = render_prompt(PromptType.PRIMARY_AGENT, ui_data)
    assert "Arabic" in rendered_ar
    assert "https://example.com" in rendered_ar

    # Technical tool templates NEVER contain {{.Lang}}
    for ptype, tmpl in PROMPT_TEMPLATES.items():
        extracted = extract_template_variables(tmpl.content)
        if tmpl.channel == PromptChannel.TECHNICAL_TOOL:
            assert "Lang" not in extracted, f"Technical template {ptype.value} leaked {{.Lang}}"
            assert "ENGLISH ONLY" in tmpl.content
        else:
            assert "Lang" in extracted, f"Operator UI template {ptype.value} missing {{.Lang}}"


def test_validator_rejects_undeclared_vars_syntax_errors_and_channel_violations():
    # Undeclared / dangling variable
    errs = validate_template(
        PromptType.TOOL_SYNTHESIZER,
        "Run {{.ToolName}} on {{.Target}} with {{.DanglingGhostVar}}",
    )
    assert any(e.error_type == "UnauthorizedVariable" for e in errs)

    # Channel violation: injecting {{.Lang}} into a technical tool template
    errs_chan = validate_template(
        PromptType.SEARCHER,
        "Query {{.Query}} in {{.Lang}}",
        declared_vars=("Query", "Lang"),
        channel=PromptChannel.TECHNICAL_TOOL,
    )
    assert any(e.error_type == "ChannelViolation" for e in errs_chan)

    # Syntax errors: unbalanced braces & unclosed if block
    errs_brace = validate_template(PromptType.CODER, "Task {{.Task")
    assert any(e.error_type == "SyntaxError" for e in errs_brace)

    errs_block = validate_template(PromptType.REFLECTOR, "{{if .Request}}hello")
    assert any(e.error_type == "SyntaxError" for e in errs_block)

    # Empty template rejected
    errs_empty = validate_template(PromptType.CODER, "   ")
    assert any(e.error_type == "EmptyTemplate" for e in errs_empty)


def test_render_prompt_strict_raises_on_missing_variable():
    with pytest.raises(KeyError):
        render_prompt(PromptType.TOOL_SYNTHESIZER, {"ToolName": "httpx"})


def test_reflector_loop_guard_detects_identical_repeats_and_oscillation():
    guard = ReflectorLoopGuard(max_repeats=3)

    # 1st and 2nd identical calls (even with reordered dict keys) do not stall
    d1 = guard.record_call("httpx", {"target": "https://example.com", "ports": "80,443"})
    d2 = guard.record_call("httpx", {"ports": "80,443", "target": "https://example.com"})
    assert d1.stalled is False and d2.stalled is False
    assert d1.signature == d2.signature

    # 3rd identical call triggers structured English reflector guidance
    d3 = guard.record_call(
        "httpx",
        {"target": "https://example.com", "ports": "80,443"},
        request="Discover live services on example.com",
    )
    assert d3.stalled is True
    assert d3.repeat_count == 3
    assert d3.loop_kind == "identical_consecutive"
    assert "STOP repeating the identical tool invocation" in d3.guidance
    assert "Discover live services on example.com" in d3.guidance
    assert d3.should_halt is False

    # Continuing to 2 * max_repeats (6) sets should_halt=True
    for _ in range(3):
        d_halt = guard.record_call("httpx", {"target": "https://example.com", "ports": "80,443"})
    assert d_halt.should_halt is True

    # Reset and verify 2-step oscillation detection (A -> B -> A -> B -> A -> B)
    guard.reset()
    decisions = []
    for _ in range(3):
        decisions.append(guard.record_call("ffuf", {"url": "https://example.com/a"}))
        decisions.append(guard.record_call("nuclei", {"url": "https://example.com/b"}))
    assert decisions[-1].stalled is True
    assert decisions[-1].loop_kind == "oscillation"
    assert "TOOL CALL WORKFLOW REFLECTOR" in decisions[-1].guidance
