"""
HunterAI Dual-Channel Prompt Templates, CI Variable Validator & Reflector Loop Guard
====================================================================================
Adapted from PentAGI ``backend/pkg/templates/`` (commit ``cffed94``, MIT License).

Separates:
  - ``PromptChannel.OPERATOR_UI``: user-facing messages/reports localized via ``{{.Lang}}``
  - ``PromptChannel.TECHNICAL_TOOL``: strict English technical tool/query/reflection templates
    (never localized so tool schemas, arguments, and query syntax remain deterministic)

Provides:
  - ``PROMPT_TEMPLATES`` & ``PROMPT_VARIABLES`` single source of truth
  - ``render_prompt`` safe Go-template-compatible renderer (no eval / no format-string injection)
  - ``extract_template_variables``, ``validate_template``, ``validate_all_templates`` CI validator
  - ``ReflectorLoopGuard`` (``max_repeats=3``) detecting stalled/identical or oscillating tool loops
"""
from __future__ import annotations

from core.prompts.templates import (
    PROMPT_TEMPLATES,
    PROMPT_VARIABLES,
    PromptChannel,
    PromptTemplate,
    PromptType,
    get_template,
    render_prompt,
)
from core.prompts.validator import (
    LoopGuardDecision,
    ReflectorLoopGuard,
    TemplateValidationError,
    assert_all_templates_valid,
    create_dummy_template_data,
    extract_template_variables,
    validate_all_templates,
    validate_template,
)

__all__ = [
    "LoopGuardDecision",
    "PROMPT_TEMPLATES",
    "PROMPT_VARIABLES",
    "PromptChannel",
    "PromptTemplate",
    "PromptType",
    "ReflectorLoopGuard",
    "TemplateValidationError",
    "assert_all_templates_valid",
    "create_dummy_template_data",
    "extract_template_variables",
    "get_template",
    "render_prompt",
    "validate_all_templates",
    "validate_template",
]
