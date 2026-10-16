"""M0 hygiene guards (LEDGER-012).

Verifies the small, high-impact cleanups stay fixed:

  1. ``config/settings.yaml`` permissions are fail-closed (no open-by-default
     switches with zero code readers).
  2. No production module hardcodes the old LAN Ollama host ``192.168.1.3``;
     the host must come from ``OLLAMA_HOST`` (default ``127.0.0.1``).
  3. ``core.tool_registry`` annotations resolve (the missing ``Tuple`` import
     made ``typing.get_type_hints`` raise).
"""
from __future__ import annotations

import typing
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]

# Production source roots that must never embed a fixed LAN host.
PRODUCTION_ROOTS = ["core", "hunter_ai", "models", "platform", "agents"]
FORBIDDEN_HOST = "192.168.1.3"


def test_settings_permissions_are_fail_closed():
    settings = yaml.safe_load((REPO_ROOT / "config" / "settings.yaml").read_text(encoding="utf-8"))
    permissions = settings.get("permissions", {})
    assert permissions, "permissions block must exist"
    for key, value in permissions.items():
        assert value is False, f"permission '{key}' must be fail-closed, got {value!r}"


def test_no_hardcoded_lan_ollama_host_in_production():
    offenders = []
    for root in PRODUCTION_ROOTS:
        base = REPO_ROOT / root
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if path.is_dir() or path.suffix not in {".py", ".json"}:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if FORBIDDEN_HOST in text:
                offenders.append(str(path.relative_to(REPO_ROOT)))
    assert offenders == [], f"hardcoded {FORBIDDEN_HOST} found in: {offenders}"


def test_tool_registry_type_hints_resolve():
    from core.tool_registry import ToolRegistry

    hints = typing.get_type_hints(ToolRegistry.check_permissions)
    assert "return" in hints
    assert hints["return"] == typing.Tuple[bool, typing.Optional[str]]
    # The other annotated method must resolve too.
    typing.get_type_hints(ToolRegistry.is_action_allowed)
