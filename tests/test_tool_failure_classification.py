"""Regression tests: a tool failure must be structured and visible.

Defect (before the fix):
    ``ToolManager.execute`` uses ``create_subprocess_shell``, so a missing
    binary never raises ``FileNotFoundError``. The shell exits 127/9009 with an
    empty error field, making "tool not installed" indistinguishable from
    "tool ran and found nothing".
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.tool_manager import ToolManager, classify_tool_failure


class TestFailureClassification:
    def test_success_has_no_category(self):
        assert classify_tool_failure(0, "") is None

    def test_posix_missing_binary(self):
        assert classify_tool_failure(127, "") == "TOOL_UNAVAILABLE"

    def test_windows_missing_binary(self):
        assert classify_tool_failure(9009, "") == "TOOL_UNAVAILABLE"

    def test_shell_reports_missing_binary_with_other_exit_code(self):
        assert classify_tool_failure(1, "'foo' is not recognized as an internal or external command") == "TOOL_UNAVAILABLE"

    def test_posix_shell_error_text(self):
        assert classify_tool_failure(1, "sh: 1: foo: not found") == "TOOL_UNAVAILABLE"

    def test_generic_nonzero_exit(self):
        assert classify_tool_failure(2, "some real tool error") == "NONZERO_EXIT"


@pytest.mark.asyncio
async def test_missing_tool_is_reported_not_silent(tmp_path):
    tm = ToolManager(output_dir=str(tmp_path))
    res = await tm.execute("definitely-not-a-real-tool-xyz --version", timeout=15)
    assert res.success is False
    assert res.error is not None, "a missing tool must not return error=None"
    assert res.error_category == "TOOL_UNAVAILABLE"


@pytest.mark.asyncio
async def test_successful_command_has_no_error(tmp_path):
    tm = ToolManager(output_dir=str(tmp_path))
    res = await tm.execute("echo hunterai-ok", timeout=20)
    assert res.success is True
    assert res.error is None
    assert res.error_category is None
    assert "hunterai-ok" in res.stdout


@pytest.mark.asyncio
async def test_timeout_reaps_process_tree(tmp_path):
    """A timeout must reap the whole tree, not just the shell parent."""

    class _SlowProc:
        pid = 999999
        returncode = None

        async def communicate(self):
            await asyncio.sleep(10)

    tm = ToolManager(output_dir=str(tmp_path))
    with patch("asyncio.create_subprocess_shell", AsyncMock(return_value=_SlowProc())), \
         patch("core.process_utils.kill_process_tree", new_callable=AsyncMock) as reaper:
        res = await tm.execute("slow-command", timeout=0.01, use_cache=False)

    assert res.error_category == "TIMEOUT"
    reaper.assert_awaited_once()
