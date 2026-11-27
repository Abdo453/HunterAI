"""Regression tests for Python httpx vs ProjectDiscovery httpx CLI collision."""
from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import pytest

from core.engine.real_tool_adapter import RealToolAdapter
from hunter_ai.core import tool_arsenal
from tools import tool_manager


def _make_script(directory: Path, name: str, win_body: str, posix_body: str) -> Path:
    if sys.platform == "win32":
        p = directory / f"{name}.cmd"
        p.write_text(f"@echo off\r\n{win_body}\r\n", encoding="utf-8")
    else:
        p = directory / name
        p.write_text(f"#!/bin/sh\n{posix_body}\n", encoding="utf-8")
        p.chmod(p.stat().st_mode | stat.S_IXUSR)
    return p


def test_python_httpx_cli_rejected_everywhere(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Python's pip httpx CLI fails `-version` with exit code 2 and must be ignored."""
    py_bin = tmp_path / "py_scripts"
    py_bin.mkdir()
    _make_script(
        py_bin,
        "httpx",
        win_body="echo Usage: httpx [OPTIONS] URL 1>&2\r\necho Error: No such option: -version 1>&2\r\nexit /b 2",
        posix_body="echo 'Usage: httpx [OPTIONS] URL' >&2\necho 'Error: No such option: -version' >&2\nexit 2",
    )

    monkeypatch.setenv("PATH", str(py_bin))
    monkeypatch.setenv("GOPATH", str(tmp_path / "empty_go"))
    monkeypatch.setattr(tool_manager, "_HTTPX_PROBE_CACHE", {})
    monkeypatch.setattr(tool_manager.os.path, "expanduser", lambda p: str(tmp_path / "no_home_go"))

    assert tool_manager.resolve_projectdiscovery_httpx() is None

    tm = tool_manager.ToolManager()
    assert tm.is_available("httpx") is False

    adapter = RealToolAdapter()
    assert adapter.is_tool_available("httpx") is False

    arsenal_map = {item["name"]: item["status"] for item in tool_arsenal.list_tools()}
    assert arsenal_map.get("httpx") == "MISSING"


def test_projectdiscovery_httpx_preferred_over_python_httpx(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """When Python httpx appears earlier in PATH, skip it and pick ProjectDiscovery httpx."""
    py_bin = tmp_path / "py_scripts"
    pd_bin = tmp_path / "pd_bin"
    py_bin.mkdir()
    pd_bin.mkdir()

    _make_script(
        py_bin,
        "httpx",
        win_body="echo Usage: httpx [OPTIONS] URL 1>&2\r\necho Error: No such option: -version 1>&2\r\nexit /b 2",
        posix_body="echo 'Usage: httpx [OPTIONS] URL' >&2\necho 'Error: No such option: -version' >&2\nexit 2",
    )
    pd_script = _make_script(
        pd_bin,
        "httpx",
        win_body="echo [INF] Current Version: v1.6.10 (projectdiscovery)",
        posix_body="echo '[INF] Current Version: v1.6.10 (projectdiscovery)'",
    )

    monkeypatch.setenv("PATH", f"{py_bin}{os.pathsep}{pd_bin}")
    monkeypatch.setenv("GOPATH", str(tmp_path / "empty_go"))
    monkeypatch.setattr(tool_manager, "_HTTPX_PROBE_CACHE", {})
    monkeypatch.setattr(tool_manager.os.path, "expanduser", lambda p: str(tmp_path / "no_home_go"))

    resolved = tool_manager.resolve_projectdiscovery_httpx()
    assert resolved is not None
    assert Path(resolved).resolve() == pd_script.resolve()

    tm = tool_manager.ToolManager()
    assert tm.is_available("httpx") is True

    adapter = RealToolAdapter()
    assert adapter.is_tool_available("httpx") is True
