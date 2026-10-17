"""
LEDGER-020 (M3) — Contract unification.

Validates that the real executor outcome (``ToolResult``) and the pipeline
metadata (``ToolExecutionMeta``) both project from/to the single canonical
``ToolExecutionResult`` contract (``core.contracts.task_contracts``), so a
tool run has one authoritative representation instead of parallel ad-hoc shapes.
"""
from __future__ import annotations

from pathlib import Path

from core.contracts.task_contracts import ToolExecutionResult
from hunter_ai.pipeline.engagement_manager import EngagementManager
from hunter_ai.pipeline.schemas import ToolExecutionMeta
from tools.tool_manager import ToolResult


def _make_result() -> ToolResult:
    return ToolResult(
        tool="nmap",
        command="nmap -sV example.com",
        stdout="PORT   STATE SERVICE\n22/tcp open  ssh",
        stderr="",
        returncode=0,
        duration=2.5,
        error_category="",
    )


def test_tool_result_to_contract(tmp_path):
    res = _make_result()
    contract = res.to_contract(task_id="TASK-01", action="nmap", parameters={"port": 22}, target="example.com")

    assert isinstance(contract, ToolExecutionResult)
    assert contract.task_id == "TASK-01"
    assert contract.tool_name == "nmap"
    assert contract.action == "nmap"
    assert contract.target == "example.com"
    assert contract.parameters == {"port": 22}
    assert contract.success is True
    assert contract.exit_code == 0
    assert contract.duration_ms == 2500.0
    assert "PORT   STATE SERVICE" in contract.raw_output
    assert contract.error_category == ""


def test_meta_from_result_and_back(tmp_path):
    res = _make_result()
    meta = ToolExecutionMeta.from_result(
        res,
        stage="05_ports",
        raw_output_file="raw.txt",
        parsed_output_file="parsed.json",
        metadata_file="meta.json",
        item_count=1,
        input_source="direct",
        next_stage="06_content",
        target="example.com",
        command="nmap -sV example.com",
    )

    assert isinstance(meta, ToolExecutionMeta)
    assert meta.tool == "nmap"
    assert meta.target == "example.com"
    assert meta.stage == "05_ports"
    assert meta.status == "success"
    assert meta.item_count == 1
    assert meta.next_stage == "06_content"
    assert meta.duration_seconds == 2.5

    back = meta.to_result()
    assert isinstance(back, ToolExecutionResult)
    assert back.tool_name == "nmap"
    assert back.target == "example.com"
    assert back.success is True
    assert back.duration_ms == 2500.0


def test_save_tool_artifact_uses_execution_result(tmp_path):
    mgr = EngagementManager(target="example.com", base_dir=tmp_path)
    res = _make_result()

    meta = mgr.save_tool_artifact(
        stage="05_ports",
        tool_name="nmap",
        command="nmap -sV example.com",
        raw_output=res.stdout,
        parsed_data=[{"port": 22, "state": "open", "service": "ssh"}],
        input_source="direct",
        next_stage="06_content",
        duration=2.5,
        status="success",
        execution_result=res,
    )

    assert meta.tool == "nmap"
    assert meta.target == "example.com"
    assert meta.stage == "05_ports"
    assert meta.status == "success"
    assert meta.duration_seconds == 2.5
    assert meta.error is None
    # Persisted files exist
    assert Path(meta.raw_output_file).exists()
    assert Path(meta.parsed_output_file).exists()
    assert Path(meta.metadata_file).exists()


def test_save_tool_artifact_derives_error_from_result(tmp_path):
    mgr = EngagementManager(target="example.com", base_dir=tmp_path)
    res = ToolResult(
        tool="nmap", command="nmap -sV example.com", stdout="", stderr="",
        returncode=1, duration=0.0, error="TOOL_UNAVAILABLE: nmap not found in PATH",
        error_category="TOOL_UNAVAILABLE",
    )

    meta = mgr.save_tool_artifact(
        stage="05_ports",
        tool_name="nmap",
        command="nmap -sV example.com",
        raw_output="",
        parsed_data=[],
        input_source="direct",
        next_stage=None,
        duration=0.0,
        status="failure",
        error="legacy error",
        execution_result=res,
    )

    # Result-driven error wins over the legacy error argument.
    assert meta.error == "TOOL_UNAVAILABLE: nmap not found in PATH"
    assert meta.status == "failure"
