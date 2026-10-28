"""Hermetic tests for the bundled recon methodology and its agent."""
from __future__ import annotations

import asyncio
import json

import pytest

from agents.base_agent import AgentTask
from agents.recon_agent import ReconAgent
from agents.recon_methodology_agent import ReconMethodologyAgent
from core.playbooks.recon_methodology import (
    EXECUTABLE_STAGES,
    UnsafeValueError,
    build_context,
    command_inventory,
    executable_summary,
    load_methodology_text,
    methodology_summary,
    render_command,
    selected_stages,
    validate_target,
)
from hunter_ai.agents.registry import AgentRegistry
from tools.tool_manager import ToolManager


class _FakeResult:
    def __init__(self, output: str = ""):
        self.output = output
        self.stdout = output
        self.stderr = ""
        self.returncode = 0
        self.duration = 0.0
        self.success = True
        self.error = None
        self.output_file = None


class _FakeManager:
    policy_gate = None

    def __init__(self, available=True, output="sub.example.com\n"):
        self.available = available
        self.output = output
        self.calls = []

    def is_available(self, tool: str) -> bool:
        return bool(self.available)

    async def execute(self, command: str, *args, **kwargs):
        self.calls.append(command)
        return _FakeResult(self.output)


def test_bundled_methodology_is_complete():
    text = load_methodology_text()
    assert len(text.splitlines()) >= 470
    summary = methodology_summary()
    assert summary["sections"] >= 20
    assert summary["commands"] >= 100
    assert len(command_inventory()) >= 100

    for title in (
        "Passive Subdomain Enumeration",
        "Active Subdomain Enumeration",
        "Subdomain Fuzzing",
        "Virtual Host",
        "Infrastructure Discovery",
        "Certificate Transparency",
        "OSINT Sources",
        "URL Discovery",
        "JavaScript Secret Discovery",
        "Secret Discovery",
        "Hidden Parameters",
        "Port Discovery",
        "Directory Fuzzing",
        "API Endpoint Discovery",
    ):
        assert title.lower() in text.lower()


def test_executable_stages_cover_the_pipeline():
    keys = {stage.key for stage in EXECUTABLE_STAGES}
    assert {
        "passive_subdomains",
        "active_subdomains",
        "subdomain_fuzzing",
        "infrastructure",
        "merge",
        "alive_hosts",
        "url_discovery",
        "parameter_mining",
        "secret_mining",
        "directory_discovery",
        "hidden_parameters",
        "ports",
        "exposure_scan",
        "takeover_origin",
        "api_discovery",
    } <= keys

    summary = executable_summary()
    assert summary["stages"] >= 15
    assert summary["commands"] >= 40
    assert {"subfinder", "httpx", "katana", "nuclei", "nmap", "sqlmap"} <= set(summary["tools"])
    assert [stage.key for stage in selected_stages("merge")] == ["merge"]


def test_target_and_render_reject_injection(tmp_path):
    assert validate_target("example.com") == "example.com"
    assert validate_target("https://example.com") == "https://example.com"
    with pytest.raises(ValueError):
        validate_target("example.com; rm -rf /")
    with pytest.raises(ValueError):
        validate_target("example.com%PATH%")
    with pytest.raises(ValueError):
        validate_target("https://example.com/?x=1")
    with pytest.raises(ValueError):
        build_context("example.com; rm -rf /", out_dir=str(tmp_path))

    ctx = build_context("example.com", out_dir=str(tmp_path))
    with pytest.raises(UnsafeValueError):
        render_command("echo {domain}", {"domain": "example.com; rm -rf /"})
    with pytest.raises(UnsafeValueError):
        render_command("echo {domain}", {"domain": "example.com && whoami"})


def test_render_command_substitutes_placeholders(tmp_path):
    ctx = build_context("https://example.com", out_dir=str(tmp_path))
    rendered = render_command("subfinder -d {domain} -o {out}/subs.txt", ctx)
    assert "example.com" in rendered
    assert str(tmp_path).replace("\\", "/") in rendered
    assert "{domain}" not in rendered


def test_plan_mode_exposes_full_playbook(tmp_path):
    mgr = ToolManager(output_dir=str(tmp_path / "tool_outputs"))
    agent = ReconMethodologyAgent(mgr)
    res = asyncio.run(agent.run(AgentTask(target="example.com", extra={"mode": "plan"})))

    assert res.success is True
    assert res.agent_name == "recon_methodology_agent"
    assert "Passive Subdomain Enumeration" in res.raw_output["methodology_text"]
    assert "executable_summary" in res.raw_output
    assert res.findings and res.findings[0]["type"] == "recon_methodology"


def test_inventory_mode_lists_commands(tmp_path):
    mgr = ToolManager(output_dir=str(tmp_path / "tool_outputs"))
    agent = ReconMethodologyAgent(mgr)
    res = asyncio.run(agent.run(AgentTask(target="example.com", extra={"mode": "inventory"})))

    assert res.success is True
    assert "subfinder -d example.com" in res.raw_output["commands"]
    assert res.findings[0]["type"] == "recon_methodology_inventory"


def test_dry_run_renders_without_executing(tmp_path):
    fake = _FakeManager(available=True)
    agent = ReconMethodologyAgent(fake)
    res = asyncio.run(
        agent.run(
            AgentTask(
                target="example.com",
                extra={
                    "mode": "dry_run",
                    "stages": ["merge"],
                    "max_risk": "safe",
                    "out_dir": str(tmp_path),
                },
            )
        )
    )

    assert res.success is True
    assert fake.calls == []
    assert "anew_subs" in res.raw_output
    assert "anew" in res.raw_output["anew_subs"]
    summary = json.loads(res.raw_output["execution_summary"])
    assert summary["executed"]


def test_run_requires_authorization(tmp_path):
    fake = _FakeManager(available=True)
    agent = ReconMethodologyAgent(fake)
    res = asyncio.run(
        agent.run(
            AgentTask(
                target="example.com",
                extra={"mode": "run", "stages": ["merge"], "out_dir": str(tmp_path)},
            )
        )
    )

    assert res.success is False
    assert any("authorized=True" in e for e in res.errors)
    assert fake.calls == []


def test_run_skips_missing_tools(tmp_path):
    fake = _FakeManager(available=False)
    agent = ReconMethodologyAgent(fake)
    res = asyncio.run(
        agent.run(
            AgentTask(
                target="example.com",
                extra={
                    "mode": "run",
                    "authorized": True,
                    "stages": ["merge"],
                    "max_risk": "safe",
                    "out_dir": str(tmp_path),
                },
            )
        )
    )

    assert res.success is True
    summary = json.loads(res.raw_output["execution_summary"])
    assert "anew" in summary["missing_tools"]
    assert summary["executed"] == []
    assert fake.calls == []


def test_run_executes_through_manager_when_authorized(tmp_path):
    fake = _FakeManager(available=True, output="sub.example.com\n")
    agent = ReconMethodologyAgent(fake)
    res = asyncio.run(
        agent.run(
            AgentTask(
                target="example.com",
                extra={
                    "mode": "run",
                    "authorized": True,
                    "stages": ["merge"],
                    "max_risk": "safe",
                    "out_dir": str(tmp_path),
                },
            )
        )
    )

    assert res.success is True
    assert fake.calls
    summary = json.loads(res.raw_output["execution_summary"])
    assert summary["executed"]
    assert any(f["type"] == "subdomains" for f in res.findings)


def test_recon_agent_delegates_methodology_mode(tmp_path):
    fake = _FakeManager(available=True)
    agent = ReconAgent(fake)
    res = asyncio.run(agent.run(AgentTask(target="example.com", mode="methodology")))

    assert res.agent_name == "recon_methodology_agent"
    assert res.success is True
    assert "methodology_text" in res.raw_output

    direct = asyncio.run(
        agent.run_methodology(AgentTask(target="example.com", extra={"mode": "inventory"}))
    )
    assert direct.agent_name == "recon_methodology_agent"
    assert direct.success is True


def test_registry_includes_methodology_agent():
    registry = AgentRegistry()
    descriptor = registry.get_agent("ReconMethodologyAgent")
    assert descriptor is not None
    assert descriptor.is_active is True
