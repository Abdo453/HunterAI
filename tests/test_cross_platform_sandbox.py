"""Phase 4 Cross-Platform Sandbox (Windows + Linux LocalSandbox & Hardened DockerSandbox) Tests."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from core.sandbox import (
    BASE_WORKER_CAPABILITIES,
    FORBIDDEN_CAPABILITIES,
    DockerSandbox,
    LocalSandbox,
    parse_sandbox_report,
    validate_docker_mounts,
    worker_capabilities,
)

ROOT = Path(__file__).resolve().parents[1]


# ── 1. LocalSandbox Cross-Platform Behavior ──────────────────────────────────

def test_local_sandbox_env_scrubs_secrets_and_preserves_windows_vars(tmp_path: Path):
    sb = LocalSandbox(allowed_workdir=str(tmp_path))
    for var in ("SYSTEMROOT", "COMSPEC", "PATHEXT", "WINDIR", "USERPROFILE", "PATH"):
        assert var in sb._SAFE_ENV_VARS

    env = sb._build_env(
        {
            "SAFE_CUSTOM": "1",
            "OPENAI_API_KEY": "sk-secret-value",
            "DB_PASSWORD": "hidden",
            "AUTH_TOKEN": "tok-123",
        }
    )
    assert env["SAFE_CUSTOM"] == "1"
    assert "OPENAI_API_KEY" not in env
    assert "DB_PASSWORD" not in env
    assert "AUTH_TOKEN" not in env


def test_local_sandbox_rejects_cwd_escape(tmp_path: Path):
    sb = LocalSandbox(allowed_workdir=str(tmp_path / "jail"))
    with pytest.raises(PermissionError):
        sb._resolve_cwd(str(tmp_path))


@pytest.mark.asyncio
async def test_local_sandbox_runs_argv_and_truncates_output(tmp_path: Path):
    sb = LocalSandbox(allowed_workdir=str(tmp_path))
    res = await sb.run(
        [sys.executable, "-c", "print('A' * 500)"],
        timeout_s=10.0,
        max_output_bytes=120,
    )
    assert res.ok is True
    assert "truncated" in res.stdout


@pytest.mark.asyncio
async def test_local_sandbox_timeout_reaps_process_tree(tmp_path: Path):
    sb = LocalSandbox(allowed_workdir=str(tmp_path))
    res = await sb.run(
        [sys.executable, "-c", "import time; time.sleep(10)"],
        timeout_s=0.6,
    )
    assert res.ok is False
    assert res.error_category == "TIMEOUT"


# ── 2. DockerSandbox Security Invariants & Async Engagement Lifecycle ────────

def test_docker_sandbox_capability_and_network_invariants():
    caps = worker_capabilities(docker_net_admin=False)
    assert set(caps) == set(BASE_WORKER_CAPABILITIES)
    assert not (set(caps) & FORBIDDEN_CAPABILITIES)
    assert "NET_ADMIN" not in caps

    caps_net = worker_capabilities(docker_net_admin=True)
    assert "NET_ADMIN" in caps_net
    assert not (set(caps_net) & FORBIDDEN_CAPABILITIES)

    with pytest.raises(PermissionError):
        DockerSandbox(network_mode="host")
    with pytest.raises(PermissionError):
        DockerSandbox(network_mode="container:victim")

    sb = DockerSandbox(image="hunterai-worker:kali", network_mode="none", pids_limit=128)
    kwargs = sb.build_container_kwargs(command=["id"])
    assert kwargs["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in kwargs["security_opt"]
    assert kwargs["read_only"] is True
    assert kwargs["pids_limit"] == 128
    assert kwargs["network_mode"] == "none"


def test_docker_sandbox_rejects_escape_mounts_and_unallowed_images():
    for bad_mount in (
        {"/var/run/docker.sock": {"bind": "/var/run/docker.sock", "mode": "rw"}},
        {"//./pipe/docker_engine": {"bind": "/pipe", "mode": "rw"}},
        {"/": {"bind": "/host", "mode": "ro"}},
        {"/etc/shadow": {"bind": "/tmp/shadow", "mode": "ro"}},
        {"/proc/1": {"bind": "/tmp/p", "mode": "ro"}},
        {"/sys/fs/cgroup": {"bind": "/tmp/c", "mode": "ro"}},
    ):
        with pytest.raises(PermissionError):
            validate_docker_mounts(bad_mount)

    sb = DockerSandbox(image="evil/untrusted:latest", allowed_images=["hunterai-worker:kali"])
    with pytest.raises(PermissionError):
        sb.build_container_kwargs(command=["id"])

    # Empty allowlist fails closed
    sb_empty = DockerSandbox(image="hunterai-worker:kali", allowed_images=[])
    with pytest.raises(PermissionError):
        sb_empty.build_container_kwargs(command=["id"])


@pytest.mark.asyncio
async def test_docker_sandbox_async_engagement_lifecycle_and_probe():
    fake_container = MagicMock()
    fake_container.id = "ctr-abc123"
    fake_container.wait.return_value = {"StatusCode": 0}
    fake_container.logs.return_value = (
        json.dumps({"kind": "info", "body": {"ID": "daemon-1", "Plugins": {"Authorization": []}}}) + "\n"
        + json.dumps({"kind": "check", "id": "no-docker-sock", "group": "isolation", "result": "pass"}) + "\n"
        + json.dumps({"kind": "summary", "total": 1, "passed": 1, "failed": 0}) + "\n"
    ).encode("utf-8")
    fake_container.exec_run.return_value = SimpleNamespace(exit_code=0, output=(b"exec-ok\n", b""))

    fake_client = MagicMock()
    fake_client.containers.run.return_value = fake_container

    sb = DockerSandbox(
        image="hunterai-worker:kali",
        docker_client=fake_client,
        allowed_images=["hunterai-worker:kali"],
    )

    probe = await sb.probe_sandbox()
    assert probe.ok is True
    assert probe.daemon_id == "daemon-1"
    assert probe.passed == 1

    cid = await sb.start_engagement_container("eng-42")
    assert cid == "ctr-abc123"
    exec_res = await sb.exec_in_engagement("eng-42", ["echo", "hi"])
    assert exec_res.ok is True
    assert "exec-ok" in exec_res.stdout
    stopped = await sb.stop_engagement_container("eng-42")
    assert stopped is True


def test_parse_sandbox_report_fails_closed_on_malformed_or_failed_checks():
    with pytest.raises(ValueError):
        parse_sandbox_report("not json at all")

    bad_check = "\n".join([
        json.dumps({"kind": "info", "body": {"ID": "daemon-2"}}),
        json.dumps({"kind": "check", "id": "no-docker-sock", "group": "isolation", "result": "fail"}),
        json.dumps({"kind": "summary", "total": 1, "passed": 0}),
    ])
    report = parse_sandbox_report(bad_check)
    assert report.ok is False
    assert "isolation/no-docker-sock" in report.failed


# ── 3. ToolManager Windows .exe Lookup & Repaired Skills Hygiene ─────────────

def test_tool_manager_windows_go_bin_exe_resolution(tmp_path: Path, monkeypatch):
    from tools.tool_manager import ToolManager

    go_bin = tmp_path / "bin"
    go_bin.mkdir()
    fake_exe = go_bin / "subfinder.exe"
    fake_exe.write_bytes(b"MZ")

    monkeypatch.setenv("GOPATH", str(tmp_path))
    monkeypatch.setattr(sys, "platform", "win32")
    tm = ToolManager(output_dir=str(tmp_path / "out"))
    resolved = tm.resolve_binary("subfinder")
    assert Path(resolved).resolve() == fake_exe.resolve()


def test_repaired_skills_have_no_unix_only_hardcoded_paths():
    repaired_skills = [
        "skills/web/xss_hunter/skill.py",
        "skills/web/sqli_hunter/skill.py",
        "skills/web/idor_tester/skill.py",
        "skills/analysis/secrets_hunter/skill.py",
        "skills/recon/param_discover/skill.py",
        "skills/analysis/logic_flaw_hunter/skill.py",
        "skills/reporting/report_generator/skill.py",
        "skills/web3/web3_audit/skill.py",
        "skills/web/endpoint_discovery/skill.py",
        "skills/web/parameter_discovery/skill.py",
        "skills/recon/live_host_detection/skill.py",
        "skills/web/crawling/skill.py",
        "skills/analysis/ssh_audit/skill.py",
        "skills/analysis/tls_audit/skill.py",
    ]
    for rel in repaired_skills:
        src = (ROOT / rel).read_text(encoding="utf-8")
        assert '"/tmp' not in src, f"Hardcoded /tmp found in {rel}"
        assert "/dev/null" not in src, f"Hardcoded /dev/null found in {rel}"
        assert "/dev/stdout" not in src, f"Hardcoded /dev/stdout found in {rel}"
        assert "bash -c" not in src, f"Hardcoded bash -c found in {rel}"
        assert "shell=True" not in src, f"shell=True found in {rel}"
