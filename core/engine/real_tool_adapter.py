"""
HunterAI Real Tool Adapter Bridge
=================================
Provides discovery and sandboxed execution of external security binaries:
  - Subfinder (DNS enumeration)
  - Nmap / Masscan (Port scanning & service fingerprinting)
  - Katana / Httpx (Web crawling & live probing)
  - Nuclei (Vulnerability templates)
  - WhatWeb (Technology profiling)

Guarantees:
  1. Fail-Closed Availability: Missing binaries return UNAVAILABLE (exit_code=127,
     success=False, used_fallback=False) — never fabricated synthetic findings.
  2. Process-Tree Reaping: Timed-out or errored child processes are terminated
     via ``await kill_process_tree(proc)`` so no orphan workers leak.
  3. Structured Output Normalization: Parses tool CLI output into structured dicts.
"""
from __future__ import annotations

import asyncio
import concurrent.futures
import json
import logging
import os
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Coroutine, Dict, List, Optional, Tuple, TypeVar

from core.process_utils import kill_process_tree

logger = logging.getLogger("hunter_ai.tool_adapter")

_T = TypeVar("_T")

# Default command timeouts in seconds
TOOL_TIMEOUTS: Dict[str, float] = {
    "subfinder": 60.0,
    "nmap": 120.0,
    "masscan": 60.0,
    "httpx": 45.0,
    "katana": 90.0,
    "nuclei": 180.0,
    "whatweb": 30.0,
}


def _run_coro_sync(coro: Coroutine[Any, Any, _T]) -> _T:
    """Execute an async coroutine safely whether or not an event loop is already running."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result()


@dataclass
class ToolExecutionResult:
    tool_name: str
    target: str
    command: List[str]
    exit_code: int
    stdout: str
    stderr: str
    duration_secs: float
    used_fallback: bool = False
    structured_data: Dict[str, Any] = field(default_factory=dict)
    status: str = ""

    def __post_init__(self) -> None:
        if not self.status:
            if self.exit_code == 0:
                self.status = "OK"
            elif self.exit_code == 127:
                self.status = "UNAVAILABLE"
            else:
                self.status = str(self.structured_data.get("status") or "ERROR")

    @property
    def success(self) -> bool:
        return self.exit_code == 0 and self.status not in ("UNAVAILABLE", "ERROR")


class RealToolAdapter:
    """Manages discovery, isolation, and invocation of external pentest binaries."""

    def __init__(self, tools_dir: Optional[Path] = None, force_fallback: bool = False):
        self.tools_dir = tools_dir
        self.force_fallback = force_fallback

    def resolve_binary(self, tool_name: str) -> str:
        """Resolves tool path defensively, prioritizing Kali toolkits and ~/go/bin."""
        t = tool_name.strip()
        if t in ("httpx", "httpx-toolkit"):
            if shutil.which("httpx-toolkit"):
                return "httpx-toolkit"
            go_httpx = Path.home() / "go" / "bin" / "httpx"
            if go_httpx.is_file() and os.access(go_httpx, os.X_OK):
                return str(go_httpx)
        go_bin = Path.home() / "go" / "bin" / t
        if go_bin.is_file() and os.access(go_bin, os.X_OK):
            return str(go_bin)
        return t

    def is_tool_available(self, tool_name: str) -> bool:
        """Checks if tool executable is found in PATH or configured directory."""
        if self.force_fallback:
            return False
        resolved = self.resolve_binary(tool_name)
        if self.tools_dir and (self.tools_dir / resolved).exists():
            return True
        return shutil.which(resolved) is not None or os.path.exists(resolved)

    def _unavailable_result(
        self,
        tool_name: str,
        target: str,
        duration: float,
        reason: str = "",
        extra_data: Optional[Dict[str, Any]] = None,
    ) -> ToolExecutionResult:
        msg = reason or f"Tool binary '{tool_name}' is not installed or unavailable."
        data: Dict[str, Any] = {
            "status": "UNAVAILABLE",
            "verified": False,
            "reason": msg,
        }
        if extra_data:
            data.update(extra_data)
        return ToolExecutionResult(
            tool_name=tool_name,
            target=target,
            command=[tool_name],
            exit_code=127,
            stdout="",
            stderr=msg,
            duration_secs=duration,
            used_fallback=False,
            status="UNAVAILABLE",
            structured_data=data,
        )

    def execute_subfinder(self, domain: str, timeout: Optional[float] = None) -> ToolExecutionResult:
        """Runs subfinder or returns honest UNAVAILABLE when binary is absent."""
        start = time.time()
        tool = "subfinder"
        t_limit = timeout or TOOL_TIMEOUTS.get(tool, 60.0)

        if not self.is_tool_available(tool):
            logger.info("[ToolAdapter] subfinder not found — returning UNAVAILABLE.")
            return self._unavailable_result(
                tool, domain, time.time() - start,
                reason="subfinder binary not installed",
                extra_data={"discovered_subdomains": []},
            )

        resolved_tool = self.resolve_binary(tool)
        cmd = [resolved_tool, "-d", domain, "-silent", "-all"]
        exit_code, stdout, stderr = self._run_subprocess(cmd, t_limit)
        duration = time.time() - start

        if exit_code == 127:
            return self._unavailable_result(
                tool, domain, duration,
                reason=stderr or "subfinder binary not installed",
                extra_data={"discovered_subdomains": []},
            )
        if exit_code != 0:
            return ToolExecutionResult(
                tool_name=tool,
                target=domain,
                command=cmd,
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr,
                duration_secs=duration,
                used_fallback=False,
                status="UNAVAILABLE" if "TimeoutExpired" in stderr else "ERROR",
                structured_data={
                    "status": "UNAVAILABLE" if "TimeoutExpired" in stderr else "ERROR",
                    "discovered_subdomains": [],
                    "error": stderr,
                },
            )

        subdomains = [line.strip() for line in stdout.splitlines() if line.strip()]
        return ToolExecutionResult(
            tool_name=tool,
            target=domain,
            command=cmd,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_secs=duration,
            used_fallback=False,
            status="OK",
            structured_data={"discovered_subdomains": list(set(subdomains))},
        )

    def execute_nmap_ports(
        self,
        host: str,
        ports: str = "80,443,8080,8443,3000,5000",
        timeout: Optional[float] = None,
    ) -> ToolExecutionResult:
        """Runs nmap port scan or returns honest UNAVAILABLE when binary is absent."""
        start = time.time()
        tool = "nmap"
        t_limit = timeout or TOOL_TIMEOUTS.get(tool, 120.0)

        if not self.is_tool_available(tool):
            logger.info("[ToolAdapter] nmap not found — returning UNAVAILABLE.")
            return self._unavailable_result(
                tool, host, time.time() - start,
                reason="nmap binary not installed",
                extra_data={"open_ports": []},
            )

        resolved_tool = self.resolve_binary(tool)
        cmd = [resolved_tool, "-sT", "-T4", "-Pn", "-p", ports, host]
        exit_code, stdout, stderr = self._run_subprocess(cmd, t_limit)
        duration = time.time() - start

        if exit_code == 127:
            return self._unavailable_result(
                tool, host, duration,
                reason=stderr or "nmap binary not installed",
                extra_data={"open_ports": []},
            )
        if exit_code != 0:
            return ToolExecutionResult(
                tool_name=tool,
                target=host,
                command=cmd,
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr,
                duration_secs=duration,
                used_fallback=False,
                status="UNAVAILABLE" if "TimeoutExpired" in stderr else "ERROR",
                structured_data={
                    "status": "UNAVAILABLE" if "TimeoutExpired" in stderr else "ERROR",
                    "open_ports": [],
                    "error": stderr,
                },
            )

        open_ports = []
        for line in stdout.splitlines():
            if "/tcp" in line and "open" in line:
                parts = line.split()
                if len(parts) >= 2 and "open" in parts[1]:
                    open_ports.append(parts[0].replace("/tcp", ""))

        return ToolExecutionResult(
            tool_name=tool,
            target=host,
            command=cmd,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_secs=duration,
            used_fallback=False,
            status="OK",
            structured_data={"open_ports": open_ports},
        )

    def execute_httpx_endpoints(self, urls: List[str], timeout: Optional[float] = None) -> ToolExecutionResult:
        """Runs httpx probe or returns honest UNAVAILABLE when binary is absent."""
        start = time.time()
        tool = "httpx"
        t_limit = timeout or TOOL_TIMEOUTS.get(tool, 45.0)
        target = urls[0] if urls else ""

        if not self.is_tool_available(tool):
            return self._unavailable_result(
                tool, target, time.time() - start,
                reason="httpx binary not installed",
                extra_data={"alive_endpoints": []},
            )

        resolved_tool = self.resolve_binary(tool)
        cmd = [resolved_tool, "-silent", "-status-code", "-title", "-tech-detect", "-json"]
        input_data = "\n".join(urls)
        exit_code, stdout, stderr = self._run_subprocess_with_input(cmd, input_data, t_limit)
        duration = time.time() - start

        if exit_code == 127:
            return self._unavailable_result(
                tool, target, duration,
                reason=stderr or "httpx binary not installed",
                extra_data={"alive_endpoints": []},
            )
        if exit_code != 0:
            return ToolExecutionResult(
                tool_name=tool,
                target=target,
                command=cmd,
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr,
                duration_secs=duration,
                used_fallback=False,
                status="UNAVAILABLE" if "TimeoutExpired" in stderr else "ERROR",
                structured_data={
                    "status": "UNAVAILABLE" if "TimeoutExpired" in stderr else "ERROR",
                    "alive_endpoints": [],
                    "error": stderr,
                },
            )

        alive_endpoints = []
        for line in stdout.splitlines():
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                alive_endpoints.append({
                    "url": data.get("url"),
                    "status_code": data.get("status_code"),
                    "title": data.get("title", ""),
                    "technologies": data.get("technologies", []),
                })
            except Exception:
                pass

        return ToolExecutionResult(
            tool_name=tool,
            target=target,
            command=cmd,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration_secs=duration,
            used_fallback=False,
            status="OK",
            structured_data={"alive_endpoints": alive_endpoints},
        )

    # ── Sandboxed Subprocess Helpers (async-native with awaited kill_process_tree(proc)) ──

    async def _run_subprocess_async(
        self,
        cmd: List[str],
        timeout: float,
        input_data: Optional[str] = None,
    ) -> Tuple[int, str, str]:
        """Run a command with strict timeout and properly ``await kill_process_tree(proc)``."""
        proc: Optional[asyncio.subprocess.Process] = None
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE if input_data is not None else None,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            payload = input_data.encode("utf-8") if input_data is not None else None
            stdout_b, stderr_b = await asyncio.wait_for(
                proc.communicate(input=payload),
                timeout=timeout,
            )
            return (
                proc.returncode if proc.returncode is not None else -1,
                stdout_b.decode("utf-8", errors="replace"),
                stderr_b.decode("utf-8", errors="replace"),
            )
        except FileNotFoundError:
            return 127, "", f"Binary not found: {cmd[0]}"
        except asyncio.TimeoutError:
            if proc is not None:
                await kill_process_tree(proc)
            logger.warning("[ToolAdapter] Tool %s timed out after %.1fs", cmd[0], timeout)
            return -1, "", f"TimeoutExpired: {timeout}s"
        except Exception as exc:
            if proc is not None:
                await kill_process_tree(proc)
            logger.error("[ToolAdapter] Subprocess error executing %s: %s", cmd, exc)
            return -1, "", str(exc)

    def _run_subprocess(self, cmd: List[str], timeout: float) -> Tuple[int, str, str]:
        """Runs a command with strict timeout and reaps the full process tree on expiration."""
        return _run_coro_sync(self._run_subprocess_async(cmd, timeout=timeout, input_data=None))

    def _run_subprocess_with_input(self, cmd: List[str], input_data: str, timeout: float) -> Tuple[int, str, str]:
        """Runs a command with stdin input and reaps the full process tree on expiration."""
        return _run_coro_sync(self._run_subprocess_async(cmd, timeout=timeout, input_data=input_data))

    # ── Legacy Fallback Method Names (strictly fail-closed UNAVAILABLE, zero synthetic data) ──

    def _fallback_subdomains(self, domain: str, duration: float) -> ToolExecutionResult:
        return self._unavailable_result(
            "subfinder", domain, duration,
            reason="subfinder unavailable; synthetic subdomain generation disabled",
            extra_data={"discovered_subdomains": []},
        )

    def _fallback_ports(self, host: str, ports_str: str, duration: float) -> ToolExecutionResult:
        return self._unavailable_result(
            "nmap", host, duration,
            reason="nmap unavailable; synthetic port generation disabled",
            extra_data={"open_ports": []},
        )

    def _fallback_httpx(self, urls: List[str], duration: float) -> ToolExecutionResult:
        return self._unavailable_result(
            "httpx", urls[0] if urls else "", duration,
            reason="httpx unavailable; synthetic endpoint generation disabled",
            extra_data={"alive_endpoints": []},
        )
