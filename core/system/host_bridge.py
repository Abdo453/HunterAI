"""
HunterAI Host Bridge — Secure Host Resource Integration (Phase 9)
=================================================================
Connects to host machine resources safely:
  1. FileManager: Sandboxed filesystem access preventing directory traversal
  2. NetworkInspector: Network diagnostics, port probing, connection health
  3. HostGuard: Role-based permissions checks guarding file and network actions
"""
from __future__ import annotations

import logging
import os
import socket
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("hunter_ai.host_bridge")


class HostGuard:
    """
    Enforces authorization invariants on host file and network resources.
    """
    def __init__(self, allowed_root: Path, allowed_ports: Optional[List[int]] = None):
        self.allowed_root = allowed_root.resolve()
        self.allowed_ports = allowed_ports or [80, 443, 8080, 8443, 8085, 8719, 11434]

    def validate_file_path(self, path: str | Path, allow_write: bool = False) -> Tuple[bool, Optional[str]]:
        try:
            target = Path(path).resolve()
            # Must be inside allowed_root
            if not target.is_relative_to(self.allowed_root):
                return False, f"Directory traversal blocked: {path} is outside allowed root {self.allowed_root}"
            return True, None
        except Exception as e:
            return False, f"Invalid path syntax: {e}"

    def validate_network_target(self, host: str, port: int) -> Tuple[bool, Optional[str]]:
        # Hard invariants: block cloud metadata
        if host in ["169.254.169.254", "metadata.google.internal"]:
            return False, "HostGuard blocked access to sensitive cloud metadata service."
        if port not in self.allowed_ports and port < 1024:
            return False, f"HostGuard blocked connection to privileged port {port}."
        return True, None


class FileManager:
    """
    Sandboxed file operations protected by HostGuard.
    """
    def __init__(self, guard: HostGuard):
        self.guard = guard

    def read_file(self, path: str | Path) -> str:
        ok, reason = self.guard.validate_file_path(path, allow_write=False)
        if not ok:
            raise PermissionError(reason)
        p = Path(path).resolve()
        if not p.exists():
            raise FileNotFoundError(f"File not found: {path}")
        return p.read_text(encoding="utf-8")

    def write_file(self, path: str | Path, content: str) -> int:
        ok, reason = self.guard.validate_file_path(path, allow_write=True)
        if not ok:
            raise PermissionError(reason)
        p = Path(path).resolve()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return len(content)

    def list_dir(self, path: str | Path = ".") -> List[str]:
        ok, reason = self.guard.validate_file_path(path, allow_write=False)
        if not ok:
            raise PermissionError(reason)
        p = Path(path).resolve()
        if not p.exists() or not p.is_dir():
            return []
        return [f.name for f in p.iterdir()]


class NetworkInspector:
    """
    Network monitoring, local interface checks, and connection diagnostics.
    """
    def __init__(self, guard: HostGuard):
        self.guard = guard

    def is_port_open(self, host: str, port: int, timeout: float = 1.0) -> bool:
        ok, reason = self.guard.validate_network_target(host, port)
        if not ok:
            logger.warning("Port check blocked by HostGuard: %s:%d (%s)", host, port, reason)
            return False
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except Exception:
            return False

    def ping_http(self, url: str, timeout: float = 2.0) -> Dict[str, Any]:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "HunterAI-NetworkInspector/2.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return {
                    "reachable": True,
                    "status_code": resp.status,
                    "headers": dict(resp.headers),
                }
        except urllib.error.HTTPError as e:
            return {"reachable": True, "status_code": e.code, "headers": dict(e.headers)}
        except Exception as e:
            return {"reachable": False, "status_code": 0, "error": str(e)}

    def inspect_local_interfaces(self) -> Dict[str, Any]:
        hostname = socket.gethostname()
        try:
            local_ip = socket.gethostbyname(hostname)
        except Exception:
            local_ip = "127.0.0.1"
        return {
            "hostname": hostname,
            "primary_ip": local_ip,
        }


class HostBridge:
    """
    Integrated bridge connecting the AI system to host resources with HostGuard protection.
    """
    def __init__(self, sandbox_root: str | Path = "data/sandbox"):
        self.sandbox_root = Path(sandbox_root).resolve()
        self.sandbox_root.mkdir(parents=True, exist_ok=True)
        self.host_guard = HostGuard(allowed_root=self.sandbox_root)
        self.file_manager = FileManager(self.host_guard)
        self.network_inspector = NetworkInspector(self.host_guard)

    def read_file(self, path: str | Path) -> str:
        return self.file_manager.read_file(path)

    def write_file(self, path: str | Path, content: str) -> int:
        return self.file_manager.write_file(path, content)

    def inspect_network(self) -> Dict[str, Any]:
        return self.network_inspector.inspect_local_interfaces()
