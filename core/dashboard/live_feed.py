"""
HunterAI Control Center — Live Feed & Operations Telemetry Engine
=================================================================
Unified thread-safe operations backend for:
- Live Findings Stream & Burp Issue Export
- Scope & Target Management (wrapping StrictScopeEngine & ScopeEnforcer)
- Emergency Controls & Evidence Bundle Export
- MCP Server Monitor (reading opencode.json dynamically)
- System Health Metrics (60s rolling history & threshold alerts via psutil)
- Evidence Court Visualizer
- Interactive Operator Terminal Console
"""
from __future__ import annotations

from collections import deque
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import re
import shlex
import shutil
import threading
import time
import types
from typing import Any, Callable, Deque, Dict, List, Optional
from urllib.parse import urlparse
import uuid

import psutil

from core.dashboard.agent_manager import AgentManager, get_agent_manager

logger = logging.getLogger("hunter_ai.dashboard.live_feed")

SEVERITY_MAP: Dict[str, str] = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
    "informational": "Info",
}

DEFAULT_FIREWALL_RULES: List[str] = [
    "Block loopback interfaces (127.0.0.0/8, ::1, localhost)",
    "Block RFC1918 private subnets (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)",
    "Block cloud metadata endpoints (169.254.169.254, metadata.google.internal)",
    "Block destructive paths (/logout, /delete-account, /reset-db)",
    "Block outbound mail relay ports (25, 465, 587)",
]

TERMINAL_COMMANDS: List[str] = [
    "help",
    "status",
    "scan --target ",
    "agent start ",
    "agent pause ",
    "agent stop ",
    "agent restart ",
    "scope list",
    "scope add ",
    "scope remove ",
    "scope lock",
    "scope unlock",
    "mcp status",
    "mcp retry",
    "court status",
    "clear",
    "emergency stop",
]

_ENV_REF_PATTERN = re.compile(r"\{env:([A-Za-z0-9_]+)\}")
_ONE_GIB_BYTES = 1024 ** 3


def _utc_iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def _hhmmss(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%H:%M:%S")


def _normalize_severity(raw: Any) -> str:
    val = raw.value if hasattr(raw, "value") else raw
    key = str(val or "Medium").strip().lower()
    return SEVERITY_MAP.get(key, "Medium")


def _normalize_verdict(raw: Any) -> str:
    val = raw.value if hasattr(raw, "value") else raw
    return str(val or "UNVERIFIED").strip().upper()


class _ClassOrInstanceMethod:
    """Descriptor binding calls on the class to ``get_live_feed_manager()``."""

    def __init__(self, func: Callable[..., Any]) -> None:
        self.func = func
        self.__name__ = func.__name__
        self.__doc__ = func.__doc__

    def __get__(self, instance: Optional["LiveFeedManager"], owner: Any = None) -> Callable[..., Any]:
        target = instance if instance is not None else get_live_feed_manager()
        return types.MethodType(self.func, target)


class LiveFeedManager:
    """Thread-safe telemetry, findings, scope, MCP, court, and console engine."""

    def __init__(self, agent_manager: Optional[AgentManager] = None) -> None:
        self._lock = threading.RLock()
        self.agent_manager: AgentManager = (
            agent_manager if agent_manager is not None else get_agent_manager()
        )

        # Findings & Alerts
        self._findings: List[Dict[str, Any]] = []
        self._findings_by_id: Dict[str, Dict[str, Any]] = {}
        self._alerts: Deque[Dict[str, Any]] = deque(maxlen=50)
        self._burp_exporter: Any = None

        # Scope & Targets
        self._targets: List[str] = []
        self._active_target: str = ""
        self._excluded_domains: List[str] = []
        self._firewall_rules: List[str] = list(DEFAULT_FIREWALL_RULES)
        self._scope_locked: bool = False

        # MCP Monitor
        self._project_root: Path = Path(__file__).resolve().parents[2]
        self._opencode_path: Path = self._project_root / "opencode.json"
        self._mcp_overrides: Dict[str, Dict[str, Any]] = {}
        self._mcp_last_probe: Dict[str, float] = {}
        self._mcp_last_status: Dict[str, str] = {}

        # System Metrics (60s rolling window)
        self._metrics_history: Deque[Dict[str, Any]] = deque(maxlen=60)
        self._cpu_high_since: Optional[float] = None
        self._last_disk_io: Any = None
        self._last_net_io: Any = None
        self._last_io_ts: Optional[float] = None
        try:
            psutil.cpu_percent(interval=None)
        except Exception:
            pass

        # Evidence Court Visualizer
        self._court_claims: Dict[str, str] = {}
        self._court_confirmed_timestamps: Deque[float] = deque(maxlen=2000)
        self._court_rejected: int = 0
        self._court_feed: Deque[Dict[str, Any]] = deque(maxlen=100)

        # Interactive Terminal Console
        self._terminal_history: Deque[str] = deque(maxlen=200)
        self._terminal_output: Deque[Dict[str, Any]] = deque(maxlen=500)
        self._append_terminal_entry(
            command="",
            output="[System] HunterAI Control Center terminal ready. Type 'help' for commands.",
            ok=True,
        )

    # ── Findings & Burp Export ────────────────────────────────────────────────

    @_ClassOrInstanceMethod
    def add_finding(self, finding: Any) -> Dict[str, Any]:
        """Register or update a finding and emit a live operator alert."""
        if hasattr(finding, "to_dict") and callable(finding.to_dict):
            raw = dict(finding.to_dict())
        elif isinstance(finding, dict):
            raw = dict(finding)
        else:
            raw = {}

        now = float(raw.get("timestamp") or time.time())
        finding_id = str(
            raw.get("id")
            or raw.get("finding_id")
            or f"FND-{uuid.uuid4().hex[:8].upper()}"
        )
        verdict = _normalize_verdict(raw.get("verdict") or raw.get("lifecycle_verdict"))
        severity = _normalize_severity(raw.get("severity"))
        title = str(raw.get("title") or raw.get("type") or "Security Finding")
        source_agent = str(
            raw.get("source_agent") or raw.get("source") or raw.get("tool") or "Brain"
        )
        target = str(raw.get("target") or "")
        endpoint = str(
            raw.get("endpoint") or raw.get("url") or raw.get("target_url") or target
        )
        evidence = str(
            raw.get("evidence") or raw.get("rationale") or raw.get("detail") or ""
        )
        false_positive = bool(raw.get("false_positive", verdict == "FALSE_POSITIVE"))

        normalized: Dict[str, Any] = {
            "id": finding_id,
            "title": title,
            "severity": severity,
            "source_agent": source_agent,
            "verdict": verdict,
            "target": target,
            "endpoint": endpoint,
            "evidence": evidence,
            "timestamp": now,
            "timestamp_iso": str(raw.get("timestamp_iso") or _utc_iso(now)),
            "exported_to_burp": bool(raw.get("exported_to_burp", False)),
            "false_positive": false_positive,
        }
        for extra_key in (
            "payload_used",
            "raw_request",
            "raw_response",
            "remediation",
            "cwe",
            "cvss",
            "confidence",
            "parameter",
            "false_positive_reason",
            "burp_export_path",
        ):
            if extra_key in raw and raw[extra_key] is not None:
                normalized[extra_key] = raw[extra_key]

        with self._lock:
            if finding_id in self._findings_by_id:
                existing = self._findings_by_id[finding_id]
                existing.update(normalized)
                stored = existing
            else:
                self._findings.append(normalized)
                self._findings_by_id[finding_id] = normalized
                stored = normalized

            self._alerts.append(
                {
                    "id": f"ALT-{uuid.uuid4().hex[:8].upper()}",
                    "finding_id": finding_id,
                    "title": title,
                    "severity": severity,
                    "source_agent": source_agent,
                    "verdict": verdict,
                    "message": f"[{severity}] {title} ({source_agent})",
                    "timestamp": now,
                    "timestamp_iso": normalized["timestamp_iso"],
                }
            )
            return dict(stored)

    @_ClassOrInstanceMethod
    def get_findings(self, limit: int = 50) -> Dict[str, Any]:
        """Return recent findings (newest first), total count, and alerts."""
        with self._lock:
            cap = max(0, int(limit)) if limit is not None else 50
            recent = list(reversed(self._findings))[:cap] if cap > 0 else []
            return {
                "findings": [dict(item) for item in recent],
                "total": len(self._findings),
                "alerts": [dict(a) for a in reversed(self._alerts)],
            }

    @_ClassOrInstanceMethod
    def get_finding_details(self, finding_id: str) -> Optional[Dict[str, Any]]:
        """Return full finding details by ID, or None if missing."""
        with self._lock:
            item = self._findings_by_id.get(str(finding_id))
            return dict(item) if item is not None else None

    def _get_burp_exporter(self) -> Any:
        if self._burp_exporter is None:
            from core.burp_gateway.issue_exporter import BurpIssueExporter

            export_dir = Path("data") / "exports" / "burp_issues"
            self._burp_exporter = BurpIssueExporter(output_dir=export_dir)
        return self._burp_exporter

    @_ClassOrInstanceMethod
    def export_finding_to_burp(self, finding_id: str) -> Dict[str, Any]:
        """Format and export a finding via BurpIssueExporter."""
        with self._lock:
            record = self._findings_by_id.get(str(finding_id))
            if record is None:
                return {
                    "ok": False,
                    "finding_id": finding_id,
                    "error": f"Finding '{finding_id}' not found",
                }
            payload = dict(record)
            payload["finding_id"] = record["id"]
            payload["lifecycle_verdict"] = record["verdict"]
            payload.setdefault("tool", record["source_agent"])

        try:
            exporter = self._get_burp_exporter()
            exported = exporter.export_finding(payload)
        except Exception as exc:
            logger.warning("Burp export failed for %s: %s", finding_id, exc)
            return {"ok": False, "finding_id": finding_id, "error": str(exc)}

        with self._lock:
            record["exported_to_burp"] = True
            if exported.get("export_path"):
                record["burp_export_path"] = exported["export_path"]
            return {
                "ok": True,
                "finding_id": record["id"],
                "exported": exported,
                "finding": dict(record),
            }

    @_ClassOrInstanceMethod
    def mark_false_positive(
        self,
        finding_id: str,
        reason: str = "Marked by operator",
    ) -> Dict[str, Any]:
        """Mark a finding as FALSE_POSITIVE and log an Evidence Court event."""
        with self._lock:
            record = self._findings_by_id.get(str(finding_id))
            if record is None:
                return {
                    "ok": False,
                    "finding_id": finding_id,
                    "error": f"Finding '{finding_id}' not found",
                }
            record["false_positive"] = True
            record["verdict"] = "FALSE_POSITIVE"
            record["false_positive_reason"] = reason
            summary = f"{record['title']} ({reason})"
            snapshot = dict(record)

        self.add_court_event(str(finding_id), summary, "FALSE_POSITIVE")
        return {
            "ok": True,
            "finding_id": str(finding_id),
            "verdict": "FALSE_POSITIVE",
            "false_positive": True,
            "reason": reason,
            "finding": snapshot,
        }

    # ── Scope & Target Management ─────────────────────────────────────────────

    @staticmethod
    def _clean_string_list(items: Optional[List[str]]) -> List[str]:
        seen = set()
        cleaned: List[str] = []
        for item in items or []:
            val = str(item).strip()
            if val and val not in seen:
                seen.add(val)
                cleaned.append(val)
        return cleaned

    def _get_scope_state_unlocked(self) -> Dict[str, Any]:
        return {
            "targets": list(self._targets),
            "active_target": self._active_target,
            "excluded_domains": list(self._excluded_domains),
            "firewall_rules": list(self._firewall_rules),
            "locked": self._scope_locked,
        }

    @_ClassOrInstanceMethod
    def get_scope_state(self) -> Dict[str, Any]:
        """Return current targets, active target, exclusions, rules, and lock state."""
        with self._lock:
            return self._get_scope_state_unlocked()

    @_ClassOrInstanceMethod
    def update_scope(
        self,
        targets: Optional[List[str]] = None,
        excluded_domains: Optional[List[str]] = None,
        firewall_rules: Optional[List[str]] = None,
        active_target: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Update scope definition unless locked."""
        with self._lock:
            if self._scope_locked:
                return {
                    "ok": False,
                    "locked": True,
                    "error": "Scope is locked. Unlock scope before modifying targets or rules.",
                    **self._get_scope_state_unlocked(),
                }

            if targets is not None:
                self._targets = self._clean_string_list(targets)
                if active_target is None:
                    if self._active_target not in self._targets:
                        self._active_target = self._targets[0] if self._targets else ""
            if excluded_domains is not None:
                self._excluded_domains = self._clean_string_list(excluded_domains)
            if firewall_rules is not None:
                self._firewall_rules = self._clean_string_list(firewall_rules)
            if active_target is not None:
                clean_active = str(active_target).strip()
                self._active_target = clean_active
                if clean_active and clean_active not in self._targets and targets is None:
                    self._targets.append(clean_active)

            return {"ok": True, **self._get_scope_state_unlocked()}

    @_ClassOrInstanceMethod
    def add_target(self, url: str) -> Dict[str, Any]:
        """Add an authorized target URL/domain unless scope is locked."""
        with self._lock:
            if self._scope_locked:
                return {
                    "ok": False,
                    "locked": True,
                    "error": "Scope is locked. Unlock scope before adding targets.",
                    **self._get_scope_state_unlocked(),
                }
            clean_url = str(url or "").strip()
            if not clean_url:
                return {"ok": False, "error": "Target URL cannot be empty"}
            if clean_url not in self._targets:
                self._targets.append(clean_url)
            if not self._active_target:
                self._active_target = clean_url
            return {"ok": True, "target": clean_url, **self._get_scope_state_unlocked()}

    @_ClassOrInstanceMethod
    def remove_target(self, url: str) -> Dict[str, Any]:
        """Remove a target URL/domain unless scope is locked."""
        with self._lock:
            if self._scope_locked:
                return {
                    "ok": False,
                    "locked": True,
                    "error": "Scope is locked. Unlock scope before removing targets.",
                    **self._get_scope_state_unlocked(),
                }
            clean_url = str(url or "").strip()
            removed = clean_url in self._targets
            self._targets = [t for t in self._targets if t != clean_url]
            if self._active_target == clean_url:
                self._active_target = self._targets[0] if self._targets else ""
            return {"ok": True, "removed": removed, **self._get_scope_state_unlocked()}

    @_ClassOrInstanceMethod
    def set_scope_locked(self, locked: bool) -> Dict[str, Any]:
        """Lock or unlock scope modifications."""
        with self._lock:
            self._scope_locked = bool(locked)
            return {"ok": True, **self._get_scope_state_unlocked()}

    @staticmethod
    def _extract_host_port_path(target: str) -> tuple[str, Optional[int], str]:
        clean = str(target or "").strip().lower()
        if clean.startswith("http://") or clean.startswith("https://"):
            parsed = urlparse(clean)
            host = parsed.hostname or clean
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            return host, port, parsed.path or ""
        host_part = clean.split("/")[0]
        path = "/" + clean.split("/", 1)[1] if "/" in clean else ""
        port: Optional[int] = None
        if host_part.startswith("["):
            end = host_part.find("]")
            if end != -1:
                host = host_part[1:end]
                rest = host_part[end + 1 :]
                if rest.startswith(":") and rest[1:].isdigit():
                    port = int(rest[1:])
            else:
                host = host_part
        elif host_part.count(":") == 1:
            host, port_str = host_part.split(":", 1)
            if port_str.isdigit():
                port = int(port_str)
        else:
            host = host_part
        return host, port, path

    @classmethod
    def _evaluate_compiled_scope(
        cls,
        engine: Any,
        target: str,
        allowed_list: List[str],
    ) -> tuple[bool, str]:
        import ipaddress
        from core.scope_engine import (
            HARD_BLOCKED_HOSTS,
            HARD_BLOCKED_IPV4_SUBNETS,
            HARD_BLOCKED_IPV6_SUBNETS,
            normalize_ip_literal,
        )

        if not target or not str(target).strip():
            return False, "Target is empty"

        host, port, path = cls._extract_host_port_path(target)
        if host in HARD_BLOCKED_HOSTS:
            return False, f"SECURITY INVARIANT: Host '{host}' is forbidden."

        ip_obj = normalize_ip_literal(host)
        if ip_obj is not None:
            if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped is not None:
                ip_obj = ip_obj.ipv4_mapped
            if isinstance(ip_obj, ipaddress.IPv4Address):
                for blk in HARD_BLOCKED_IPV4_SUBNETS:
                    if ip_obj in blk:
                        return False, f"SECURITY INVARIANT: IP {host} belongs to blocked subnet {blk}."
            elif isinstance(ip_obj, ipaddress.IPv6Address):
                for blk in HARD_BLOCKED_IPV6_SUBNETS:
                    if ip_obj in blk:
                        return False, f"SECURITY INVARIANT: IPv6 {host} belongs to blocked subnet {blk}."

        if port and port in engine.policy.excluded_ports:
            return False, f"SECURITY INVARIANT: Port {port} is in excluded ports policy."

        if path:
            low_path = path.lower()
            for exp in engine.policy.excluded_paths:
                if exp.lower() in low_path:
                    return False, f"Path '{path}' matches excluded path rule '{exp}'"

        try:
            ipv4 = ipaddress.IPv4Address(host)
            for net in engine.out_of_scope_subnets:
                if ipv4 in net:
                    return False, f"Target IP {host} matches Out-of-Scope subnet: {net}"
        except ValueError:
            pass

        for pat in engine.out_of_scope_patterns:
            if pat.search(host):
                return False, f"Target {host} matches Out-of-Scope domain pattern"

        if not allowed_list:
            return False, "Target is not covered by any in-scope rule (fail-closed policy)."

        try:
            ipv4 = ipaddress.IPv4Address(host)
            for net in engine.in_scope_subnets:
                if ipv4 in net:
                    return True, f"Target IP {host} matched In-Scope subnet: {net}"
        except ValueError:
            pass

        for pat in engine.in_scope_patterns:
            if pat.search(host):
                return True, f"Target {host} matched In-Scope domain rule"

        return False, f"Target '{host}' is outside authorized scope"

    @_ClassOrInstanceMethod
    def check_target_scope(
        self,
        target: str,
        scope: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Validate a target against StrictScopeEngine and ScopeEnforcer invariants."""
        from core.scope_enforcer import ScopeEnforcer
        from core.scope_engine import ScopePolicy, StrictScopeEngine
        from core.scope_guard import ScopeGuard
        from core.security_mode import unrestricted_mode

        with self._lock:
            allowed_list = (
                self._clean_string_list(scope)
                if scope is not None
                else list(self._targets)
            )
            excluded_list = list(self._excluded_domains)

        policy = ScopePolicy(
            allowed_targets=allowed_list,
            excluded_targets=excluded_list,
            fail_closed=True,
        )
        engine = StrictScopeEngine(policy)

        if unrestricted_mode():
            allowed, reason = self._evaluate_compiled_scope(engine, target, allowed_list)
        else:
            allowed, reason = engine.is_allowed(target)
            if allowed:
                guard = ScopeGuard(in_scope=allowed_list, out_of_scope=excluded_list)
                enforcer = ScopeEnforcer(guard=guard, rate_limit_per_min=None)
                enf_ok, enf_reason = enforcer.enforce_target(target)
                if not enf_ok:
                    allowed = False
                    reason = enf_reason

        return {
            "ok": True,
            "target": target,
            "allowed": bool(allowed),
            "in_scope": bool(allowed),
            "reason": reason,
            "scope": allowed_list,
            "excluded_domains": excluded_list,
        }

    # ── Emergency Controls ────────────────────────────────────────────────────

    @_ClassOrInstanceMethod
    def emergency_stop_all(self) -> Dict[str, Any]:
        """Immediately stop all agents via AgentManager and log to console."""
        agent_res = self.agent_manager.emergency_stop_all()
        with self._lock:
            self._append_terminal_entry(
                command="emergency stop",
                output="[EMERGENCY] All agents stopped immediately by operator.",
                ok=True,
            )
        return {"ok": True, "emergency_stopped": True, "agents": agent_res}

    @_ClassOrInstanceMethod
    def pause_all_scans(self) -> Dict[str, Any]:
        """Pause all running agents via AgentManager."""
        agent_res = self.agent_manager.pause_all()
        with self._lock:
            self._append_terminal_entry(
                command="pause-all",
                output="[Control] All active scans paused.",
                ok=True,
            )
        return {"ok": True, "paused_all": True, "agents": agent_res}

    @_ClassOrInstanceMethod
    def clear_all_data(self) -> Dict[str, Any]:
        """Clear collected findings, alerts, court telemetry, metrics, and console logs."""
        with self._lock:
            self._findings.clear()
            self._findings_by_id.clear()
            self._alerts.clear()
            self._court_claims.clear()
            self._court_confirmed_timestamps.clear()
            self._court_rejected = 0
            self._court_feed.clear()
            self._metrics_history.clear()
            self._cpu_high_since = None
            self._terminal_output.clear()
            now = time.time()
            return {"ok": True, "cleared": True, "timestamp": now}

    @_ClassOrInstanceMethod
    def export_all_evidence(self) -> Dict[str, Any]:
        """Export a timestamped JSON evidence bundle under data/exports."""
        export_dir = Path("data") / "exports"
        export_dir.mkdir(parents=True, exist_ok=True)
        now = time.time()
        filename = f"evidence_bundle_{int(now)}_{uuid.uuid4().hex[:6]}.json"
        export_path = export_dir / filename

        with self._lock:
            findings_copy = [dict(f) for f in self._findings]
            scope_copy = self._get_scope_state_unlocked()

        bundle = {
            "exported_at": _utc_iso(now),
            "timestamp": now,
            "scope": scope_copy,
            "agents": self.agent_manager.get_all_status(),
            "findings": findings_copy,
            "court": self.get_court_status(),
            "mcp": self.get_mcp_status(),
            "metrics": self.sample_metrics(),
        }
        export_path.write_text(
            json.dumps(bundle, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8",
        )
        return {
            "ok": True,
            "export_path": str(export_path),
            "filename": filename,
            "findings_count": len(findings_copy),
            "bundle": bundle,
        }

    # ── MCP Server Monitor ────────────────────────────────────────────────────

    def _load_opencode_mcp_config(self) -> Dict[str, Dict[str, Any]]:
        if not self._opencode_path.exists():
            return {}
        try:
            raw = json.loads(self._opencode_path.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.warning("Failed to parse %s: %s", self._opencode_path, exc)
            return {}
        mcp_cfg = raw.get("mcp", {})
        if not isinstance(mcp_cfg, dict):
            return {}
        merged: Dict[str, Dict[str, Any]] = {}
        for server_id, cfg in mcp_cfg.items():
            entry = dict(cfg) if isinstance(cfg, dict) else {}
            if server_id in self._mcp_overrides:
                entry.update(self._mcp_overrides[server_id])
            merged[server_id] = entry
        for server_id, override in self._mcp_overrides.items():
            if server_id not in merged:
                merged[server_id] = dict(override)
        return merged

    def _probe_mcp_server(self, server_id: str, cfg: Dict[str, Any], now: float) -> Dict[str, Any]:
        srv_type = str(cfg.get("type", "local")).strip().lower()
        enabled = bool(cfg.get("enabled", True))
        raw_cmd = cfg.get("command")
        raw_url = cfg.get("url")

        if srv_type == "remote":
            command_or_url = str(raw_url or "")
        elif isinstance(raw_cmd, list):
            command_or_url = " ".join(str(part) for part in raw_cmd)
        else:
            command_or_url = str(raw_cmd or "")

        status = "disabled"
        error: Optional[str] = None

        if enabled:
            if srv_type == "remote":
                parsed = urlparse(command_or_url)
                if parsed.scheme in ("http", "https") and parsed.netloc:
                    status = "connected"
                else:
                    status = "failed"
                    error = f"Invalid remote MCP URL: {command_or_url!r}"
            else:
                cmd_parts = (
                    [str(x) for x in raw_cmd]
                    if isinstance(raw_cmd, list)
                    else shlex.split(command_or_url) if command_or_url else []
                )
                error = self._validate_local_mcp_command(cmd_parts, cfg.get("environment"))
                status = "failed" if error else "connected"

        self._mcp_last_probe[server_id] = now
        self._mcp_last_status[server_id] = status
        return {
            "id": server_id,
            "name": str(cfg.get("name") or server_id),
            "type": srv_type,
            "status": status,
            "enabled": enabled,
            "error": error,
            "command_or_url": command_or_url,
            "timeout": cfg.get("timeout"),
            "last_checked": now,
            "last_checked_iso": _utc_iso(now),
        }

    def _validate_local_mcp_command(
        self,
        cmd_parts: List[str],
        env_map: Any,
    ) -> Optional[str]:
        if not cmd_parts:
            return "Missing local MCP command"

        exe = cmd_parts[0]
        resolved = shutil.which(exe)
        if resolved is None and exe in ("python", "python3"):
            alt = "python3" if exe == "python" else "python"
            resolved = shutil.which(alt)
        if resolved is None:
            return f"Executable '{exe}' not found in PATH"

        if exe.lower() in ("cmd", "cmd.exe") and len(cmd_parts) >= 3 and cmd_parts[1].lower() == "/c":
            wrapped_exe = cmd_parts[2]
            if shutil.which(wrapped_exe) is None:
                return f"Executable '{wrapped_exe}' not found in PATH"

        if isinstance(env_map, dict):
            for env_val in env_map.values():
                for match in _ENV_REF_PATTERN.findall(str(env_val)):
                    if not os.environ.get(match):
                        return f"Missing required environment variable: {match}"
        return None

    @_ClassOrInstanceMethod
    def get_mcp_status(self) -> Dict[str, Any]:
        """Inspect opencode.json MCP entries rapidly (<50ms) without blocking."""
        with self._lock:
            now = time.time()
            configs = self._load_opencode_mcp_config()
            servers: List[Dict[str, Any]] = []
            counts = {"configured": 0, "connected": 0, "failed": 0, "disabled": 0}
            for server_id, cfg in configs.items():
                info = self._probe_mcp_server(server_id, cfg, now)
                servers.append(info)
                counts["configured"] += 1
                if info["status"] in counts:
                    counts[info["status"]] += 1

            return {**counts, "servers": servers}

    @_ClassOrInstanceMethod
    def retry_failed_mcp(self, server_id: Optional[str] = None) -> Dict[str, Any]:
        """Re-probe failed MCP servers (or a specific server_id)."""
        with self._lock:
            configs = self._load_opencode_mcp_config()
            if server_id is not None and server_id not in configs:
                return {"ok": False, "server_id": server_id, "error": f"Unknown MCP server: {server_id}"}

            now = time.time()
            retried: List[str] = []
            for sid, cfg in configs.items():
                if server_id is not None and sid != server_id:
                    continue
                prev_status = self._mcp_last_status.get(sid)
                probe = self._probe_mcp_server(sid, cfg, now)
                if server_id is not None or prev_status == "failed" or probe["status"] == "failed":
                    self._mcp_last_probe[sid] = now
                    retried.append(sid)

            status_snapshot = self.get_mcp_status()
            return {"ok": True, "retried": retried, **status_snapshot}

    @_ClassOrInstanceMethod
    def configure_mcp(
        self,
        server_id: str,
        enabled: Optional[bool] = None,
        timeout: Optional[int] = None,
        command_or_url: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Update runtime configuration overrides for an MCP server."""
        with self._lock:
            configs = self._load_opencode_mcp_config()
            if server_id not in configs:
                return {"ok": False, "server_id": server_id, "error": f"Unknown MCP server: {server_id}"}

            current = dict(configs[server_id])
            override = dict(self._mcp_overrides.get(server_id, {}))
            if enabled is not None:
                override["enabled"] = bool(enabled)
            if timeout is not None:
                override["timeout"] = int(timeout)
            if command_or_url is not None:
                val = str(command_or_url).strip()
                srv_type = str(current.get("type", "local")).strip().lower()
                if srv_type == "remote" or val.startswith(("http://", "https://")):
                    override["type"] = "remote"
                    override["url"] = val
                else:
                    override["type"] = "local"
                    override["command"] = shlex.split(val) if val else []

            self._mcp_overrides[server_id] = override
            status_snapshot = self.get_mcp_status()
            server_entry = next(
                (s for s in status_snapshot["servers"] if s["id"] == server_id),
                None,
            )
            return {"ok": True, "server": server_entry, **status_snapshot}

    # ── System Health Metrics ─────────────────────────────────────────────────

    def _compute_io_rates(self, now: float, disk_io: Any, net_io: Any) -> Dict[str, float]:
        disk_read_kb_s = 0.0
        disk_write_kb_s = 0.0
        net_sent_kb_s = 0.0
        net_recv_kb_s = 0.0

        if self._last_io_ts is not None:
            dt = max(now - self._last_io_ts, 0.1)
            if disk_io is not None and self._last_disk_io is not None:
                disk_read_kb_s = max(0.0, (disk_io.read_bytes - self._last_disk_io.read_bytes) / 1024.0 / dt)
                disk_write_kb_s = max(0.0, (disk_io.write_bytes - self._last_disk_io.write_bytes) / 1024.0 / dt)
            if net_io is not None and self._last_net_io is not None:
                net_sent_kb_s = max(0.0, (net_io.bytes_sent - self._last_net_io.bytes_sent) / 1024.0 / dt)
                net_recv_kb_s = max(0.0, (net_io.bytes_recv - self._last_net_io.bytes_recv) / 1024.0 / dt)

        self._last_io_ts = now
        self._last_disk_io = disk_io
        self._last_net_io = net_io
        return {
            "disk_read_kb_s": round(disk_read_kb_s, 2),
            "disk_write_kb_s": round(disk_write_kb_s, 2),
            "disk_io_mb_s": round((disk_read_kb_s + disk_write_kb_s) / 1024.0, 3),
            "net_sent_kb_s": round(net_sent_kb_s, 2),
            "net_recv_kb_s": round(net_recv_kb_s, 2),
            "net_throughput_kb_s": round(net_sent_kb_s + net_recv_kb_s, 2),
        }

    @_ClassOrInstanceMethod
    def sample_metrics(self) -> Dict[str, Any]:
        """Collect system CPU, RAM, Disk, and Network metrics and evaluate threshold alerts."""
        now = time.time()
        now_iso = _utc_iso(now)

        cpu_pct = float(psutil.cpu_percent(interval=None))
        vm = psutil.virtual_memory()
        ram_pct = float(vm.percent)
        ram_used_mb = round(vm.used / (1024.0 * 1024.0), 2)
        ram_total_mb = round(vm.total / (1024.0 * 1024.0), 2)

        disk = psutil.disk_usage(str(Path.cwd()))
        disk_pct = float(disk.percent)
        disk_free_bytes = int(disk.free)
        disk_free_gb = round(disk_free_bytes / _ONE_GIB_BYTES, 3)
        disk_total_gb = round(disk.total / _ONE_GIB_BYTES, 3)

        try:
            disk_io = psutil.disk_io_counters()
        except Exception:
            disk_io = None
        try:
            net_io = psutil.net_io_counters()
        except Exception:
            net_io = None

        with self._lock:
            io_rates = self._compute_io_rates(now, disk_io, net_io)

            alerts: List[str] = []
            if cpu_pct > 80.0:
                if self._cpu_high_since is None:
                    self._cpu_high_since = now
                if (now - self._cpu_high_since) >= 30.0:
                    alerts.append("🟡 CPU > 80% for 30s")
            else:
                self._cpu_high_since = None

            if ram_pct > 90.0:
                alerts.append("🔴 RAM > 90%")

            if disk_free_bytes < _ONE_GIB_BYTES:
                alerts.append("🟡 Disk < 1GB free")

            sample = {
                "timestamp": now,
                "timestamp_iso": now_iso,
                "cpu_percent": round(cpu_pct, 2),
                "ram_percent": round(ram_pct, 2),
                "ram_used_mb": ram_used_mb,
                "ram_total_mb": ram_total_mb,
                "disk_percent": round(disk_pct, 2),
                "disk_free_gb": disk_free_gb,
                "disk_total_gb": disk_total_gb,
                **io_rates,
            }
            self._metrics_history.append(sample)
            return {
                **sample,
                "alerts": alerts,
                "history": list(self._metrics_history),
            }

    @_ClassOrInstanceMethod
    def get_system_metrics(self) -> Dict[str, Any]:
        """Return live system metrics snapshot."""
        return self.sample_metrics()

    # ── Evidence Court Visualizer ─────────────────────────────────────────────

    @_ClassOrInstanceMethod
    def add_court_event(
        self,
        claim_id: str,
        summary: str,
        verdict: str,
    ) -> Dict[str, Any]:
        """Record an Evidence Court adjudication transition and update counters."""
        now = time.time()
        norm_verdict = _normalize_verdict(verdict)
        cid = str(claim_id or f"CLM-{uuid.uuid4().hex[:6].upper()}")

        with self._lock:
            prev_state = self._court_claims.get(cid)
            if norm_verdict in ("PENDING", "SUBMITTED", "QUEUED"):
                self._court_claims[cid] = "PENDING"
            elif norm_verdict in ("VERIFYING", "UNDER_VERIFICATION", "ADJUDICATING"):
                self._court_claims[cid] = "VERIFYING"
            elif norm_verdict == "CONFIRMED":
                self._court_claims[cid] = "CONFIRMED"
                if prev_state != "CONFIRMED":
                    self._court_confirmed_timestamps.append(now)
            elif norm_verdict in ("FALSE_POSITIVE", "DISPROVED", "REJECTED"):
                self._court_claims[cid] = "REJECTED"
                if prev_state != "REJECTED":
                    self._court_rejected += 1
            else:
                self._court_claims[cid] = norm_verdict

            entry = {
                "id": cid,
                "time": _hhmmss(now),
                "summary": str(summary),
                "verdict": norm_verdict,
            }
            self._court_feed.append(entry)
            return dict(entry)

    @_ClassOrInstanceMethod
    def get_court_status(self) -> Dict[str, Any]:
        """Return Evidence Court adjudication counters and live feed."""
        now = time.time()
        one_hour_ago = now - 3600.0
        with self._lock:
            while (
                self._court_confirmed_timestamps
                and self._court_confirmed_timestamps[0] < one_hour_ago
            ):
                self._court_confirmed_timestamps.popleft()

            pending = sum(1 for state in self._court_claims.values() if state == "PENDING")
            verifying = sum(1 for state in self._court_claims.values() if state == "VERIFYING")
            return {
                "pending_claims": pending,
                "under_verification": verifying,
                "confirmed_last_hour": len(self._court_confirmed_timestamps),
                "false_positives_rejected": self._court_rejected,
                "feed": list(self._court_feed)[-50:],
            }

    # ── Interactive Terminal Console ──────────────────────────────────────────

    def _append_terminal_entry(self, command: str, output: str, ok: bool) -> None:
        now = time.time()
        self._terminal_output.append(
            {
                "timestamp": now,
                "time": _hhmmss(now),
                "command": command,
                "output": output,
                "ok": ok,
            }
        )

    def _get_terminal_state_unlocked(self) -> Dict[str, Any]:
        entries = list(self._terminal_output)
        lines: List[str] = []
        for item in entries:
            if item["command"]:
                lines.append(f"hunterai> {item['command']}")
            if item["output"]:
                lines.append(item["output"])
        return {
            "prompt": "hunterai>",
            "output": entries,
            "text": "\n".join(lines),
            "history": list(self._terminal_history),
            "commands": list(TERMINAL_COMMANDS),
        }

    @_ClassOrInstanceMethod
    def get_terminal_state(self) -> Dict[str, Any]:
        """Return terminal history, output buffer, and autocomplete commands."""
        with self._lock:
            return self._get_terminal_state_unlocked()

    @_ClassOrInstanceMethod
    def execute_command(self, command: str) -> Dict[str, Any]:
        """Parse and execute a Control Center console command."""
        raw_cmd = str(command or "").strip()
        now = time.time()
        if not raw_cmd:
            with self._lock:
                return {
                    "ok": True,
                    "command": "",
                    "output": "",
                    "lines": [],
                    "cleared": False,
                    "timestamp": now,
                    "state": self._get_terminal_state_unlocked(),
                }

        with self._lock:
            if not self._terminal_history or self._terminal_history[-1] != raw_cmd:
                self._terminal_history.append(raw_cmd)

        try:
            tokens = shlex.split(raw_cmd)
        except ValueError:
            tokens = raw_cmd.split()

        cmd = tokens[0].lower()
        args = tokens[1:]
        ok = True
        cleared = False
        lines: List[str] = []

        if cmd == "help":
            lines = [
                "Available commands:",
                "  help                                      Show this command reference",
                "  status                                    Show agents, scope, MCP, and court status",
                "  scan --target <url> [--mode full|recon|quick]  Launch scan within authorized scope",
                "  agent <start|pause|stop|restart> <id>     Control brain, browser, burp, code_intel",
                "  scope <list|add|remove|lock|unlock> [arg] Manage authorized scope & lock",
                "  mcp <status|retry>                        Inspect or retry MCP servers",
                "  court status                              Show Evidence Court counters & feed",
                "  clear                                     Clear terminal output",
                "  emergency stop                            Trigger EMERGENCY STOP ALL",
            ]
        elif cmd == "clear":
            with self._lock:
                self._terminal_output.clear()
                cleared = True
                return {
                    "ok": True,
                    "command": raw_cmd,
                    "output": "",
                    "lines": [],
                    "cleared": True,
                    "timestamp": now,
                    "state": self._get_terminal_state_unlocked(),
                }
        elif cmd == "status":
            agent_snap = self.agent_manager.get_all_status()
            scope_snap = self.get_scope_state()
            mcp_snap = self.get_mcp_status()
            court_snap = self.get_court_status()
            lines = [
                f"[Agents] total={agent_snap['summary']['total']} running={agent_snap['summary']['running']} "
                f"idle={agent_snap['summary']['idle']} stopped={agent_snap['summary']['stopped']} "
                f"emergency_stopped={agent_snap['emergency_stopped']}",
                f"[Scope] active={scope_snap['active_target'] or 'None'} targets={len(scope_snap['targets'])} "
                f"locked={scope_snap['locked']}",
                f"[MCP] configured={mcp_snap['configured']} connected={mcp_snap['connected']} "
                f"failed={mcp_snap['failed']} disabled={mcp_snap['disabled']}",
                f"[Court] pending={court_snap['pending_claims']} verifying={court_snap['under_verification']} "
                f"confirmed_1h={court_snap['confirmed_last_hour']} rejected={court_snap['false_positives_rejected']}",
            ]
        elif cmd == "emergency" and args and args[0].lower() == "stop":
            self.emergency_stop_all()
            return {
                "ok": True,
                "command": raw_cmd,
                "output": "[EMERGENCY] ALL AGENTS STOPPED",
                "lines": ["[EMERGENCY] ALL AGENTS STOPPED"],
                "cleared": False,
                "timestamp": now,
                "state": self.get_terminal_state(),
            }
        elif cmd == "scan":
            ok, lines = self._handle_scan_command(args)
        elif cmd == "agent":
            ok, lines = self._handle_agent_command(args)
        elif cmd == "scope":
            ok, lines = self._handle_scope_command(args)
        elif cmd == "mcp":
            ok, lines = self._handle_mcp_command(args)
        elif cmd == "court":
            ok, lines = self._handle_court_command(args)
        else:
            ok = False
            lines = [f"[Error] Unknown command: '{raw_cmd}'. Type 'help' for commands."]

        output_text = "\n".join(lines)
        with self._lock:
            self._append_terminal_entry(command=raw_cmd, output=output_text, ok=ok)
            state = self._get_terminal_state_unlocked()

        return {
            "ok": ok,
            "command": raw_cmd,
            "output": output_text,
            "lines": lines,
            "cleared": cleared,
            "timestamp": now,
            "state": state,
        }

    def _handle_scan_command(self, args: List[str]) -> tuple[bool, List[str]]:
        target = ""
        mode = "full"
        i = 0
        while i < len(args):
            tok = args[i]
            if tok == "--target" and i + 1 < len(args):
                target = args[i + 1].strip()
                i += 2
            elif tok.startswith("--target="):
                target = tok.split("=", 1)[1].strip()
                i += 1
            elif tok == "--mode" and i + 1 < len(args):
                mode = args[i + 1].strip().lower()
                i += 2
            elif tok.startswith("--mode="):
                mode = tok.split("=", 1)[1].strip().lower()
                i += 1
            else:
                i += 1

        if not target:
            return False, ["[Error] Usage: scan --target <url> [--mode full|recon|quick]"]
        if mode not in ("full", "recon", "quick"):
            return False, [f"[Error] Invalid scan mode '{mode}'. Expected full, recon, or quick."]

        with self._lock:
            has_targets = bool(self._targets)
            locked = self._scope_locked

        scope_to_check = None if has_targets else [target]
        scope_res = self.check_target_scope(target, scope=scope_to_check)
        if not scope_res["allowed"]:
            return False, [f"[Scope BLOCKED] {scope_res['reason']}"]

        if not has_targets:
            if locked:
                return False, ["[Scope BLOCKED] Scope is locked with no targets configured."]
            self.add_target(target)
        else:
            if not locked:
                self.update_scope(active_target=target)

        res = self.agent_manager.start_agent("brain", target=target, task=f"Scan ({mode}) -> {target}")
        if not res.get("ok"):
            return False, [f"[Error] {res.get('error', 'Failed to start Brain agent')}"]
        return True, [f"[Agent-Brain] Started {mode} scan on {target}"]

    def _handle_agent_command(self, args: List[str]) -> tuple[bool, List[str]]:
        if len(args) < 2:
            return False, ["[Error] Usage: agent <start|pause|stop|restart> <id>"]
        action = args[0].lower()
        agent_id = args[1]
        dispatch = {
            "start": self.agent_manager.start_agent,
            "pause": self.agent_manager.pause_agent,
            "stop": self.agent_manager.stop_agent,
            "restart": self.agent_manager.restart_agent,
        }
        fn = dispatch.get(action)
        if fn is None:
            return False, [f"[Error] Unsupported agent action '{action}'."]
        res = fn(agent_id)
        if not res.get("ok"):
            return False, [f"[Error] {res.get('error', 'Agent command failed')}"]
        agent = res["agent"]
        return True, [f"[Agent-{agent['name']}] {action} -> {agent['status_badge']} ({agent['current_task']})"]

    def _handle_scope_command(self, args: List[str]) -> tuple[bool, List[str]]:
        if not args:
            return False, ["[Error] Usage: scope <list|add|remove|lock|unlock> [arg]"]
        sub = args[0].lower()
        if sub == "list":
            st = self.get_scope_state()
            return True, [
                f"[Scope] Locked: {st['locked']} | Active: {st['active_target'] or 'None'}",
                f"[Scope] Targets ({len(st['targets'])}): {', '.join(st['targets']) or 'None'}",
                f"[Scope] Excluded ({len(st['excluded_domains'])}): {', '.join(st['excluded_domains']) or 'None'}",
            ]
        if sub == "add":
            if len(args) < 2:
                return False, ["[Error] Usage: scope add <url>"]
            res = self.add_target(args[1])
            if not res.get("ok"):
                return False, [f"[Scope] {res.get('error')}"]
            return True, [f"[Scope] Added target: {args[1]}"]
        if sub == "remove":
            if len(args) < 2:
                return False, ["[Error] Usage: scope remove <url>"]
            res = self.remove_target(args[1])
            if not res.get("ok"):
                return False, [f"[Scope] {res.get('error')}"]
            return True, [f"[Scope] Removed target: {args[1]}"]
        if sub == "lock":
            self.set_scope_locked(True)
            return True, ["[Scope] Scope LOCKED."]
        if sub == "unlock":
            self.set_scope_locked(False)
            return True, ["[Scope] Scope UNLOCKED."]
        return False, [f"[Error] Unknown scope subcommand '{sub}'."]

    def _handle_mcp_command(self, args: List[str]) -> tuple[bool, List[str]]:
        if not args:
            return False, ["[Error] Usage: mcp <status|retry> [server_id]"]
        sub = args[0].lower()
        if sub == "status":
            st = self.get_mcp_status()
            lines = [
                f"[MCP] configured={st['configured']} connected={st['connected']} "
                f"failed={st['failed']} disabled={st['disabled']}"
            ]
            for srv in st["servers"]:
                err_suffix = f" ({srv['error']})" if srv["error"] else ""
                lines.append(f"  - {srv['id']} [{srv['type']}]: {srv['status']}{err_suffix}")
            return True, lines
        if sub == "retry":
            srv_id = args[1] if len(args) > 1 else None
            res = self.retry_failed_mcp(server_id=srv_id)
            if not res.get("ok"):
                return False, [f"[MCP] {res.get('error')}"]
            return True, [f"[MCP] Retried: {', '.join(res['retried']) or 'none'} (failed={res['failed']})"]
        return False, [f"[Error] Unknown mcp subcommand '{sub}'."]

    def _handle_court_command(self, args: List[str]) -> tuple[bool, List[str]]:
        if not args or args[0].lower() != "status":
            return False, ["[Error] Usage: court status"]
        st = self.get_court_status()
        lines = [
            f"[Court] pending={st['pending_claims']} verifying={st['under_verification']} "
            f"confirmed_last_hour={st['confirmed_last_hour']} rejected={st['false_positives_rejected']}"
        ]
        for ev in st["feed"][-5:]:
            lines.append(f"  [{ev['time']}] Claim #{ev['id']}: {ev['summary']} -> {ev['verdict']}")
        return True, lines


_LIVE_FEED_SINGLETON: Optional[LiveFeedManager] = None
_LIVE_FEED_LOCK = threading.Lock()


def get_live_feed_manager(
    agent_manager: Optional[AgentManager] = None,
) -> LiveFeedManager:
    """Return the process-wide thread-safe LiveFeedManager singleton."""
    global _LIVE_FEED_SINGLETON
    if _LIVE_FEED_SINGLETON is None:
        with _LIVE_FEED_LOCK:
            if _LIVE_FEED_SINGLETON is None:
                _LIVE_FEED_SINGLETON = LiveFeedManager(agent_manager=agent_manager)
    elif agent_manager is not None:
        _LIVE_FEED_SINGLETON.agent_manager = agent_manager
    return _LIVE_FEED_SINGLETON
