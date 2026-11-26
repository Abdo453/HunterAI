"""
HunterAI Control Center — Agent Manager
=======================================
Thread-safe orchestration and lifecycle tracking for the four primary
Control Center agents (Brain, Browser, Burp, Code Intel).

Supports both singleton instance calls via ``get_agent_manager()`` and
class-level delegates such as ``AgentManager.get_all_status()``.
"""
from __future__ import annotations

import logging
import threading
import time
import types
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import psutil

logger = logging.getLogger("hunter_ai.dashboard.agent_manager")

VALID_STATUSES = ("running", "idle", "error", "stopped")

STATUS_BADGES: Dict[str, str] = {
    "running": "🟢 Running",
    "idle": "🟡 Idle",
    "error": "🔴 Error",
    "stopped": "⚫ Stopped",
}

DEFAULT_AGENTS: Tuple[Tuple[str, str, str], ...] = (
    ("brain", "Brain", "Autonomous OODA Orchestrator"),
    ("browser", "Browser", "Playwright DOM & Auth Explorer"),
    ("burp", "Burp", "Burp Suite Traffic & Issue Sensor"),
    ("code_intel", "Code Intel", "JS Bundle & Secret Intelligence"),
)

_AGENT_ID_ALIASES: Dict[str, str] = {
    "brain": "brain",
    "autonomous_brain": "brain",
    "browser": "browser",
    "browser_agent": "browser",
    "burp": "burp",
    "burp_agent": "burp",
    "code_intel": "code_intel",
    "code-intel": "code_intel",
    "codeintel": "code_intel",
    "code": "code_intel",
}


def _utc_iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def _normalize_status(status: str) -> str:
    norm = str(status or "idle").strip().lower()
    if norm in STATUS_BADGES:
        return norm
    if norm in ("paused", "standby", "waiting"):
        return "idle"
    if norm in ("active", "scanning", "working"):
        return "running"
    if norm in ("failed", "crashed"):
        return "error"
    if norm in ("halted", "killed", "offline"):
        return "stopped"
    raise ValueError(f"Unsupported agent status: {status!r}")


class _ClassOrInstanceMethod:
    """Descriptor allowing a method to be called on either an instance or the class.

    When accessed on the class (e.g. ``AgentManager.get_all_status()``), it binds
    automatically to the module singleton ``get_agent_manager()``.
    """

    def __init__(self, func: Callable[..., Any]) -> None:
        self.func = func
        self.__name__ = func.__name__
        self.__doc__ = func.__doc__

    def __get__(self, instance: Optional["AgentManager"], owner: Any = None) -> Callable[..., Any]:
        target = instance if instance is not None else get_agent_manager()
        return types.MethodType(self.func, target)


@dataclass
class _AgentRecord:
    id: str
    name: str
    role: str
    status: str = "idle"
    current_task: str = "Standby"
    cpu_percent: float = 0.0
    memory_mb: float = 0.0
    last_action_ts: float = 0.0
    last_action_iso: str = ""
    error: Optional[str] = None
    started_at: Optional[float] = None
    target: Optional[str] = None

    def to_dict(self, now: float) -> Dict[str, Any]:
        uptime_sec = (
            round(max(0.0, now - self.started_at), 2)
            if self.status == "running" and self.started_at is not None
            else 0.0
        )
        return {
            "id": self.id,
            "name": self.name,
            "role": self.role,
            "status": self.status,
            "status_badge": STATUS_BADGES.get(self.status, STATUS_BADGES["idle"]),
            "current_task": self.current_task,
            "cpu_percent": round(float(self.cpu_percent), 2),
            "memory_mb": round(float(self.memory_mb), 2),
            "last_action_ts": self.last_action_ts,
            "last_action_iso": self.last_action_iso,
            "error": self.error,
            "uptime_sec": uptime_sec,
            "target": self.target,
        }


class AgentManager:
    """Thread-safe lifecycle and telemetry manager for HunterAI core agents."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._brain: Any = None
        self._emergency_stopped: bool = False
        self._paused_all: bool = False
        self._tripped_kill_switch: bool = False

        try:
            self._process: Optional[psutil.Process] = psutil.Process()
            self._process.cpu_percent(interval=None)
        except Exception:
            self._process = None

        now = time.time()
        iso = _utc_iso(now)
        self._agents: Dict[str, _AgentRecord] = {
            agent_id: _AgentRecord(
                id=agent_id,
                name=name,
                role=role,
                status="idle",
                current_task="Standby",
                cpu_percent=0.0,
                memory_mb=0.0,
                last_action_ts=now,
                last_action_iso=iso,
            )
            for agent_id, name, role in DEFAULT_AGENTS
        }

    @staticmethod
    def _resolve_agent_id(agent_id: str) -> str:
        key = str(agent_id or "").strip().lower()
        return _AGENT_ID_ALIASES.get(key, key)

    def _sample_process_resources(self, status: str) -> Tuple[float, float]:
        """Collect non-blocking process CPU and RSS memory via psutil."""
        if status == "stopped" or self._process is None:
            return 0.0, 0.0
        try:
            mem_mb = round(self._process.memory_info().rss / (1024.0 * 1024.0), 2)
        except Exception:
            mem_mb = 0.0
        if status != "running":
            return 0.0, mem_mb
        try:
            cpu_pct = round(float(self._process.cpu_percent(interval=None)), 2)
        except Exception:
            cpu_pct = 0.0
        return max(0.0, cpu_pct), max(0.0, mem_mb)

    def _touch_agent(
        self,
        record: _AgentRecord,
        status: Optional[str] = None,
        task: Optional[str] = None,
        error: Optional[str] = None,
        clear_error: bool = False,
        now: Optional[float] = None,
    ) -> None:
        ts = now if now is not None else time.time()
        if status is not None:
            norm_status = _normalize_status(status)
            record.status = norm_status
            if norm_status == "running" and record.started_at is None:
                record.started_at = ts
            elif norm_status != "running":
                record.started_at = None
        if task is not None:
            record.current_task = str(task)
        if clear_error:
            record.error = None
        if error is not None:
            record.error = error
        cpu_pct, mem_mb = self._sample_process_resources(record.status)
        record.cpu_percent = cpu_pct
        record.memory_mb = mem_mb
        record.last_action_ts = ts
        record.last_action_iso = _utc_iso(ts)

    def _reset_kill_switch_if_tripped(self) -> None:
        if not self._tripped_kill_switch:
            return
        try:
            from core.safety.kill_switch import EmergencyKillSwitch

            EmergencyKillSwitch().reset()
            export_save = Path("data") / "exports" / "emergency_save.json"
            if export_save.exists():
                export_save.unlink()
        except Exception as exc:
            logger.debug("Could not reset EmergencyKillSwitch: %s", exc)
        finally:
            self._tripped_kill_switch = False

    def _notify_brain_stop(self) -> None:
        brain = self._brain
        if brain is None:
            return
        for method_name in ("emergency_stop", "abort", "stop", "cancel"):
            fn = getattr(brain, method_name, None)
            if callable(fn):
                try:
                    fn()
                except Exception as exc:
                    logger.debug("Brain %s hook warning: %s", method_name, exc)
                break

    def _snapshot_unlocked(self) -> Dict[str, Any]:
        now = time.time()
        agents_list: List[Dict[str, Any]] = []
        counts = {"total": 0, "running": 0, "idle": 0, "error": 0, "stopped": 0}
        for record in self._agents.values():
            cpu_pct, mem_mb = self._sample_process_resources(record.status)
            record.cpu_percent = cpu_pct
            record.memory_mb = mem_mb
            data = record.to_dict(now)
            agents_list.append(data)
            counts["total"] += 1
            if record.status in counts:
                counts[record.status] += 1
        return {
            "agents": agents_list,
            "summary": counts,
            "emergency_stopped": self._emergency_stopped,
            "paused_all": self._paused_all,
            "timestamp": now,
        }

    @_ClassOrInstanceMethod
    def get_all_status(self) -> Dict[str, Any]:
        """Return live telemetry, per-agent state, and summary counts."""
        with self._lock:
            return self._snapshot_unlocked()

    @_ClassOrInstanceMethod
    def get_agent(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """Return current state dictionary for a single agent, or None."""
        with self._lock:
            key = self._resolve_agent_id(agent_id)
            record = self._agents.get(key)
            if record is None:
                return None
            return record.to_dict(time.time())

    @_ClassOrInstanceMethod
    def start_agent(
        self,
        agent_id: str,
        target: Optional[str] = None,
        task: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Start or resume an agent on an optional target and task."""
        with self._lock:
            key = self._resolve_agent_id(agent_id)
            record = self._agents.get(key)
            if record is None:
                return {"ok": False, "agent_id": agent_id, "error": f"Unknown agent: {agent_id}"}

            self._emergency_stopped = False
            self._paused_all = False
            self._reset_kill_switch_if_tripped()

            if target is not None:
                record.target = str(target).strip() or None
            resolved_task = task or (f"Active on {record.target}" if record.target else "Running")
            now = time.time()
            record.started_at = now
            self._touch_agent(
                record,
                status="running",
                task=resolved_task,
                clear_error=True,
                now=now,
            )
            agent_dict = record.to_dict(now)
            return {
                "ok": True,
                "agent_id": key,
                "status": agent_dict["status"],
                "status_badge": agent_dict["status_badge"],
                "agent": agent_dict,
            }

    @_ClassOrInstanceMethod
    def pause_agent(self, agent_id: str) -> Dict[str, Any]:
        """Pause a running agent and transition it to idle."""
        with self._lock:
            key = self._resolve_agent_id(agent_id)
            record = self._agents.get(key)
            if record is None:
                return {"ok": False, "agent_id": agent_id, "error": f"Unknown agent: {agent_id}"}

            prev = record.current_task
            paused_task = (
                prev
                if prev.startswith("Paused") or prev in ("Standby", "Stopped")
                else f"Paused ({prev})"
            )
            now = time.time()
            self._touch_agent(record, status="idle", task=paused_task, now=now)
            agent_dict = record.to_dict(now)
            return {
                "ok": True,
                "agent_id": key,
                "status": agent_dict["status"],
                "status_badge": agent_dict["status_badge"],
                "agent": agent_dict,
            }

    @_ClassOrInstanceMethod
    def stop_agent(self, agent_id: str) -> Dict[str, Any]:
        """Stop an agent cleanly."""
        with self._lock:
            key = self._resolve_agent_id(agent_id)
            record = self._agents.get(key)
            if record is None:
                return {"ok": False, "agent_id": agent_id, "error": f"Unknown agent: {agent_id}"}

            now = time.time()
            self._touch_agent(record, status="stopped", task="Stopped", clear_error=True, now=now)
            if key == "brain":
                self._notify_brain_stop()
            agent_dict = record.to_dict(now)
            return {
                "ok": True,
                "agent_id": key,
                "status": agent_dict["status"],
                "status_badge": agent_dict["status_badge"],
                "agent": agent_dict,
            }

    @_ClassOrInstanceMethod
    def restart_agent(self, agent_id: str) -> Dict[str, Any]:
        """Restart an agent, resetting error state and uptime."""
        with self._lock:
            key = self._resolve_agent_id(agent_id)
            record = self._agents.get(key)
            if record is None:
                return {"ok": False, "agent_id": agent_id, "error": f"Unknown agent: {agent_id}"}

            self._emergency_stopped = False
            self._paused_all = False
            self._reset_kill_switch_if_tripped()

            record.started_at = None
            now = time.time()
            record.started_at = now
            task_msg = f"Restarted on {record.target}" if record.target else "Restarted & Running"
            self._touch_agent(record, status="running", task=task_msg, clear_error=True, now=now)
            agent_dict = record.to_dict(now)
            return {
                "ok": True,
                "agent_id": key,
                "status": agent_dict["status"],
                "status_badge": agent_dict["status_badge"],
                "agent": agent_dict,
            }

    @_ClassOrInstanceMethod
    def pause_all(self) -> Dict[str, Any]:
        """Pause all active agents to idle without killing stopped agents."""
        with self._lock:
            now = time.time()
            self._paused_all = True
            for record in self._agents.values():
                if record.status == "running":
                    self._touch_agent(record, status="idle", task="Paused (all)", now=now)
                elif record.status == "idle":
                    self._touch_agent(record, now=now)
            snapshot = self._snapshot_unlocked()
            return {"ok": True, **snapshot}

    @_ClassOrInstanceMethod
    def emergency_stop_all(self) -> Dict[str, Any]:
        """Immediately halt all agents and notify attached brain/kill switch."""
        with self._lock:
            now = time.time()
            self._emergency_stopped = True
            self._paused_all = False
            for record in self._agents.values():
                self._touch_agent(
                    record,
                    status="stopped",
                    task="Emergency stopped",
                    now=now,
                )
            self._notify_brain_stop()
            if self._brain is not None:
                try:
                    from core.safety.kill_switch import EmergencyKillSwitch

                    save_dir = Path("data") / "exports"
                    save_dir.mkdir(parents=True, exist_ok=True)
                    EmergencyKillSwitch().trigger(
                        reason="Control Center Emergency Stop All",
                        save_dir=save_dir,
                    )
                    self._tripped_kill_switch = True
                except Exception as exc:
                    logger.warning("EmergencyKillSwitch trigger warning: %s", exc)

            snapshot = self._snapshot_unlocked()
            return {"ok": True, **snapshot}

    @_ClassOrInstanceMethod
    def report_activity(
        self,
        agent_id: str,
        task: str,
        status: Optional[str] = None,
        error: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Update an agent's current task, status, and last-action timestamp."""
        with self._lock:
            key = self._resolve_agent_id(agent_id)
            record = self._agents.get(key)
            if record is None:
                return {"ok": False, "agent_id": agent_id, "error": f"Unknown agent: {agent_id}"}

            now = time.time()
            try:
                norm_status = _normalize_status(status) if status is not None else None
            except ValueError as exc:
                return {"ok": False, "agent_id": key, "error": str(exc)}

            clear_err = norm_status == "running" and error is None
            resolved_err = error if error is not None else (task if norm_status == "error" else None)
            self._touch_agent(
                record,
                status=norm_status,
                task=task,
                error=resolved_err,
                clear_error=clear_err,
                now=now,
            )
            agent_dict = record.to_dict(now)
            return {"ok": True, "agent_id": key, "agent": agent_dict}

    @_ClassOrInstanceMethod
    def attach_brain(self, brain: Any) -> Dict[str, Any]:
        """Attach an AutonomousBrain instance for lifecycle coordination."""
        with self._lock:
            self._brain = brain
            record = self._agents["brain"]
            now = time.time()
            if brain is not None and record.current_task == "Standby":
                self._touch_agent(record, task="Brain attached (Standby)", now=now)
            else:
                self._touch_agent(record, now=now)
            return {
                "ok": True,
                "attached": brain is not None,
                "agent": record.to_dict(now),
            }

    def reset(self) -> None:
        """Restore default idle state for all agents (primarily for test isolation)."""
        with self._lock:
            self._emergency_stopped = False
            self._paused_all = False
            self._reset_kill_switch_if_tripped()
            now = time.time()
            for record in self._agents.values():
                record.started_at = None
                record.target = None
                self._touch_agent(
                    record,
                    status="idle",
                    task="Standby",
                    clear_error=True,
                    now=now,
                )


_AGENT_MANAGER_SINGLETON: Optional[AgentManager] = None
_AGENT_MANAGER_LOCK = threading.Lock()


def get_agent_manager() -> AgentManager:
    """Return the process-wide thread-safe AgentManager singleton."""
    global _AGENT_MANAGER_SINGLETON
    if _AGENT_MANAGER_SINGLETON is None:
        with _AGENT_MANAGER_LOCK:
            if _AGENT_MANAGER_SINGLETON is None:
                _AGENT_MANAGER_SINGLETON = AgentManager()
    return _AGENT_MANAGER_SINGLETON
