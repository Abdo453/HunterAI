"""
HunterAI Memory 2.0 — Multi-Tiered Memory Architecture (Phase 5)
================================================================
Three integrated tiers:
  1. ExplorationMemory: Short-term browser session data, visited URLs, clicks, DOM fragments.
  2. ProjectMemory: Long-term persistent state across runs (endpoints, findings, parameters).
  3. BlackboardState: Inter-agent shared blackboard for real-time collaboration.

Includes memory curation via `curate_memory()` to purge outdated/stale entries.
"""
from __future__ import annotations

import json
import logging
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("hunter_ai.memory_v2")


@dataclass
class BrowserInteraction:
    action: str
    target_url: str
    element_id: str = ""
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)


class ExplorationMemory:
    """
    Short-term memory storing transient browser session data, navigation trails,
    form submissions, and ephemeral telemetry.
    """
    def __init__(self, max_items: int = 500):
        self.max_items = max_items
        self.visited_urls: List[Dict[str, Any]] = []
        self.interactions: List[BrowserInteraction] = []
        self.dom_snapshots: Dict[str, Dict[str, Any]] = {}  # url -> dom metadata

    def record_visit(self, url: str, status_code: int = 200, title: str = "") -> None:
        self.visited_urls.append({
            "url": url,
            "status_code": status_code,
            "title": title,
            "timestamp": time.time(),
        })
        if len(self.visited_urls) > self.max_items:
            self.visited_urls.pop(0)

    def record_interaction(self, action: str, target_url: str, element_id: str = "", metadata: Optional[Dict[str, Any]] = None) -> None:
        self.interactions.append(BrowserInteraction(
            action=action,
            target_url=target_url,
            element_id=element_id,
            timestamp=time.time(),
            metadata=metadata or {},
        ))
        if len(self.interactions) > self.max_items:
            self.interactions.pop(0)

    def save_dom_snapshot(self, url: str, dom_data: Dict[str, Any]) -> None:
        self.dom_snapshots[url] = {
            "timestamp": time.time(),
            "dom": dom_data,
        }

    def purge_older_than(self, max_age_seconds: float) -> int:
        now = time.time()
        initial_count = len(self.visited_urls) + len(self.interactions)
        self.visited_urls = [u for u in self.visited_urls if now - u["timestamp"] <= max_age_seconds]
        self.interactions = [i for i in self.interactions if now - i.timestamp <= max_age_seconds]
        
        expired_doms = [url for url, snap in self.dom_snapshots.items() if now - snap["timestamp"] > max_age_seconds]
        for url in expired_doms:
            del self.dom_snapshots[url]
            
        pruned = (initial_count - len(self.visited_urls) - len(self.interactions)) + len(expired_doms)
        return pruned


class ProjectMemory:
    """
    Long-term persistent state across runs (endpoints, findings, parameters, scope).
    """
    def __init__(self, project_id: str, storage_path: Optional[Path] = None):
        self.project_id = project_id
        self.storage_path = storage_path
        self.endpoints: Set[str] = set()
        self.parameters: Dict[str, Set[str]] = {}  # endpoint -> set(param_names)
        self.findings: List[Dict[str, Any]] = []
        self.kv_store: Dict[str, Any] = {}
        self.created_at = time.time()

    def add_endpoint(self, url: str, params: Optional[List[str]] = None) -> None:
        self.endpoints.add(url)
        if params:
            if url not in self.parameters:
                self.parameters[url] = set()
            self.parameters[url].update(params)

    def add_finding(self, finding: Dict[str, Any]) -> None:
        # Deduplicate by title + endpoint
        key = (finding.get("title"), finding.get("endpoint"))
        existing = {(f.get("title"), f.get("endpoint")) for f in self.findings}
        if key not in existing:
            self.findings.append({
                **finding,
                "recorded_at": time.time(),
            })

    def set(self, key: str, value: Any) -> None:
        self.kv_store[key] = value

    def get(self, key: str, default: Any = None) -> Any:
        return self.kv_store.get(key, default)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "project_id": self.project_id,
            "created_at": self.created_at,
            "endpoints": sorted(list(self.endpoints)),
            "parameters": {k: sorted(list(v)) for k, v in self.parameters.items()},
            "findings": self.findings,
            "kv_store": self.kv_store,
        }

    def purge_duplicates(self) -> int:
        initial = len(self.findings)
        seen = set()
        unique = []
        for f in self.findings:
            sig = (f.get("title"), f.get("endpoint"), f.get("vuln_type"))
            if sig not in seen:
                seen.add(sig)
                unique.append(f)
        self.findings = unique
        return initial - len(self.findings)


class BlackboardState:
    """
    Shared memory between agents for collaborative planning, task handoffs,
    and live hypothesis tracking.
    """
    def __init__(self):
        self._state: Dict[str, Any] = {}
        self._events: List[Dict[str, Any]] = []
        self._locks: Set[str] = set()

    def set(self, key: str, value: Any, agent_id: str = "orchestrator") -> None:
        self._state[key] = value
        self._events.append({
            "timestamp": time.time(),
            "agent_id": agent_id,
            "key": key,
            "value": value,
        })
        if len(self._events) > 1000:
            self._events.pop(0)

    def get(self, key: str, default: Any = None) -> Any:
        return self._state.get(key, default)

    def acquire_lock(self, resource: str, agent_id: str) -> bool:
        if resource in self._locks:
            return False
        self._locks.add(resource)
        self.set(f"lock:{resource}", agent_id, agent_id)
        return True

    def release_lock(self, resource: str, agent_id: str) -> bool:
        if resource in self._locks:
            self._locks.remove(resource)
            self._state.pop(f"lock:{resource}", None)
            return True
        return False

    def purge_events(self, max_age_seconds: float) -> int:
        now = time.time()
        initial = len(self._events)
        self._events = [e for e in self._events if now - e["timestamp"] <= max_age_seconds]
        return initial - len(self._events)


class MemoryManager:
    """
    Orchestrates the three memory tiers and handles active memory curation.
    """
    def __init__(self, project_id: str = "default_project"):
        self.project_id = project_id
        self.exploration = ExplorationMemory()
        self.project = ProjectMemory(project_id)
        self.blackboard = BlackboardState()

    def curate_memory(self, max_age_seconds: float = 3600.0) -> Dict[str, int]:
        """
        Purges outdated entries across all tiers and consolidates state.
        """
        pruned_exploration = self.exploration.purge_older_than(max_age_seconds)
        pruned_project = self.project.purge_duplicates()
        pruned_blackboard = self.blackboard.purge_events(max_age_seconds)

        curated = {
            "pruned_exploration": pruned_exploration,
            "pruned_project_duplicates": pruned_project,
            "pruned_blackboard_events": pruned_blackboard,
            "total_pruned": pruned_exploration + pruned_project + pruned_blackboard,
        }
        logger.info("Memory curation executed: %s", curated)
        return curated
