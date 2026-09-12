"""
Exploration Memory
==================
Maintains detailed forensic memory of the browser exploration lifecycle:
- What has been seen (URLs, DOM states, element signatures)
- What has been clicked/interacted with (timestamps, results, DOM effects)
- What failed (timeouts, dead selectors, navigation errors)
- What changed (DOM mutations, auth transitions)
- What generated new attack surface (new endpoints, forms, parameters)
- What was filtered as duplicate or blocked by scope firewall
"""
from __future__ import annotations

import json
import logging
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("hunter_ai.exploration_memory")


@dataclass
class ActionRecord:
    selector: str
    action_type: str
    url: str
    timestamp: float = field(default_factory=lambda: time.time())
    success: bool = True
    new_surface_generated: bool = False
    error: Optional[str] = None
    dom_diff_summary: Optional[Dict[str, Any]] = None
    network_requests_triggered: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ExplorationMemory:
    """Forensic memory of actions and observations across the browser session"""

    def __init__(self, target_host: str):
        self.target_host = target_host
        self.what_seen_urls: Set[str] = set()
        self.what_seen_states: Set[str] = set()
        self.what_seen_elements: Set[str] = set()

        self.what_clicked: List[ActionRecord] = []
        self.what_failed: List[Dict[str, Any]] = []
        self.what_changed: List[Dict[str, Any]] = []
        self.what_generated_new_surface: List[Dict[str, Any]] = []
        self.what_is_duplicate: Set[str] = set()
        self.what_is_blocked: Set[str] = set()

    def record_seen_url(self, url: str) -> None:
        self.what_seen_urls.add(url)

    def record_seen_state(self, state_id: str) -> None:
        self.what_seen_states.add(state_id)

    def record_seen_element(self, element_sig: str) -> None:
        self.what_seen_elements.add(element_sig)

    def record_action(
        self,
        selector: str,
        action_type: str,
        url: str,
        success: bool = True,
        new_surface_generated: bool = False,
        error: Optional[str] = None,
        dom_diff_summary: Optional[Dict[str, Any]] = None,
        network_requests_triggered: int = 0,
    ) -> ActionRecord:
        record = ActionRecord(
            selector=selector,
            action_type=action_type,
            url=url,
            success=success,
            new_surface_generated=new_surface_generated,
            error=error,
            dom_diff_summary=dom_diff_summary,
            network_requests_triggered=network_requests_triggered,
        )
        self.what_clicked.append(record)
        if not success or error:
            self.what_failed.append(record.to_dict())
        if new_surface_generated:
            self.what_generated_new_surface.append(record.to_dict())
        return record

    def record_state_change(self, from_state: str, to_state: str, trigger: str, diff_summary: Optional[Dict] = None) -> None:
        self.what_changed.append({
            "from_state": from_state,
            "to_state": to_state,
            "trigger": trigger,
            "timestamp": time.time(),
            "diff": diff_summary or {},
        })

    def record_duplicate(self, url_or_sig: str) -> None:
        self.what_is_duplicate.add(url_or_sig)

    def record_blocked(self, url: str, reason: str = "scope_firewall") -> None:
        self.what_is_blocked.add(f"{url} ({reason})")

    def has_clicked(self, selector: str, url: str) -> bool:
        return any(a.selector == selector and a.url == url for a in self.what_clicked)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_host": self.target_host,
            "stats": {
                "seen_urls": len(self.what_seen_urls),
                "seen_states": len(self.what_seen_states),
                "total_actions": len(self.what_clicked),
                "successful_actions": sum(1 for a in self.what_clicked if a.success),
                "failed_actions": len(self.what_failed),
                "new_surface_actions": len(self.what_generated_new_surface),
                "duplicates_suppressed": len(self.what_is_duplicate),
                "firewalled_blocked": len(self.what_is_blocked),
            },
            "what_seen_urls": sorted(list(self.what_seen_urls)),
            "what_seen_states": sorted(list(self.what_seen_states)),
            "what_clicked": [a.to_dict() for a in self.what_clicked[-50:]],
            "what_failed": self.what_failed[-20:],
            "what_changed": self.what_changed[-20:],
            "what_generated_new_surface": self.what_generated_new_surface[-20:],
            "what_is_duplicate_count": len(self.what_is_duplicate),
            "what_is_blocked": sorted(list(self.what_is_blocked)),
        }

    def save_json(self, filepath: Path) -> None:
        filepath.parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)
