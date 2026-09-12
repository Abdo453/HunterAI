"""
Application State Graph
=======================
Models application states, dynamic user flows, and state transitions.
- Tracks state_id based on normalized URL, DOM structure, and auth status
- Detects loops and pagination traps to prevent infinite crawling
- Maps transitions: (from_state, action, to_state, network_calls, dom_diff)
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

logger = logging.getLogger("hunter_ai.state_graph")


@dataclass
class AppState:
    state_id: str
    url: str
    normalized_url: str
    dom_hash: str
    title: str = ""
    auth_status: str = "GUEST"  # GUEST | AUTHENTICATED | ADMIN
    discovered_endpoints: List[str] = field(default_factory=list)
    forms_count: int = 0
    inputs_count: int = 0
    interactive_affordances: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=lambda: time.time())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class StateTransition:
    transition_id: str
    from_state_id: str
    to_state_id: str
    trigger_action: str
    network_requests: List[Dict[str, Any]] = field(default_factory=list)
    dom_diff: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=lambda: time.time())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ApplicationStateGraph:
    """Manages the directed graph of application states and transitions"""

    def __init__(self, target_host: str):
        self.target_host = target_host.lower()
        self.states: Dict[str, AppState] = {}
        self.transitions: List[StateTransition] = []
        self.current_state_id: Optional[str] = None
        self._action_history: List[Tuple[str, str]] = []  # (state_id, action_key)
        self._visited_signatures: Set[str] = set()

    @staticmethod
    def normalize_url(url: str) -> str:
        """Normalizes pagination and tracking parameters to prevent crawling traps"""
        if not url:
            return ""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        normalized_params = {}
        for k, vals in sorted(params.items()):
            k_low = k.lower()
            if k_low in ("page", "p", "pg", "offset", "start"):
                normalized_params[k] = ["{PAGE}"]
            elif k_low in ("limit", "size", "count"):
                normalized_params[k] = ["{LIMIT}"]
            elif k_low in ("utm_source", "utm_medium", "utm_campaign", "ref", "fbclid", "gclid"):
                continue  # strip tracking parameters
            else:
                normalized_params[k] = vals

        new_query = urlencode(normalized_params, doseq=True)
        # Strip trailing slash from path
        path = parsed.path.rstrip("/") if parsed.path != "/" else "/"
        return urlunparse((parsed.scheme, parsed.netloc, path, parsed.params, new_query, ""))

    @classmethod
    def generate_state_id(cls, url: str, dom_hash: str, auth_status: str = "GUEST") -> str:
        norm_url = cls.normalize_url(url)
        sig = f"{norm_url}::{dom_hash}::{auth_status}"
        return hashlib.sha256(sig.encode("utf-8")).hexdigest()[:16]

    def register_state(
        self,
        url: str,
        dom_hash: str,
        title: str = "",
        auth_status: str = "GUEST",
        discovered_endpoints: Optional[List[str]] = None,
        forms_count: int = 0,
        inputs_count: int = 0,
        interactive_affordances: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AppState:
        norm_url = self.normalize_url(url)
        state_id = self.generate_state_id(url, dom_hash, auth_status)

        if state_id not in self.states:
            state = AppState(
                state_id=state_id,
                url=url,
                normalized_url=norm_url,
                dom_hash=dom_hash,
                title=title,
                auth_status=auth_status,
                discovered_endpoints=discovered_endpoints or [],
                forms_count=forms_count,
                inputs_count=inputs_count,
                interactive_affordances=interactive_affordances or [],
                metadata=metadata or {},
            )
            self.states[state_id] = state
            logger.info(f"STATE GRAPH: Discovered new application state {state_id} ({url})")
        else:
            state = self.states[state_id]
            # Merge endpoints if new ones discovered
            if discovered_endpoints:
                for ep in discovered_endpoints:
                    if ep not in state.discovered_endpoints:
                        state.discovered_endpoints.append(ep)

        return state

    def record_transition(
        self,
        from_state_id: str,
        to_state_id: str,
        trigger_action: str,
        network_requests: Optional[List[Dict[str, Any]]] = None,
        dom_diff: Optional[Dict[str, Any]] = None,
    ) -> StateTransition:
        trans = StateTransition(
            transition_id=str(uuid.uuid4())[:8],
            from_state_id=from_state_id,
            to_state_id=to_state_id,
            trigger_action=trigger_action,
            network_requests=network_requests or [],
            dom_diff=dom_diff or {},
        )
        self.transitions.append(trans)
        self.current_state_id = to_state_id
        self._action_history.append((from_state_id, trigger_action))
        self._visited_signatures.add(f"{from_state_id}->{to_state_id}::{trigger_action}")
        return trans

    def is_loop(self, state_id: str, action_key: str, max_repeats: int = 2) -> bool:
        """Detects if performing this action from this state constitutes an infinite loop"""
        pair = (state_id, action_key)
        count = sum(1 for p in self._action_history if p == pair)
        return count >= max_repeats

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_host": self.target_host,
            "total_states": len(self.states),
            "total_transitions": len(self.transitions),
            "states": {sid: s.to_dict() for sid, s in self.states.items()},
            "transitions": [t.to_dict() for t in self.transitions],
        }

    def save_json(self, output_file: Path) -> None:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)