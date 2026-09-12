"""
Human-like Stateful Exploration Engine
======================================
Autonomous browser exploration loop for web applications:
- Prioritizes high-value security surfaces (Auth > Input > API > Nav)
- Interacts with dynamic controls (modals, tabs, buttons)
- Correlates UI actions with network traffic and DOM diff mutations
- Detects and halts infinite navigation loops and duplicate requests
- Produces exploration_manifest.json and exploration_lessons.json
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urljoin, urlparse

from core.attack_surface_graph import ThirdPartyDependencyFirewall
from core.browser.action_discovery import ActionCategory, ActionDiscovery, ActionCandidate, RequestDeduplicator
from core.browser.dom_diff import DOMDiffEngine, DOMDiffResult
from core.browser.session import StatefulBrowserSession
from core.browser.state_graph import ApplicationStateGraph, AppState

logger = logging.getLogger("hunter_ai.explorer")


class StopReason(str, Enum):
    COMPLETED = "COMPLETED"
    NO_NEW_SURFACE = "NO_NEW_SURFACE"
    PAGE_LIMIT = "PAGE_LIMIT"
    DEPTH_LIMIT = "DEPTH_LIMIT"
    TIME_LIMIT = "TIME_LIMIT"
    AUTH_REQUIRED = "AUTH_REQUIRED"
    LOOP_DETECTED = "LOOP_DETECTED"
    BROWSER_ERROR = "BROWSER_ERROR"


@dataclass
class ExplorationManifest:
    target_url: str
    pages_visited: int = 0
    states_discovered: int = 0
    api_endpoints: int = 0
    forms: int = 0
    buttons: int = 0
    js_files: int = 0
    network_requests: int = 0
    authenticated: bool = False
    external_domains_blocked: bool = True
    stop_reason: str = StopReason.COMPLETED.value
    duration: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ExplorationLessons:
    missed_surfaces: List[str] = field(default_factory=list)
    blocked_states: List[str] = field(default_factory=list)
    duplicate_patterns_filtered: int = 0
    disproved_hypotheses: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class HumanLikeExplorationEngine:
    """Orchestrates human-like, deep exploratory navigation of web applications"""

    def __init__(
        self,
        session: StatefulBrowserSession,
        max_pages: int = 10,
        max_depth: int = 2,
        time_budget_sec: float = 120.0,
        on_progress_cb: Optional[Callable[[str], Any]] = None,
    ):
        self.session = session
        self.base_host = (urlparse(session.target_url).hostname or "").lower()
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.time_budget_sec = time_budget_sec
        self.on_progress = on_progress_cb

        self.state_graph = ApplicationStateGraph(self.base_host)
        self.request_dedup = RequestDeduplicator()

        self.discovered_endpoints: Set[str] = set()
        self.discovered_params: Set[str] = set()
        self.discovered_js_files: Set[str] = set()
        self.discovered_forms: List[Dict[str, Any]] = []

        # Queue: list of dict(url=str, depth=int, referrer=str)
        self._queue: List[Dict[str, Any]] = []
        self._visited: Set[str] = set()
        self._stop_reason = StopReason.COMPLETED
        self._duplicate_patterns_count = 0

    async def _emit(self, msg: str):
        logger.info(msg)
        if self.on_progress:
            try:
                res = self.on_progress(msg)
                if asyncio.iscoroutine(res):
                    await res
            except Exception:
                pass

    def _is_in_scope(self, url: str) -> bool:
        if not url:
            return False
        return not ThirdPartyDependencyFirewall.is_external_dependency(url, self.base_host)

    async def explore(self) -> Dict[str, Any]:
        """Main exploration execution loop"""
        t0 = time.time()
        await self._emit(f"[EXPLORER] Starting human-like exploration on {self.session.target_url} (Max Pages: {self.max_pages}, Max Depth: {self.max_depth})")

        # Start browser session
        await self.session.start()

        # Seed queue with target URL
        self._queue.append({"url": self.session.target_url, "depth": 0, "referrer": ""})

        while self._queue:
            # Check limits
            if len(self._visited) >= self.max_pages:
                self._stop_reason = StopReason.PAGE_LIMIT
                await self._emit(f"[EXPLORER] Reached max page budget ({self.max_pages}). Halting exploration.")
                break

            if time.time() - t0 > self.time_budget_sec:
                self._stop_reason = StopReason.TIME_LIMIT
                await self._emit(f"[EXPLORER] Exploration time budget ({self.time_budget_sec}s) exhausted.")
                break

            item = self._queue.pop(0)
            url = item["url"]
            depth = item["depth"]

            norm_url = ApplicationStateGraph.normalize_url(url)
            if norm_url in self._visited:
                self._duplicate_patterns_count += 1
                continue
            self._visited.add(norm_url)

            await self._emit(f"[EXPLORER] Visiting page [{len(self._visited)}/{self.max_pages}] (Depth {depth}): {url}")

            # 1. Navigate
            html, status, headers = await self.session.navigate(url)
            if not html:
                continue

            # 2. Extract DOM and compute state
            dom_hash = DOMDiffEngine.compute_structural_hash(html)
            title_match = re.search(r"<title>(.*?)</title>", html, re.IGNORECASE)
            page_title = title_match.group(1).strip() if title_match else ""

            # 3. Action Discovery
            actions = ActionDiscovery.discover_actions_from_html(html, url, self.base_host)
            affordance_labels = [a.label for a in actions[:15]]

            state = self.state_graph.register_state(
                url=url,
                dom_hash=dom_hash,
                title=page_title,
                forms_count=sum(1 for a in actions if a.category == ActionCategory.USER_INPUT),
                interactive_affordances=affordance_labels,
            )

            # 4. Harvest endpoints & JS from HTML & Network
            self._harvest_page_artifacts(html, url)

            # 5. Execute High-Value Safe Interactions (Modals, Tabs, Dynamic Buttons)
            await self._explore_interactive_affordances(state, actions, html, url)

            # 6. Enqueue In-Scope Candidate Links
            if depth < self.max_depth:
                self._enqueue_actions(actions, depth + 1, url)

        # Exploration completed
        duration = round(time.time() - t0, 1)
        if not self._queue and self._stop_reason == StopReason.COMPLETED:
            self._stop_reason = StopReason.NO_NEW_SURFACE

        manifest = ExplorationManifest(
            target_url=self.session.target_url,
            pages_visited=len(self._visited),
            states_discovered=len(self.state_graph.states),
            api_endpoints=len(self.discovered_endpoints),
            forms=len(self.discovered_forms),
            buttons=sum(s.forms_count for s in self.state_graph.states.values()),
            js_files=len(self.discovered_js_files),
            network_requests=len(self.session.network_history),
            authenticated=any(s.auth_status != "GUEST" for s in self.state_graph.states.values()),
            external_domains_blocked=True,
            stop_reason=self._stop_reason.value,
            duration=duration,
        )

        lessons = ExplorationLessons(
            missed_surfaces=[q["url"] for q in self._queue[:10]],
            duplicate_patterns_filtered=self._duplicate_patterns_count,
            recommendations=[
                f"App contains {len(self.discovered_endpoints)} client-side API endpoints; focus fuzzing on API vectors.",
                "Client-side SPA states mapped; verify authenticated state access control."
            ]
        )

        # Save artifacts
        self.state_graph.save_json(self.session.output_dir / "states.json")
        with open(self.session.output_dir / "exploration_manifest.json", "w", encoding="utf-8") as f:
            json.dump(manifest.to_dict(), f, indent=2)
        with open(self.session.output_dir / "exploration_lessons.json", "w", encoding="utf-8") as f:
            json.dump(lessons.to_dict(), f, indent=2)
        with open(self.session.output_dir / "discovered_endpoints.json", "w", encoding="utf-8") as f:
            json.dump(sorted(list(self.discovered_endpoints)), f, indent=2)

        self.session.save_artifacts()

        await self._emit(
            f"[EXPLORER] Finished in {duration}s | StopReason={self._stop_reason.value} | "
            f"Pages={manifest.pages_visited} | States={manifest.states_discovered} | "
            f"API Endpoints={manifest.api_endpoints} | Network Requests={manifest.network_requests}"
        )

        return {
            "manifest": manifest.to_dict(),
            "lessons": lessons.to_dict(),
            "state_graph": self.state_graph.to_dict(),
            "endpoints": sorted(list(self.discovered_endpoints)),
            "params": sorted(list(self.discovered_params)),
            "js_urls": sorted(list(self.discovered_js_files)),
            "forms": self.discovered_forms,
        }

    def _harvest_page_artifacts(self, html: str, page_url: str):
        """Extracts scripts, endpoints, and form fields from HTML and session network activity"""
        # Script tags
        scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE)
        for s in scripts:
            full_s = urljoin(page_url, s)
            if self._is_in_scope(full_s):
                self.discovered_js_files.add(full_s)

        # Inline API route hints
        api_matches = re.findall(r'["\'](/(?:api|v1|v2|graphql|auth)/[^"\'\s<>]+)["\']', html)
        for ep in api_matches:
            full_ep = urljoin(page_url, ep)
            self.discovered_endpoints.add(full_ep)

        # Recent network requests from session
        for req in self.session.network_history[-50:]:
            if self._is_in_scope(req.url):
                parsed = urlparse(req.url)
                if any(kw in parsed.path.lower() for kw in ("/api/", "/_next/", ".json", "/v1/")):
                    self.discovered_endpoints.add(req.url)
                for qk in parse_qs(parsed.query).keys():
                    self.discovered_params.add(qk)

    async def _explore_interactive_affordances(self, state: AppState, actions: List[ActionCandidate], current_html: str, current_url: str):
        """Interacts with top high-priority safe elements (modals, tabs, load more)"""
        # Take up to 2 safe interactive actions per page
        interactable_candidates = [
            a for a in actions
            if a.category in (ActionCategory.API_TRIGGER, ActionCategory.USER_INPUT)
            and a.element_type in ("button", "tab")
            and not any(bad in a.label.lower() for bad in ("logout", "delete", "remove", "cancel"))
        ][:2]

        for action in interactable_candidates:
            if self.state_graph.is_loop(state.state_id, action.action_id):
                continue

            network_snapshot_idx = len(self.session.network_history)
            interacted = await self.session.interact(action.selector, "click")
            if not interacted:
                continue

            # Check DOM mutation after interaction
            after_html = await self.session.get_dom()
            if after_html:
                diff = DOMDiffEngine.diff(current_html, after_html)
                if diff.has_changes:
                    new_network = [r.to_dict() for r in self.session.network_history[network_snapshot_idx:]]
                    new_state_id = ApplicationStateGraph.generate_state_id(current_url, DOMDiffEngine.compute_structural_hash(after_html))
                    self.state_graph.record_transition(
                        from_state_id=state.state_id,
                        to_state_id=new_state_id,
                        trigger_action=f"click:{action.label}",
                        network_requests=new_network,
                        dom_diff=diff.to_dict()
                    )
                    await self._emit(f"   -> Triggered '{action.label}' => DOM mutation detected (+{len(diff.added_elements)} elems, {len(new_network)} network calls)")

    def _enqueue_actions(self, actions: List[ActionCandidate], next_depth: int, current_url: str):
        """Adds in-scope navigation targets to queue sorted by score"""
        for a in actions:
            if a.target_url and self._is_in_scope(a.target_url):
                norm = ApplicationStateGraph.normalize_url(a.target_url)
                if norm not in self._visited and not any(q["url"] == a.target_url for q in self._queue):
                    self._queue.append({"url": a.target_url, "depth": next_depth, "referrer": current_url})

    async def explore_endpoint(self, url_or_path: str) -> Dict[str, Any]:
        """Bidirectional feedback method: explicitly navigates to an endpoint discovered by Code Intel"""
        target = urljoin(self.session.target_url, url_or_path)
        if not self._is_in_scope(target):
            return {"status": "BLOCKED_BY_FIREWALL", "url": target}

        await self._emit(f"[EXPLORER] Bidirectional feedback: exploring Code-Intel discovered route {target}")
        html, status, headers = await self.session.navigate(target)
        if html:
            self._harvest_page_artifacts(html, target)
        return {
            "status": "EXPLORED",
            "url": target,
            "status_code": status,
            "html_len": len(html),
        }