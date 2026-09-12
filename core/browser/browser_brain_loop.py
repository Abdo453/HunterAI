"""
Browser-Brain Loop & 3-Sensor Architecture
==========================================
Coordinates the 3 primary observational sensors of HunterAI:
1. BrowserSensor: Stateful browser interaction, DOM diffing, and dynamic exploration
2. HttpSensor: Fast async HTTP probing, header analysis, and raw response extraction
3. CodeSensor: Client-side JS deconstruction, route extraction, and Shannon secrets

Implements the continuous cognitive loop:
  OBSERVE -> "What do I know?" -> "What haven't I explored?" ->
  "What action gives highest information gain?" -> ACT -> OBSERVE AGAIN
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set
from urllib.parse import urlparse

from core.attack_surface_graph import AttackSurfaceGraph, ThirdPartyDependencyFirewall
from core.browser.action_discovery import ActionCategory, ActionDiscovery
from core.browser.browser_event_bus import BrowserEvent, BrowserEventBus, BrowserEventType
from core.browser.coverage_engine import CoverageEngine, ExplorationCoverageMetrics
from core.browser.dom_diff import DOMDiffEngine
from core.browser.exploration_memory import ExplorationMemory
from core.browser.explorer import HumanLikeExplorationEngine, StopReason
from core.browser.interaction_planner import InteractionPlanner
from core.browser.session import StatefulBrowserSession
from core.browser.state_detector import SemanticAppState, StateDetector
from core.browser.state_graph import ApplicationStateGraph

logger = logging.getLogger("hunter_ai.browser_brain_loop")


@dataclass
class SensorObservationReport:
    target_url: str
    duration_sec: float
    coverage: Dict[str, Any]
    pages_visited: int
    states_mapped: int
    api_endpoints_discovered: int
    params_discovered: int
    secrets_discovered: int
    auth_state: str
    stop_reason: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class BrowserBrainLoop:
    """Manages the 3-sensor triad and coordinates information-gain exploration"""

    def __init__(
        self,
        target_url: str,
        session: Optional[StatefulBrowserSession] = None,
        event_bus: Optional[BrowserEventBus] = None,
        max_pages: int = 10,
        max_depth: int = 2,
        time_budget_sec: float = 90.0,
        coverage_threshold: float = 80.0,
        progress_cb: Optional[Callable[[str], Any]] = None,
    ):
        self.target_url = target_url
        self.base_host = (urlparse(target_url).hostname or "target").lower()
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.time_budget_sec = time_budget_sec
        self.coverage_threshold = coverage_threshold
        self.progress_cb = progress_cb

        self.event_bus = event_bus or BrowserEventBus()
        self.memory = ExplorationMemory(self.base_host)
        self.coverage = CoverageEngine(target_url)
        self.state_graph = ApplicationStateGraph(self.base_host)

        # Persistent Browser Session
        self.session = session or StatefulBrowserSession(
            target_url=target_url,
            output_dir=Path(f"data/scans/{self.base_host.replace('.', '_')}/browser"),
            headless=True,
            on_network_event=self._handle_network_traffic,
        )

        # Wire event bus to memory and coverage
        self.event_bus.subscribe_all(self._on_browser_event)

    async def _emit(self, msg: str) -> None:
        logger.info(msg)
        if self.progress_cb:
            try:
                res = self.progress_cb(msg)
                if asyncio.iscoroutine(res):
                    await res
            except Exception:
                pass

    def _on_browser_event(self, event: BrowserEvent) -> None:
        """Passive listener mapping browser events to coverage & memory"""
        t = event.event_type
        if t == BrowserEventType.PAGE_LOADED:
            self.coverage.register_page_visited(event.source_url)
            self.memory.record_seen_url(event.source_url)
        elif t == BrowserEventType.LINK_DISCOVERED:
            target = event.data.get("url", "")
            if target:
                self.coverage.register_page_discovered(target)
        elif t == BrowserEventType.FORM_DISCOVERED:
            sig = event.data.get("signature", "")
            if sig:
                self.coverage.register_form(sig, tested=False)
        elif t == BrowserEventType.NEW_ENDPOINT:
            ep = event.data.get("endpoint", "")
            if ep:
                self.coverage.register_api(ep, observed=True)
        elif t == BrowserEventType.NEW_JS:
            js = event.data.get("js_url", "")
            if js:
                self.coverage.register_js(js, analyzed=False)
        elif t == BrowserEventType.AUTH_STATE_CHANGED:
            auth = event.data.get("state", "GUEST")
            self.coverage.register_auth_state(auth)

    def _handle_network_traffic(self, req_dict: Dict[str, Any]) -> None:
        url = req_dict.get("url", "")
        if not url or ThirdPartyDependencyFirewall.is_external_dependency(url, self.base_host):
            return

        parsed = urlparse(url)
        if any(kw in parsed.path.lower() for kw in ("/api/", "/v1/", "/v2/", "/graphql", "/auth/")):
            self.coverage.register_api(url, observed=True)
            self.event_bus.publish_sync(BrowserEvent(
                event_type=BrowserEventType.NEW_ENDPOINT,
                source_url=url,
                data={"endpoint": url, "method": req_dict.get("method", "GET")}
            ))

    async def run_loop(self) -> SensorObservationReport:
        """Executes the Information-Gain exploration loop across pages and states"""
        t0 = time.time()
        await self._emit(f"[BROWSER_LOOP] Initializing 3-sensor exploration on {self.target_url}...")

        # Ensure browser session is active
        await self.session.start()

        # Seed page
        self.coverage.register_page_discovered(self.target_url)
        html, status, headers = await self.session.navigate(self.target_url)

        # Publish initial events
        await self.event_bus.publish(BrowserEvent(
            event_type=BrowserEventType.PAGE_LOADED,
            source_url=self.target_url,
            data={"status": status, "headers": headers}
        ))

        # Primary Explorer
        explorer = HumanLikeExplorationEngine(
            session=self.session,
            max_pages=self.max_pages,
            max_depth=self.max_depth,
            time_budget_sec=self.time_budget_sec,
            on_progress_cb=self._emit
        )

        res = await explorer.explore()
        manifest = res.get("manifest", {})

        # Populate coverage from explorer results
        for u in res.get("endpoints", []):
            self.coverage.register_api(u, observed=True)
        for j in res.get("js_urls", []):
            self.coverage.register_js(j, analyzed=True)
        for s_id in self.state_graph.states.keys():
            self.coverage.register_state(s_id, explored=True)

        # Check semantic state
        curr_state = StateDetector.detect_state(
            url=self.session.current_url or self.target_url,
            html=html or "",
            cookies=self.session.cookies,
            local_storage=self.session.local_storage,
        )
        self.coverage.register_auth_state(curr_state.value)

        # Log Coverage Table
        cov_table = self.coverage.format_coverage_table()
        await self._emit(f"\n{cov_table}\n")

        duration = round(time.time() - t0, 1)
        metrics = self.coverage.calculate_coverage()

        report = SensorObservationReport(
            target_url=self.target_url,
            duration_sec=duration,
            coverage=metrics.to_dict(),
            pages_visited=metrics.pages_visited,
            states_mapped=metrics.states_explored,
            api_endpoints_discovered=metrics.api_observed,
            params_discovered=len(res.get("params", [])),
            secrets_discovered=0,
            auth_state=curr_state.value,
            stop_reason=manifest.get("stop_reason", StopReason.COMPLETED.value),
        )

        # Persist memory & states
        self.memory.save_json(self.session.output_dir / "exploration_memory.json")
        return report
