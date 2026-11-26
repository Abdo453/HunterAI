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
from urllib.parse import urljoin, urlparse

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
from core.code_intel.agent import CodeIntelligenceAgent

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
    forms_discovered: int = 0
    source_sink_flows_discovered: int = 0

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
        state_graph: Optional[ApplicationStateGraph] = None,
        coverage: Optional[CoverageEngine] = None,
        discovered_forms: Optional[List[Dict[str, Any]]] = None,
        code_intel_agent: Optional[CodeIntelligenceAgent] = None,
        script_fetcher: Optional[Callable[[str], Any]] = None,
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
        self.coverage = coverage if coverage is not None else CoverageEngine(target_url)
        self.state_graph = state_graph if state_graph is not None else ApplicationStateGraph(self.base_host)
        self.discovered_forms: List[Dict[str, Any]] = (
            discovered_forms if discovered_forms is not None else []
        )
        self.code_intel_agent = code_intel_agent or CodeIntelligenceAgent()
        self.script_fetcher = script_fetcher

        self.explorer: Optional[HumanLikeExplorationEngine] = None
        self.discovered_secrets: List[Dict[str, Any]] = []
        self.source_sink_flows: List[Dict[str, Any]] = []
        self.code_intel_reports: List[Dict[str, Any]] = []

        # Persistent Browser Session
        self.session = session or StatefulBrowserSession(
            target_url=target_url,
            output_dir=Path(f"data/scans/{self.base_host.replace('.', '_')}/browser"),
            headless=True,
            on_network_event=self._handle_network_traffic,
            event_bus=self.event_bus,
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

    async def _fetch_in_scope_asset(self, url: str) -> Optional[str]:
        """Safely fetch an in-scope JS or source-map asset without crashing offline runs."""
        if not url or ThirdPartyDependencyFirewall.is_external_dependency(url, self.base_host):
            return None
        if self.script_fetcher is not None:
            try:
                res = self.script_fetcher(url)
                if asyncio.iscoroutine(res):
                    res = await res
                return res if isinstance(res, str) and res else None
            except Exception:
                return None

        http_client = getattr(self.session, "_http_client", None)
        if http_client is not None:
            try:
                resp = await http_client.get(url, timeout=6.0)
                if getattr(resp, "status_code", 0) == 200 and getattr(resp, "text", ""):
                    return resp.text
            except Exception:
                return None
        return None

    async def _run_code_intelligence(
        self,
        captured_pages: Dict[str, str],
        js_urls: List[str],
        initial_headers: Optional[Dict[str, str]] = None,
    ) -> None:
        """Invoke CodeIntelligenceAgent across explored pages + fetched JS so secrets_discovered is truthful."""
        fetched_scripts: Dict[str, str] = {}
        for js_url in js_urls[:10]:
            content = await self._fetch_in_scope_asset(js_url)
            if content:
                fetched_scripts[js_url] = content

        cookie_map: Dict[str, str] = {}
        for c in getattr(self.session, "cookies", []) or []:
            if isinstance(c, dict) and c.get("name"):
                cookie_map[str(c["name"])] = str(c.get("value", ""))

        seen_secret_keys: Set[tuple] = set()
        seen_flow_keys: Set[tuple] = set()
        self.discovered_secrets = []
        self.source_sink_flows = []
        self.code_intel_reports = []

        pages_items = list(captured_pages.items())
        for idx, (page_url, page_html) in enumerate(pages_items):
            if not page_html:
                continue
            try:
                ci_res = await self.code_intel_agent.analyze_page(
                    target_url=page_url,
                    raw_html=page_html,
                    headers=initial_headers if idx == 0 else None,
                    cookies=cookie_map or None,
                    fetched_scripts=fetched_scripts if idx == 0 else None,
                    source_map_fetcher=self._fetch_in_scope_asset,
                )
            except Exception as exc:
                logger.debug("[BROWSER_LOOP] CodeIntelligenceAgent failed for %s: %s", page_url, exc)
                continue

            self.code_intel_reports.append(ci_res)

            for ep in ci_res.get("endpoints", []):
                ep_path = ep.get("url_or_path", "") if isinstance(ep, dict) else ""
                if ep_path:
                    full_ep = urljoin(page_url, ep_path)
                    if not ThirdPartyDependencyFirewall.is_external_dependency(full_ep, self.base_host):
                        self.coverage.register_api(full_ep, observed=False)

            for sec in ci_res.get("secrets", []):
                if not isinstance(sec, dict):
                    continue
                if str(sec.get("status", "")).upper() == "REJECTED":
                    continue
                key = (
                    sec.get("secret_type", ""),
                    sec.get("redacted_preview", ""),
                    sec.get("source_file", ""),
                    sec.get("line_number", 0),
                )
                if key not in seen_secret_keys:
                    seen_secret_keys.add(key)
                    self.discovered_secrets.append(sec)

            for flow in ci_res.get("source_sink_flows", []):
                if not isinstance(flow, dict) or not flow.get("is_exploitable", False):
                    continue
                fkey = (
                    flow.get("source", ""),
                    flow.get("sink", ""),
                    flow.get("source_file", ""),
                    flow.get("line_number", 0),
                )
                if fkey not in seen_flow_keys:
                    seen_flow_keys.add(fkey)
                    self.source_sink_flows.append(flow)

        for js_url in fetched_scripts:
            self.coverage.register_js(js_url, analyzed=True)

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

        # Primary Explorer sharing the exact same StateGraph, CoverageEngine, Memory, and discovered_forms
        explorer = HumanLikeExplorationEngine(
            session=self.session,
            max_pages=self.max_pages,
            max_depth=self.max_depth,
            time_budget_sec=self.time_budget_sec,
            coverage_target_pct=self.coverage_threshold,
            on_progress_cb=self._emit,
            state_graph=self.state_graph,
            coverage=self.coverage,
            memory=self.memory,
            event_bus=self.event_bus,
            discovered_forms=self.discovered_forms,
        )
        self.explorer = explorer

        res = await explorer.explore()
        manifest = res.get("manifest", {})

        # Populate coverage from explorer results
        for u in res.get("endpoints", []):
            self.coverage.register_api(u, observed=True)
        for j in res.get("js_urls", []):
            self.coverage.register_js(j, analyzed=False)
        self.coverage.register_forms(self.discovered_forms, tested=False)
        for s_id in self.state_graph.states.keys():
            self.coverage.register_state(s_id, explored=True)

        # Code Intelligence sensor pass across explored pages & scripts
        captured_pages: Dict[str, str] = dict(res.get("captured_pages") or {})
        if html and self.target_url not in captured_pages:
            captured_pages[self.target_url] = html
        await self._run_code_intelligence(
            captured_pages=captured_pages,
            js_urls=list(res.get("js_urls", [])),
            initial_headers=headers,
        )

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
            secrets_discovered=len(self.discovered_secrets),
            auth_state=curr_state.value,
            stop_reason=manifest.get("stop_reason", StopReason.COMPLETED.value),
            forms_discovered=metrics.forms_discovered,
            source_sink_flows_discovered=len(self.source_sink_flows),
        )

        # Persist memory & states
        self.session.output_dir.mkdir(parents=True, exist_ok=True)
        self.memory.save_json(self.session.output_dir / "exploration_memory.json")
        return report
