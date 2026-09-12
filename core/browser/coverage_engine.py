"""
Exploration Coverage Engine
===========================
Measures multi-dimensional exploration completeness across 7 key surfaces:
- Page / Route coverage (visited vs discovered)
- Application State coverage (states mapped vs candidates)
- Form coverage (forms tested vs discovered)
- Action coverage (interactive affordances executed vs available)
- API endpoint coverage (endpoints observed/called vs discovered)
- JS script coverage (scripts collected & analyzed vs discovered)
- Auth-state coverage (guest vs authenticated states reached)
"""
from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("hunter_ai.coverage_engine")


@dataclass
class ExplorationCoverageMetrics:
    pages_visited: int = 0
    pages_discovered: int = 0
    states_explored: int = 0
    states_discovered: int = 0
    forms_tested: int = 0
    forms_discovered: int = 0
    actions_executed: int = 0
    actions_discovered: int = 0
    api_observed: int = 0
    api_discovered: int = 0
    js_analyzed: int = 0
    js_discovered: int = 0
    auth_states_reached: int = 0
    auth_states_total: int = 2  # GUEST + AUTHENTICATED
    overall_percentage: float = 0.0

    @property
    def pages_pct(self) -> float:
        return (self.pages_visited / max(1, self.pages_discovered)) * 100.0

    @property
    def states_pct(self) -> float:
        return (self.states_explored / max(1, self.states_discovered)) * 100.0

    @property
    def forms_pct(self) -> float:
        return (self.forms_tested / max(1, self.forms_discovered)) * 100.0

    @property
    def actions_pct(self) -> float:
        return (self.actions_executed / max(1, self.actions_discovered)) * 100.0

    @property
    def api_pct(self) -> float:
        return (self.api_observed / max(1, self.api_discovered)) * 100.0

    @property
    def js_pct(self) -> float:
        return (self.js_analyzed / max(1, self.js_discovered)) * 100.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pages": {"visited": self.pages_visited, "discovered": self.pages_discovered, "pct": round(self.pages_pct, 1)},
            "states": {"explored": self.states_explored, "discovered": self.states_discovered, "pct": round(self.states_pct, 1)},
            "forms": {"tested": self.forms_tested, "discovered": self.forms_discovered, "pct": round(self.forms_pct, 1)},
            "actions": {"executed": self.actions_executed, "discovered": self.actions_discovered, "pct": round(self.actions_pct, 1)},
            "api": {"observed": self.api_observed, "discovered": self.api_discovered, "pct": round(self.api_pct, 1)},
            "js": {"analyzed": self.js_analyzed, "discovered": self.js_discovered, "pct": round(self.js_pct, 1)},
            "auth_states": {"reached": self.auth_states_reached, "total": self.auth_states_total},
            "overall_percentage": round(self.overall_percentage, 1),
        }


class CoverageEngine:
    """Tracks coverage metrics across pages, states, forms, and network surface"""

    def __init__(self, target_url: str):
        self.target_url = target_url
        self.discovered_pages: Set[str] = set()
        self.visited_pages: Set[str] = set()

        self.discovered_states: Set[str] = set()
        self.explored_states: Set[str] = set()

        self.discovered_forms: Set[str] = set()
        self.tested_forms: Set[str] = set()

        self.discovered_actions: Set[str] = set()
        self.executed_actions: Set[str] = set()

        self.discovered_apis: Set[str] = set()
        self.observed_apis: Set[str] = set()

        self.discovered_js: Set[str] = set()
        self.analyzed_js: Set[str] = set()

        self.reached_auth_states: Set[str] = {"GUEST"}

    def register_page_discovered(self, url: str) -> None:
        self.discovered_pages.add(url)

    def register_page_visited(self, url: str) -> None:
        self.discovered_pages.add(url)
        self.visited_pages.add(url)

    def register_state(self, state_id: str, explored: bool = False) -> None:
        self.discovered_states.add(state_id)
        if explored:
            self.explored_states.add(state_id)

    def register_form(self, form_sig: str, tested: bool = False) -> None:
        self.discovered_forms.add(form_sig)
        if tested:
            self.tested_forms.add(form_sig)

    def register_action(self, action_id: str, executed: bool = False) -> None:
        self.discovered_actions.add(action_id)
        if executed:
            self.executed_actions.add(action_id)

    def register_api(self, api_url: str, observed: bool = False) -> None:
        self.discovered_apis.add(api_url)
        if observed:
            self.observed_apis.add(api_url)

    def register_js(self, js_url: str, analyzed: bool = False) -> None:
        self.discovered_js.add(js_url)
        if analyzed:
            self.analyzed_js.add(js_url)

    def register_auth_state(self, auth_state: str) -> None:
        self.reached_auth_states.add(auth_state.upper())

    def calculate_coverage(self) -> ExplorationCoverageMetrics:
        """Computes weighted overall exploration coverage percentage"""
        p_pct = len(self.visited_pages) / max(1, len(self.discovered_pages))
        s_pct = len(self.explored_states) / max(1, len(self.discovered_states))
        f_pct = len(self.tested_forms) / max(1, len(self.discovered_forms))
        a_pct = len(self.executed_actions) / max(1, len(self.discovered_actions))
        api_pct = len(self.observed_apis) / max(1, len(self.discovered_apis))
        js_pct = len(self.analyzed_js) / max(1, len(self.discovered_js))

        weights = [0.25, 0.20, 0.15, 0.15, 0.15, 0.10]
        values = [p_pct, s_pct, f_pct, a_pct, api_pct, js_pct]
        overall = sum(w * v for w, v in zip(weights, values)) * 100.0

        return ExplorationCoverageMetrics(
            pages_visited=len(self.visited_pages),
            pages_discovered=len(self.discovered_pages),
            states_explored=len(self.explored_states),
            states_discovered=len(self.discovered_states),
            forms_tested=len(self.tested_forms),
            forms_discovered=len(self.discovered_forms),
            actions_executed=len(self.executed_actions),
            actions_discovered=len(self.discovered_actions),
            api_observed=len(self.observed_apis),
            api_discovered=len(self.discovered_apis),
            js_analyzed=len(self.analyzed_js),
            js_discovered=len(self.discovered_js),
            auth_states_reached=len(self.reached_auth_states),
            auth_states_total=2,
            overall_percentage=overall,
        )

    def format_coverage_table(self) -> str:
        """Renders the terminal/CLI coverage summary table"""
        metrics = self.calculate_coverage()
        lines = [
            "Exploration Coverage ━━━━━━━━━━━━━━━━━━━━",
            f"Pages       {metrics.pages_visited:>3}/{metrics.pages_discovered:<3}  {metrics.pages_pct:>5.1f}%",
            f"States      {metrics.states_explored:>3}/{metrics.states_discovered:<3}  {metrics.states_pct:>5.1f}%",
            f"Forms       {metrics.forms_tested:>3}/{metrics.forms_discovered:<3}  {metrics.forms_pct:>5.1f}%",
            f"API         {metrics.api_observed:>3}/{metrics.api_discovered:<3}  {metrics.api_pct:>5.1f}%",
            f"JS          {metrics.js_analyzed:>3}/{metrics.js_discovered:<3}  {metrics.js_pct:>5.1f}%",
            f"Actions     {metrics.actions_executed:>3}/{metrics.actions_discovered:<3}  {metrics.actions_pct:>5.1f}%",
            "─────────────────────────────────────────",
            f"Overall:                      {metrics.overall_percentage:>5.1f}%",
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
        ]
        return "\n".join(lines)

    def is_coverage_sufficient(self, target_threshold: float = 80.0) -> bool:
        return self.calculate_coverage().overall_percentage >= target_threshold
