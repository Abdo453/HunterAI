"""
HunterOS — Terminal Security Operations Dashboard
==================================================
Strix-style TUI for HunterAI.

Launch:
    python ui/tui/hunter_os.py --target target.com
    python ui/tui/hunter_os.py --target target.com --gateway http://localhost:8719

Architecture:
    - Reads live data from BurpGateway HTTP API (if reachable)
    - Falls back to BlackboardState shared memory (in-process)
    - Updates every second via Textual's set_interval()
"""

from __future__ import annotations

import argparse
import asyncio
import json
import time
import urllib.request
import urllib.error
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.color import Color
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
from textual.reactive import reactive
from textual.widget import Widget
from textual.widgets import (
    DataTable,
    Footer,
    Header,
    Label,
    Log,
    ProgressBar,
    RichLog,
    Rule,
    Static,
)
from textual.css.query import NoMatches
from rich.text import Text
from rich.table import Table
from rich.panel import Panel
from rich.console import Group


# ── Severity colours ─────────────────────────────────────────────────────────
SEVER_COLOR = {
    "CRITICAL": "bold red",
    "HIGH":     "bold orange1",
    "MEDIUM":   "bold yellow",
    "LOW":      "bold cyan",
    "INFO":     "dim white",
}
CONFIDENCE_BAR = {
    "95+": "🔴",
    "80+": "🟠",
    "60+": "🟡",
    "0+":  "🟢",
}


def _conf_icon(pct: float) -> str:
    if pct >= 95: return "🔴"
    if pct >= 80: return "🟠"
    if pct >= 60: return "🟡"
    return "🟢"


def _elapsed(start_ts: float) -> str:
    delta = timedelta(seconds=int(time.time() - start_ts))
    h, rem = divmod(int(delta.total_seconds()), 3600)
    m, s = divmod(rem, 60)
    return f"{h:02d}:{m:02d}:{s:02d}"


# ── Live data model ───────────────────────────────────────────────────────────

class HunterState:
    """Central data model — polled from gateway or simulated locally."""

    def __init__(self, target: str, gateway_url: str = ""):
        self.target = target
        self.gateway_url = gateway_url.rstrip("/")
        self.start_ts = time.time()
        self.scope_locked = True

        # Attack surface
        self.domains: int = 0
        self.live_hosts: int = 0
        self.endpoints: int = 0
        self.apis: int = 0
        self.js_files: int = 0
        self.total_requests: int = 0

        # Agents
        self.agents: Dict[str, str] = {
            "Strategist": "IDLE",
            "Recon":      "IDLE",
            "Web":        "IDLE",
            "Browser":    "IDLE",
            "Verifier":   "IDLE",
        }

        # Activity log  (timestamp_str, message)
        self.activity: List[tuple[str, str]] = []

        # Findings  {id, title, severity, confidence, status}
        self.findings: List[Dict[str, Any]] = []

        # Internal counters
        self.evidence_count: int = 0
        self.hypothesis_count: int = 0
        self.test_count: int = 0

        # Phase
        self.phase: str = "RECON"

    # ── Gateway poll ─────────────────────────────────────────────────────────

    def _get_json(self, path: str) -> Optional[Dict]:
        if not self.gateway_url:
            return None
        try:
            url = f"{self.gateway_url}{path}"
            with urllib.request.urlopen(url, timeout=2) as r:
                return json.loads(r.read())
        except Exception:
            return None

    def refresh(self) -> None:
        """Pulls latest data from gateway. Falls back to simulation if offline."""
        summary = self._get_json("/api/v27/attack-surface")
        health  = self._get_json("/health/integration")
        issues  = self._get_json("/api/issues/export")
        events  = self._get_json("/api/events/recent?limit=20")

        if summary:
            self.domains    = summary.get("total_domains",    self.domains)
            self.live_hosts = summary.get("live_hosts",       self.live_hosts)
            self.endpoints  = summary.get("total_endpoints",  self.endpoints)
            self.apis       = summary.get("api_endpoints",    self.apis)
            self.js_files   = summary.get("js_files",         self.js_files)

        if health:
            self.total_requests = health.get("total_transactions", self.total_requests)
            self.evidence_count = health.get("confirmed_findings",  self.evidence_count)
            # map component health to agent status
            for agent, key in [("Recon", "agent"), ("Browser", "browser")]:
                self.agents[agent] = "RUNNING" if health.get(key) == "PASS" else "IDLE"

        if issues and isinstance(issues, list):
            self.findings = [
                {
                    "id":         f.get("finding_id", "?"),
                    "title":      f.get("title",       "Unknown"),
                    "severity":   f.get("severity",    "INFO"),
                    "confidence": float(f.get("confidence", 0.5)) * 100,
                    "status":     f.get("status",      "UNVERIFIED"),
                }
                for f in issues
            ]
            self.hypothesis_count = len(self.findings)

        if events and isinstance(events, list):
            for ev in events[-5:]:
                ts   = ev.get("timestamp", "")[:5] or datetime.now().strftime("%H:%M")
                msg  = ev.get("data", {}).get("host", ev.get("event_type", "?"))
                entry = (ts, msg)
                if entry not in self.activity:
                    self.activity.append(entry)
            self.activity = self.activity[-50:]  # keep last 50


# ── Widgets ───────────────────────────────────────────────────────────────────

class HeaderBanner(Static):
    """Top banner with target, scope, uptime."""

    state: reactive[HunterState] = reactive(None, recompose=False)

    def __init__(self, state: HunterState) -> None:
        super().__init__()
        self._state = state

    def on_mount(self) -> None:
        self.set_interval(1, self._tick)

    def _tick(self) -> None:
        s = self._state
        elapsed = _elapsed(s.start_ts)
        scope   = "[bold green]● LOCKED[/]" if s.scope_locked else "[bold red]● OPEN[/]"
        phase   = f"[bold cyan]{s.phase}[/]"
        self.update(
            f"[bold white]HUNTEROS[/]  [dim]──[/]  "
            f"[bold white]{s.target}[/]  {scope}  [dim]|[/]  "
            f"Phase: {phase}  [dim]|[/]  "
            f"⏱  [bold white]{elapsed}[/]"
        )


class AttackSurfacePanel(Static):
    """Left column: attack surface metrics."""

    def __init__(self, state: HunterState) -> None:
        super().__init__()
        self._state = state

    def on_mount(self) -> None:
        self.set_interval(2, self._tick)

    def _tick(self) -> None:
        s = self._state
        lines = [
            "[bold underline cyan]ATTACK SURFACE[/]",
            "",
            f"  Domains      [bold white]{s.domains:>5}[/]",
            f"  Live Hosts   [bold green]{s.live_hosts:>5}[/]",
            f"  Endpoints    [bold white]{s.endpoints:>5}[/]",
            f"  APIs         [bold yellow]{s.apis:>5}[/]",
            f"  JS Files     [bold magenta]{s.js_files:>5}[/]",
        ]
        self.update("\n".join(lines))


class AgentStatusPanel(Static):
    """Left column: agent status."""

    STATUS_ICON = {
        "RUNNING": "[bold green]●[/]",
        "IDLE":    "[dim]○[/]",
        "ERROR":   "[bold red]✗[/]",
        "WAITING": "[bold yellow]◌[/]",
    }

    def __init__(self, state: HunterState) -> None:
        super().__init__()
        self._state = state

    def on_mount(self) -> None:
        self.set_interval(1, self._tick)

    def _tick(self) -> None:
        s = self._state
        lines = ["[bold underline cyan]AGENTS[/]", ""]
        for name, status in s.agents.items():
            icon = self.STATUS_ICON.get(status, "○")
            lines.append(f"  {icon} [white]{name:<12}[/] [dim]{status}[/]")
        self.update("\n".join(lines))


class ActivityFeed(RichLog):
    """Right column: scrolling live activity log."""

    BORDER_TITLE = "LIVE ACTIVITY"

    def __init__(self, state: HunterState) -> None:
        super().__init__(highlight=True, markup=True, max_lines=200, wrap=True)
        self._state = state
        self._seen: set[tuple] = set()

    def on_mount(self) -> None:
        self.set_interval(1, self._tick)

    def _tick(self) -> None:
        s = self._state
        for entry in s.activity:
            if entry not in self._seen:
                ts, msg = entry
                self.write(f"[dim]{ts}[/]  {msg}")
                self._seen.add(entry)


class FindingsPanel(Static):
    """Bottom: findings table with confidence."""

    def __init__(self, state: HunterState) -> None:
        super().__init__()
        self._state = state

    def on_mount(self) -> None:
        self.set_interval(2, self._tick)

    def _tick(self) -> None:
        s = self._state
        lines = ["[bold underline cyan]FINDINGS[/]", ""]
        if not s.findings:
            lines.append("  [dim]No findings yet — reconnaissance in progress…[/]")
        else:
            for f in s.findings[-8:]:  # show last 8
                icon = _conf_icon(f["confidence"])
                cid  = f["id"][:6]
                title = f["title"][:36]
                conf  = f"{f['confidence']:.0f}%"
                sev   = f["severity"][:4].upper()
                color = {"CRIT": "red", "HIGH": "orange1", "MEDI": "yellow", "LOW": "cyan"}.get(sev[:4], "white")
                lines.append(
                    f"  {icon}  [dim]{cid}[/]  [{color}]{title:<36}[/]  "
                    f"CONF [bold white]{conf:>4}[/]  [{color}]{sev}[/]"
                )
        self.update("\n".join(lines))


class StatsBar(Static):
    """Bottom stats bar."""

    def __init__(self, state: HunterState) -> None:
        super().__init__()
        self._state = state

    def on_mount(self) -> None:
        self.set_interval(2, self._tick)

    def _tick(self) -> None:
        s = self._state
        self.update(
            f"  Evidence: [bold white]{s.evidence_count}[/]    "
            f"Hypotheses: [bold white]{s.hypothesis_count}[/]    "
            f"Tests: [bold white]{s.test_count}[/]    "
            f"Requests: [bold white]{s.total_requests}[/]"
        )


# ── Main App ──────────────────────────────────────────────────────────────────

class HunterOSApp(App):
    """HunterOS — Autonomous Bug Bounty Operations Dashboard."""

    CSS = """
    Screen {
        background: #0d0d0d;
        color: #e0e0e0;
    }

    HeaderBanner {
        height: 1;
        background: #111827;
        color: #60a5fa;
        padding: 0 2;
        border-bottom: solid #1e3a5f;
    }

    #left-col {
        width: 28;
        min-width: 26;
        border-right: solid #1e3a5f;
        padding: 1 1;
    }

    #right-col {
        width: 1fr;
        padding: 0 1;
    }

    AttackSurfacePanel {
        height: auto;
        margin-bottom: 1;
        border: solid #1e3a5f;
        padding: 1;
    }

    AgentStatusPanel {
        height: auto;
        border: solid #1e3a5f;
        padding: 1;
    }

    ActivityFeed {
        height: 1fr;
        border: solid #1e3a5f;
        padding: 0 1;
    }

    #findings-wrapper {
        height: auto;
        max-height: 16;
        border: solid #1e3a5f;
        padding: 1;
        margin-top: 1;
    }

    FindingsPanel {
        height: auto;
    }

    StatsBar {
        height: 1;
        background: #111827;
        color: #6b7280;
        border-top: solid #1e3a5f;
        padding: 0 2;
    }

    #body {
        height: 1fr;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("r", "refresh", "Refresh Now"),
        Binding("p", "pause",   "Pause/Resume"),
    ]

    TITLE = "HunterOS"
    SUB_TITLE = "Autonomous Bug Bounty Operations"

    def __init__(self, state: HunterState) -> None:
        super().__init__()
        self._state   = state
        self._paused  = False

    def compose(self) -> ComposeResult:
        s = self._state
        yield HeaderBanner(s)
        with Horizontal(id="body"):
            with Vertical(id="left-col"):
                yield AttackSurfacePanel(s)
                yield AgentStatusPanel(s)
            with Vertical(id="right-col"):
                yield ActivityFeed(s)
                with Container(id="findings-wrapper"):
                    yield FindingsPanel(s)
        yield StatsBar(s)
        yield Footer()

    def on_mount(self) -> None:
        # Poll gateway every 3 seconds
        self.set_interval(3, self._poll_gateway)
        # Seed initial activity if no gateway
        if not self._state.gateway_url:
            self._seed_demo()

    def _poll_gateway(self) -> None:
        if not self._paused:
            self._state.refresh()

    def _seed_demo(self) -> None:
        """Populate demo data when running without a live gateway."""
        s = self._state
        s.domains    = 24
        s.live_hosts = 17
        s.endpoints  = 143
        s.apis       = 38
        s.js_files   = 27
        s.total_requests = 892
        s.evidence_count = 32
        s.hypothesis_count = 11
        s.test_count = 47
        s.phase = "ANALYZE"
        s.scope_locked = True

        s.agents = {
            "Strategist": "RUNNING",
            "Recon":      "RUNNING",
            "Web":        "RUNNING",
            "Browser":    "RUNNING",
            "Verifier":   "RUNNING",
        }

        now = datetime.now()
        s.activity = [
            ((now - timedelta(minutes=4)).strftime("%H:%M"), "httpx → 17 hosts live"),
            ((now - timedelta(minutes=3)).strftime("%H:%M"), "Katana → 143 endpoints discovered"),
            ((now - timedelta(minutes=2)).strftime("%H:%M"), "Analyzing API /v1/users"),
            ((now - timedelta(minutes=1)).strftime("%H:%M"), "Playwright session active"),
            (now.strftime("%H:%M"),                          "Testing hypothesis H-004"),
        ]

        s.findings = [
            {"id": "H-004", "title": "IDOR candidate /api/v1/users/{id}", "severity": "HIGH",   "confidence": 94.0, "status": "TESTING"},
            {"id": "H-007", "title": "CORS misconfiguration on /api/*",   "severity": "MEDIUM", "confidence": 81.0, "status": "HYPOTHESIS"},
            {"id": "H-011", "title": "Missing security headers (HSTS)",   "severity": "LOW",    "confidence": 65.0, "status": "HYPOTHESIS"},
        ]

    def action_refresh(self) -> None:
        self._state.refresh()

    def action_pause(self) -> None:
        self._paused = not self._paused
        status = "PAUSED" if self._paused else "RUNNING"
        self.notify(f"Dashboard {status}", timeout=2)


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="HunterOS Terminal Dashboard")
    parser.add_argument("--target",  default="target.com",         help="Target domain")
    parser.add_argument("--gateway", default="",                   help="BurpGateway URL e.g. http://localhost:8719")
    args = parser.parse_args()

    state = HunterState(target=args.target, gateway_url=args.gateway)
    app   = HunterOSApp(state=state)
    app.run()


if __name__ == "__main__":
    main()
