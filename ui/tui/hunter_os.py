"""
HunterOS — Terminal Security Operations Dashboard v2
=====================================================
Strix-style TUI for HunterAI with tabbed views:
  Tab 1: Overview  — Attack Surface + Agents + Live Activity + Findings
  Tab 2: Trace     — Live Agent Trace (WHO did WHAT and WHY)
  Tab 3: Requests  — Request/Response recorder log
  Tab 4: Evidence  — Hypothesis lifecycle tracker

Launch:
    python ui/tui/hunter_os.py --target target.com
    python ui/tui/hunter_os.py --target target.com --gateway http://localhost:8719

Keybindings:
    1-4  Switch tabs
    r    Refresh now
    p    Pause/Resume
    q    Quit
"""

from __future__ import annotations

import argparse
import json
import time
import urllib.request
import urllib.error
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.reactive import reactive
from textual.widgets import (
    ContentSwitcher,
    Footer,
    Label,
    RichLog,
    Static,
    Tab,
    Tabs,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _elapsed(start_ts: float) -> str:
    delta = int(time.time() - start_ts)
    h, rem = divmod(delta, 3600)
    m, s = divmod(rem, 60)
    return f"{h:02d}:{m:02d}:{s:02d}"


def _conf_icon(pct: float) -> str:
    if pct >= 95: return "🔴"
    if pct >= 80: return "🟠"
    if pct >= 60: return "🟡"
    return "🟢"


def _sev_color(sev: str) -> str:
    return {"CRITICAL": "red", "HIGH": "orange1", "MEDIUM": "yellow", "LOW": "cyan"}.get(sev.upper(), "white")


# ── Live Data Model ───────────────────────────────────────────────────────────

class HunterState:
    """Central engagement state — polled from gateway or seeded with demo data."""

    def __init__(self, target: str, gateway_url: str = ""):
        self.target = target
        self.gateway_url = gateway_url.rstrip("/")
        self.start_ts = time.time()
        self.scope_locked = True
        self.phase = "RECON"

        # Attack surface
        self.domains: int = 0
        self.live_hosts: int = 0
        self.endpoints: int = 0
        self.apis: int = 0
        self.js_files: int = 0
        self.total_requests: int = 0

        # Agents status
        self.agents: Dict[str, str] = {
            "Strategist": "IDLE",
            "Recon":      "IDLE",
            "Web":        "IDLE",
            "Browser":    "IDLE",
            "Verifier":   "IDLE",
        }

        # Activity feed (ts, message)
        self.activity: List[Tuple[str, str]] = []

        # Agent trace (ts, agent, message)
        self.agent_trace: List[Dict] = []

        # Request log (req_id, method, url, status, agent, ts)
        self.request_log: List[Dict] = []

        # Hypotheses
        self.hypotheses: List[Dict] = []

        # Findings
        self.findings: List[Dict] = []

        # Stats
        self.evidence_count: int = 0
        self.hypothesis_count: int = 0
        self.test_count: int = 0

    # ── Gateway polling ───────────────────────────────────────────────────────

    def _get_json(self, path: str) -> Optional[Any]:
        if not self.gateway_url:
            return None
        try:
            with urllib.request.urlopen(f"{self.gateway_url}{path}", timeout=2) as r:
                return json.loads(r.read())
        except Exception:
            return None

    def refresh(self) -> None:
        summary = self._get_json("/api/v27/attack-surface")
        health  = self._get_json("/health/integration")
        issues  = self._get_json("/api/issues/export")
        events  = self._get_json("/api/events/recent?limit=20")

        if summary:
            self.domains    = summary.get("total_domains",   self.domains)
            self.live_hosts = summary.get("live_hosts",      self.live_hosts)
            self.endpoints  = summary.get("total_endpoints", self.endpoints)
            self.apis       = summary.get("api_endpoints",   self.apis)
            self.js_files   = summary.get("js_files",        self.js_files)

        if health:
            self.total_requests = health.get("total_transactions", self.total_requests)
            self.evidence_count = health.get("confirmed_findings",  self.evidence_count)

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

        if events and isinstance(events, list):
            for ev in events[-5:]:
                ts  = ev.get("timestamp", "")[:5] or datetime.now().strftime("%H:%M")
                msg = ev.get("data", {}).get("host", ev.get("event_type", "?"))
                entry = (ts, msg)
                if entry not in self.activity:
                    self.activity.append(entry)
            self.activity = self.activity[-100:]


# ── Panels ────────────────────────────────────────────────────────────────────

class HeaderBar(Static):
    def __init__(self, state: HunterState) -> None:
        super().__init__()
        self._state = state

    def on_mount(self) -> None:
        self.set_interval(1, self._tick)

    def _tick(self) -> None:
        s = self._state
        scope_badge = "[bold green]● LOCKED[/]" if s.scope_locked else "[bold red]● OPEN[/]"
        self.update(
            f" [bold white]HUNTEROS[/]  [dim]│[/]  [bold cyan]{s.target}[/]  {scope_badge}"
            f"  [dim]│[/]  Phase: [bold yellow]{s.phase}[/]"
            f"  [dim]│[/]  ⏱  [bold white]{_elapsed(s.start_ts)}[/]"
        )


# ── TAB 1: Overview ───────────────────────────────────────────────────────────

class AttackSurfaceWidget(Static):
    def __init__(self, state: HunterState) -> None:
        super().__init__()
        self._state = state

    def on_mount(self) -> None:
        self.set_interval(2, self._tick)

    def _tick(self) -> None:
        s = self._state
        self.update(
            "[bold underline cyan]ATTACK SURFACE[/]\n\n"
            f"  Domains      [bold white]{s.domains:>5}[/]\n"
            f"  Live Hosts   [bold green]{s.live_hosts:>5}[/]\n"
            f"  Endpoints    [bold white]{s.endpoints:>5}[/]\n"
            f"  APIs         [bold yellow]{s.apis:>5}[/]\n"
            f"  JS Files     [bold magenta]{s.js_files:>5}[/]"
        )


class AgentsWidget(Static):
    ICONS = {"RUNNING": "[bold green]●[/]", "IDLE": "[dim]○[/]",
             "STALLED": "[bold red]✗[/]", "WAITING": "[bold yellow]◌[/]", "DONE": "[bold blue]✓[/]"}

    def __init__(self, state: HunterState) -> None:
        super().__init__()
        self._state = state

    def on_mount(self) -> None:
        self.set_interval(1, self._tick)

    def _tick(self) -> None:
        lines = ["[bold underline cyan]AGENTS[/]\n"]
        for name, status in self._state.agents.items():
            icon = self.ICONS.get(status, "○")
            lines.append(f"  {icon} [white]{name:<12}[/] [dim]{status}[/]")
        self.update("\n".join(lines))


class ActivityWidget(RichLog):
    BORDER_TITLE = "LIVE ACTIVITY"

    def __init__(self, state: HunterState) -> None:
        super().__init__(highlight=True, markup=True, max_lines=300, wrap=True)
        self._state = state
        self._seen: set = set()

    def on_mount(self) -> None:
        self.set_interval(1, self._tick)

    def _tick(self) -> None:
        for entry in self._state.activity:
            if entry not in self._seen:
                ts, msg = entry
                self.write(f"[dim]{ts}[/]  {msg}")
                self._seen.add(entry)


class FindingsWidget(Static):
    def __init__(self, state: HunterState) -> None:
        super().__init__()
        self._state = state

    def on_mount(self) -> None:
        self.set_interval(2, self._tick)

    def _tick(self) -> None:
        s = self._state
        lines = ["[bold underline cyan]FINDINGS[/]\n"]
        if not s.findings:
            lines.append("  [dim]No findings yet — reconnaissance in progress…[/]")
        else:
            for f in s.findings[-10:]:
                icon  = _conf_icon(f["confidence"])
                color = _sev_color(f["severity"])
                title = f["title"][:38]
                conf  = f"{f['confidence']:.0f}%"
                lines.append(
                    f"  {icon}  [dim]{f['id'][:6]}[/]  [{color}]{title:<38}[/]  "
                    f"CONF [bold white]{conf:>4}[/]  [{color}]{f['severity'][:4]}[/]"
                )
        self.update("\n".join(lines))


class StatsBar(Static):
    def __init__(self, state: HunterState) -> None:
        super().__init__()
        self._state = state

    def on_mount(self) -> None:
        self.set_interval(2, self._tick)

    def _tick(self) -> None:
        s = self._state
        self.update(
            f"  Evidence: [bold white]{s.evidence_count}[/]"
            f"    Hypotheses: [bold white]{s.hypothesis_count}[/]"
            f"    Tests: [bold white]{s.test_count}[/]"
            f"    Requests: [bold white]{s.total_requests}[/]"
        )


class OverviewTab(Container):
    def __init__(self, state: HunterState) -> None:
        super().__init__(id="tab-overview")
        self._state = state

    def compose(self) -> ComposeResult:
        s = self._state
        with Horizontal():
            with Vertical(id="left-col"):
                yield AttackSurfaceWidget(s)
                yield AgentsWidget(s)
            with Vertical(id="right-col"):
                yield ActivityWidget(s)
                with Container(id="findings-box"):
                    yield FindingsWidget(s)
        yield StatsBar(s)


# ── TAB 2: Agent Trace ────────────────────────────────────────────────────────

class AgentTraceTab(Container):
    """
    Shows full agent reasoning chain:
    14:02:11  Strategist   └─ identified CDN endpoint
    14:02:14  Recon        └─ discovered 17 hosts
    """

    def __init__(self, state: HunterState) -> None:
        super().__init__(id="tab-trace")
        self._state = state

    def compose(self) -> ComposeResult:
        yield Label("[bold cyan]LIVE AGENT TRACE[/]  [dim](why each agent did what it did)[/]", id="trace-title")
        yield RichLog(highlight=True, markup=True, max_lines=500, wrap=True, id="trace-log")

    def on_mount(self) -> None:
        self._seen_trace: set = set()
        self.set_interval(1, self._tick)

    def _tick(self) -> None:
        log = self.query_one("#trace-log", RichLog)
        for entry in self._state.agent_trace:
            key = (entry.get("ts"), entry.get("agent"), entry.get("message"))
            if key not in self._seen_trace:
                ts    = entry.get("ts", "??:??:??")
                agent = entry.get("agent", "?")
                msg   = entry.get("message", "")
                color = {
                    "Strategist": "bold cyan",
                    "Recon":      "bold green",
                    "Web":        "bold yellow",
                    "Browser":    "bold magenta",
                    "Verifier":   "bold orange1",
                    "Evidence":   "bold blue",
                    "Verdict":    "bold red",
                }.get(agent, "white")
                log.write(f"[dim]{ts}[/]  [{color}]{agent:<12}[/]  [dim]└─[/] {msg}")
                self._seen_trace.add(key)


# ── TAB 3: Requests ───────────────────────────────────────────────────────────

class RequestsTab(Container):
    """Request/Response recorder log with REQ-XXXXXX IDs."""

    def __init__(self, state: HunterState) -> None:
        super().__init__(id="tab-requests")
        self._state = state

    def compose(self) -> ComposeResult:
        yield Label(
            "[bold cyan]REQUEST LOG[/]  [dim]All HTTP interactions with REQ-ID tracking[/]",
            id="req-title"
        )
        yield RichLog(highlight=True, markup=True, max_lines=500, wrap=False, id="req-log")

    def on_mount(self) -> None:
        self._seen_reqs: set = set()
        self.set_interval(1, self._tick)

    def _tick(self) -> None:
        log = self.query_one("#req-log", RichLog)
        for req in self._state.request_log:
            req_id = req.get("req_id", "REQ-?")
            if req_id not in self._seen_reqs:
                method  = req.get("method", "GET")
                url     = req.get("url", "?")[:60]
                status  = req.get("status_code", 0)
                agent   = req.get("agent", "?")
                ts      = req.get("ts", "?")
                status_color = "green" if 200 <= status < 300 else ("yellow" if 300 <= status < 400 else "red")
                log.write(
                    f"[dim]{ts}[/]  [bold white]{req_id}[/]  "
                    f"[bold cyan]{method:<6}[/]  [{status_color}]{status}[/]  "
                    f"[dim]{agent:<12}[/]  {url}"
                )
                self._seen_reqs.add(req_id)


# ── TAB 4: Evidence / Hypotheses ──────────────────────────────────────────────

class EvidenceTab(Container):
    """Hypothesis lifecycle tracker."""

    def __init__(self, state: HunterState) -> None:
        super().__init__(id="tab-evidence")
        self._state = state

    def compose(self) -> ComposeResult:
        yield Label("[bold cyan]HYPOTHESIS ENGINE[/]  [dim]Observation → Hypothesis → Experiment → Verdict[/]")
        yield Static("", id="hyp-table")

    def on_mount(self) -> None:
        self.set_interval(2, self._tick)

    def _tick(self) -> None:
        widget = self.query_one("#hyp-table", Static)
        s = self._state
        if not s.hypotheses:
            widget.update("[dim]  No active hypotheses. Recon in progress…[/]")
            return

        STATUS_COLOR = {
            "CREATED": "dim", "ASSIGNED": "cyan", "DESIGNING": "yellow",
            "TESTING": "orange1", "EVIDENCE": "blue", "VERIFIED": "bold green",
            "REJECTED": "dim red", "INCONCLUSIVE": "dim yellow",
        }
        lines = [
            f"  {'ID':<8}  {'TYPE':<22}  {'STATUS':<18}  {'CONF':>5}  ENDPOINT",
            f"  {'─'*8}  {'─'*22}  {'─'*18}  {'─'*5}  {'─'*40}",
        ]
        for h in s.hypotheses[-15:]:
            hid    = h.get("hyp_id", "H-???")[:8]
            vtype  = h.get("vuln_type", "UNKNOWN")[:22]
            status = h.get("status", "?")
            conf   = f"{h.get('confidence', 0)*100:.0f}%"
            ep     = h.get("endpoint", "?")[:40]
            color  = STATUS_COLOR.get(status, "white")
            icon   = _conf_icon(h.get("confidence", 0) * 100)
            lines.append(
                f"  {icon} [dim]{hid}[/]  [bold white]{vtype:<22}[/]  [{color}]{status:<18}[/]  "
                f"[bold white]{conf:>5}[/]  [dim]{ep}[/]"
            )
        widget.update("\n".join(lines))


# ── Main App ──────────────────────────────────────────────────────────────────

class HunterOSApp(App):
    """HunterOS v2 — Security Assessment Operating System Dashboard."""

    CSS = """
    Screen {
        background: #0a0a0f;
        color: #e0e0e0;
    }
    HeaderBar {
        height: 1;
        background: #0f1923;
        color: #60a5fa;
        padding: 0 1;
        border-bottom: solid #1e3a5f;
        dock: top;
    }
    Tabs {
        dock: top;
        background: #0f1923;
        border-bottom: solid #1e3a5f;
    }
    Tab {
        background: #0f1923;
        color: #6b7280;
    }
    Tab.-active {
        background: #1e3a5f;
        color: #60a5fa;
    }
    ContentSwitcher {
        height: 1fr;
    }
    #tab-overview {
        height: 100%;
    }
    #tab-trace, #tab-requests, #tab-evidence {
        height: 100%;
        padding: 1;
    }
    #left-col {
        width: 28;
        border-right: solid #1e3a5f;
        padding: 1;
    }
    #right-col {
        width: 1fr;
        padding: 0 1;
    }
    AttackSurfaceWidget {
        height: auto;
        border: solid #1e3a5f;
        padding: 1;
        margin-bottom: 1;
    }
    AgentsWidget {
        height: auto;
        border: solid #1e3a5f;
        padding: 1;
    }
    ActivityWidget {
        height: 1fr;
        border: solid #1e3a5f;
        padding: 0 1;
    }
    #findings-box {
        height: auto;
        max-height: 14;
        border: solid #1e3a5f;
        padding: 1;
        margin-top: 1;
    }
    StatsBar {
        height: 1;
        background: #0f1923;
        color: #6b7280;
        border-top: solid #1e3a5f;
        dock: bottom;
    }
    #trace-title, #req-title {
        height: 1;
        margin-bottom: 1;
        color: #60a5fa;
    }
    #trace-log, #req-log {
        height: 1fr;
        border: solid #1e3a5f;
    }
    #hyp-table {
        height: 1fr;
        border: solid #1e3a5f;
        padding: 1;
    }
    """

    BINDINGS = [
        Binding("q", "quit",    "Quit"),
        Binding("r", "refresh", "Refresh"),
        Binding("p", "pause",   "Pause"),
        Binding("1", "show_tab('tab-overview')", "Overview"),
        Binding("2", "show_tab('tab-trace')",    "Trace"),
        Binding("3", "show_tab('tab-requests')", "Requests"),
        Binding("4", "show_tab('tab-evidence')", "Evidence"),
    ]

    TITLE = "HunterOS"
    SUB_TITLE = "Security Assessment Operating System"

    def __init__(self, state: HunterState) -> None:
        super().__init__()
        self._state   = state
        self._paused  = False

    def compose(self) -> ComposeResult:
        s = self._state
        yield HeaderBar(s)
        yield Tabs(
            Tab("① Overview",  id="tab-overview"),
            Tab("② Trace",     id="tab-trace"),
            Tab("③ Requests",  id="tab-requests"),
            Tab("④ Evidence",  id="tab-evidence"),
        )
        with ContentSwitcher(initial="tab-overview"):
            yield OverviewTab(s)
            yield AgentTraceTab(s)
            yield RequestsTab(s)
            yield EvidenceTab(s)
        yield Footer()

    def on_mount(self) -> None:
        self.set_interval(3, self._poll)
        if not self._state.gateway_url:
            self._seed_demo()

    def on_tabs_tab_activated(self, event: Tabs.TabActivated) -> None:
        self.query_one(ContentSwitcher).current = event.tab.id

    def action_show_tab(self, tab_id: str) -> None:
        self.query_one(Tabs).active = tab_id

    def _poll(self) -> None:
        if not self._paused:
            self._state.refresh()

    def action_refresh(self) -> None:
        self._state.refresh()
        self.notify("Refreshed", timeout=1)

    def action_pause(self) -> None:
        self._paused = not self._paused
        self.notify("PAUSED" if self._paused else "RUNNING", timeout=2)

    def _seed_demo(self) -> None:
        """Demo data for running without a live gateway."""
        s = self._state
        s.domains = 24; s.live_hosts = 17; s.endpoints = 143
        s.apis = 38; s.js_files = 27; s.total_requests = 892
        s.evidence_count = 32; s.hypothesis_count = 11
        s.test_count = 47; s.phase = "ANALYZE"

        s.agents = {
            "Strategist": "RUNNING", "Recon": "RUNNING",
            "Web": "RUNNING", "Browser": "RUNNING", "Verifier": "RUNNING",
        }

        now = datetime.now()
        s.activity = [
            ((now - timedelta(minutes=4)).strftime("%H:%M"), "httpx → 17 hosts live"),
            ((now - timedelta(minutes=3)).strftime("%H:%M"), "Katana → 143 endpoints"),
            ((now - timedelta(minutes=2)).strftime("%H:%M"), "Analyzing API /v1/users"),
            ((now - timedelta(minutes=1)).strftime("%H:%M"), "Playwright session active"),
            (now.strftime("%H:%M"),                          "Testing hypothesis H-004"),
        ]

        # Agent trace (Tab 2)
        s.agent_trace = [
            {"ts": (now - timedelta(minutes=5, seconds=49)).strftime("%H:%M:%S"), "agent": "Strategist", "message": "identified CDN endpoint, dispatching Recon"},
            {"ts": (now - timedelta(minutes=5, seconds=46)).strftime("%H:%M:%S"), "agent": "Recon",      "message": "discovered 17 live hosts via httpx"},
            {"ts": (now - timedelta(minutes=5, seconds=39)).strftime("%H:%M:%S"), "agent": "Recon",      "message": "subfinder found 24 subdomains"},
            {"ts": (now - timedelta(minutes=5, seconds=21)).strftime("%H:%M:%S"), "agent": "Web",        "message": "katana crawled → 143 endpoints discovered"},
            {"ts": (now - timedelta(minutes=5, seconds=15)).strftime("%H:%M:%S"), "agent": "Web",        "message": "detected object identifier in /api/v1/users/{id}"},
            {"ts": (now - timedelta(minutes=5, seconds=9)).strftime("%H:%M:%S"),  "agent": "Browser",    "message": "opened authenticated Playwright session"},
            {"ts": (now - timedelta(minutes=5, seconds=3)).strftime("%H:%M:%S"),  "agent": "Strategist", "message": "hypothesis H-004 generated: IDOR candidate"},
            {"ts": (now - timedelta(minutes=4, seconds=56)).strftime("%H:%M:%S"), "agent": "Verifier",   "message": "preparing differential test: swap user_id between account A/B"},
            {"ts": (now - timedelta(minutes=4, seconds=40)).strftime("%H:%M:%S"), "agent": "Evidence",   "message": "E-093 created: request A + request B captured"},
            {"ts": (now - timedelta(minutes=4, seconds=20)).strftime("%H:%M:%S"), "agent": "Verdict",    "message": "H-004 → CONFIDENCE 94% — SUSPECTED IDOR"},
        ]

        # Request log (Tab 3)
        import uuid
        reqs = [
            ("GET",  "https://target.com/api/v1/users/100",  200, "Web"),
            ("GET",  "https://target.com/api/v1/users/101",  200, "Verifier"),
            ("POST", "https://target.com/api/v1/payment",    403, "Web"),
            ("GET",  "https://target.com/.well-known/cors",  200, "Recon"),
            ("GET",  "https://target.com/api/v1/admin",      401, "Verifier"),
        ]
        for i, (method, url, status, agent) in enumerate(reqs):
            ts = (now - timedelta(minutes=5 - i)).strftime("%H:%M:%S")
            s.request_log.append({
                "req_id": f"REQ-{uuid.uuid4().hex[:6].upper()}",
                "method": method, "url": url,
                "status_code": status,
                "agent": agent, "ts": ts,
            })

        # Hypotheses (Tab 4)
        s.hypotheses = [
            {"hyp_id": "H-004", "vuln_type": "IDOR",               "status": "TESTING",      "confidence": 0.94, "endpoint": "/api/v1/users/{id}"},
            {"hyp_id": "H-007", "vuln_type": "CORS_MISCONFIGURATION","status": "EVIDENCE",   "confidence": 0.81, "endpoint": "/api/*"},
            {"hyp_id": "H-011", "vuln_type": "MISSING_HEADER",      "status": "HYPOTHESIS",  "confidence": 0.65, "endpoint": "*.target.com"},
            {"hyp_id": "H-015", "vuln_type": "OPEN_REDIRECT",       "status": "ASSIGNED",    "confidence": 0.55, "endpoint": "/login?next="},
        ]

        # Confirmed finding
        s.findings = [
            {"id": "H-004", "title": "IDOR candidate /api/v1/users/{id}",      "severity": "HIGH",   "confidence": 94.0, "status": "TESTING"},
            {"id": "H-007", "title": "CORS misconfiguration on /api/*",         "severity": "MEDIUM", "confidence": 81.0, "status": "HYPOTHESIS"},
            {"id": "H-011", "title": "Missing security headers (HSTS, CSP)",    "severity": "LOW",    "confidence": 65.0, "status": "HYPOTHESIS"},
        ]


# ── Entry Point ───────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="HunterOS — Security Assessment Dashboard")
    parser.add_argument("--target",  default="target.com", help="Target domain")
    parser.add_argument("--gateway", default="",           help="BurpGateway URL e.g. http://localhost:8719")
    args = parser.parse_args()

    state = HunterState(target=args.target, gateway_url=args.gateway)
    HunterOSApp(state=state).run()


if __name__ == "__main__":
    main()
