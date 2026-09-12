"""
HunterAI Assessment Dashboard Generator
=======================================
Renders the real-time and post-assessment operational dashboard:
Scope, Mode, Attack Surface Metrics, Findings Breakdown, Evidence Quality, Safety Statistics
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class DashboardMetrics:
    scope_domain: str = "example.local"
    mode: str = "Passive"
    endpoints_count: int = 0
    parameters_count: int = 0
    js_files_count: int = 0
    api_routes_count: int = 0
    confirmed_findings: int = 0
    probable_findings: int = 0
    rejected_findings: int = 0
    complete_evidence_count: int = 0
    incomplete_evidence_count: int = 0
    reproducible_count: int = 0
    out_of_scope_violations: int = 0
    blocked_requests_count: int = 0
    approval_gates_count: int = 0

    def render_terminal_dashboard(self) -> str:
        sep = "═" * 48
        sub = "─" * 48
        return f"""{sep}
 🚀 HunterAI Assessment Dashboard
{sep}
 Scope:   {self.scope_domain}
 Mode:    {self.mode}
{sub}
 Attack Surface Discovery
   • Endpoints:        {self.endpoints_count:>6}
   • Parameters:       {self.parameters_count:>6}
   • JS Files:         {self.js_files_count:>6}
   • API Routes:       {self.api_routes_count:>6}
{sub}
 Findings Breakdown
   • Confirmed:        {self.confirmed_findings:>6}
   • Probable:         {self.probable_findings:>6}
   • Rejected (FPs):   {self.rejected_findings:>6}
{sub}
 Evidence & Reproducibility
   • Complete PoE:     {self.complete_evidence_count:>6}
   • Incomplete:       {self.incomplete_evidence_count:>6}
   • Reproducible:     {self.reproducible_count:>6}
{sub}
 Safety & Governance
   • Out-of-scope:     {self.out_of_scope_violations:>6}
   • Blocked requests: {self.blocked_requests_count:>6}
   • Approval gates:   {self.approval_gates_count:>6}
{sep}"""
