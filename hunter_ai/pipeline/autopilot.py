"""
HunterAI Autopilot — Full Autonomous Hunt Loop
==============================================
scope → recon → rank → hunt → validate → report
"""
from __future__ import annotations

import asyncio
from typing import Any, Dict


async def run_autopilot(target: str) -> Dict[str, Any]:
    """Run the full autonomous hunt loop."""
    print(f"[Autopilot] Starting full hunt loop for {target}")
    state: Dict[str, Any] = {
        "target": target,
        "phase": "scope",
        "steps": [],
        "findings": [],
        "report": None,
    }

    # Step 1: Scope
    print("[Autopilot] Phase 1: Scope validation")
    from hunter_ai.core.scope_engine import StrictScopeEngine
    engine = StrictScopeEngine()
    if not engine.is_allowed(target):
        state["phase"] = "blocked"
        print("[Autopilot] Target out of scope — aborting")
        return state
    state["steps"].append("scope ✅")

    # Step 2: Recon
    print("[Autopilot] Phase 2: Recon")
    from hunter_ai.pipeline.recon_engine import run_recon
    recon = await run_recon(target)
    state["steps"].append("recon ✅")
    state["recon"] = recon

    # Step 3: Rank surface
    print("[Autopilot] Phase 3: Rank attack surface")
    from hunter_ai.pipeline.recon_engine import surface_summary
    state["surface"] = surface_summary(target)
    state["steps"].append("surface-rank ✅")

    # Step 4: Hunt
    print("[Autopilot] Phase 4: Hunt vulnerabilities")
    from hunter_ai.pipeline.hunt_engine import run_hunt
    hunt = await run_hunt(target, mode="full", authorized=True)
    state["steps"].append("hunt ✅")
    state["findings"] = hunt.get("findings", [])

    # Step 5: Validate each finding
    print("[Autopilot] Phase 5: Validate findings")
    from hunter_ai.validation_gate import ValidationGate
    gate = ValidationGate()
    proven = []
    for f in state["findings"]:
        r = gate.validate(f)
        if r["status"] == "PROVEN":
            proven.append(f)
    state["steps"].append(f"validate ✅ ({len(proven)} proven)")

    # Step 6: Report
    print("[Autopilot] Phase 6: Generate reports")
    from hunter_ai.report_writer import ReportWriter
    writer = ReportWriter(platform="hackerone")
    for f in proven:
        path = writer.generate(target, f)
        print(f"  📄 {path}")
    state["steps"].append("report ✅")
    state["phase"] = "complete"

    print(f"\n[Autopilot] Complete! {len(proven)} findings ready to report")
    return state


__all__ = ["run_autopilot"]
