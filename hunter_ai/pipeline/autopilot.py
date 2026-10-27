"""
HunterAI Autopilot — Full Autonomous Hunt Loop
===============================================
scope → recon → rank → plan(TDA) → hunt(ATT&CK) → validate → report

Intégrates all 6 agent-intelligence techniques:
1. Difficulty-Aware Planning (TDA) — decide EXPLOIT vs EXPLORE per technique
2. Guided Reasoning (MITRE ATT&CK) — deterministic task tree
3. Structured Memory — working / semantic / failure-episodic
4. RAG — knowledge retrieval from CWE / MITRE / OWASP
5. Multi-Agent Orchestration — global orchestrator / executor / reviewer
6. Neuro-Symbolic Safety Loop — deterministic safety check before execution
"""
from __future__ import annotations

import asyncio
import time
from typing import Any, Dict, List


async def run_autopilot(target: str) -> Dict[str, Any]:
    """Run the full autonomous hunt loop with all 6 intelligence techniques."""
    print(f"[Autopilot] Starting full hunt loop for {target}")
    state: Dict[str, Any] = {
        "target": target,
        "phase": "scope",
        "steps": [],
        "findings": [],
        "report": None,
        "techniques_attempted": [],
        "decisions": [],
    }

    # ══════════════════════════════════════════════════════════════════════════════
    # Phase 1: Scope validation (with Neuro-Symbolic Safety)
    # ══════════════════════════════════════════════════════════════════════════════
    print("[Autopilot] Phase 1: Scope validation")
    from hunter_ai.core.scope_engine import StrictScopeEngine
    engine = StrictScopeEngine()
    if not engine.is_allowed(target):
        state["phase"] = "blocked"
        print("[Autopilot] Target out of scope — aborting")
        return state
    state["steps"].append("scope ✅")

    # Initialize safety knowledge graph and mark target in scope
    from hunter_ai.safety.neuro_symbolic_loop import KnowledgeGraph, NeuroSymbolicSafetyLoop
    kg = KnowledgeGraph()
    kg.add_in_scope(target)
    safety = NeuroSymbolicSafetyLoop(kg)

    # ══════════════════════════════════════════════════════════════════════════════
    # Phase 2: Recon
    # ══════════════════════════════════════════════════════════════════════════════
    print("[Autopilot] Phase 2: Recon")
    from hunter_ai.pipeline.recon_engine import run_recon
    recon = await run_recon(target)
    state["steps"].append("recon ✅")
    state["recon"] = recon

    # ══════════════════════════════════════════════════════════════════════════════
    # Phase 3: Rank attack surface
    # ══════════════════════════════════════════════════════════════════════════════
    print("[Autopilot] Phase 3: Rank attack surface")
    from hunter_ai.pipeline.recon_engine import surface_summary
    state["surface"] = surface_summary(target)
    state["steps"].append("surface-rank ✅")

    # ══════════════════════════════════════════════════════════════════════════════
    # Phase 4: Initialize intelligence subsystems
    # ══════════════════════════════════════════════════════════════════════════════
    print("[Autopilot] Phase 4: Initialize TDA, Memory, RAG, Orchestrator")
    from hunter_ai.planning.difficulty_assessor import TaskDifficultyAssessor
    from hunter_ai.planning.mitre_tree import MITREATTACKTree
    from hunter_ai.memory.structured_memory import StructuredMemory, MemoryType
    from hunter_ai.knowledge.rag_engine import RAGEngine
    from hunter_ai.orchestration.multi_agent_orchestrator import (
        MultiAgentOrchestrator, AgentRole, TaskStatus,
    )

    assessor = TaskDifficultyAssessor()
    mitre = MITREATTACKTree()
    memory = StructuredMemory()
    rag = RAGEngine()
    orch = MultiAgentOrchestrator()

    # Load past failures from memory to avoid repeating
    past_failures = memory.get_failures(target)
    failed_techniques = {f.value.get("technique", "") for f in past_failures if f.value}
    if failed_techniques:
        print(f"[Autopilot] Learned from {len(failed_techniques)} past failures: {failed_techniques}")
        state["steps"].append(f"memory-loaded ({len(failed_techniques)} failures)")

    # ══════════════════════════════════════════════════════════════════════════════

    # ═══════════════════════════════════════════════════════════════════════════════
    # Phase 4.5: WAF Detection & Bypass
    # ═══════════════════════════════════════════════════════════════════════════════
    print("[Autopilot] Phase 4.5: WAF Detection & Bypass")
    from hunter_ai.waf.fingerprint_spoofing import FingerprintSpoofer
    spoofer = FingerprintSpoofer()
    fp_result = spoofer.test_spoofing(target, "chrome_win10")
    state["waf_fingerprint"] = fp_result
    if fp_result.get("status") == "READY":
        print(f"[Autopilot] WAF fingerprint spoofing ready: {fp_result['spoofing_result']['profile_name']}")
    state["steps"].append("waf-fingerprint ✅")

    # تجربة سلم التجاوز إذا كان هناك WAF مشتبه
    ladder = WAFBypassLadder(safety_loop=safety)
    ladder_result = ladder.run_ladder(
        target=target,
        original_payload="<script>alert(1)</script>",
    )
    state["waf_ladder"] = ladder_result.to_dict()
    if ladder_result.successful_step:
        print(f"[Autopilot] WAF bypass successful at level {ladder_result.successful_step['level']}: {ladder_result.successful_step['name']}")
    else:
        print(f"[Autopilot] WAF bypass ladder completed - {len(ladder_result.steps)} levels tested")
    state["steps"].append("waf-bypass-ladder ✅")

    # Phase 5: Hunt with TDA + MITRE + RAG + Orchestrator + Safety
    # ══════════════════════════════════════════════════════════════════════════════
    print("[Autopilot] Phase 5: Hunt vulnerabilities (guided by ATT&CK + TDA + RAG)")
    from hunter_ai.pipeline.hunt_engine import run_hunt
    hunt = await run_hunt(target, mode="full", authorized=True)
    state["steps"].append("hunt ✅")
    state["findings"] = hunt.get("findings", [])

    # Apply TDA to each technique from the hunt results
    techniques_to_try = [
        ("T1190.001", "sqli", 30, 0.6, 0.3),
        ("T1190.002", "xss", 20, 0.5, 0.4),
        ("T1190.003", "ssrf", 25, 0.4, 0.5),
        ("T1190.004", "idor", 35, 0.7, 0.2),
        ("T1552.001", "secrets", 15, 0.8, 0.2),
    ]

    for technique_id, technique_name, duration, confidence, context_pct in techniques_to_try:
        # Skip techniques that failed in the past (failure-episodic memory)
        if technique_name in failed_techniques:
            print(f"[Autopilot] Skipping {technique_name} — failed previously (failure memory)")
            continue

        # RAG: retrieve knowledge about this technique
        rag_results = rag.retrieve(query=technique_name, top_k=2, source_filter="mitre")
        if rag_results:
            print(f"[Autopilot] RAG knowledge for {technique_name}: {rag_results[0].title} (score={rag_results[0].score:.2f})")

        # TDA: assess difficulty
        current_findings = len([f for f in state["findings"] if technique_name in str(f).lower()])
        assessment = assessor.assess(
            task_id=f"hunt-{technique_name}",
            target=target,
            technique=technique_name,
            expected_duration_min=duration,
            evidence_confidence=confidence,
            context_consumed_pct=context_pct,
            current_findings=current_findings,
        )
        state["decisions"].append(assessment.to_dict())
        state["techniques_attempted"].append(technique_name)

        print(f"[Autopilot] TDA for {technique_name}: {assessment.decision.value} "
              f"(difficulty={assessment.difficulty.value}, score={assessment.score:.2f})")

        if assessment.decision.value == "explore":
            print(f"[Autopilot]  → Switching away from {technique_name} (EXPLORE)")
            continue

        # Safety check before executing technique
        check_cmd = f"hunt-{technique_name} --target {target}"
        safety_result = safety.check_command(check_cmd, target, require_proof=False)
        if safety_result.verdict.value != "ALLOWED":
            print(f"[Autopilot]  → BLOCKED by safety: {safety_result.reason}")
            memory.record_failure(target, technique_name, safety_result.reason)
            continue

        # Create orchestration task
        task = orch.create_task(
            target=target,
            role=AgentRole.EXECUTOR,
            description=f"Hunt {technique_name} on {target}",
            technique=technique_id,
        )
        orch.assign_task(task.task_id, "ReconAgent")

        # Simulate execution result (real implementation would call the tool)
        succeeded = current_findings > 0  # simplified heuristic
        orch.complete_task(
            task_id=task.task_id,
            agent_name="ReconAgent",
            output={"technique": technique_name, "assessment": assessment.to_dict()},
            evidence={"safety": safety_result.to_dict()},
            findings=[f for f in state["findings"] if technique_name in str(f).lower()],
        )

        if not succeeded:
            memory.record_failure(target, technique_name, "No findings produced")
            assessor.record_outcome(technique_name, False)
        else:
            assessor.record_outcome(technique_name, True)

    # ══════════════════════════════════════════════════════════════════════════════
    # Phase 6: Validate each finding (with Neuro-Symbolic Safety)
    # ══════════════════════════════════════════════════════════════════════════════
    print("[Autopilot] Phase 6: Validate findings")
    from hunter_ai.validation_gate import ValidationGate
    gate = ValidationGate()
    proven = []
    for f in state["findings"]:
        r = gate.validate(f)
        if r["status"] == "PROVEN":
            proven.append(f)
    state["steps"].append(f"validate ✅ ({len(proven)} proven)")

    # ══════════════════════════════════════════════════════════════════════════════
    # Phase 7: Generate reports
    # ══════════════════════════════════════════════════════════════════════════════
    print("[Autopilot] Phase 7: Generate reports")
    from hunter_ai.report_writer import ReportWriter
    writer = ReportWriter(platform="hackerone")
    for f in proven:
        path = writer.generate(target, f)
        print(f"  📄 {path}")
    state["steps"].append("report ✅")
    state["phase"] = "complete"

    print(f"\n[Autopilot] Complete! {len(proven)} findings ready to report")
    print(f"[Autopilot] Techniques attempted: {state['techniques_attempted']}")
    print(f"[Autopilot] TDA decisions: {len(state['decisions'])}")
    return state


__all__ = ["run_autopilot"]
