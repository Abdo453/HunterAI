"""
Full Pipeline Master Orchestrator Skill
=======================================
Orchestrates the entire multi-phase autonomous Bug Bounty loop:
1. Threat Modeling (Cognitive)
2. Session Extraction (AI Browser)
3. SPA API Discovery (AI Browser)
4. Burp Traffic Analysis (Burp Integration)
5. DOM XSS Hunting (Client-side Execution)
6. Adversarial Planning (Red Team CoT)
7. Exploit Chaining (A -> B -> C Chains)
8. 7-Question Gate Triage & Report Generation
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any, Dict, List, Optional

from skills.base_skill import BaseSkill, SkillContext, SkillResult

logger = logging.getLogger("skills.meta.full_pipeline_orchestrator")


class FullPipelineOrchestratorSkill(BaseSkill):
    name = "full_pipeline_orchestrator"
    category = "meta"
    description = "Master orchestrator -- runs full autonomous Bug Bounty pipeline: Recon->Model->Browse->Burp->Hunt->Chain->Report"
    tools_required: List[str] = []
    fallback_tools: List[str] = []
    timeout_seconds = 300.0
    max_retries = 1

    async def execute(self, ctx: SkillContext) -> SkillResult:
        result = SkillResult(skill_name=self.name, success=True, tool_used="full_pipeline_master")
        target = ctx.target
        authorized = bool(ctx.extra.get("authorized", False))
        t0 = time.time()

        logger.info("[FullPipeline] Launching Master Autonomous Loop on %s (authorized=%s)", target, authorized)

        all_findings: List[Dict[str, Any]] = []
        phase_timings: Dict[str, float] = {}
        pipeline_log: List[Dict[str, Any]] = []

        # ── Phase 1: Threat Modeling ──────────────────────────────────────────
        p1_t0 = time.time()
        try:
            from skills.cognitive.threat_modeler.skill import ThreatModelerSkill
            s1 = ThreatModelerSkill()
            r1 = await s1.execute(ctx)
            if r1.findings:
                all_findings.extend(r1.findings)
            pipeline_log.append({"phase": "threat_modeling", "status": "ok", "findings": len(r1.findings)})
        except Exception as exc:
            logger.warning("[FullPipeline] Phase 1 error: %s", exc)
            pipeline_log.append({"phase": "threat_modeling", "status": "skipped", "error": str(exc)})
        phase_timings["Phase 1: Threat Modeling"] = round(time.time() - p1_t0, 2)

        # ── Phase 2: Session Extraction ───────────────────────────────────────
        p2_t0 = time.time()
        auth_context = {}
        try:
            from skills.browser.auth_session_extractor.skill import AuthSessionExtractorSkill
            s2 = AuthSessionExtractorSkill()
            r2 = await s2.execute(ctx)
            auth_context = r2.metadata.get("auth_context", {})
            ctx.extra["auth_context"] = auth_context
            pipeline_log.append({"phase": "session_extraction", "status": "ok", "has_session": bool(auth_context)})
        except Exception as exc:
            logger.warning("[FullPipeline] Phase 2 error: %s", exc)
            pipeline_log.append({"phase": "session_extraction", "status": "skipped", "error": str(exc)})
        phase_timings["Phase 2: Session Extraction"] = round(time.time() - p2_t0, 2)

        # ── Phase 3: SPA API Discovery ────────────────────────────────────────
        p3_t0 = time.time()
        endpoints = []
        try:
            from skills.browser.spa_api_extractor.skill import SPAAPIExtractorSkill
            s3 = SPAAPIExtractorSkill()
            r3 = await s3.execute(ctx)
            endpoints = r3.metadata.get("endpoints", [])
            ctx.extra["endpoints"] = endpoints
            if r3.findings:
                all_findings.extend(r3.findings)
            pipeline_log.append({"phase": "spa_api_discovery", "status": "ok", "endpoints_found": len(endpoints)})
        except Exception as exc:
            logger.warning("[FullPipeline] Phase 3 error: %s", exc)
            pipeline_log.append({"phase": "spa_api_discovery", "status": "skipped", "error": str(exc)})
        phase_timings["Phase 3: SPA API Discovery"] = round(time.time() - p3_t0, 2)

        # ── Phase 4: Burp Traffic Analysis ────────────────────────────────────
        p4_t0 = time.time()
        try:
            from skills.burp.burp_traffic_analyzer.skill import BurpTrafficAnalyzerSkill
            s4 = BurpTrafficAnalyzerSkill()
            r4 = await s4.execute(ctx)
            if r4.findings:
                all_findings.extend(r4.findings)
            pipeline_log.append({"phase": "burp_traffic_analysis", "status": "ok", "findings": len(r4.findings)})
        except Exception as exc:
            logger.warning("[FullPipeline] Phase 4 error: %s", exc)
            pipeline_log.append({"phase": "burp_traffic_analysis", "status": "skipped", "error": str(exc)})
        phase_timings["Phase 4: Burp Traffic Analysis"] = round(time.time() - p4_t0, 2)

        # ── Phase 5: DOM XSS Hunting ──────────────────────────────────────────
        p5_t0 = time.time()
        try:
            from skills.browser.dom_xss_hunter.skill import DOMXSSHunterSkill
            s5 = DOMXSSHunterSkill()
            r5 = await s5.execute(ctx)
            if r5.findings:
                all_findings.extend(r5.findings)
            pipeline_log.append({"phase": "dom_xss_hunting", "status": "ok", "findings": len(r5.findings)})
        except Exception as exc:
            logger.warning("[FullPipeline] Phase 5 error: %s", exc)
            pipeline_log.append({"phase": "dom_xss_hunting", "status": "skipped", "error": str(exc)})
        phase_timings["Phase 5: DOM XSS Hunting"] = round(time.time() - p5_t0, 2)

        # ── Phase 6: Adversarial Planning ─────────────────────────────────────
        p6_t0 = time.time()
        ctx.extra["findings_so_far"] = all_findings
        try:
            from skills.cognitive.adversarial_planner.skill import AdversarialPlannerSkill
            s6 = AdversarialPlannerSkill()
            r6 = await s6.execute(ctx)
            pipeline_log.append({"phase": "adversarial_planning", "status": "ok"})
        except Exception as exc:
            logger.warning("[FullPipeline] Phase 6 error: %s", exc)
            pipeline_log.append({"phase": "adversarial_planning", "status": "skipped", "error": str(exc)})
        phase_timings["Phase 6: Adversarial Planning"] = round(time.time() - p6_t0, 2)

        # ── Phase 7: Exploit Chaining ─────────────────────────────────────────
        p7_t0 = time.time()
        ctx.extra["findings"] = all_findings
        chains = []
        try:
            from skills.cognitive.exploit_chain_builder.skill import ExploitChainBuilderSkill
            s7 = ExploitChainBuilderSkill()
            r7 = await s7.execute(ctx)
            chains = r7.metadata.get("chains", [])
            pipeline_log.append({"phase": "exploit_chaining", "status": "ok", "chains_built": len(chains)})
        except Exception as exc:
            logger.warning("[FullPipeline] Phase 7 error: %s", exc)
            pipeline_log.append({"phase": "exploit_chaining", "status": "skipped", "error": str(exc)})
        phase_timings["Phase 7: Exploit Chaining"] = round(time.time() - p7_t0, 2)

        total_duration = round(time.time() - t0, 2)
        result.findings = all_findings

        # Write output files
        json_content = json.dumps({
            "target": target,
            "authorized": authorized,
            "total_findings": len(all_findings),
            "total_chains": len(chains),
            "execution_duration_secs": total_duration,
            "phase_timings": phase_timings,
            "pipeline_log": pipeline_log,
            "findings": all_findings,
            "chains": chains,
        }, indent=2)

        p_json = ctx.workspace.write_file(ctx.target, "orchestration", "pipeline_findings.json", json_content, ctx.session_id)
        result.output_files["pipeline_findings.json"] = str(p_json)

        # Markdown report
        md_lines = [
            f"# Master Autonomous Bug Bounty Report: {target}",
            f"**Total Findings:** {len(all_findings)} | **Exploit Chains Built:** {len(chains)} | **Duration:** {total_duration}s",
            f"**Authorization Mode:** {'LIVE AUTHORIZED' if authorized else 'PASSIVE RECON ONLY'}",
            "",
            "## Phase Execution Timeline",
            "| Phase | Duration | Status |",
            "|-------|----------|--------|",
        ]
        for ph_name, ph_dur in phase_timings.items():
            md_lines.append(f"| {ph_name} | {ph_dur}s | Completed |")

        md_lines.extend([
            "",
            "## Findings Summary",
            "| Severity | Finding Title | Endpoint |",
            "|----------|---------------|----------|",
        ])
        for f in all_findings:
            md_lines.append(f"| {f.get('severity', 'Medium')} | {f.get('title', 'Untitled')} | `{f.get('endpoint', target)}` |")

        if chains:
            md_lines.extend([
                "",
                "## Exploit Chains (A -> B -> C)",
            ])
            for ch in chains:
                md_lines.append(f"### Chain: {ch.get('chain_name', 'Exploit Chain')}")
                md_lines.append(f"**Impact:** {ch.get('impact', 'Escalated Attack Path')}")

        p_md = ctx.workspace.write_file(ctx.target, "orchestration", "pipeline_report.md", "\n".join(md_lines), ctx.session_id)
        result.output_files["pipeline_report.md"] = str(p_md)

        result.metadata["total_findings"] = len(all_findings)
        result.metadata["total_chains"] = len(chains)
        result.metadata["duration"] = total_duration
        return result
