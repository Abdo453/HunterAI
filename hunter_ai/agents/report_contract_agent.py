"""
Reporting & Compliance Specialist Agent (Contract-Compliant)
===========================================================
Enforces the Report Contract:
- Declares skills: CWE mapping, CVSS scoring, HTML report synthesis
- Aggregates Level 1 Summary and Level 2 Evidence from Blackboard
- Produces Final Enterprise Report
- Concludes the multi-agent mission
"""
from __future__ import annotations

import time
import json
import logging
from pathlib import Path
from typing import Optional, Dict, Any, List

from hunter_ai.brain.agent_manager import BaseContractAgent
from hunter_ai.protocol.contract import AgentContract, ModelTierPreference
from hunter_ai.protocol.blackboard import ThreeTierBlackboardMemory
from hunter_ai.protocol.handoff import HandoffEnvelope
from hunter_ai.protocol.result import StructuredTaskResult, StructuredFinding
from hunter_ai.brain.model_router import AIModelRouter
from hunter_ai.brain.memory_hierarchy import MemoryHierarchy

logger = logging.getLogger("hunter_ai.report_agent")


class ReportContractAgent(BaseContractAgent):
    """
    وكيل التوثيق وإعداد التقارير المعياري (Report Contract Agent)
    """

    def __init__(self):
        contract = AgentContract(
            name="ReportAgent",
            skills=["CWE mapping", "CVSS scoring", "HTML report synthesis", "Executive briefing"],
            input_format="VulnerabilityFinding_v1",
            output_format="EnterpriseReport_v1",
            version="1.0.0",
            required_permissions=["file_write"],
            preferred_model_tier=ModelTierPreference.LOCAL_CODE,
            description="Compiles multi-agent telemetry into executive and technical bug bounty reports."
        )
        super().__init__(contract)

    async def execute_task(
        self,
        task_id: str,
        job_id: str,
        blackboard: ThreeTierBlackboardMemory,
        memory: MemoryHierarchy,
        router: AIModelRouter,
        handoff_input: Optional[HandoffEnvelope] = None
    ) -> StructuredTaskResult:
        t0 = time.time()
        summary = blackboard.get_or_create_summary(job_id, target="target.local")
        evidences = blackboard.list_evidence_for_job(job_id)

        logger.info(f"[ReportAgent] Synthesizing report for {summary.target} with {len(evidences)} evidence items...")

        # 1. Query Knowledge Base for CWE Taxonomy
        cwe_info = memory.query_knowledge("CWE-89") or {"name": "SQL Injection", "severity": "High"}

        # 2. Build Structured Report File
        report_data = {
            "job_id": job_id,
            "target": summary.target,
            "generated_at": time.time(),
            "summary_tags": summary.important_tags,
            "evidence_count": len(evidences),
            "findings": [
                {
                    "title": f"SQL Injection in {ev.parameter}",
                    "cwe": ev.vulnerability_type,
                    "cwe_details": cwe_info,
                    "url": ev.url,
                    "evidence": ev.differential_notes,
                    "remediation": "Use prepared statements with parameterized inputs."
                }
                for ev in evidences
            ]
        }
        report_path = blackboard.save_raw_data(summary.target, f"{job_id}_final_report.json", report_data)

        # 3. Formulate 5-Question Task Result
        return StructuredTaskResult(
            task_id=task_id,
            agent_name="ReportAgent",
            completed=True,
            action_summary=f"Compiled enterprise report for {summary.target} referencing {len(evidences)} verified evidence items.",
            findings=[],
            confidence_score=1.0,
            next_step="Mission concluded. Deliver report to bug bounty triage portal.",
            next_agent=None,  # Terminal Agent
            need=None,
            handoff_envelope=None,
            artifacts_created=[report_path],
            latency_ms=round((time.time() - t0) * 1000, 2)
        )
