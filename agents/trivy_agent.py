"""Trivy Agent — L1→L5 pipeline with verification"""
from __future__ import annotations

import asyncio
import logging
from typing import List, Dict, Any, Optional

from agents.base_agent import BaseAgent, AgentTask, AgentResult
from tools.tool_manager import ToolManager
from tools.trivy_tools import TrivyTools
from core.trivy.schemas import (
    TrivyVulnerabilityRecord, TrivyEvidenceLevel,
)
from core.trivy.analyzer import (
    TrivyNormalizer, DuplicateDetector, EvidenceReviewer,
)
from core.trivy.context import ContextEnricher, AdaptiveTestAdvisor

log = logging.getLogger("trivy.agent")


class TrivyAgent(BaseAgent):
    def __init__(self, mgr: ToolManager, cb=None):
        super().__init__(
            "trivy_agent",
            "Trivy Dependency Risk Analyzer — L1→L5 pipeline with verification",
            mgr,
            cb,
        )
        self.tools = TrivyTools(mgr)
        self.normalizer = TrivyNormalizer()
        self.dedup = DuplicateDetector()
        self.reviewer = EvidenceReviewer()

    async def run(self, task: AgentTask) -> AgentResult:
        target = task.target
        extra = task.extra or {}
        scan_type = extra.get("scan_type", "fs")

        r = AgentResult(agent_name=self.name, target=target)
        await self.emit("start", {"message": f"Trivy L1→L5 pipeline on {target}"})

        if not self.tools.is_available():
            r.success = False
            r.errors.append("trivy binary not available")
            await self.emit("complete", {"findings": 0, "error": "trivy_missing"})
            return r

        await self.emit("tool_start", {"tool": "trivy", "target": target, "scan_type": scan_type})
        try:
            tool_res = await self.tools.scan(target=target, scan_type=scan_type)
            await self.emit("tool_done", {"tool": "trivy", "output_len": len(tool_res.stdout)})
        except Exception as e:
            log.exception("Trivy scan failed")
            r.success = False
            r.errors.append(str(e))
            await self.emit("complete", {"findings": 0, "error": str(e)})
            return r

        records = self.normalizer.normalize_batch(tool_res.stdout)
        final_records: List[TrivyVulnerabilityRecord] = []
        dup_count = 0

        for rec in records:
            if self.dedup.add(rec):
                dup_count += 1
            else:
                final_records.append(rec)

        enricher = ContextEnricher()
        advisor = AdaptiveTestAdvisor()

        for rec in final_records:
            ctx = enricher.enrich(rec)
            advice = advisor.advise(rec, ctx)
            review = self.reviewer.review(rec)

            rec.evidence_level = review["evidence_level"]

            finding = {
                "record_id": rec.record_id,
                "vulnerability_id": rec.vulnerability_id,
                "package_name": rec.package_name,
                "installed_version": rec.installed_version,
                "fixed_version": rec.fixed_version,
                "severity": rec.severity,
                "title": rec.title,
                "evidence_level": rec.evidence_level,
                "confidence": review["confidence"],
                "confidence_label": review["confidence_label"],
                "evidence_status": review["evidence_status"],
                "needs_verification": review["needs_verification"],
                "context": ctx,
                "adaptive_suggestions": advice,
                "recommendation": review["recommendation"],
                "raw_json": rec.raw_json,
            }
            r.findings.append(finding)

        await self.emit("complete", {
            "findings": len(r.findings),
            "duplicates_removed": dup_count,
            "raw_matches": len(records),
        })
        return r
