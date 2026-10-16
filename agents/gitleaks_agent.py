"""Gitleaks Agent — L1→L5 pipeline with verification"""
from __future__ import annotations

import asyncio
import logging
from typing import List, Dict, Any, Optional

from agents.base_agent import BaseAgent, AgentTask, AgentResult
from tools.tool_manager import ToolManager
from tools.gitleaks_tools import GitleaksTools
from core.gitleaks.schemas import GitleaksFindingRecord, GitleaksEvidenceLevel
from core.gitleaks.analyzer import GitleaksNormalizer, DuplicateDetector, EvidenceReviewer
from core.gitleaks.context import ContextEnricher, AdaptiveAdvisor

log = logging.getLogger("gitleaks.agent")


class GitleaksAgent(BaseAgent):
    def __init__(self, mgr: ToolManager, cb=None):
        super().__init__(
            "gitleaks_agent",
            "Gitleaks Secret Context Analyzer — L1→L5 pipeline with verification",
            mgr,
            cb,
        )
        self.tools = GitleaksTools(mgr)
        self.normalizer = GitleaksNormalizer()
        self.dedup = DuplicateDetector()
        self.reviewer = EvidenceReviewer()

    async def run(self, task: AgentTask) -> AgentResult:
        target = task.target
        r = AgentResult(agent_name=self.name, target=target)
        await self.emit("start", {"message": f"Gitleaks L1→L5 pipeline on {target}"})

        if not self.tools.is_available():
            r.success = False
            r.errors.append("gitleaks binary not available")
            await self.emit("complete", {"findings": 0, "error": "gitleaks_missing"})
            return r

        await self.emit("tool_start", {"tool": "gitleaks", "target": target})
        try:
            tool_res = await self.tools.scan(target=target)
            await self.emit("tool_done", {"tool": "gitleaks", "output_len": len(tool_res.stdout)})
        except Exception as e:
            log.exception("Gitleaks scan failed")
            r.success = False
            r.errors.append(str(e))
            await self.emit("complete", {"findings": 0, "error": str(e)})
            return r

        records = self.normalizer.normalize_batch(tool_res.stdout)
        final_records: List[GitleaksFindingRecord] = []
        dup_count = 0

        for rec in records:
            if self.dedup.add(rec):
                dup_count += 1
            else:
                final_records.append(rec)

        enricher = ContextEnricher()
        advisor = AdaptiveAdvisor()

        for rec in final_records:
            ctx = enricher.enrich(rec)
            advice = advisor.advise(rec, ctx)
            review = self.reviewer.review(rec)

            finding = {
                "record_id": rec.record_id,
                "rule_id": rec.rule_id,
                "secret_type": rec.secret_type,
                "file_path": rec.file_path,
                "start_line": rec.start_line,
                "end_line": rec.end_line,
                "secret_value": rec.secret_value,
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
