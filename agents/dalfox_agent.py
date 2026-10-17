"""Dalfox Agent — L1→L5 pipeline with verification"""
from __future__ import annotations

import asyncio
import logging
from typing import List, Dict, Any, Optional

from agents.base_agent import BaseAgent, AgentTask, AgentResult
from tools.tool_manager import ToolManager
from tools.dalfox_tools import DalfoxTools
from core.dalfox.schemas import DalfoxFindingRecord, DalfoxEvidenceLevel
from core.dalfox.analyzer import DalfoxNormalizer, DuplicateDetector, EvidenceReviewer
from core.dalfox.context import ContextEnricher, AdaptiveTestAdvisor

log = logging.getLogger("dalfox.agent")


class DalfoxAgent(BaseAgent):
    def __init__(self, mgr: ToolManager, cb=None):
        super().__init__(
            "dalfox_agent",
            "Dalfox XSS Context Analyzer — L1→L5 pipeline with verification",
            mgr,
            cb,
        )
        self.tools = DalfoxTools(mgr)
        self.normalizer = DalfoxNormalizer()
        self.dedup = DuplicateDetector()
        self.reviewer = EvidenceReviewer()

    async def run(self, task: AgentTask) -> AgentResult:
        target = task.target
        r = AgentResult(agent_name=self.name, target=target)
        await self.emit("start", {"message": f"Dalfox L1→L5 pipeline on {target}"})

        if not self.tools.is_available():
            r.success = False
            r.errors.append("dalfox binary not available")
            await self.emit("complete", {"findings": 0, "error": "dalfox_missing"})
            return r

        await self.emit("tool_start", {"tool": "dalfox", "target": target})
        try:
            tool_res = await self.tools.scan(url=target)
            await self.emit("tool_done", {"tool": "dalfox", "output_len": len(tool_res.stdout)})
        except Exception as e:
            log.exception("Dalfox scan failed")
            r.success = False
            r.errors.append(str(e))
            await self.emit("complete", {"findings": 0, "error": str(e)})
            return r

        records = self.normalizer.normalize_batch(tool_res.stdout)
        final_records: List[DalfoxFindingRecord] = []
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
                "url": rec.url,
                "injection_point": rec.injection_point,
                "payload": rec.payload,
                "type": rec.type,
                "evidence": rec.evidence,
                "evidence_level": rec.evidence_level,
                "confidence": review["confidence"],
                "confidence_label": review["confidence_label"],
                "evidence_status": review["evidence_status"],
                "is_vulnerable": review["is_vulnerable"],
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
