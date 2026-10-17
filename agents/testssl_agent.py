"""testssl.sh Agent — L1→L5 pipeline with verification"""
from __future__ import annotations

import asyncio
import logging
from typing import List, Dict, Any, Optional

from agents.base_agent import BaseAgent, AgentTask, AgentResult
from tools.tool_manager import ToolManager
from tools.testssl_tools import TestsslTools
from core.testssl.schemas import (
    TestsslFindingRecord, TestsslEvidenceLevel,
)
from core.testssl.analyzer import (
    TestsslNormalizer, DuplicateDetector, EvidenceReviewer,
)
from core.testssl.context import ContextEnricher, AdaptiveTestAdvisor

log = logging.getLogger("testssl.agent")


class TestsslAgent(BaseAgent):
    def __init__(self, mgr: ToolManager, cb=None):
        super().__init__(
            "testssl_agent",
            "testssl.sh TLS Configuration Intelligence — L1→L5 pipeline with verification",
            mgr,
            cb,
        )
        self.tools = TestsslTools(mgr)
        self.normalizer = TestsslNormalizer()
        self.dedup = DuplicateDetector()
        self.reviewer = EvidenceReviewer()

    async def run(self, task: AgentTask) -> AgentResult:
        target = task.target
        r = AgentResult(agent_name=self.name, target=target)
        await self.emit("start", {"message": f"testssl.sh L1→L5 pipeline on {target}"})

        if not self.tools.is_available():
            r.success = False
            r.errors.append("testssl.sh binary not available")
            await self.emit("complete", {"findings": 0, "error": "testssl_missing"})
            return r

        await self.emit("tool_start", {"tool": "testssl.sh", "target": target})
        try:
            tool_res = await self.tools.scan(target=target)
            await self.emit("tool_done", {"tool": "testssl.sh", "output_len": len(tool_res.stdout)})
        except Exception as e:
            log.exception("testssl.sh scan failed")
            r.success = False
            r.errors.append(str(e))
            await self.emit("complete", {"findings": 0, "error": str(e)})
            return r

        records = self.normalizer.normalize_batch(tool_res.stdout)
        final_records: List[TestsslFindingRecord] = []
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
                "severity": rec.severity,
                "title": rec.title,
                "description": rec.description,
                "cve": rec.cve,
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
