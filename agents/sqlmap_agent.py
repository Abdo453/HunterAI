"""SQLmap Agent — L1→L5 pipeline with verification"""
from __future__ import annotations

import asyncio
import logging
from typing import List, Dict, Any, Optional

from agents.base_agent import BaseAgent, AgentTask, AgentResult
from tools.tool_manager import ToolManager
from tools.sqlmap_tools import SQLmapTools
from core.sqlmap.schemas import SQLmapFindingRecord, SQLmapEvidenceLevel
from core.sqlmap.analyzer import SQLmapNormalizer, DuplicateDetector, EvidenceReviewer
from core.sqlmap.context import ContextEnricher, AdaptiveAdvisor

log = logging.getLogger("sqlmap.agent")


class SQLmapAgent(BaseAgent):
    def __init__(self, mgr: ToolManager, cb=None):
        super().__init__(
            "sqlmap_agent",
            "SQLmap Result Interpreter — L1→L5 pipeline with verification",
            mgr,
            cb,
        )
        self.tools = SQLmapTools(mgr)
        self.normalizer = SQLmapNormalizer()
        self.dedup = DuplicateDetector()
        self.reviewer = EvidenceReviewer()

    async def run(self, task: AgentTask) -> AgentResult:
        target = task.target
        extra = task.extra or {}
        data = extra.get("data")
        level = int(extra.get("level", 1))
        risk = int(extra.get("risk", 1))

        r = AgentResult(agent_name=self.name, target=target)
        await self.emit("start", {"message": f"SQLmap L1→L5 pipeline on {target}"})

        if not self.tools.is_available():
            r.success = False
            r.errors.append("sqlmap binary not available")
            await self.emit("complete", {"findings": 0, "error": "sqlmap_missing"})
            return r

        await self.emit("tool_start", {"tool": "sqlmap", "target": target})
        try:
            tool_res = await self.tools.scan(url=target, data=data, level=level, risk=risk)
            await self.emit("tool_done", {"tool": "sqlmap", "output_len": len(tool_res.stdout)})
        except Exception as e:
            log.exception("SQLmap scan failed")
            r.success = False
            r.errors.append(str(e))
            await self.emit("complete", {"findings": 0, "error": str(e)})
            return r

        records = self.normalizer.normalize_batch(tool_res.stdout)
        final_records: List[SQLmapFindingRecord] = []
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
                "parameter": rec.parameter,
                "payload": rec.payload,
                "technique": rec.technique,
                "dbms": rec.dbms,
                "evidence": rec.evidence,
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
