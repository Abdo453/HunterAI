"""Burp Suite Agent — L1→L5 pipeline with verification"""
from __future__ import annotations

import asyncio
import logging
from typing import List, Dict, Any, Optional

from agents.base_agent import BaseAgent, AgentTask, AgentResult
from tools.tool_manager import ToolManager
from tools.burp_tools import BurpTools
from core.burp.schemas import BurpTrafficRecord, BurpEvidenceLevel
from core.burp.analyzer import BurpNormalizer, DuplicateDetector, EvidenceReviewer
from core.burp.context import ContextEnricher, AdaptiveAdvisor

log = logging.getLogger("burp.agent")


class BurpAgent(BaseAgent):
    def __init__(self, mgr: ToolManager, cb=None):
        super().__init__(
            "burp_agent",
            "Burp Suite Traffic Intelligence — L1→L5 pipeline with verification",
            mgr,
            cb,
        )
        self.tools = BurpTools(mgr)
        self.normalizer = BurpNormalizer()
        self.dedup = DuplicateDetector()
        self.reviewer = EvidenceReviewer()

    async def run(self, task: AgentTask) -> AgentResult:
        target = task.target
        extra = task.extra or {}
        config = extra.get("config")

        r = AgentResult(agent_name=self.name, target=target)
        await self.emit("start", {"message": f"Burp L1→L5 pipeline on {target}"})

        if not self.tools.is_available():
            r.success = False
            r.errors.append("burp binary not available")
            await self.emit("complete", {"findings": 0, "error": "burp_missing"})
            return r

        await self.emit("tool_start", {"tool": "burp", "target": target})
        try:
            tool_res = await self.tools.scan(target=target, config=config)
            await self.emit("tool_done", {"tool": "burp", "output_len": len(tool_res.stdout)})
        except Exception as e:
            log.exception("Burp scan failed")
            r.success = False
            r.errors.append(str(e))
            await self.emit("complete", {"findings": 0, "error": str(e)})
            return r

        records = self.normalizer.normalize_batch(tool_res.stdout)
        final_records: List[BurpTrafficRecord] = []
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
                "url": rec.request_url,
                "method": rec.request_method,
                "status": record.response_status if False else rec.response_status,
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
