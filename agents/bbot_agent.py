"""BBOT Agent — L1→L5 pipeline with verification"""
from __future__ import annotations

import asyncio
import logging
from typing import List, Dict, Any, Optional

from agents.base_agent import BaseAgent, AgentTask, AgentResult
from tools.tool_manager import ToolManager
from tools.bbot_tools import BBOTTools
from core.bbot.schemas import BBOTAssetRecord, BBOTEvidenceLevel
from core.bbot.analyzer import BBOTNormalizer, DuplicateDetector, EvidenceReviewer
from core.bbot.context import ContextEnricher, AdaptiveAdvisor

log = logging.getLogger("bbot.agent")


class BBOTAgent(BaseAgent):
    def __init__(self, mgr: ToolManager, cb=None):
        super().__init__(
            "bbot_agent",
            "BBOT Asset Relationship Analyzer — L1→L5 pipeline with verification",
            mgr,
            cb,
        )
        self.tools = BBOTTools(mgr)
        self.normalizer = BBOTNormalizer()
        self.dedup = DuplicateDetector()
        self.reviewer = EvidenceReviewer()

    async def run(self, task: AgentTask) -> AgentResult:
        target = task.target
        extra = task.extra or {}
        modules = extra.get("modules")

        r = AgentResult(agent_name=self.name, target=target)
        await self.emit("start", {"message": f"BBOT L1→L5 pipeline on {target}"})

        if not self.tools.is_available():
            r.success = False
            r.errors.append("bbot binary not available")
            await self.emit("complete", {"findings": 0, "error": "bbot_missing"})
            return r

        await self.emit("tool_start", {"tool": "bbot", "target": target})
        try:
            tool_res = await self.tools.scan(target=target, modules=modules)
            await self.emit("tool_done", {"tool": "bbot", "output_len": len(tool_res.stdout)})
        except Exception as e:
            log.exception("BBOT scan failed")
            r.success = False
            r.errors.append(str(e))
            await self.emit("complete", {"findings": 0, "error": str(e)})
            return r

        records = self.normalizer.normalize_batch(tool_res.stdout)
        final_records: List[BBOTAssetRecord] = []
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
                "asset_type": rec.asset_type,
                "asset_value": rec.asset_value,
                "source_module": rec.source_module,
                "relationship": rec.relationship,
                "related_asset": rec.related_asset,
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
