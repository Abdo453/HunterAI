"""Subjack Agent — L1→L5 pipeline with verification"""
from __future__ import annotations

import asyncio
import logging
from typing import List, Dict, Any, Optional

from agents.base_agent import BaseAgent, AgentTask, AgentResult
from tools.tool_manager import ToolManager
from tools.subjack_tools import SubjackTools
from core.subjack.schemas import SubdomainTakeoverRecord, SubjackEvidenceLevel
from core.subjack.analyzer import SubjackNormalizer, DuplicateDetector, EvidenceReviewer
from core.subjack.context import ContextEnricher, AdaptiveTestAdvisor

log = logging.getLogger("subjack.agent")


class SubjackAgent(BaseAgent):
    def __init__(self, mgr: ToolManager, cb=None):
        super().__init__(
            "subjack_agent",
            "Subjack Subdomain Takeover — L1→L5 pipeline with verification",
            mgr,
            cb,
        )
        self.tools = SubjackTools(mgr)
        self.normalizer = SubjackNormalizer()
        self.dedup = DuplicateDetector()
        self.reviewer = EvidenceReviewer()

    async def run(self, task: AgentTask) -> AgentResult:
        target = task.target
        extra = task.extra or {}
        katana_endpoints = extra.get("katana_endpoints", [])
        httpx_results = extra.get("httpx_results", {})

        r = AgentResult(agent_name=self.name, target=target)
        await self.emit("start", {"message": f"Subjack L1→L5 pipeline on {target}"})

        if not self.tools.is_available():
            r.success = False
            r.errors.append("subjack binary not available")
            await self.emit("complete", {"findings": 0, "error": "subjack_missing"})
            return r

        await self.emit("tool_start", {"tool": "subjack", "target": target})
        try:
            tool_res = await self.tools.scan(target=target)
            await self.emit("tool_done", {"tool": "subjack", "output_len": len(tool_res.stdout)})
        except Exception as e:
            log.exception("Subjack scan failed")
            r.success = False
            r.errors.append(str(e))
            await self.emit("complete", {"findings": 0, "error": str(e)})
            return r

        records = self.normalizer.normalize_batch(tool_res.stdout)
        deduped_groups: Dict[str, List[SubdomainTakeoverRecord]] = {}
        final_records: List[SubdomainTakeoverRecord] = []

        for rec in records:
            group = self.dedup.add(rec)
            if group is None:
                final_records.append(rec)
            else:
                key = rec.canonical_key
                deduped_groups.setdefault(key, group)

        deduped_groups = self.dedup.flush()

        enricher = ContextEnricher(
            katana_endpoints=katana_endpoints,
            httpx_results=httpx_results,
        )
        advisor = AdaptiveTestAdvisor()

        for rec in final_records:
            ctx = enricher.enrich(rec)
            advice = advisor.advise(rec, ctx)
            review = self.reviewer.review(rec)

            rec.evidence_level = review["evidence_level"]

            profile = {
                "record_id": rec.record_id,
                "subdomain": rec.subdomain,
                "cname": rec.cname,
                "status_code": rec.status_code,
                "fingerprint": rec.fingerprint,
                "takeover_risk": rec.takeover_risk,
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
            r.findings.append(profile)

        await self.emit("complete", {
            "findings": len(r.findings),
            "duplicates_removed": sum(len(v) - 1 for v in deduped_groups.values()),
            "raw_matches": len(records),
        })
        return r
