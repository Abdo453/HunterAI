"""Subfinder Agent — L1→L5 pipeline with verification"""
from __future__ import annotations

import asyncio
import logging
from typing import List, Dict, Any, Optional

from agents.base_agent import BaseAgent, AgentTask, AgentResult
from tools.tool_manager import ToolManager
from tools.subfinder_tools import SubfinderTools
from core.subfinder.schemas import SubfinderAssetRecord, SubfinderEvidenceLevel
from core.subfinder.analyzer import SubfinderNormalizer, DuplicateDetector, EvidenceReviewer
from core.subfinder.context import ContextEnricher, AdaptiveAdvisor

log = logging.getLogger("subfinder.agent")


class SubfinderAgent(BaseAgent):
    def __init__(self, mgr: ToolManager, cb=None):
        super().__init__(
            "subfinder_agent",
            "Subfinder Asset Coverage — L1→L5 pipeline with verification",
            mgr,
            cb,
        )
        self.tools = SubfinderTools(mgr)
        self.normalizer = SubfinderNormalizer()
        self.dedup = DuplicateDetector()
        self.reviewer = EvidenceReviewer()

    async def run(self, task: AgentTask) -> AgentResult:
        target = task.target
        extra = task.extra or {}
        sources = extra.get("sources")
        recursive = extra.get("recursive", False)
        httpx_results = extra.get("httpx_results", {})
        nmap_ports = extra.get("nmap_ports", {})

        r = AgentResult(agent_name=self.name, target=target)
        await self.emit("start", {"message": f"Subfinder L1→L5 pipeline on {target}"})

        if not self.tools.is_available():
            r.success = False
            r.errors.append("subfinder binary not available")
            await self.emit("complete", {"findings": 0, "error": "subfinder_missing"})
            return r

        await self.emit("tool_start", {"tool": "subfinder", "target": target})
        try:
            tool_res = await self.tools.enum(
                domain=target,
                sources=sources,
                recursive=recursive,
            )
            await self.emit("tool_done", {"tool": "subfinder", "output_len": len(tool_res.stdout)})
        except Exception as e:
            log.exception("Subfinder enum failed")
            r.success = False
            r.errors.append(str(e))
            await self.emit("complete", {"findings": 0, "error": str(e)})
            return r

        records = self.normalizer.normalize_batch(tool_res.stdout)
        deduped_groups: Dict[str, List[SubfinderAssetRecord]] = {}
        final_records: List[SubfinderAssetRecord] = []

        for rec in records:
            group = self.dedup.add(rec)
            if group is None:
                final_records.append(rec)
            else:
                key = rec.canonical_key
                deduped_groups.setdefault(key, group)

        deduped_groups = self.dedup.flush()

        enricher = ContextEnricher(httpx_results=httpx_results, nmap_ports=nmap_ports)
        advisor = AdaptiveAdvisor()

        for rec in final_records:
            ctx = enricher.enrich(rec)
            advice = advisor.advise(rec, ctx)
            review = self.reviewer.review(rec)
            rec.evidence_level = review["evidence_level"]

            finding = {
                "record_id": rec.record_id,
                "subdomain": rec.subdomain,
                "source": rec.source,
                "source_type": rec.source_type,
                "ip": rec.ip,
                "cdn": rec.cdn,
                "evidence_level": rec.evidence_level,
                "confidence": review["confidence"],
                "confidence_label": review["confidence_label"],
                "evidence_status": review["evidence_status"],
                "needs_verification": review["needs_verification"],
                "is_high_value": ctx.get("is_high_value", False),
                "is_live_web": ctx.get("is_live_web", False),
                "context": ctx,
                "adaptive_suggestions": advice,
                "recommendation": review["recommendation"],
                "raw_json": rec.raw_json,
            }
            r.findings.append(finding)

        await self.emit("complete", {
            "findings": len(r.findings),
            "duplicates_removed": sum(len(v) - 1 for v in deduped_groups.values()),
            "raw_matches": len(records),
        })
        return r
