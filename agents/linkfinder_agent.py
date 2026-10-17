"""LinkFinder Agent — L1→L5 pipeline with verification"""
from __future__ import annotations

import asyncio
import logging
from typing import List, Dict, Any, Optional

from agents.base_agent import BaseAgent, AgentTask, AgentResult
from tools.tool_manager import ToolManager
from tools.linkfinder_tools import LinkFinderTools
from core.linkfinder.schemas import JSFindingRecord, LinkFinderEvidenceLevel
from core.linkfinder.analyzer import LinkFinderNormalizer, DuplicateDetector, EvidenceReviewer
from core.linkfinder.context import ContextEnricher, AdaptiveTestAdvisor

log = logging.getLogger("linkfinder.agent")


class LinkFinderAgent(BaseAgent):
    """
    وكيل LinkFinder المطور (L1→L5):
      L1 Tool Adapter:    LinkFinderTools.scan()
      L2 AI Analyzer:     LinkFinderNormalizer + DuplicateDetector
      L3 Context:         ContextEnricher (Katana endpoints + HTTPx results)
      L4 Adaptive:        AdaptiveTestAdvisor (اقتراح أدوات/قوالب إضافية)
      L5 Verification:    EvidenceReviewer (evidence status + confidence)
    """

    def __init__(self, mgr: ToolManager, cb=None):
        super().__init__(
            "linkfinder_agent",
            "LinkFinder JS Endpoints — L1→L5 pipeline with verification",
            mgr,
            cb,
        )
        self.tools = LinkFinderTools(mgr)
        self.normalizer = LinkFinderNormalizer()
        self.dedup = DuplicateDetector()
        self.reviewer = EvidenceReviewer()

    async def run(self, task: AgentTask) -> AgentResult:
        target = task.target
        extra = task.extra or {}
        katana_endpoints = extra.get("katana_endpoints", [])
        httpx_results = extra.get("httpx_results", {})

        r = AgentResult(agent_name=self.name, target=target)
        await self.emit("start", {"message": f"LinkFinder L1→L5 pipeline on {target}"})

        if not self.tools.is_available():
            r.success = False
            r.errors.append("linkfinder binary not available")
            await self.emit("complete", {"findings": 0, "error": "linkfinder_missing"})
            return r

        # ── L1: تشغيل linkfinder ─────────────────────────────────────
        await self.emit("tool_start", {"tool": "linkfinder", "target": target})
        try:
            tool_res = await self.tools.scan(target=target)
            await self.emit("tool_done", {"tool": "linkfinder", "output_len": len(tool_res.stdout)})
        except Exception as e:
            log.exception("LinkFinder scan failed")
            r.success = False
            r.errors.append(str(e))
            await self.emit("complete", {"findings": 0, "error": str(e)})
            return r

        # ── L2: Normalize + Deduplicate ──────────────────────────
        records = self.normalizer.normalize_batch(tool_res.stdout)
        deduped_groups: Dict[str, List[JSFindingRecord]] = {}
        final_records: List[JSFindingRecord] = []

        for rec in records:
            group = self.dedup.add(rec)
            if group is None:
                final_records.append(rec)  # نقطة نهاية جديدة (ممثل المجموعة)
            else:
                key = rec.canonical_key
                deduped_groups.setdefault(key, group)

        deduped_groups = self.dedup.flush()

        # ── L3: enrichment السياق ────────────────────────────────
        enricher = ContextEnricher(
            katana_endpoints=katana_endpoints,
            httpx_results=httpx_results,
        )
        advisor = AdaptiveTestAdvisor()

        # ── L5: مراجعة الأدلة + بناء JSEndpointProfile ─────────
        for rec in final_records:
            ctx = enricher.enrich(rec)
            advice = advisor.advise(rec, ctx)
            review = self.reviewer.review(rec)

            # تحديث السجل
            rec.evidence_level = review["evidence_level"]

            profile = JSEndpointProfile(
                endpoint=rec.endpoint,
                source_file=rec.source_file,
                line_number=rec.line_number,
                method=rec.method,
                parameter=rec.parameter,
                code_snippet=rec.code_snippet,
                confidence_score=review["confidence"],
                confidence_label=review["confidence_label"],
                evidence_level=rec.evidence_level,
                is_auth_endpoint=review["is_auth_endpoint"],
                is_admin_endpoint=review["is_admin_endpoint"],
                is_api_endpoint=review["is_api_endpoint"],
                context_notes=ctx.get("notes", []),
                adaptive_suggestions=advice,
            )

            finding = {
                "record_id": rec.record_id,
                "endpoint": rec.endpoint,
                "source_file": rec.source_file,
                "line_number": rec.line_number,
                "method": rec.method,
                "parameter": rec.parameter,
                "code_snippet": rec.code_snippet,
                "evidence_level": rec.evidence_level,
                "confidence": review["confidence"],
                "confidence_label": review["confidence_label"],
                "evidence_status": review["evidence_status"],
                "is_auth_endpoint": review["is_auth_endpoint"],
                "is_admin_endpoint": review["is_admin_endpoint"],
                "is_api_endpoint": review["is_api_endpoint"],
                "needs_verification": review["needs_verification"],
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
