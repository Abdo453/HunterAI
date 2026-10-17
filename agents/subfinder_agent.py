"""Subfinder Agent — يربط L1→L5 معًا في وكيل BaseAgent واحد.
يدير Pipeline: تشغيل Subfinder → Normalize → Dedup → Enrich → Advise → Review.
يُنتج Asset Profiles مع مستويات الثقة — längst E1 (لا يُرفع إلى Confirmed بدون تحقق يدوي).
"""
from __future__ import annotations

import asyncio
import logging
from typing import List, Dict, Any, Optional

from agents.base_agent import BaseAgent, AgentTask, AgentResult
from tools.tool_manager import ToolManager
from tools.subfinder_tools import SubfinderTools
from core.subfinder.schemas import SubfinderAssetRecord, SubfinderEvidenceLevel
from core.subfinder.analyzer import SubfinderNormalizer, DuplicateDetector, EvidenceReviewer
from core.subfinder.context import ContextEnricher, AdaptiveTestAdvisor

log = logging.getLogger("subfinder.agent")


class SubfinderAgent(BaseAgent):
    """
    وكيل Subfinder المطور (L1→L5):
      L1 Tool Adapter:    SubfinderTools.enum()
      L2 AI Analyzer:     SubfinderNormalizer + DuplicateDetector
      L3 Context:         ContextEnricher (HTTPx results + Katana endpoints)
      L4 Adaptive:        AdaptiveTestAdvisor (اقتراح أدوات/قوالب إضافية)
      L5 Verification:    EvidenceReviewer (evidence status + confidence)
    """

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
        katana_endpoints = extra.get("katana_endpoints", [])

        r = AgentResult(agent_name=self.name, target=target)
        await self.emit("start", {"message": f"Subfinder L1→L5 pipeline on {target}"})

        if not self.tools.is_available():
            r.success = False
            r.errors.append("subfinder binary not available")
            await self.emit("complete", {"findings": 0, "error": "subfinder_missing"})
            return r

        # ── L1: تشغيل Subfinder ─────────────────────────────────────
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

        # ── L2: Normalize + Deduplicate ──────────────────────────
        records = self.normalizer.normalize_batch(tool_res.stdout)
        deduped_groups: Dict[str, List[SubfinderAssetRecord]] = {}
        final_records: List[SubfinderAssetRecord] = []

        for rec in records:
            group = self.dedup.add(rec)
            if group is None:
                final_records.append(rec)  # أصل جديد (ممثل المجموعة)
            else:
                key = rec.canonical_key
                deduped_groups.setdefault(key, group)

        deduped_groups = self.dedup.flush()

        # ── L3: enrichment السياق ────────────────────────────────
        enricher = ContextEnricher(
            httpx_results=httpx_results,
            katana_endpoints=katana_endpoints,
        )
        advisor = AdaptiveTestAdvisor()

        # ── L5: مراجعة الأدلة + بناء Asset Coverage Profile ─────────
        for rec in final_records:
            ctx = enricher.enrich(rec)
            advice = advisor.advise(rec, ctx)
            review = self.reviewer.review(rec)

            # تحديث السجل
            rec.evidence_level = review["evidence_level"]

            profile = AssetCoverageProfile(
                subdomain=rec.subdomain,
                source=rec.source,
                ip=rec.ip,
                cdn=rec.cdn,
                is_high_value=review["is_high_value"],
                is_live_web=context.get("is_live_web", False),
                confidence_score=review["confidence"],
                confidence_label=review["confidence_label"],
                evidence_level=rec.evidence_level,
                context_notes=ctx.get("notes", []),
                adaptive_suggestions=advice,
            )

            finding = {
                "record_id": rec.record_id,
                "subdomain": rec.subdomain,
                "source": rec.source,
                "ip": rec.ip,
                "cdn": rec.cdn,
                "evidence_level": rec.evidence_level,
                "confidence": review["confidence"],
                "confidence_label": review["confidence_label"],
                "evidence_status": review["evidence_status"],
                "is_high_value": review["is_high_value"],
                "is_live_web": context.get("is_live_web", False),
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
