"""Soft-404 Agent — L1→L5 pipeline with verification"""
from __future__ import annotations

import asyncio
import logging
from typing import List, Dict, Any, Optional

from agents.base_agent import BaseAgent, AgentTask, AgentResult
from tools.tool_manager import ToolManager
from tools.soft_404_tools import Soft404Tools
from core.soft_404.schemas import Soft404Record, Soft404EvidenceLevel
from core.soft_404.analyzer import Soft404Normalizer, DuplicateDetector, EvidenceReviewer
from core.soft_404.context import ContextEnricher, AdaptiveTestAdvisor

log = logging.getLogger("soft_404.agent")


class Soft404Agent(BaseAgent):
    """
    وكيل soft-404-detector المطور (L1→L5):
      L1 Tool Adapter:    Soft404Tools.scan()
      L2 AI Analyzer:     Soft404Normalizer + DuplicateDetector
      L3 Context:         ContextEnricher (Katana endpoints + HTTPx results)
      L4 Adaptive:        AdaptiveTestAdvisor (اقتراح أدوات/قوالب إضافية)
      L5 Verification:    EvidenceReviewer (evidence status + confidence)
    """

    def __init__(self, mgr: ToolManager, cb=None):
        super().__init__(
            "soft_404_agent",
            "Soft-404 Detector — L1→L5 pipeline with verification",
            mgr,
            cb,
        )
        self.tools = Soft404Tools(mgr)
        self.normalizer = Soft404Normalizer()
        self.dedup = DuplicateDetector()
        self.reviewer = EvidenceReviewer()

    async def run(self, task: AgentTask) -> AgentResult:
        target = task.target
        extra = task.extra or {}
        katana_endpoints = extra.get("katana_endpoints", [])
        httpx_results = extra.get("httpx_results", {})

        r = AgentResult(agent_name=self.name, target=target)
        await self.emit("start", {"message": f"Soft-404 L1→L5 pipeline on {target}"})

        if not self.tools.is_available():
            r.success = False
            r.errors.append("soft-404-detector binary not available")
            await self.emit("complete", {"findings": 0, "error": "soft-404-detector_missing"})
            return r

        # ── L1: تشغيل soft-404-detector ─────────────────────────────────────
        await self.emit("tool_start", {"tool": "soft-404-detector", "target": target})
        try:
            tool_res = await self.tools.scan(target=target)
            await self.emit("tool_done", {"tool": "soft-404-detector", "output_len": len(tool_res.stdout)})
        except Exception as e:
            log.exception("soft-404-detector scan failed")
            r.success = False
            r.errors.append(str(e))
            await self.emit("complete", {"findings": 0, "error": str(e)})
            return r

        # ── L2: Normalize + Deduplicate ──────────────────────────
        records = self.normalizer.normalize_batch(tool_res.stdout)
        deduped_groups: Dict[str, List[Soft404Record]] = {}
        final_records: List[Soft404Record] = []

        for rec in records:
            group = self.dedup.add(rec)
            if group is None:
                final_records.append(rec)  # صفحة جديدة (ممثل المجموعة)
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

        # ── L5: مراجعة الأدلة + بناء Soft404Profile ─────────
        for rec in final_records:
            ctx = enricher.enrich(rec)
            advice = advisor.advise(rec, ctx)
            review = self.reviewer.review(rec)

            # تحديث السجل
            rec.evidence_level = review["evidence_level"]

            profile = Soft404Profile(
                url=rec.url,
                status_code=rec.status_code,
                content_length=rec.content_length,
                content_type=rec.content_type,
                title=rec.title,
                is_soft_404=rec.is_soft_404,
                similarity_score=rec.similarity_score,
                confidence_score=review["confidence"],
                confidence_label=review["confidence_label"],
                evidence_level=rec.evidence_level,
                context_notes=ctx.get("notes", []),
                adaptive_suggestions=advice,
            )

            finding = {
                "record_id": rec.record_id,
                "url": rec.url,
                "status_code": rec.status_code,
                "content_length": rec.content_length,
                "content_type": rec.content_type,
                "title": rec.title,
                "is_soft_404": rec.is_soft_404,
                "similarity_score": rec.similarity_score,
                "evidence_level": rec.evidence_level,
                "confidence": review["confidence"],
                "confidence_label": review["confidence_label"],
                "evidence_status": review["evidence_status"],
                "is_true_soft_404": review["is_true_soft_404"],
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
