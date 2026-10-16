"""Katana Agent — يربط L1→L5 معًا في وكيل BaseAgent واحد.
يدير Pipeline: تشغيل Katana → Normalize → Dedup → Enrich → Advise → Review.
يُنتج Endpoint Profiles مع مستويات الثقة — längst E1 (لا يُرفع إلى Confirmed بدون تحقق يدوي).
"""
from __future__ import annotations

import asyncio
import logging
from typing import List, Dict, Any, Optional

from agents.base_agent import BaseAgent, AgentTask, AgentResult
from tools.tool_manager import ToolManager
from tools.katana_tools import KatanaTools
from core.katana.schemas import KatanaEndpointRecord, KatanaEvidenceLevel
from core.katana.analyzer import KatanaNormalizer, DuplicateDetector, EvidenceReviewer
from core.katana.context import ContextEnricher, AdaptiveTestAdvisor

log = logging.getLogger("katana.agent")


class KatanaAgent(BaseAgent):
    """
    وكيل Katana المطور (L1→L5):
      L1 Tool Adapter:    KatanaTools.crawl()
      L2 AI Analyzer:     KatanaNormalizer + DuplicateDetector
      L3 Context:         ContextEnricher (HTTPx tech + endpoint classification)
      L4 Adaptive:        AdaptiveTestAdvisor (اقتراح أدوات/قوالب إضافية)
      L5 Verification:    EvidenceReviewer (evidence status + confidence)
    """

    def __init__(self, mgr: ToolManager, cb=None):
        super().__init__(
            "katana_agent",
            "Katana Endpoint Intelligence — L1→L5 pipeline with verification",
            mgr,
            cb,
        )
        self.tools = KatanaTools(mgr)
        self.normalizer = KatanaNormalizer()
        self.dedup = DuplicateDetector()
        self.reviewer = EvidenceReviewer()

    async def run(self, task: AgentTask) -> AgentResult:
        target = task.target
        extra = task.extra or {}
        depth = int(extra.get("depth", 2))
        rate_limit = int(extra.get("rate_limit", 50))
        httpx_tech = extra.get("httpx_tech", {})
        existing_endpoints = set(extra.get("existing_endpoints", []))

        r = AgentResult(agent_name=self.name, target=target)
        await self.emit("start", {"message": f"Katana L1→L5 pipeline on {target}"})

        if not self.tools.is_available():
            r.success = False
            r.errors.append("katana binary not available")
            await self.emit("complete", {"findings": 0, "error": "katana_missing"})
            return r

        # ── L1: تشغيل Katana ─────────────────────────────────────
        await self.emit("tool_start", {"tool": "katana", "target": target, "depth": depth})
        try:
            tool_res = await self.tools.crawl(
                url=target,
                depth=depth,
                rate_limit=rate_limit,
            )
            await self.emit("tool_done", {"tool": "katana", "output_len": len(tool_res.stdout)})
        except Exception as e:
            log.exception("Katana crawl failed")
            r.success = False
            r.errors.append(str(e))
            await self.emit("complete", {"findings": 0, "error": str(e)})
            return r

        # ── L2: Normalize + Deduplicate ──────────────────────────
        records = self.normalizer.normalize_batch(tool_res.stdout)
        deduped_groups: Dict[str, List[KatanaEndpointRecord]] = {}
        final_records: List[KatanaEndpointRecord] = []

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
            httpx_tech=httpx_tech,
            existing_endpoints=existing_endpoints,
        )
        advisor = AdaptiveTestAdvisor()

        # ── L5: مراجعة الأدلة + بناء EndpointProfile ──────────
        for rec in final_records:
            ctx = enricher.enrich(rec)
            advice = advisor.advise(rec, ctx)
            review = self.reviewer.review(rec)

            # تحديث السجل
            rec.evidence_level = review["evidence_level"]

            profile = EndpointProfile(
                url=rec.url,
                method=rec.method,
                category=rec.category,
                confidence_score=review["confidence"],
                confidence_label=review["confidence_label"],
                evidence_level=rec.evidence_level,
                is_auth_sensitive=review["is_auth_sensitive"],
                is_admin_sensitive=review["is_admin_sensitive"],
                is_api=review["is_api"],
                context_notes=ctx.get("notes", []),
                adaptive_suggestions=advice,
            )

            finding = {
                "record_id": rec.record_id,
                "url": rec.url,
                "method": rec.method,
                "category": rec.category,
                "status_code": rec.status_code,
                "content_length": rec.content_length,
                "content_type": rec.content_type,
                "is_js": rec.is_js,
                "is_form": rec.is_form,
                "parameters": rec.parameters,
                "evidence_level": rec.evidence_level,
                "confidence": review["confidence"],
                "confidence_label": review["confidence_label"],
                "evidence_status": review["evidence_status"],
                "is_auth_sensitive": review["is_auth_sensitive"],
                "is_admin_sensitive": review["is_admin_sensitive"],
                "is_api": review["is_api"],
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
