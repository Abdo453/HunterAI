"""Cloud-Enum Agent — L1→L5 pipeline with verification"""
from __future__ import annotations

import asyncio
import logging
from typing import List, Dict, Any, Optional

from agents.base_agent import BaseAgent, AgentTask, AgentResult
from tools.tool_manager import ToolManager
from tools.cloud_enum_tools import CloudEnumTools
from core.cloud_enum.schemas import CloudBucketRecord, CloudEnumEvidenceLevel
from core.cloud_enum.analyzer import CloudEnumNormalizer, DuplicateDetector, EvidenceReviewer
from core.cloud_enum.context import ContextEnricher, AdaptiveTestAdvisor

log = logging.getLogger("cloud_enum.agent")


class CloudEnumAgent(BaseAgent):
    """
    وكيل cloud-enum المطور (L1→L5):
      L1 Tool Adapter:    CloudEnumTools.scan()
      L2 AI Analyzer:     CloudEnumNormalizer + DuplicateDetector
      L3 Context:         ContextEnricher (HTTPx results)
      L4 Adaptive:        AdaptiveTestAdvisor (اقتراح أدوات/قوالب إضافية)
      L5 Verification:    EvidenceReviewer (evidence status + confidence)
    """

    def __init__(self, mgr: ToolManager, cb=None):
        super().__init__(
            "cloud_enum_agent",
            "Cloud-Enum Cloud Storage — L1→L5 pipeline with verification",
            mgr,
            cb,
        )
        self.tools = CloudEnumTools(mgr)
        self.normalizer = CloudEnumNormalizer()
        self.dedup = DuplicateDetector()
        self.reviewer = EvidenceReviewer()

    async def run(self, task: AgentTask) -> AgentResult:
        target = task.target
        extra = task.extra or {}
        httpx_results = extra.get("httpx_results", {})

        r = AgentResult(agent_name=self.name, target=target)
        await self.emit("start", {"message": f"Cloud-Enum L1→L5 pipeline on {target}"})

        if not self.tools.is_available():
            r.success = False
            r.errors.append("cloud-enum binary not available")
            await self.emit("complete", {"findings": 0, "error": "cloud-enum_missing"})
            return r

        # ── L1: تشغيل cloud-enum ─────────────────────────────────────
        await self.emit("tool_start", {"tool": "cloud-enum", "target": target})
        try:
            tool_res = await self.tools.scan(target=target)
            await self.emit("tool_done", {"tool": "cloud-enum", "output_len": len(tool_res.stdout)})
        except Exception as e:
            log.exception("cloud-enum scan failed")
            r.success = False
            r.errors.append(str(e))
            await self.emit("complete", {"findings": 0, "error": str(e)})
            return r

        # ── L2: Normalize + Deduplicate ──────────────────────────
        records = self.normalizer.normalize_batch(tool_res.stdout)
        deduped_groups: Dict[str, List[CloudBucketRecord]] = {}
        final_records: List[CloudBucketRecord] = []

        for rec in records:
            group = self.dedup.add(rec)
            if group is None:
                final_records.append(rec)  # دلو جديد (ممثل المجموعة)
            else:
                key = rec.canonical_key
                deduped_groups.setdefault(key, group)

        deduped_groups = self.dedup.flush()

        # ── L3: enrichment السياق ────────────────────────────────
        enricher = ContextEnricher(
            httpx_results=httpx_results,
        )
        advisor = AdaptiveTestAdvisor()

        # ── L5: مراجعة الأدلة + بناء CloudBucketProfile ─────────
        for rec in final_records:
            ctx = enricher.enrich(rec)
            advice = advisor.advise(rec, ctx)
            review = self.reviewer.review(rec)

            # تحديث السجل
            rec.evidence_level = review["evidence_level"]

            profile = CloudBucketProfile(
                bucket_name=rec.bucket_name,
                provider=rec.provider,
                access_level=rec.access_level,
                region=rec.region,
                url=rec.url,
                confidence_score=review["confidence"],
                confidence_label=review["confidence_label"],
                evidence_level=rec.evidence_level,
                is_public=review["is_public"],
                context_notes=ctx.get("notes", []),
                adaptive_suggestions=advice,
            )

            finding = {
                "record_id": rec.record_id,
                "bucket_name": rec.bucket_name,
                "provider": rec.provider,
                "access_level": rec.access_level,
                "region": rec.region,
                "url": rec.url,
                "evidence_level": rec.evidence_level,
                "confidence": review["confidence"],
                "confidence_label": review["confidence_label"],
                "evidence_status": review["evidence_status"],
                "is_public": review["is_public"],
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
