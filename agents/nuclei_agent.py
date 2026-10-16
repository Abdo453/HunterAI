"""Nuclei Agent — يربط L1→L5 معًا في وكيل BaseAgent واحد.
يدير Pipeline: تشغيل Nuclei → Normalize → Dedup → Enrich → Advise → Review.
يُنتج Findings بحالة pending/needs_verification — أبدًا Confirmed بدون E2.
"""
from __future__ import annotations

import asyncio
import logging
from typing import List, Dict, Any, Optional

from agents.base_agent import BaseAgent, AgentTask, AgentResult
from tools.tool_manager import ToolManager
from tools.nuclei_tools import NucleiTools
from core.nuclei.schemas import (
    NucleiFindingRecord, NucleiEvidenceLevel, FindingStatus,
)
from core.nuclei.analyzer import FindingNormalizer, DuplicateDetector, EvidenceReviewer
from core.nuclei.context import ContextEnricher, AdaptiveTestAdvisor

log = logging.getLogger("nuclei.agent")


class NucleiAgent(BaseAgent):
    """
    وكيل Nuclei المطور (L1→L5):
      L1 Tool Adapter:    NucleiTools.scan()
      L2 AI Analyzer:     FindingNormalizer + DuplicateDetector
      L3 Context:         ContextEnricher (Katana + HTTPx)
      L4 Adaptive:        AdaptiveTestAdvisor (اقتراح قوالب إضافية)
      L5 Verification:    EvidenceReviewer (case status + scope check)
    """

    def __init__(self, mgr: ToolManager, cb=None):
        super().__init__(
            "nuclei_agent",
            "Nuclei Finding Analyzer — L1→L5 pipeline with verification",
            mgr,
            cb,
        )
        self.tools = NucleiTools(mgr)
        self.normalizer = FindingNormalizer()
        self.dedup = DuplicateDetector()
        self.reviewer = EvidenceReviewer(in_scope=True)  # يُحدّث من الـ scope gate

    async def run(self, task: AgentTask) -> AgentResult:
        target = task.target
        extra = task.extra or {}
        templates = extra.get("templates")
        severity = extra.get("severity")
        tags = extra.get("tags")
        katana_endpoints = extra.get("katana_endpoints", [])
        detected_tech = extra.get("detected_tech", [])

        r = AgentResult(agent_name=self.name, target=target)
        await self.emit("start", {"message": f"Nuclei L1→L5 pipeline on {target}"})

        if not self.tools.is_available():
            r.success = False
            r.errors.append("nuclei binary not available")
            await self.emit("complete", {"findings": 0, "error": "nuclei_missing"})
            return r

        # ── L1: تشغيل Nuclei ─────────────────────────────────────
        await self.emit("tool_start", {"tool": "nuclei", "target": target})
        try:
            tool_res = await self.tools.scan(
                target=target,
                templates=templates,
                severity=severity,
                tags=tags,
            )
            await self.emit("tool_done", {"tool": "nuclei", "output_len": len(tool_res.stdout)})
        except Exception as e:
            log.exception("Nuclei scan failed")
            r.success = False
            r.errors.append(str(e))
            await self.emit("complete", {"findings": 0, "error": str(e)})
            return r

        # ── L2: Normalize + Deduplicate ──────────────────────────
        records = self.normalizer.normalize_batch(tool_res.stdout)
        deduped_groups = []
        final_records: List[NucleiFindingRecord] = []

        for rec in records:
            group = self.dedup.add(rec)
            if group is None:
                final_records.append(rec)  # سجل جديد (ممثل المجموعة)
            else:
                # تكراري — يُضاف إلى raw_output لكنه لا يدخل النتائج الرئيسية
                r.raw_output.setdefault("duplicates", []).append(rec.to_dict())

        # flushed groups (للإحصاء)
        deduped_groups = self.dedup.flush()

        # ── L3: enrich السياق ────────────────────────────────────
        enricher = ContextEnricher(
            katana_endpoints=katana_endpoints,
            detected_tech=set(detected_tech),
        )
        advisor = AdaptiveTestAdvisor()

        # ── L5: مراجعة الأدلة ───────────────────────────────────
        for rec in final_records:
            ctx = enricher.enrich(rec)
            advice = advisor.advise(rec, ctx)
            review = self.reviewer.review(rec)

            # تحديث السجل بالنتيجة
            rec.status = review["status"]
            rec.evidence_level = review["evidence_level"]
            rec.validation_note += f" | review: {review['evidence_status']}"

            # إضافة إلى نتائج الوكيل (فقط pending/needs_verification — ليس confirmed)
            finding = {
                "record_id": rec.record_id,
                "template_id": rec.template_id,
                "template_name": rec.template_name,
                "severity": rec.severity,
                "matched_at": rec.matched_at,
                "matcher_name": rec.matcher_name,
                "evidence_level": rec.evidence_level,
                "status": rec.status,
                "confidence": review["confidence"],
                "needs_verification": review["needs_verification"],
                "scope_check": review["scope_check"],
                "context": ctx,
                "adaptive_templates": advice,
                "recommendation": review["recommendation"],
                "raw_match": rec.raw_match_json,
            }
            r.findings.append(finding)

        await self.emit("complete", {
            "findings": len(r.findings),
            "duplicates_removed": len(deduped_groups),
            "raw_matches": len(records),
        })
        return r
