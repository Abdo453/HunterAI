"""Nmap Agent — يربط L1→L5 معًا في وكيل BaseAgent واحد.
يدير Pipeline: تشغيل Nmap → Normalize → Dedup → Enrich → Advise → Review.
يُنتج Service Profiles مع مستويات الثقة — längst E1 (لا يُرفع إلى Confirmed بدون تحقق يدوي).
"""
from __future__ import annotations

import asyncio
import logging
from typing import List, Dict, Any, Optional

from agents.base_agent import BaseAgent, AgentTask, AgentResult
from tools.tool_manager import ToolManager
from tools.nmap_tools import NmapTools
from core.nmap.schemas import NmapPortRecord, NmapEvidenceLevel, ServiceProfile
from core.nmap.analyzer import NmapNormalizer, DuplicateDetector, EvidenceReviewer
from core.nmap.context import ContextEnricher, AdaptiveTestAdvisor

log = logging.getLogger("nmap.agent")


class NmapAgent(BaseAgent):
    """
    وكيل Nmap المطور (L1→L5):
      L1 Tool Adapter:    NmapTools.scan()
      L2 AI Analyzer:     NmapNormalizer + DuplicateDetector
      L3 Context:         ContextEnricher (HTTPx results + Katana endpoints)
      L4 Adaptive:        AdaptiveTestAdvisor (اقتراح أدوات/قوالب إضافية)
      L5 Verification:    EvidenceReviewer (evidence status + WAF detection + confidence)
    """

    def __init__(self, mgr: ToolManager, cb=None):
        super().__init__(
            "nmap_agent",
            "Nmap Service Fingerprint — L1→L5 pipeline with verification",
            mgr,
            cb,
        )
        self.tools = NmapTools(mgr)
        self.normalizer = NmapNormalizer()
        self.dedup = DuplicateDetector()
        self.reviewer = EvidenceReviewer()

    async def run(self, task: AgentTask) -> AgentResult:
        target = task.target
        extra = task.extra or {}
        ports = extra.get("ports")
        service_detection = extra.get("service_detection", True)
        version_detection = extra.get("version_detection", True)
        scripts = extra.get("scripts")
        timing = extra.get("timing", "T4")
        httpx_results = extra.get("httpx_results", {})
        katana_endpoints = extra.get("katana_endpoints", [])

        r = AgentResult(agent_name=self.name, target=target)
        await self.emit("start", {"message": f"Nmap L1→L5 pipeline on {target}"})

        if not self.tools.is_available():
            r.success = False
            r.errors.append("nmap binary not available")
            await self.emit("complete", {"findings": 0, "error": "nmap_missing"})
            return r

        # ── L1: تشغيل Nmap ─────────────────────────────────────
        await self.emit("tool_start", {"tool": "nmap", "target": target, "ports": ports or "all"})
        try:
            tool_res = await self.tools.scan(
                target=target,
                ports=ports,
                service_detection=service_detection,
                version_detection=version_detection,
                scripts=scripts,
                timing=timing,
            )
            await self.emit("tool_done", {"tool": "nmap", "output_len": len(tool_res.stdout)})
        except Exception as e:
            log.exception("Nmap scan failed")
            r.success = False
            r.errors.append(str(e))
            await self.emit("complete", {"findings": 0, "error": str(e)})
            return r

        # ── L2: Normalize + Deduplicate ──────────────────────────
        records = self.normalizer.normalize_batch(tool_res.stdout)
        deduped_groups: Dict[str, List[NmapPortRecord]] = {}
        final_records: List[NmapPortRecord] = []

        for rec in records:
            group = self.dedup.add(rec)
            if group is None:
                final_records.append(rec)  # منفذ جديد (ممثل المجموعة)
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

        # ── L5: مراجعة الأدلة + بناء ServiceProfile ──────────
        for rec in final_records:
            ctx = enricher.enrich(rec)
            advice = advisor.advise(rec, ctx)
            review = self.reviewer.review(rec)

            # تحديث السجل
            rec.evidence_level = review["evidence_level"]

            profile = ServiceProfile(
                host=rec.host,
                port=rec.port,
                protocol=rec.protocol,
                state=rec.state,
                service_name=rec.service_name,
                service_version=rec.service_version,
                service_product=rec.service_product,
                banner=rec.banner,
                confidence=review["confidence_label"],
                confidence_score=review["confidence_score"],
                evidence_level=rec.evidence_level,
                is_high_value=review["is_high_value"],
                is_likely_waf=review["is_likely_waf"],
                context_notes=ctx.get("notes", []),
                adaptive_suggestions=advice,
            )

            finding = {
                "record_id": rec.record_id,
                "host": rec.host,
                "port": rec.port,
                "protocol": rec.protocol,
                "state": rec.state,
                "service_name": rec.service_name,
                "service_version": rec.service_version,
                "service_product": rec.service_product,
                "banner": rec.banner,
                "confidence": review["confidence_score"],
                "confidence_label": review["confidence_label"],
                "evidence_level": rec.evidence_level,
                "evidence_status": review["evidence_status"],
                "is_high_value": review["is_high_value"],
                "is_likely_waf": review["is_likely_waf"],
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
