"""HTTPx Agent — يربط L1→L5 معًا في وكيل BaseAgent واحد.
يدير Pipeline: تشغيل HTTPx → Normalize → Dedup → Enrich → Advise → Review.
يُنتج Technology Profiles مع مستويات الثقة — längst E1 (لا يُرفع إلى Confirmed بدون تحقق فعلي).
"""
from __future__ import annotations

import asyncio
import logging
from typing import List, Dict, Any, Optional

from agents.base_agent import BaseAgent, AgentTask, AgentResult
from tools.tool_manager import ToolManager
from tools.httpx_tools import HTTPxTools
from core.httpx.schemas import HTTPxAssetRecord, HTTPxEvidenceLevel, TechnologyProfile
from core.httpx.analyzer import HTTPxNormalizer, DuplicateDetector, EvidenceReviewer
from core.httpx.context import ContextEnricher, AdaptiveTestAdvisor

log = logging.getLogger("httpx.agent")


class HTTPxAgent(BaseAgent):
    """
    وكيل HTTPx المطور (L1→L5):
      L1 Tool Adapter:    HTTPxTools.probe()
      L2 AI Analyzer:     HTTPxNormalizer + DuplicateDetector
      L3 Context:         ContextEnricher (DNS + ports + Katana endpoints)
      L4 Adaptive:        AdaptiveTestAdvisor (اقتراح أدوات/قوالب إضافية)
      L5 Verification:    EvidenceReviewer (evidence status + WAF/CDN detection + confidence)
    """

    def __init__(self, mgr: ToolManager, cb=None):
        super().__init__(
            "httpx_agent",
            "HTTPx Technology Profiler — L1→L5 pipeline with verification",
            mgr,
            cb,
        )
        self.tools = HTTPxTools(mgr)
        self.normalizer = HTTPxNormalizer()
        self.dedup = DuplicateDetector()
        self.reviewer = EvidenceReviewer()

    async def run(self, task: AgentTask) -> AgentResult:
        target = task.target
        extra = task.extra or {}
        targets_file = extra.get("targets_file")
        dns_records = extra.get("dns_records", {})
        open_ports = extra.get("open_ports", {})
        katana_endpoints = extra.get("katana_endpoints", [])
        rate_limit = int(extra.get("rate_limit", 150))

        r = AgentResult(agent_name=self.name, target=target)
        await self.emit("start", {"message": f"HTTPx L1→L5 pipeline on {target}"})

        if not self.tools.is_available():
            r.success = False
            r.errors.append("httpx binary not available")
            await self.emit("complete", {"findings": 0, "error": "httpx_missing"})
            return r

        # إعداد قائمة الأهداف
        targets: List[str] = [target]
        if targets_file:
            try:
                with open(targets_file, "r", encoding="utf-8") as f:
                    file_targets = [line.strip() for line in f if line.strip() and not line.startswith("#")]
                targets = file_targets if file_targets else [target]
            except Exception as e:
                r.success = False
                r.errors.append(f"Cannot read targets file: {e}")
                await self.emit("complete", {"findings": 0, "error": str(e)})
                return r

        # ── L1: تشغيل HTTPx ─────────────────────────────────────
        await self.emit("tool_start", {"tool": "httpx", "target": len(targets), "targets": targets[:5]})
        try:
            tool_res = await self.tools.probe(
                targets=targets,
                rate_limit=rate_limit,
            )
            await self.emit("tool_done", {"tool": "httpx", "output_len": len(tool_res.stdout)})
        except Exception as e:
            log.exception("HTTPx scan failed")
            r.success = False
            r.errors.append(str(e))
            await self.emit("complete", {"findings": 0, "error": str(e)})
            return r

        # ── L2: Normalize + Deduplicate ──────────────────────────
        records = self.normalizer.normalize_batch(tool_res.stdout)
        deduped_groups: Dict[str, List[HTTPxAssetRecord]] = {}
        final_records: List[HTTPxAssetRecord] = []

        for rec in records:
            group = self.dedup.add(rec)
            if group is None:
                final_records.append(rec)  # أصل جديد (ممثل المجموعة)
            else:
                # تكرار — يُسجل في raw_output لكن لا يدخل النتائج الرئيسية
                key = rec.canonical_key
                deduped_groups.setdefault(key, group)

        # flushed groups للإحصاء
        deduped_groups = self.dedup.flush()

        # ── L3: enrich السياق ────────────────────────────────────
        enricher = ContextEnricher(
            dns_records=dns_records,
            open_ports=open_ports,
            katana_endpoints=katana_endpoints,
        )
        advisor = AdaptiveTestAdvisor()

        # ── L5: مراجعة الأدلة + بناء TechnologyProfile ──────────
        for rec in final_records:
            ctx = enricher.enrich(rec)
            advice = advisor.advise(rec, ctx)
            review = self.reviewer.review(rec)

            # تحديث السجل
            rec.evidence_level = review["evidence_level"]

            profile = TechnologyProfile(
                host=rec.host,
                url=rec.url,
                port=rec.port,
                scheme=rec.scheme,
                status_code=rec.status_code,
                web_server=rec.web_server,
                technologies=rec.technologies,
                cdn=rec.cdn,
                confidence_score=review["confidence"],
                confidence_label=review["confidence_label"],
                evidence_level=rec.evidence_level,
                is_likely_waf=review["is_likely_waf"],
                is_likely_cdn=review["is_likely_cdn"],
                context_notes=ctx.get("notes", []),
                adaptive_suggestions=advice,
            )

            finding = {
                "record_id": rec.record_id,
                "host": rec.host,
                "url": rec.url,
                "port": rec.port,
                "scheme": rec.scheme,
                "status_code": rec.status_code,
                "content_length": rec.content_length,
                "content_type": rec.content_type,
                "title": rec.title,
                "web_server": rec.web_server,
                "technologies": rec.technologies,
                "cdn": rec.cdn,
                "ip": rec.ip,
                "cname": rec.cname,
                "evidence_level": rec.evidence_level,
                "confidence": review["confidence"],
                "confidence_label": review["confidence_label"],
                "evidence_status": review["evidence_status"],
                "needs_verification": review["needs_verification"],
                "is_likely_waf": review["is_likely_waf"],
                "is_likely_cdn": review["is_likely_cdn"],
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
