"""ffuf Agent — يربط L1→L5 معًا في وكيل BaseAgent واحد.
يدير Pipeline: تشغيل ffuf → Normalize → Dedup → Soft-404 Detection → Enrich → Advise → Review.
يُنتج نتائج استجابة مع مستويات الثقة — längst E1 (لا يُرفع إلى Confirmed بدون تحقق يدوي).
"""
from __future__ import annotations

import asyncio
import logging
from typing import List, Dict, Any, Optional

from agents.base_agent import BaseAgent, AgentTask, AgentResult
from tools.tool_manager import ToolManager
from tools.ffuf_tools import FfufTools
from core.ffuf.schemas import FfufResultRecord, FfufEvidenceLevel
from core.ffuf.analyzer import FfufNormalizer, DuplicateDetector, Soft404Detector, EvidenceReviewer
from core.ffuf.context import ContextEnricher, AdaptiveWordlistAdvisor

log = logging.getLogger("ffuf.agent")


class FfufAgent(BaseAgent):
    """
    وكيل ffuf المطور (L1→L5):
      L1 Tool Adapter:    FfufTools.run()
      L2 AI Analyzer:     FfufNormalizer + DuplicateDetector
      L3 Context:         ContextEnricher (Katana endpoints + path classification)
      L4 Adaptive:        AdaptiveWordlistAdvisor (اقتراح قوائم كلمات بناءً على السياق)
      L5 Verification:    Soft404Detector + EvidenceReviewer (case status + confidence)
    """

    def __init__(self, mgr: ToolManager, cb=None):
        super().__init__(
            "ffuf_agent",
            "ffuf Response Intelligence — L1→L5 pipeline with verification",
            mgr,
            cb,
        )
        self.tools = FfufTools(mgr)
        self.normalizer = FfufNormalizer()
        self.dedup = DuplicateDetector()
        self.soft404 = Soft404Detector()
        self.reviewer = EvidenceReviewer()

    async def run(self, task: AgentTask) -> AgentResult:
        target = task.target
        extra = task.extra or {}
        wordlist = extra.get("wordlist", "common.txt")
        extensions = extra.get("extensions")
        filter_status = extra.get("filter_status")
        filter_size = extra.get("filter_size")
        filter_words = extra.get("filter_words")
        rate_limit = int(extra.get("rate_limit", 50))
        katana_endpoints = extra.get("katana_endpoints", [])

        r = AgentResult(agent_name=self.name, target=target)
        await self.emit("start", {"message": f"ffuf L1→L5 pipeline on {target}"})

        if not self.tools.is_available():
            r.success = False
            r.errors.append("ffuf binary not available")
            await self.emit("complete", {"findings": 0, "error": "ffuf_missing"})
            return r

        # بناء URL الهدف (إضافة FUZZ إذا لم يحتوي على كلمة FUZZ)
        fuzz_url = target
        if "FUZZ" not in fuzz_url:
            if fuzz_url.endswith("/"):
                fuzz_url = fuzz_url + "FUZZ"
            else:
                fuzz_url = fuzz_url + "/FUZZ"

        # ── L1: تشغيل ffuf ─────────────────────────────────────
        await self.emit("tool_start", {"tool": "ffuf", "target": fuzz_url, "wordlist": wordlist})
        try:
            tool_res = await self.tools.run(
                url=fuzz_url,
                wordlist=wordlist,
                extensions=extensions,
                filter_status=filter_status,
                filter_size=filter_size,
                filter_words=filter_words,
                rate_limit=rate_limit,
            )
            await self.emit("tool_done", {"tool": "ffuf", "output_len": len(tool_res.stdout)})
        except Exception as e:
            log.exception("ffuf scan failed")
            r.success = False
            r.errors.append(str(e))
            await self.emit("complete", {"findings": 0, "error": str(e)})
            return r

        # ── L2: Normalize + Deduplicate ──────────────────────────
        records = self.normalizer.normalize_batch(tool_res.stdout)
        deduped_groups: Dict[str, List[FfufResultRecord]] = {}
        final_records: List[FfufResultRecord] = []

        for rec in records:
            group = self.dedup.add(rec)
            if group is None:
                final_records.append(rec)  # نتيجة جديدة (ممثل المجموعة)
            else:
                key = rec.canonical_key
                deduped_groups.setdefault(key, group)

        deduped_groups = self.dedup.flush()

        # ── L3: enrichment السياق ────────────────────────────────
        enricher = ContextEnricher(
            katana_endpoints=katana_endpoints,
        )
        advisor = AdaptiveWordlistAdvisor()

        # ── L4 + L5: Soft-404 detection + مراجعة الأدلة ─────────
        final_records = self.soft404.detect(final_records)

        for rec in final_records:
            ctx = enricher.enrich(rec)
            advice = advisor.advise(rec, ctx)
            review = self.reviewer.review(rec)

            # تحديث السجل
            rec.evidence_level = review["evidence_level"]
            rec.confidence_score = review["confidence"]
            rec.confidence_label = review["confidence_label"]

            finding = {
                "record_id": rec.record_id,
                "url": rec.url,
                "method": rec.method,
                "status_code": rec.status_code,
                "content_length": rec.content_length,
                "content_words": rec.content_words,
                "content_lines": rec.content_lines,
                "redirect_location": rec.redirect_location,
                "category": rec.category,
                "evidence_level": rec.evidence_level,
                "confidence": review["confidence"],
                "confidence_label": review["confidence_label"],
                "evidence_status": review["evidence_status"],
                "is_interesting": review["is_interesting"],
                "needs_verification": review["needs_verification"],
                "context": ctx,
                "adaptive_wordlist": advice,
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
