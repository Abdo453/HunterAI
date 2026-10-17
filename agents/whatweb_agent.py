"""WhatWeb Agent — يربط L1→L5 معًا في وكيل BaseAgent واحد.
يدير Pipeline: تشغيل whatweb → Normalize → Dedup → Enrich → Advise → Review.
ينتج تقنيات بصمات مع مستويات ثقة — لا يُرفع أي اكتشاف إلى Confirmed هنا.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from agents.base_agent import BaseAgent, AgentTask, AgentResult
from tools.tool_manager import ToolManager
from tools.whatweb_tools import WhatWebTools
from core.whatweb.schemas import (
    TechFingerprintProfile,
    WhatWebAssetRecord,
    WhatWebEvidenceLevel,
)
from core.whatweb.analyzer import DuplicateDetector, EvidenceReviewer, WhatWebNormalizer
from core.whatweb.context import AdaptiveTestAdvisor, ContextEnricher

log = logging.getLogger("whatweb.agent")


class WhatWebAgent(BaseAgent):
    """
    وكيل WhatWeb المطور (L1→L5):
      L1 Tool Adapter:    WhatWebTools.scan()
      L2 AI Analyzer:     WhatWebNormalizer + DuplicateDetector
      L3 Context:         ContextEnricher (CMS/خادم الويب/مكتبات JS)
      L4 Adaptive:        AdaptiveTestAdvisor (اقتراح nuclei/wpscan)
      L5 Verification:    EvidenceReviewer (درجة ثقة + مستوى دليل)
    """

    def __init__(self, mgr: ToolManager, cb=None):
        super().__init__(
            "whatweb_agent",
            "WhatWeb Technology Fingerprint — L1→L5 pipeline with verification",
            mgr,
            cb,
        )
        self.tools = WhatWebTools(mgr)
        self.normalizer = WhatWebNormalizer()
        self.dedup = DuplicateDetector()
        self.reviewer = EvidenceReviewer()

    async def run(self, task: AgentTask) -> AgentResult:
        target = task.target
        extra = task.extra or {}
        aggressive = int(extra.get("aggressive", 3))
        plugins = extra.get("plugins")

        r = AgentResult(agent_name=self.name, target=target)
        await self.emit(
            "start", {"message": f"WhatWeb L1→L5 pipeline on {target}"}
        )

        if not self.tools.is_available():
            r.success = False
            r.errors.append("whatweb binary not available")
            await self.emit("complete", {"findings": 0, "error": "whatweb_missing"})
            return r

        await self.emit("tool_start", {"tool": "whatweb", "target": target})
        try:
            tool_res = await self.tools.scan(
                target=target, aggressive=aggressive, plugins=plugins
            )
        except Exception as e:
            log.exception("whatweb scan failed")
            r.success = False
            r.errors.append(str(e))
            await self.emit("complete", {"findings": 0, "error": str(e)})
            return r

        # L2
        records = self.normalizer.normalize(tool_res.stdout)
        merged = [self.dedup.add(rec) for rec in records]
        merged = self.dedup.flush() or merged

        enricher = ContextEnricher()
        advisor = AdaptiveTestAdvisor()

        for rec in merged:
            ctx = enricher.enrich(rec)
            review = self.reviewer.review(rec)
            advice = advisor.advise(rec, ctx)

            profile = TechFingerprintProfile(
                target=rec.target,
                url=rec.url,
                http_status=rec.http_status,
                server=rec.server,
                plugin_count=len(rec.plugins),
                technology_count=len(rec.technologies),
                cms_detected=bool(ctx.get("cms")),
                web_server_detected=bool(ctx.get("web_server")),
                javascript_libraries=ctx.get("javascript_libraries", []),
                confidence_score=review["confidence"],
                confidence_label=review["confidence_label"],
                evidence_level=rec.evidence_level,
                context_notes=review["notes"] + ctx.get("notes", []),
                adaptive_suggestions=advice,
            )
            r.raw_output[f"fingerprint::{rec.url}"] = str(profile.to_dict())

            r.findings.append(
                {
                    "record_id": rec.record_id,
                    "target": rec.target,
                    "url": rec.url,
                    "http_status": rec.http_status,
                    "server": rec.server,
                    "cms": ctx.get("cms"),
                    "web_server": ctx.get("web_server"),
                    "plugins": [p.name for p in rec.plugins],
                    "technologies": rec.technologies,
                    "javascript_libraries": ctx.get("javascript_libraries", []),
                    "is_cms": ctx.get("is_cms", False),
                    "is_ecommerce": ctx.get("is_ecommerce", False),
                    "attack_surface": ctx.get("attack_surface", []),
                    "confidence": review["confidence"],
                    "confidence_label": review["confidence_label"],
                    "evidence_level": rec.evidence_level,
                    "evidence_status": review["evidence_status"],
                    "needs_verification": review["needs_verification"],
                    "context_notes": profile.context_notes,
                    "adaptive_suggestions": advice,
                    "recommendation": review["recommendation"],
                }
            )

        await self.emit(
            "complete",
            {
                "findings": len(r.findings),
                "targets": len(merged),
                "total_plugins": sum(len(m.plugins) for m in merged),
            },
        )
        return r
