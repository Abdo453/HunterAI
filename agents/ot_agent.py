"""OT Agent — يربط L1→L5 معًا في وكيل BaseAgent واحد.
يدير Pipeline: تشغيل nmap ICS scripts → Normalize → Dedup → Enrich → Advise → Review.
ينتج ملفات OT مع مستويات ثقة — لا يُرفع أي اكتشاف إلى Confirmed هنا.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from agents.base_agent import BaseAgent, AgentTask, AgentResult
from tools.tool_manager import ToolManager
from tools.ot_tools import OTTools
from core.ot.schemas import OTAssetRecord, OTEvidenceLevel
from core.ot.analyzer import DuplicateDetector, EvidenceReviewer, OTNormalizer
from core.ot.context import AdaptiveTestAdvisor, ContextEnricher

log = logging.getLogger("ot.agent")


class OTAgent(BaseAgent):
    """
    وكيل OT المطور (L1→L5):
      L1 Tool Adapter:    OTTools (nmap ICS scripts / modbus-cli)
      L2 AI Analyzer:     OTNormalizer + DuplicateDetector
      L3 Context:         ContextEnricher (البروتوكول، صلاحية الكتابة، تأثير السلامة)
      L4 Adaptive:        AdaptiveTestAdvisor (modbus-cli / s7-info)
      L5 Verification:    EvidenceReviewer (مستوى دليل + ثقة)
    """

    def __init__(self, mgr: ToolManager, cb=None):
        super().__init__(
            "ot_agent",
            "OT / ICS Asset Discovery — L1→L5 pipeline with verification",
            mgr,
            cb,
        )
        self.tools = OTTools(mgr)
        self.normalizer = OTNormalizer()
        self.dedup = DuplicateDetector()
        self.reviewer = EvidenceReviewer()

    async def run(self, task: AgentTask) -> AgentResult:
        target = task.target
        extra = task.extra or {}
        ports = extra.get("ports", "502,102,44818")
        timeout = int(extra.get("timeout", 300))

        r = AgentResult(agent_name=self.name, target=target)
        await self.emit("start", {"message": f"OT L1→L5 pipeline on {target}"})

        if not self.tools.is_available("nmap"):
            r.success = False
            r.errors.append("nmap binary not available")
            await self.emit("complete", {"findings": 0, "error": "ot_missing"})
            return r

        await self.emit("tool_start", {"tool": "nmap", "target": target, "ports": ports})
        try:
            tool_res = await self.tools.nmap_ics(target=target, ports=ports, timeout=timeout)
        except Exception as e:
            log.exception("ot discovery failed")
            r.success = False
            r.errors.append(str(e))
            await self.emit("complete", {"findings": 0, "error": str(e)})
            return r

        # L2
        records = self.normalizer.normalize(tool_res.stdout, source="nmap")
        merged = [self.dedup.add(rec) for rec in records]
        merged = self.dedup.flush() or merged

        enricher = ContextEnricher()
        advisor = AdaptiveTestAdvisor()

        for rec in merged:
            ctx = enricher.enrich(rec)
            review = self.reviewer.review(rec)
            advice = advisor.advise(rec, ctx)

            r.findings.append(
                {
                    "record_id": rec.record_id,
                    "ip": rec.ip,
                    "port": rec.port,
                    "protocol": rec.protocol,
                    "vendor": rec.vendor,
                    "model": rec.model,
                    "unit_id": rec.unit_id,
                    "function_codes": rec.function_codes,
                    "unauthenticated": rec.unauthenticated,
                    "write_access": rec.write_access,
                    "is_high_risk": rec.is_high_risk,
                    "safety_impact": ctx.get("safety_impact", "low"),
                    "process_control": ctx.get("process_control", False),
                    "protocol_risk": ctx.get("protocol_risk", []),
                    "confidence": review["confidence"],
                    "confidence_label": review["confidence_label"],
                    "evidence_level": rec.evidence_level,
                    "evidence_status": review["evidence_status"],
                    "needs_verification": review["needs_verification"],
                    "context_notes": review["notes"] + ctx.get("notes", []),
                    "adaptive_suggestions": advice,
                    "recommendation": review["recommendation"],
                }
            )

        await self.emit(
            "complete",
            {
                "findings": len(r.findings),
                "assets": len(merged),
                "high_risk": sum(1 for m in merged if m.is_high_risk),
            },
        )
        return r
