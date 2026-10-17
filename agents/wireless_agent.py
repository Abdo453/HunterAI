"""Wireless Agent — يربط L1→L5 معًا في وكيل BaseAgent واحد.
يدير Pipeline: تشغيل kismet/airodump-ng → Normalize → Dedup → Enrich → Advise → Review.
ينتج ملفات WiFi مع مستويات ثقة — لا يُرفع أي اكتشاف إلى Confirmed هنا.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from agents.base_agent import BaseAgent, AgentTask, AgentResult
from tools.tool_manager import ToolManager
from tools.wireless_tools import WirelessTools
from core.wireless.schemas import (
    WiFiNetworkRecord,
    WirelessEvidenceLevel,
)
from core.wireless.analyzer import DuplicateDetector, EvidenceReviewer, WirelessNormalizer
from core.wireless.context import AdaptiveTestAdvisor, ContextEnricher

log = logging.getLogger("wireless.agent")


class WirelessAgent(BaseAgent):
    """
    وكيل Wireless المطور (L1→L5):
      L1 Tool Adapter:    WirelessTools (kismet / airodump-ng / aircrack-ng / wifite)
      L2 AI Analyzer:     WirelessNormalizer + DuplicateDetector
      L3 Context:         ContextEnricher (قنوات متداخلة، SSID مخفي، WPS)
      L4 Adaptive:        AdaptiveTestAdvisor (aircrack-ng / reaver / wifite)
      L5 Verification:    EvidenceReviewer (مستوى دليل + ثقة)
    """

    def __init__(self, mgr: ToolManager, cb=None):
        super().__init__(
            "wireless_agent",
            "WiFi Discovery & Security — L1→L5 pipeline with verification",
            mgr,
            cb,
        )
        self.tools = WirelessTools(mgr)
        self.normalizer = WirelessNormalizer()
        self.dedup = DuplicateDetector()
        self.reviewer = EvidenceReviewer()

    async def run(self, task: AgentTask) -> AgentResult:
        target = task.target  # interface or target spec
        extra = task.extra or {}
        source = extra.get("source", "auto")  # kismet | airodump | auto
        timeout = int(extra.get("timeout", 300))

        r = AgentResult(agent_name=self.name, target=target)
        await self.emit(
            "start", {"message": f"Wireless L1→L5 pipeline on {target}"}
        )

        if not self.tools.is_available("kismet") and not self.tools.is_available(
            "airodump-ng"
        ):
            r.success = False
            r.errors.append("kismet/airodump-ng binary not available")
            await self.emit("complete", {"findings": 0, "error": "wireless_missing"})
            return r

        await self.emit("tool_start", {"tool": source, "target": target})
        try:
            if source == "airodump":
                tool_res = await self.tools.airodump_csv(
                    interface=target, timeout=timeout
                )
            else:
                tool_res = await self.tools.kismet_json(target=target, timeout=timeout)
        except Exception as e:
            log.exception("wireless scan failed")
            r.success = False
            r.errors.append(str(e))
            await self.emit("complete", {"findings": 0, "error": str(e)})
            return r

        # L2
        records = self.normalizer.normalize(tool_res.stdout, source=source)
        merged = [self.dedup.add(rec) for rec in records]
        merged = self.dedup.flush() or merged

        enricher = ContextEnricher(other_networks=merged)
        advisor = AdaptiveTestAdvisor()

        for rec in merged:
            ctx = enricher.enrich(rec)
            review = self.reviewer.review(rec)
            advice = advisor.advise(rec, ctx)

            r.findings.append(
                {
                    "record_id": rec.record_id,
                    "ssid": rec.ssid,
                    "bssid": rec.bssid,
                    "channel": rec.channel,
                    "signal_dbm": rec.signal_dbm,
                    "encryption": rec.encryption,
                    "cipher": rec.cipher,
                    "auth": rec.auth,
                    "wps": rec.wps,
                    "hidden": rec.hidden,
                    "vendor": rec.vendor,
                    "is_open": rec.is_open,
                    "is_weak": rec.is_weak,
                    "channel_overlap": ctx.get("channel_overlap", False),
                    "overlapping_count": ctx.get("overlapping_count", 0),
                    "risk_tier": ctx.get("risk_tier", "low"),
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
                "networks": len(merged),
                "weak": sum(1 for m in merged if m.is_weak),
                "open": sum(1 for m in merged if m.is_open),
            },
        )
        return r
