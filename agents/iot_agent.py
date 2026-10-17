"""IoT Agent — يربط L1→L5 معًا في وكيل BaseAgent واحد.
يدير Pipeline: تشغيل zigbee2mqtt/nmap → Normalize → Dedup → Enrich → Advise → Review.
ينتج ملفات أجهزة IoT مع مستويات ثقة — لا يُرفع أي اكتشاف إلى Confirmed هنا.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from agents.base_agent import BaseAgent, AgentTask, AgentResult
from tools.tool_manager import ToolManager
from tools.iot_tools import IoTTools
from core.iot.schemas import IoTDeviceRecord, IoTEvidenceLevel
from core.iot.analyzer import DuplicateDetector, EvidenceReviewer, IoTNormalizer
from core.iot.context import AdaptiveTestAdvisor, ContextEnricher

log = logging.getLogger("iot.agent")


class IoTAgent(BaseAgent):
    """
    وكيل IoT المطور (L1→L5):
      L1 Tool Adapter:    IoTTools (zigbee2mqtt / nmap iot scripts / ble)
      L2 AI Analyzer:     IoTNormalizer + DuplicateDetector
      L3 Context:         ContextEnricher (البروتوكول، المنافذ، خطر البيانات الافتراضية)
      L4 Adaptive:        AdaptiveTestAdvisor (mqtt / upnp / ble / hydra)
      L5 Verification:    EvidenceReviewer (مستوى دليل + ثقة)
    """

    def __init__(self, mgr: ToolManager, cb=None):
        super().__init__(
            "iot_agent",
            "IoT Device Discovery — L1→L5 pipeline with verification",
            mgr,
            cb,
        )
        self.tools = IoTTools(mgr)
        self.normalizer = IoTNormalizer()
        self.dedup = DuplicateDetector()
        self.reviewer = EvidenceReviewer()

    async def run(self, task: AgentTask) -> AgentResult:
        target = task.target
        extra = task.extra or {}
        source = extra.get("source", "zigbee2mqtt")  # zigbee2mqtt | nmap | ble
        timeout = int(extra.get("timeout", 180))

        r = AgentResult(agent_name=self.name, target=target)
        await self.emit("start", {"message": f"IoT L1→L5 pipeline on {target}"})

        if not self.tools.is_available(source):
            r.success = False
            r.errors.append(f"{source} binary/tool not available")
            await self.emit("complete", {"findings": 0, "error": "iot_missing"})
            return r

        await self.emit("tool_start", {"tool": source, "target": target})
        try:
            if source == "nmap":
                tool_res = await self.tools.nmap_iot(target=target, timeout=timeout)
            elif source == "ble":
                tool_res = await self.tools.ble_scan(timeout=timeout)
            else:
                tool_res = await self.tools.zigbee2mqtt(target=target, timeout=timeout)
        except Exception as e:
            log.exception("iot discovery failed")
            r.success = False
            r.errors.append(str(e))
            await self.emit("complete", {"findings": 0, "error": str(e)})
            return r

        # L2
        records = self.normalizer.normalize(tool_res.stdout, source=source)
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
                    "mac": rec.mac,
                    "ip": rec.ip,
                    "vendor": rec.vendor,
                    "protocol": rec.protocol,
                    "fingerprint": rec.fingerprint,
                    "ports": rec.ports,
                    "default_creds": rec.default_creds,
                    "unauthenticated": rec.unauthenticated,
                    "is_high_risk": rec.is_high_risk,
                    "network_exposed": ctx.get("network_exposed", False),
                    "protocol_risk": ctx.get("protocol_risk", []),
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
                "devices": len(merged),
                "high_risk": sum(1 for m in merged if m.is_high_risk),
            },
        )
        return r
