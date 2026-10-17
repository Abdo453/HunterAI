"""SSLScan Agent — يربط L1→L5 معًا في وكيل BaseAgent واحد.
يدير Pipeline: تشغيل sslscan → Normalize → Dedup → Enrich → Advise → Review.
ينتج ملفات تكوين TLS مع مستويات ثقة — لا يُرفع أي اكتشاف إلى Confirmed هنا.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from agents.base_agent import BaseAgent, AgentTask, AgentResult
from tools.tool_manager import ToolManager
from tools.sslscan_tools import SSLScanTools
from core.sslscan.schemas import (
    SSLAssetRecord,
    SSLEvidenceLevel,
    TLSConfigProfile,
)
from core.sslscan.analyzer import DuplicateDetector, EvidenceReviewer, SSLScanNormalizer
from core.sslscan.context import AdaptiveTestAdvisor, ContextEnricher

log = logging.getLogger("sslscan.agent")


class SSLScanAgent(BaseAgent):
    """
    وكيل SSLScan المطور (L1→L5):
      L1 Tool Adapter:    SSLScanTools.scan()
      L2 AI Analyzer:     SSLScanNormalizer + DuplicateDetector
      L3 Context:         ContextEnricher (البروتوكولات القديمة/التشفيرات الضعيفة)
      L4 Adaptive:        AdaptiveTestAdvisor (اقتراح nmap ssl-enum-ciphers/heartbleed)
      L5 Verification:    EvidenceReviewer (درجة ثقة + مستوى دليل)
    """

    def __init__(self, mgr: ToolManager, cb=None):
        super().__init__(
            "sslscan_agent",
            "SSLScan TLS Configuration Intelligence — L1→L5 pipeline with verification",
            mgr,
            cb,
        )
        self.tools = SSLScanTools(mgr)
        self.normalizer = SSLScanNormalizer()
        self.dedup = DuplicateDetector()
        self.reviewer = EvidenceReviewer()

    async def run(self, task: AgentTask) -> AgentResult:
        target = task.target  # host or host:port
        extra = task.extra or {}

        r = AgentResult(agent_name=self.name, target=target)
        await self.emit(
            "start", {"message": f"SSLScan L1→L5 pipeline on {target}"}
        )

        if not self.tools.is_available():
            r.success = False
            r.errors.append("sslscan binary not available")
            await self.emit("complete", {"findings": 0, "error": "sslscan_missing"})
            return r

        await self.emit("tool_start", {"tool": "sslscan", "target": target})
        try:
            tool_res = await self.tools.scan(target=target)
        except Exception as e:
            log.exception("sslscan scan failed")
            r.success = False
            r.errors.append(str(e))
            await self.emit("complete", {"findings": 0, "error": str(e)})
            return r

        # L2
        records = self.normalizer.normalize_xml(tool_res.stdout)
        merged = [self.dedup.add(rec) for rec in records]
        merged = self.dedup.flush() or merged

        enricher = ContextEnricher()
        advisor = AdaptiveTestAdvisor()

        for rec in merged:
            ctx = enricher.enrich(rec)
            review = self.reviewer.review(rec)
            advice = advisor.advise(rec, ctx)

            profile = TLSConfigProfile(
                host=rec.host,
                port=rec.port,
                enabled_protocols=rec.enabled_protocols,
                legacy_protocols=[
                    p for p in rec.enabled_protocols if p.strip().lower() in {"sslv2", "sslv3", "tlsv1", "tlsv1.1"}
                ],
                cipher_count=len(rec.ciphers),
                weak_cipher_count=len(rec.weak_ciphers),
                heartbleed=rec.heartbleed,
                poodle=rec.poodle,
                confidence_score=review["confidence"],
                confidence_label=review["confidence_label"],
                evidence_level=rec.evidence_level,
                context_notes=review["notes"] + ctx.get("notes", []),
                adaptive_suggestions=advice,
            )
            r.raw_output[f"tls::{rec.host}:{rec.port}"] = str(profile.to_dict())

            r.findings.append(
                {
                    "record_id": rec.record_id,
                    "host": rec.host,
                    "port": rec.port,
                    "enabled_protocols": rec.enabled_protocols,
                    "legacy_protocols": profile.legacy_protocols,
                    "ciphers": [c.name for c in rec.ciphers],
                    "weak_ciphers": rec.weak_ciphers,
                    "heartbleed": rec.heartbleed,
                    "poodle": rec.poodle,
                    "certificates": [c.subject for c in rec.certificates if c.subject],
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
                "weak_ciphers": sum(len(m.weak_ciphers) for m in merged),
            },
        )
        return r
