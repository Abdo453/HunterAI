"""Masscan Agent — يربط L1→L5 معًا في وكيل BaseAgent واحد.
يدير Pipeline: تشغيل masscan → Normalize → Dedup → Enrich → Advise → Review.
ينتج PortScanProfile لكل مضيف مع مستويات ثقة — لا يُرفع أي منفذ إلى Confirmed هنا.
"""
from __future__ import annotations

import logging
from typing import List, Dict, Any, Optional

from agents.base_agent import BaseAgent, AgentTask, AgentResult
from tools.tool_manager import ToolManager
from tools.masscan_tools import MasscanTools
from core.masscan.schemas import MasscanPortRecord, PortScanProfile, MasscanEvidenceLevel
from core.masscan.analyzer import MasscanNormalizer, DuplicateDetector, EvidenceReviewer
from core.masscan.context import ContextEnricher, AdaptiveTestAdvisor

log = logging.getLogger("masscan.agent")


class MasscanAgent(BaseAgent):
    """
    وكيل Masscan المطور (L1→L5):
      L1 Tool Adapter:    MasscanTools.scan()
      L2 AI Analyzer:     MasscanNormalizer + DuplicateDetector
      L3 Context:         ContextEnricher (خدمة متوقعة + منافذ عالية القيمة)
      L4 Adaptive:        AdaptiveTestAdvisor (اقتراح خطوة التأكيد nmap -sV)
      L5 Verification:    EvidenceReviewer (درجة ثقة + مستوى دليل)
    """

    def __init__(self, mgr: ToolManager, cb=None):
        super().__init__(
            "masscan_agent",
            "Masscan Port Discovery — L1→L5 pipeline with verification",
            mgr,
            cb,
        )
        self.tools = MasscanTools(mgr)
        self.normalizer = MasscanNormalizer()
        self.dedup = DuplicateDetector()
        self.reviewer = EvidenceReviewer()

    async def run(self, task: AgentTask) -> AgentResult:
        target = task.target
        extra = task.extra or {}
        ports = extra.get("ports", "1-65535")
        rate = int(extra.get("rate", 1000))
        wait = int(extra.get("wait", 0))
        top_ports = bool(extra.get("top_ports", False))
        nmap_services = extra.get("nmap_services", {})

        r = AgentResult(agent_name=self.name, target=target)
        await self.emit("start", {"message": f"Masscan L1→L5 pipeline on {target}"})

        if not self.tools.is_available():
            r.success = False
            r.errors.append("masscan binary not available")
            await self.emit("complete", {"findings": 0, "error": "masscan_missing"})
            return r

        # ── L1: تشغيل masscan ─────────────────────────────────────
        await self.emit("tool_start", {"tool": "masscan", "target": target, "ports": ports})
        try:
            if top_ports:
                tool_res = await self.tools.scan_top_ports(target=target, rate=rate)
            else:
                tool_res = await self.tools.scan(target=target, ports=ports, rate=rate, wait=wait)
            await self.emit("tool_done", {"tool": "masscan", "output_len": len(tool_res.stdout)})
        except Exception as e:
            log.exception("masscan scan failed")
            r.success = False
            r.errors.append(str(e))
            await self.emit("complete", {"findings": 0, "error": str(e)})
            return r

        # ── L2: Normalize + Deduplicate ──────────────────────────
        records = self.normalizer.normalize_batch(tool_res.stdout)
        final_records: List[MasscanPortRecord] = []
        for rec in records:
            group = self.dedup.add(rec)
            if group is None:
                final_records.append(rec)  # منفذ جديد (ممثل المجموعة)
        deduped_groups = self.dedup.flush()

        # ── L3/L4/L5: Enrich + Advise + Review (مجمّعة حسب المضيف) ──
        enricher = ContextEnricher(nmap_services=nmap_services)
        advisor = AdaptiveTestAdvisor()

        by_host: Dict[str, List[MasscanPortRecord]] = {}
        for rec in final_records:
            by_host.setdefault(rec.host, []).append(rec)

        for host, host_records in by_host.items():
            open_ports: List[int] = []
            high_value_ports: List[int] = []
            host_notes: List[str] = []
            host_suggestions: List[str] = []
            evidence_level = MasscanEvidenceLevel.E0
            score_sum = 0.0

            for rec in host_records:
                ctx = enricher.enrich(rec)
                advice = advisor.advise(rec, ctx)
                review = self.reviewer.review(rec)
                rec.evidence_level = review["evidence_level"]

                if rec.state == "open":
                    open_ports.append(rec.port)
                if ctx.get("is_high_value"):
                    high_value_ports.append(rec.port)
                host_notes.extend(ctx.get("notes", []))
                host_suggestions.extend(advice)
                if review["evidence_level"] == MasscanEvidenceLevel.E1:
                    evidence_level = MasscanEvidenceLevel.E1
                score_sum += review["confidence"]

                r.findings.append({
                    "record_id": rec.record_id,
                    "host": rec.host,
                    "port": rec.port,
                    "protocol": rec.protocol,
                    "state": rec.state,
                    "reason": rec.reason,
                    "ttl": rec.ttl,
                    "confidence": review["confidence"],
                    "confidence_label": review["confidence_label"],
                    "evidence_level": rec.evidence_level,
                    "evidence_status": review["evidence_status"],
                    "needs_verification": review["needs_verification"],
                    "context": ctx,
                    "adaptive_suggestions": advice,
                    "recommendation": review["recommendation"],
                    "raw_json": rec.raw_json,
                })

            avg_score = (score_sum / len(host_records)) if host_records else 0.0
            profile = PortScanProfile(
                host=host,
                open_ports=sorted(set(open_ports)),
                open_count=len(set(open_ports)),
                high_value_ports=sorted(set(high_value_ports)),
                confidence_score=round(avg_score, 2),
                confidence_label=self.reviewer._label(avg_score),
                evidence_level=evidence_level,
                context_notes=sorted(set(host_notes)),
                adaptive_suggestions=list(dict.fromkeys(host_suggestions))[:8],
            )
            r.raw_output[f"profile::{host}"] = str(profile.to_dict())

        await self.emit("complete", {
            "findings": len(r.findings),
            "hosts": len(by_host),
            "duplicates_removed": sum(len(v) - 1 for v in deduped_groups.values()),
            "raw_matches": len(records),
        })
        return r
