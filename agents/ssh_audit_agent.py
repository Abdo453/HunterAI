"""SSH-Audit Agent — يربط L1→L5 معًا في وكيل BaseAgent واحد.
يدير Pipeline: تشغيل ssh-audit → Normalize → Dedup → Enrich → Advise → Review.
يُنتج SSH Profiles مع مستويات الثقة — längst E1 (لا يُرفع إلى Confirmed بدون تحقق يدوي).
"""
from __future__ import annotations

import asyncio
import logging
from typing import List, Dict, Any, Optional

from agents.base_agent import BaseAgent, AgentTask, AgentResult
from tools.tool_manager import ToolManager
from tools.ssh_audit_tools import SSHAuditTools
from core.ssh_audit.schemas import SSHAssetRecord, SSHAuditEvidenceLevel
from core.ssh_audit.analyzer import SSHAuditNormalizer, DuplicateDetector, EvidenceReviewer
from core.ssh_audit.context import ContextEnricher, AdaptiveTestAdvisor

log = logging.getLogger("ssh_audit.agent")


class SSHAuditAgent(BaseAgent):
    """
    وكيل SSH-Audit المطور (L1→L5):
      L1 Tool Adapter:    SSHAuditTools.scan()
      L2 AI Analyzer:     SSHAuditNormalizer + DuplicateDetector
      L3 Context:         ContextEnricher (Nmap results + port classification)
      L4 Adaptive:        AdaptiveTestAdvisor (اقتراح أدوات/قوالب إضافية)
      L5 Verification:    EvidenceReviewer (evidence status + confidence)
    """

    def __init__(self, mgr: ToolManager, cb=None):
        super().__init__(
            "ssh_audit_agent",
            "SSH-Audit Security Profiler — L1→L5 pipeline with verification",
            mgr,
            cb,
        )
        self.tools = SSHAuditTools(mgr)
        self.normalizer = SSHAuditNormalizer()
        self.dedup = DuplicateDetector()
        self.reviewer = EvidenceReviewer()

    async def run(self, task: AgentTask) -> AgentResult:
        target = task.target
        extra = task.extra or {}
        port = int(extra.get("port", 22))
        nmap_results = extra.get("nmap_results", {})

        r = AgentResult(agent_name=self.name, target=target)
        await self.emit("start", {"message": f"SSH-Audit L1→L5 pipeline on {target}:{port}"})

        if not self.tools.is_available():
            r.success = False
            r.errors.append("ssh-audit binary not available")
            await self.emit("complete", {"findings": 0, "error": "ssh-audit_missing"})
            return r

        # ── L1: تشغيل ssh-audit ─────────────────────────────────────
        await self.emit("tool_start", {"tool": "ssh-audit", "target": target, "port": port})
        try:
            tool_res = await self.tools.scan(
                target=target,
                port=port,
            )
            await self.emit("tool_done", {"tool": "ssh-audit", "output_len": len(tool_res.stdout)})
        except Exception as e:
            log.exception("ssh-audit scan failed")
            r.success = False
            r.errors.append(str(e))
            await self.emit("complete", {"findings": 0, "error": str(e)})
            return r

        # ── L2: Normalize + Deduplicate ──────────────────────────
        records = self.normalizer.normalize_batch(tool_res.stdout)
        deduped_groups: Dict[str, List[SSHAssetRecord]] = {}
        final_records: List[SSHAssetRecord] = []

        for rec in records:
            group = self.dedup.add(rec)
            if group is None:
                final_records.append(rec)  # أصل جديد (ممثل المجموعة)
            else:
                key = rec.canonical_key
                deduped_groups.setdefault(key, group)

        deduped_groups = self.dedup.flush()

        # ── L3: enrichment السياق ────────────────────────────────
        enricher = ContextEnricher(
            nmap_results=nmap_results,
        )
        advisor = AdaptiveTestAdvisor()

        # ── L5: مراجعة الأدلة + بناء SSH Security Profile ─────────
        for rec in final_records:
            ctx = enricher.enrich(rec)
            advice = advisor.advise(rec, ctx)
            review = self.reviewer.review(rec)

            # تحديث السجل
            rec.evidence_level = review["evidence_level"]

            profile = SSHSecurityProfile(
                host=rec.host,
                port=rec.port,
                banner=rec.banner,
                kex_count=len(rec.kex_algorithms),
                key_algorithms_count=len(rec.server_host_key_algorithms),
                encryption_count=len(rec.encryption_algorithms),
                mac_count=len(rec.mac_algorithms),
                issues_count=len(record.issues),
                critical_issues=review["critical_issues"],
                high_issues=review["high_issues"],
                medium_issues=review["medium_issues"],
                low_issues=review["low_issues"],
                info_issues=review["info_issues"],
                confidence_score=review["confidence"],
                confidence_label=review["confidence_label"],
                evidence_level=rec.evidence_level,
                context_notes=ctx.get("notes", []),
                adaptive_suggestions=advice,
            )

            finding = {
                "record_id": rec.record_id,
                "host": rec.host,
                "port": rec.port,
                "banner": rec.banner,
                "kex_algorithms": rec.kex_algorithms[:5],  # أول 5 فقط للعرض
                "server_host_key_algorithms": rec.server_host_key_algorithms[:5],
                "encryption_algorithms": rec.encryption_algorithms[:5],
                "mac_algorithms": rec.mac_algorithms[:5],
                "compression_algorithms": rec.compression_algorithms[:5],
                "issues": rec.issues[:10],  # أول 10 فقط للعرض
                "evidence_level": rec.evidence_level,
                "confidence": review["confidence"],
                "confidence_label": review["confidence_label"],
                "evidence_status": review["evidence_status"],
                "critical_issues": review["critical_issues"],
                "high_issues": review["high_issues"],
                "medium_issues": review["medium_issues"],
                "low_issues": review["low_issues"],
                "info_issues": review["info_issues"],
                "total_issues": review["total_issues"],
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
