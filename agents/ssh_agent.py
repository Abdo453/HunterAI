"""SSH-Audit Agent — L1→L5 pipeline"""
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


class SSHAgent(BaseAgent):
    def __init__(self, mgr: ToolManager, cb=None):
        super().__init__(
            "ssh_agent",
            "SSH Security Fingerprint — L1→L5 pipeline with verification",
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

        r = AgentResult(agent_name=self.name, target=target)
        await self.emit("start", {"message": f"SSH L1→L5 pipeline on {target}:{port}"})

        if not self.tools.is_available():
            r.success = False
            r.errors.append("ssh-audit binary not available")
            await self.emit("complete", {"findings": 0, "error": "ssh-audit_missing"})
            return r

        await self.emit("tool_start", {"tool": "ssh-audit", "target": target, "port": port})
        try:
            tool_res = await self.tools.scan(target=target, port=port)
            await self.emit("tool_done", {"tool": "ssh-audit", "output_len": len(tool_res.stdout)})
        except Exception as e:
            log.exception("SSH-Audit scan failed")
            r.success = False
            r.errors.append(str(e))
            await self.emit("complete", {"findings": 0, "error": str(e)})
            return r

        records = self.normalizer.normalize_batch(tool_res.stdout)
        final_records: List[SSHAssetRecord] = []
        deduped_groups: Dict[str, List[SSHAssetRecord]] = {}

        for rec in records:
            group = self.dedup.add(rec)
            if group is None:
                final_records.append(rec)
            else:
                key = rec.canonical_key
                deduped_groups.setdefault(key, group)

        deduped_groups = self.dedup.flush()
        enricher = ContextEnricher()
        advisor = AdaptiveTestAdvisor()

        for rec in final_records:
            ctx = enricher.enrich(rec)
            advice = advisor.advise(rec, ctx)
            review = self.reviewer.review(rec)
            rec.evidence_level = review["evidence_level"]

            profile = {
                "record_id": rec.record_id,
                "host": rec.host,
                "port": rec.port,
                "banner": rec.banner,
                "web_server": rec.web_server,
                "technologies": rec.technologies,
                "cdn": rec.cdn,
                "ip": rec.ip,
                "cname": rec.cname,
                "evidence_level": rec.evidence_level,
                "confidence": review["confidence"],
                "confidence_label": review["confidence_label"],
                "evidence_status": review["evidence_status"],
                "is_likely_waf": review["is_likely_waf"],
                "is_likely_cdn": review["is_likely_cdn"],
                "needs_verification": review["needs_verification"],
                "context": ctx,
                "adaptive_suggestions": advice,
                "recommendation": review["recommendation"],
                "raw_json": rec.raw_json,
            }
            r.findings.append(profile)

        await self.emit("complete", {
            "findings": len(r.findings),
            "duplicates_removed": sum(len(v) - 1 for v in deduped_groups.values()),
            "raw_matches": len(records),
        })
        return r
