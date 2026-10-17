"""NetExec (nxc) Agent — يربط L1→L5 معًا في وكيل BaseAgent واحد.
يدير Pipeline: netexec → Normalize → Dedup → Enrich → Advise → Review.
ينتج host profiles لكل بروتوكول — لا يُرقّي أي شيء إلى Confirmed من تلقاء نفسه.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from agents.base_agent import BaseAgent, AgentTask, AgentResult
from tools.tool_manager import ToolManager
from tools.netexec_tools import NetExecTools
from core.netexec.schemas import (
    NetExecEvidenceLevel,
    NetExecHostRecord,
    NetExecProfile,
)
from core.netexec.analyzer import (
    DuplicateDetector,
    EvidenceReviewer,
    NetExecNormalizer,
)
from core.netexec.context import AdaptiveTestAdvisor, ContextEnricher
from core.ad_model import ADDomainController, ADGraph

log = logging.getLogger("netexec.agent")

_DEFAULT_PROTOCOLS = ["smb"]


class NetExecAgent(BaseAgent):
    """
    وكيل NetExec المطور (L1→L5):
      L1 Tool Adapter:    NetExecTools.<protocol>()
      L2 AI Analyzer:     NetExecNormalizer + DuplicateDetector
      L3 Context:         ContextEnricher (دور المضيف + surface)
      L4 Adaptive:        AdaptiveTestAdvisor (sam/lsassy/ntds/bloodhound)
      L5 Verification:    EvidenceReviewer (مستوى دليل + ثقة)
    """

    def __init__(self, mgr: ToolManager, cb=None):
        super().__init__(
            "netexec_agent",
            "NetExec AD/SMB Intelligence — L1→L5 pipeline with verification",
            mgr,
            cb,
        )
        self.tools = NetExecTools(mgr)
        self.normalizer = NetExecNormalizer()
        self.dedup = DuplicateDetector()
        self.reviewer = EvidenceReviewer()
        self.ad_graph = ADGraph()

    async def run(self, task: AgentTask) -> AgentResult:
        target = task.target
        extra = task.extra or {}
        protocols = extra.get("protocols") or _DEFAULT_PROTOCOLS
        args = extra.get("args", "")

        r = AgentResult(agent_name=self.name, target=target)
        await self.emit("start", {"message": f"NetExec L1→L5 pipeline on {target} ({protocols})"})

        if not self.tools.is_available():
            r.success = False
            r.errors.append("netexec/nxc binary not available")
            await self.emit("complete", {"findings": 0, "error": "netexec_missing"})
            return r

        records: List[NetExecHostRecord] = []
        for proto in protocols:
            await self.emit("tool_start", {"tool": self.tools._binary(), "protocol": proto, "target": target})
            try:
                res = await self.tools._run(proto, target, args)
                records.extend(self.normalizer.normalize_text(res.stdout))
            except Exception as e:
                log.exception("netexec %s failed", proto)
                r.errors.append(f"{proto}: {e}")

        merged = [self.dedup.add(rec) for rec in records]
        merged = self.dedup.flush() or merged

        enricher = ContextEnricher()
        advisor = AdaptiveTestAdvisor()

        for rec in merged:
            ctx = enricher.enrich(rec)
            review = self.reviewer.review(rec)
            advice = advisor.advise(rec, ctx)

            # Feed the AD graph (raw E0/E1 facts only).
            if rec.protocol == "smb" and (rec.domain or ctx.get("role") != "unknown"):
                self.ad_graph.add_dc(ADDomainController(
                    host=rec.host, domain=rec.domain,
                    services=["smb"], os_family=rec.os_family,
                    smb_signing=rec.signing, smbv1_enabled=rec.smbv1,
                    source_tool="netexec",
                ))

            profile = NetExecProfile(
                host=rec.host,
                protocol=rec.protocol,
                domain=rec.domain,
                signing=rec.signing,
                smbv1=rec.smbv1,
                pwned=rec.pwned,
                credentials_valid=rec.credentials_valid,
                confidence_score=review["confidence"],
                confidence_label=review["confidence_label"],
                evidence_level=rec.evidence_level,
                context_notes=review["notes"] + ctx.get("notes", []),
                adaptive_suggestions=advice,
            )
            r.raw_output[f"profile::{rec.protocol}://{rec.host}"] = str(profile.to_dict())

            r.findings.append({
                "record_id": rec.record_id,
                "host": rec.host,
                "protocol": rec.protocol,
                "port": rec.port,
                "hostname": rec.hostname,
                "domain": rec.domain,
                "role": ctx.get("role"),
                "signing": rec.signing,
                "smbv1": rec.smbv1,
                "pwned": rec.pwned,
                "credentials_valid": rec.credentials_valid,
                "attack_surface": ctx.get("attack_surface", []),
                "confidence": review["confidence"],
                "confidence_label": review["confidence_label"],
                "evidence_level": rec.evidence_level,
                "evidence_status": review["evidence_status"],
                "needs_verification": review["needs_verification"],
                "context_notes": profile.context_notes,
                "adaptive_suggestions": advice,
                "recommendation": review["recommendation"],
            })

        await self.emit("complete", {"findings": len(r.findings), "records": len(records)})
        return r
