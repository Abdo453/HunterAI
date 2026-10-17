"""enum4linux-ng Agent — يربط L1→L5 معًا في وكيل BaseAgent واحد.
يدير Pipeline: enum4linux-ng → Normalize → Dedup → Enrich → Advise → Review.
ينتج AD/SMB host profiles مع مستويات دليل — لا يُرقّي أي شيء إلى Confirmed.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from agents.base_agent import BaseAgent, AgentTask, AgentResult
from tools.tool_manager import ToolManager
from tools.enum4linux_tools import Enum4LinuxTools
from core.enum4linux.schemas import (
    ADHostProfile,
    Enum4LinuxAssetRecord,
    Enum4LinuxEvidenceLevel,
)
from core.enum4linux.analyzer import (
    DuplicateDetector,
    Enum4LinuxNormalizer,
    EvidenceReviewer,
)
from core.enum4linux.context import AdaptiveTestAdvisor, ContextEnricher
from core.ad_model import ADGraph, ADPrincipal, ADShare

log = logging.getLogger("enum4linux.agent")


class Enum4LinuxAgent(BaseAgent):
    """
    وكيل enum4linux-ng المطور (L1→L5):
      L1 Tool Adapter:    Enum4LinuxTools.scan()
      L2 AI Analyzer:     Enum4LinuxNormalizer + DuplicateDetector
      L3 Context:         ContextEnricher (role: DC/member + attack surface)
      L4 Adaptive:        AdaptiveTestAdvisor (AS-REP/Kerberoast/BloodHound)
      L5 Verification:    EvidenceReviewer (مستوى دليل + ثقة)
    """

    def __init__(self, mgr: ToolManager, cb=None):
        super().__init__(
            "enum4linux_agent",
            "enum4linux-ng SMB/AD Enumeration — L1→L5 pipeline with verification",
            mgr,
            cb,
        )
        self.tools = Enum4LinuxTools(mgr)
        self.normalizer = Enum4LinuxNormalizer()
        self.dedup = DuplicateDetector()
        self.reviewer = EvidenceReviewer()
        self.ad_graph = ADGraph()

    async def run(self, task: AgentTask) -> AgentResult:
        target = task.target
        extra = task.extra or {}
        all_simple = bool(extra.get("all_simple", True))
        nmap_services = extra.get("nmap_services", {})

        r = AgentResult(agent_name=self.name, target=target)
        await self.emit("start", {"message": f"enum4linux-ng L1→L5 pipeline on {target}"})

        if not self.tools.is_available():
            r.success = False
            r.errors.append("enum4linux-ng binary not available")
            await self.emit("complete", {"findings": 0, "error": "enum4linux_missing"})
            return r

        await self.emit("tool_start", {"tool": self.tools._binary(), "target": target})
        try:
            tool_res = await self.tools.scan(target=target, all_simple=all_simple)
        except Exception as e:
            log.exception("enum4linux-ng scan failed")
            r.success = False
            r.errors.append(str(e))
            await self.emit("complete", {"findings": 0, "error": str(e)})
            return r

        # L2
        records = self.normalizer.normalize(tool_res.stdout)
        merged = [self.dedup.add(rec) for rec in records]
        merged = self.dedup.flush() or merged

        enricher = ContextEnricher(nmap_services=nmap_services)
        advisor = AdaptiveTestAdvisor()

        for rec in merged:
            ctx = enricher.enrich(rec)
            review = self.reviewer.review(rec)
            advice = advisor.advise(rec, ctx)

            # Feed the AD graph (E0 raw facts only).
            for u in rec.users:
                self.ad_graph.add_principal(ADPrincipal(
                    name=u.full_name or u.username,
                    sam_account_name=u.username,
                    domain=rec.domain,
                    kind="user",
                    description=u.description,
                    source_tool="enum4linux-ng",
                ))
            for sh in rec.shares:
                self.ad_graph.add_share(ADShare(
                    name=sh.name, host=sh.host, domain=rec.domain,
                    access=sh.access, comment=sh.comment,
                    is_anonymous=sh.is_anonymous, source_tool="enum4linux-ng",
                ))

            profile = ADHostProfile(
                host=rec.host,
                domain=rec.domain,
                is_dc=rec.is_dc,
                anonymous_access=rec.anonymous_access,
                user_count=len(rec.users),
                share_count=len(rec.shares),
                writable_shares=len([s for s in rec.shares if s.writable]),
                confidence_score=review["confidence"],
                confidence_label=review["confidence_label"],
                evidence_level=rec.evidence_level,
                context_notes=review["notes"] + ctx.get("notes", []),
                adaptive_suggestions=advice,
            )
            r.raw_output[f"profile::{rec.host}"] = str(profile.to_dict())

            r.findings.append({
                "record_id": rec.record_id,
                "host": rec.host,
                "domain": rec.domain,
                "is_dc": rec.is_dc,
                "anonymous_access": rec.anonymous_access,
                "user_count": len(rec.users),
                "share_count": len(rec.shares),
                "writable_shares": profile.writable_shares,
                "confidence": review["confidence"],
                "confidence_label": review["confidence_label"],
                "evidence_level": rec.evidence_level,
                "evidence_status": review["evidence_status"],
                "needs_verification": review["needs_verification"],
                "role": ctx.get("role"),
                "attack_surface": ctx.get("attack_surface", []),
                "context_notes": profile.context_notes,
                "adaptive_suggestions": advice,
                "recommendation": review["recommendation"],
            })

        await self.emit("complete", {
            "findings": len(r.findings),
            "hosts": len(merged),
            "principals": len(self.ad_graph.principals()),
            "shares": len(self.ad_graph.shares()),
        })
        return r
