"""OSINT Identity Agent — اكتشاف الهوية الرقمية وربط الحسابات.
يُنتج IdentityEvidence (E0/E1) فقط — أبدًا Findings مؤكدة.
يتبع نمط BaseAgent / AgentTask / AgentResult الموجود في النظام.
"""
from __future__ import annotations

import asyncio
import logging
from typing import List, Dict, Any, Optional

from agents.base_agent import BaseAgent, AgentTask, AgentResult
from tools.tool_manager import ToolManager
from tools.osint_tools import OSINTTools
from core.osint import (
    EvidenceNormalizer,
    FPGuards,
    ConfidenceModel,
    IdentityCorrelationEngine,
    IdentityEvidenceRecord,
    OSINTVector,
    platform_entry,
)

log = logging.getLogger("osint.identity_agent")


class OSINTIdentityAgent(BaseAgent):
    """
    OSINT Identity Agent — يشغّل أدوات OSINT على username / email،
    يُطبّق FP Guards، ويبني IdentityClusters مع درجات ثقة محسوبة.

    مستويات التطوير المطبق على هذا الوكيل (من خطة تطوير الأدوات):
      L1 Tool Adapter:    OSINTTools wrapper + EvidenceNormalizer schema
      L2 AI Analyzer:     FPGuards + ConfidenceModel (بدون LLM لكل خطوة)
      L3 Context:         cross-vector (username ↔ email) + multi-tool corroboration
      L4 Adaptive:        اختيار المتجهات حسب trigger conditions
      L5 Verification:    E0/E1 فقط؛ ट्र上げ إلى E2 يتطلب Browser verification لاحقًا
    """

    def __init__(self, mgr: ToolManager, cb=None):
        super().__init__(
            "osint_identity_agent",
            "OSINT Identity — username/email enumeration + correlation",
            mgr,
            cb,
        )
        self.osint = OSINTTools(mgr)
        self.normalizer = EvidenceNormalizer()
        self.fp_guards = FPGuards()
        self.confidence = ConfidenceModel()
        self.correlator = IdentityCorrelationEngine()

    # ── BaseAgent contract ────────────────────────────────────────

    async def run(self, task: AgentTask) -> AgentResult:
        target = task.target
        extra = task.extra or {}
        r = AgentResult(agent_name=self.name, target=target)

        username = extra.get("username")
        email = extra.get("email")
        vectors = extra.get("vectors", ["username", "email"])
        max_platforms = int(extra.get("max_platforms", 60))

        await self.emit("start", {
            "message": f"OSINT Identity on username={username}, email={email}",
            "vectors": vectors,
        })

        # Trigger conditions (P0 scope gate يُفترض أنّه تم التحقق منه قبل استدعاء الوكيل)
        if not username and not email:
            r.success = False
            r.errors.append("No username or email provided in task.extra")
            await self.emit("complete", {"findings": 0, "error": "missing_input"})
            return r

        all_records: List[IdentityEvidenceRecord] = []

        # ── Phase A: Fan-out على المتجهات المطلوبة ────────────────

        tasks = []

        if "username" in vectors and username:
            if self.mgr.is_available("sherlock"):
                tasks.append(self._run_username_tool("sherlock", self.osint.sherlock(username), username, OSINTVector.USERNAME))
            if self.mgr.is_available("maigret"):
                tasks.append(self._run_username_tool("maigret", self.osint.maigret(username), username, OSINTVector.USERNAME))
            if self.mgr.is_available("blackbird"):
                tasks.append(self._run_username_tool("blackbird", self.osint.blackbird(username), username, OSINTVector.USERNAME))

        if "email" in vectors and email:
            if self.mgr.is_available("holehe"):
                tasks.append(self._run_email_tool("holehe", self.osint.holehe(email), email, OSINTVector.EMAIL))
            if self.mgr.is_available("ghunt"):
                tasks.append(self._run_email_tool("ghunt", self.osint.ghunt(email), email, OSINTVector.EMAIL))

        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for res in results:
                if isinstance(res, Exception):
                    log.exception("OSINT tool task failed", exc_info=res)
                    continue
                all_records.extend(res)

        # dedupe + corroboration عبر normalizer
        deduped_records = self.normalizer.flush()

        # ── Phase B: FP Guards ────────────────────────────────────

        passed_records: List[IdentityEvidenceRecord] = []
        for rec in deduped_records:
            guard_results = self.fp_guards.evaluate_record(rec)
            critical = self.fp_guards.critical_failures(guard_results)
            if critical:
                log.debug(f"[FPGuard] rejected {rec.platform}:{rec.match_url} due to {critical}")
                continue
            passed_records.append(rec)

        # ── Phase C: Correlation + Confidence ─────────────────────

        clusters = self.correlator.correlate_multi_anchor(passed_records)

        # تطبيق Penalties من FP guards على كل 클래ستر (single source، إلخ)
        for cl in clusters:
            fp_penalties: Dict[str, float] = {}
            # single source penalty
            platforms = {m.platform for m in cl.members}
            tools_used = set()
            for m in cl.members:
                tools_used.update(m.corroborating_tools)
            if len(platforms) == 1 and len(tools_used) < 2:
                fp_penalties["single_source"] = -0.20
            self.confidence.apply_to_cluster(cl, fp_penalties)

        #── Phase D: تحويل إلى Findings (E0/E1 فقط — severity Info) ──
        for cl in clusters:
            # clusters Weak لا تُعرض في التقرير؛ تبقى في الأدلة للاستكشاف اللاحق
            if cl.confidence_label == "weak":
                continue

            finding = cl.to_finding_dict(severity="Info")
            r.findings.append(finding)
            r.raw_output[cl.cluster_id] = cl.to_dict()

        await self.emit("complete", {
            "findings": len(r.findings),
            "clusters": len(clusters),
            "records_processed": len(passed_records),
        })
        return r

    # ── مساعدات التشغيل الفردي لكل أداة ──────────────────────────

    async def _run_username_tool(
        self,
        tool_name: str,
        coro,
        username: str,
        vector: str,
    ) -> List[IdentityEvidenceRecord]:
        await self.emit("tool_start", {"tool": tool_name, "target": username})
        try:
            res = await coro
            records = self.normalizer.normalize(
                tool_name=tool_name,
                vector=vector,
                query_value=username,
                tool_result_stdout=res.stdout,
                tool_result_stderr=res.stderr,
                detection_method="web_status",
            )
            await self.emit("tool_done", {"tool": tool_name, "found": len(records)})
            return records
        except Exception as e:
            log.exception(f"{tool_name} failed for {username}")
            await self.emit("tool_error", {"tool": tool_name, "error": str(e)})
            return []

    async def _run_email_tool(
        self,
        tool_name: str,
        coro,
        email: str,
        vector: str,
    ) -> List[IdentityEvidenceRecord]:
        await self.emit("tool_start", {"tool": tool_name, "target": email})
        try:
            res = await coro
            records = self.normalizer.normalize(
                tool_name=tool_name,
                vector=vector,
                query_value=email,
                tool_result_stdout=res.stdout,
                tool_result_stderr=res.stderr,
                detection_method="api_enumeration",
            )
            await self.emit("tool_done", {"tool": tool_name, "found": len(records)})
            return records
        except Exception as e:
            log.exception(f"{tool_name} failed for {email}")
            await self.emit("tool_error", {"tool": tool_name, "error": str(e)})
            return []
