"""
HunterAI Orchestrator v2.0 (Evidence-Driven Agentic Architecture)
================================================================
Implements the decoupled, evidence-driven multi-agent pipeline:
  Orchestrator -> Evidence Collector (0 AI tokens) -> Evidence Store (Blackboard)
               -> Analyst Agent (Hypothesis Queue) -> Validation Agent (Active Proof)
               -> Confirmed Findings -> Report Agent

Strict 4-State Finding Lifecycle:
  OBSERVED -> HYPOTHESIS -> VALIDATING -> CONFIRMED / REJECTED
"""
import asyncio
import uuid
import os
import time
import re
from urllib.parse import urlparse, parse_qs, urljoin
from typing import Dict, Any, Optional, Callable, List

import httpx

from core.session_manager import SessionManager, Finding, PentestSession
from core.report_engine import ReportEngine
from tools.tool_manager import ToolManager
from hunter_ai.protocol.blackboard import (
    ThreeTierBlackboardMemory, Level1Summary, Level2EvidenceItem
)
from hunter_ai.protocol.handoff import HandoffEnvelope, HandoffPriority
from agents.skills.sqli_skill import run_sqli_skill

SEV_CVSS = {"Critical": 9.5, "High": 7.5, "Medium": 5.5, "Low": 2.5, "Info": 0.0}


# ─────────────────────────────────────────────────────────────────────────────
# 1. Evidence Collector (Stage 1: Ingestion & Passive Recon — 0 AI Tokens)
# ─────────────────────────────────────────────────────────────────────────────
class EvidenceCollector:
    """جمع الأدلة الميكانيكية واستكشاف المسارات والبارامترات دون استهلاك الذكاء الاصطناعي"""

    def __init__(self, proxy: Optional[str] = None):
        self.proxy = proxy

    async def collect(self, target: str) -> Dict[str, Any]:
        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        transport = None
        if self.proxy:
            transport = httpx.AsyncHTTPTransport(proxy=self.proxy, verify=False)

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36"
        }

        observations = []
        endpoints = []
        params = []
        raw_html = ""
        status_code = 0
        resp_headers = {}

        # 1. جلب الصفحة الرئيسية
        try:
            async with httpx.AsyncClient(headers=headers, transport=transport, verify=False, timeout=12.0) as client:
                resp = await client.get(target)
                status_code = resp.status_code
                raw_html = resp.text
                resp_headers = dict(resp.headers)
        except Exception as e:
            raw_html = ""
            status_code = 0

        # 2. استخراج البارامترات من رابط الهدف
        target_qs = parse_qs(parsed.query)
        for p in target_qs.keys():
            params.append(p)
            observations.append({
                "id": f"obs_{len(observations)+1:03d}",
                "type": "parameter_in_target",
                "endpoint": target,
                "parameter": p,
                "source": "query_string"
            })

        # 3. استكشاف الروابط والمسارات من الـ HTML
        if raw_html:
            matches = re.findall(r'href=[\'"]([^\'"]+)[\'"]', raw_html, re.I)
            for m in matches:
                if m.startswith("#") or m.startswith("javascript:"):
                    continue
                full_ep = urljoin(target, m)
                ep_parsed = urlparse(full_ep)
                if ep_parsed.netloc == parsed.netloc or not ep_parsed.netloc:
                    if full_ep not in endpoints:
                        endpoints.append(full_ep)
                    ep_qs = parse_qs(ep_parsed.query)
                    for p in ep_qs.keys():
                        if p not in params:
                            params.append(p)
                        observations.append({
                            "id": f"obs_{len(observations)+1:03d}",
                            "type": "discovered_endpoint_param",
                            "endpoint": full_ep,
                            "parameter": p,
                            "source": "html_href"
                        })

        # 4. Fallback إذا لم نجد روابط ببارامترات
        if not params:
            common_candidates = ["category", "id", "search", "q", "filter", "item"]
            for p in common_candidates:
                ep = urljoin(target, f"/filter?{p}=Gifts")
                endpoints.append(ep)
                params.append(p)
                observations.append({
                    "id": f"obs_{len(observations)+1:03d}",
                    "type": "candidate_endpoint_param",
                    "endpoint": ep,
                    "parameter": p,
                    "source": "heuristic_candidate"
                })

        return {
            "status_code": status_code,
            "target": target,
            "endpoints": endpoints,
            "params": params,
            "observations": observations,
            "headers": resp_headers,
            "html_snippet": raw_html[:1500] if raw_html else ""
        }


# ─────────────────────────────────────────────────────────────────────────────
# 2. Analyst Agent (Stage 2: Hypothesis Generation)
# ─────────────────────────────────────────────────────────────────────────────
class AnalystAgent:
    """تحليل الأدلة وبناء قائمة الفرضيات الأمنية بدقة وثقة محسوبة"""

    async def analyze(self, target: str, recon_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        hypotheses = []
        observations = recon_data.get("observations", [])

        # بناء الفرضيات بناءً على البارامترات والمسارات المكتشفة
        for obs in observations:
            param = obs.get("parameter", "")
            ep = obs.get("endpoint", target)
            obs_id = obs.get("id", "obs_000")

            # بارامترات التصنيف والبحث والأرقام مؤشرات قوية لـ SQLi
            if param.lower() in ("category", "id", "search", "q", "filter", "item", "order", "sort"):
                hypotheses.append({
                    "id": f"hyp_{len(hypotheses)+1:03d}",
                    "vulnerability_type": "sqli",
                    "title": f"Potential SQL Injection on parameter '{param}'",
                    "target_endpoint": ep,
                    "parameter": param,
                    "confidence": 0.65,
                    "status": "HYPOTHESIS",
                    "evidence_ids": [obs_id],
                    "recommended_action": "execute_sqli_state_machine"
                })

            # بارامترات الروابط والتحويل مؤشرات لـ SSRF / Open Redirect
            elif param.lower() in ("url", "dest", "redirect", "uri", "target", "path", "feed"):
                hypotheses.append({
                    "id": f"hyp_{len(hypotheses)+1:03d}",
                    "vulnerability_type": "ssrf",
                    "title": f"Potential Server-Side Request Forgery on '{param}'",
                    "target_endpoint": ep,
                    "parameter": param,
                    "confidence": 0.55,
                    "status": "HYPOTHESIS",
                    "evidence_ids": [obs_id],
                    "recommended_action": "execute_ssrf_metadata_matrix"
                })

        return hypotheses


# ─────────────────────────────────────────────────────────────────────────────
# 3. Validation Agent (Stage 3: Active Verification & Proof Execution)
# ─────────────────────────────────────────────────────────────────────────────
class ValidationAgent:
    """التحقق العملي من الفرضيات وترقيتها إلى ثغرات مؤكدة بالأدلة القاطعة"""

    def __init__(self, proxy: Optional[str] = None):
        self.proxy = proxy

    async def validate(self, hypothesis: Dict[str, Any], progress_cb: Optional[Callable] = None) -> Optional[Dict[str, Any]]:
        vuln_type = hypothesis.get("vulnerability_type", "")
        endpoint = hypothesis.get("target_endpoint", "")
        param = hypothesis.get("parameter", "")

        hypothesis["status"] = "VALIDATING"

        # ── SQLi Verification via Autonomous Skill State Machine ──
        if vuln_type == "sqli":
            try:
                res = await run_sqli_skill(
                    target_url=endpoint,
                    param_name=param,
                    proxy=self.proxy,
                    objective="retrieve_db_version"
                )
                
                # إذا اكتمل الاستغلال أو تم استخراج البيانات
                if res.get("state") == "COMPLETE" or res.get("extracted_data") or res.get("objective_met"):
                    extracted = res.get("extracted_data", "")
                    dbms = res.get("dbms", "unknown").upper()
                    winning_payload = res.get("union_payload", "?")
                    col_count = res.get("col_count", 0)

                    return {
                        "id": f"conf_{uuid.uuid4().hex[:8]}",
                        "hypothesis_id": hypothesis.get("id"),
                        "status": "CONFIRMED",
                        "type": "sqli",
                        "title": f"SQL Injection Confirmed & Exploited ({dbms}) on '{param}'",
                        "severity": "Critical",
                        "confidence": 0.98,
                        "endpoint": endpoint,
                        "parameter": param,
                        "evidence": f"DBMS: {dbms} | Columns: {col_count} | Extracted: {extracted}",
                        "payload": winning_payload,
                        "remediation": (
                            "Use parameterized queries / prepared statements. "
                            "Do not concatenate user input directly into dynamic SQL queries."
                        ),
                        "evidence_ids": hypothesis.get("evidence_ids", []) + [f"ev_{uuid.uuid4().hex[:6]}"]
                    }
            except Exception as e:
                pass

        hypothesis["status"] = "REJECTED"
        return None


# ─────────────────────────────────────────────────────────────────────────────
# 4. Orchestrator Engine (Stage 4 & 5: Pipeline Coordinator & Reporter)
# ─────────────────────────────────────────────────────────────────────────────
class Orchestrator:
    """المدير الرئيسي لخط الأنابيب المتسلسل المبني على الأدلة والتسليم المهيكل"""

    def __init__(self, progress_callback: Optional[Callable] = None, proxy: Optional[str] = None):
        self.cb = progress_callback
        self.proxy = proxy or os.getenv("HTTP_PROXY") or None
        self.sessions = SessionManager()
        self.tools = ToolManager()
        self.blackboard = ThreeTierBlackboardMemory()
        self.evidence_collector = EvidenceCollector(proxy=self.proxy)
        self.analyst = AnalystAgent()
        self.validator = ValidationAgent(proxy=self.proxy)

    async def _emit(self, event: str, data: dict):
        if self.cb:
            try:
                await self.cb({"event": event, **data})
            except Exception:
                pass

    async def run_scan(self, target: str, mode: str = "web", use_browser: bool = False) -> Dict[str, Any]:
        session = self.sessions.create_session(target, mode)
        job_id = session.id

        await self._emit("session_created", {"session_id": job_id, "target": target, "mode": mode})

        # ── STAGE 1: Mechanical Evidence Collection (0 AI Tokens) ──
        await self._emit("phase", {"phase": "evidence_collection", "message": "[STAGE 1] Collecting deterministic recon & endpoints (0 AI)..."})
        recon_data = await self.evidence_collector.collect(target)
        
        # حفظ في Blackboard Memory
        self.blackboard.create_job(job_id=job_id, target=target, important_tags=["web_target"])
        for obs in recon_data.get("observations", []):
            self.blackboard.add_evidence(
                job_id=job_id,
                url=obs.get("endpoint", target),
                method="GET",
                parameter=obs.get("parameter", ""),
                vulnerability_type="candidate",
                request_snippet=f"Observed on {obs.get('endpoint')}",
                response_snippet=f"Status: {recon_data.get('status_code')}"
            )

        # ── STAGE 2: Analyst Agent (Hypothesis Formation) ──
        await self._emit("phase", {"phase": "hypothesis_generation", "message": "[STAGE 2] Analyst Agent generating security hypotheses..."})
        hypotheses = await self.analyst.analyze(target, recon_data)
        await self._emit("hypotheses_ready", {"count": len(hypotheses), "hypotheses": hypotheses})

        # ── STAGE 3: Validation Agent (Active Proof Verification) ──
        await self._emit("phase", {"phase": "validation", "message": f"[STAGE 3] Validation Agent verifying {len(hypotheses)} hypotheses..."})
        confirmed_findings = []

        for hyp in hypotheses:
            await self._emit("validating_hypothesis", {"id": hyp["id"], "type": hyp["vulnerability_type"], "param": hyp["parameter"]})
            confirmed = await self.validator.validate(hyp, self.cb)
            if confirmed:
                confirmed_findings.append(confirmed)
                await self._emit("finding_confirmed", confirmed)

        # ── STAGE 4: Handoff Package Creation ──
        handoff = HandoffEnvelope(
            from_agent="ValidationAgent",
            to_agent="ReportAgent",
            task="generate_enterprise_report",
            context_id=job_id,
            priority=HandoffPriority.CRITICAL if confirmed_findings else HandoffPriority.LOW,
            summary={
                "target": target,
                "endpoints_audited": len(recon_data.get("endpoints", [])),
                "hypotheses_count": len(hypotheses),
                "confirmed_count": len(confirmed_findings)
            },
            completed=True
        )

        # ── STAGE 5: Report Agent & Session Persistence ──
        await self._emit("phase", {"phase": "reporting", "message": "[STAGE 5] Report Agent compiling confirmed findings..."})
        for cf in confirmed_findings:
            f = Finding(
                id=cf["id"],
                title=cf["title"],
                description=cf["evidence"],
                severity=cf["severity"],
                cvss_score=SEV_CVSS.get(cf["severity"], 9.0),
                tool="ValidationAgent/SQLiSkill",
                evidence=f"Payload: {cf.get('payload')}\n{cf.get('evidence')}",
                recommendation=cf.get("remediation", "Apply parameterized queries.")
            )
            self.sessions.add_finding(session, f)

        session = self.sessions.load(session.id)
        reports = ReportEngine().generate_all(session)
        self.sessions.complete(session)

        summary = {
            "session_id": session.id,
            "target": target,
            "mode": mode,
            "total_findings": len(session.findings),
            "critical": sum(1 for f in session.findings if f.severity == "Critical"),
            "high": sum(1 for f in session.findings if f.severity == "High"),
            "medium": sum(1 for f in session.findings if f.severity == "Medium"),
            "low": sum(1 for f in session.findings if f.severity == "Low"),
            "findings": [
                {
                    "title": f.title,
                    "severity": f.severity,
                    "param_name": cf.get("parameter"),
                    "endpoint": cf.get("endpoint"),
                    "tool": f.tool,
                    "evidence": f.evidence
                }
                for f, cf in zip(session.findings, confirmed_findings)
            ] if confirmed_findings else [],
            "reports": reports,
            "handoff": handoff.to_dict()
        }

        await self._emit("scan_complete", summary)
        return summary

