"""
Autonomous Mission Agent — الوكيل المستقل لإدارة وتنسيق المهام
ينسق تنفيذ الـ Skills وفق مخطط حتمي/ذكي مع دعم التنفيذ المتوازي، إعادة المحاولة التلقائية، والمراقبة الحية (WebSocket Broadcast).
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Callable, Dict, List, Optional, Set

from agents.base_agent import AgentResult, AgentTask, BaseAgent
from core.app_mapper import ApplicationMapper
from core.correlation.ui_traffic_correlator import UITrafficCorrelator
from core.cvss_calculator import CVSSCalculator
from core.database.knowledge_db import KnowledgeDB
from core.evidence_manager import EvidenceManager
from core.mission_planner import MissionPlanner
from core.mission_reporter import MissionReporter
from core.mission_state import MissionState
from core.reasoning.hypothesis_reasoning_engine import HypothesisReasoningEngine
from core.skill_registry import SkillMeta, SkillRegistry
from core.vrt_mapper import VRTMapper
from core.workspace_manager import WorkspaceManager
from skills.base_skill import BaseSkill, SkillContext, SkillResult
from tools.tool_manager import ToolManager

logger = logging.getLogger(__name__)

# Global WebSocket listener callbacks registry: session_id -> Set[Callable]
MISSION_EVENT_LISTENERS: Dict[str, Set[Callable]] = {}


def register_mission_listener(session_id: str, callback: Callable) -> None:
    MISSION_EVENT_LISTENERS.setdefault(session_id, set()).add(callback)


def unregister_mission_listener(session_id: str, callback: Callable) -> None:
    if session_id in MISSION_EVENT_LISTENERS:
        MISSION_EVENT_LISTENERS[session_id].discard(callback)


class AutonomousMissionAgent(BaseAgent):
    """
    الوكيل المستقل للمهام الأمنية (Autonomous Mission Agent):
    - يكتشف الـ Skills المتاحة ديناميكياً
    - ينشئ Workspace منظم مع قاعدة بيانات علائقية KnowledgeDB (traffic.db)
    - ينفذ المهارات المستقلة بالتوازي (Parallel Execution)
    - يدير محرك الفرضيات (Observation -> Hypothesis -> Validation)
    - يربط تفاعلات الواجهة بحركة مرور الشبكة (Playwright ↔ Burp Traffic Correlator)
    - يبني خريطة التطبيق الهيكلية (Application Topology Map)
    - يدير إعادة المحاولة الذكية وتجربة الأدوات والمهارات البديلة (Fallbacks)
    - يحمي الجلسة بـ Global Mission Watchdog
    - يبث الأحداث والتقدم لحظياً للمتصفح عبر WebSocket
    """

    def __init__(
        self,
        tool_manager: ToolManager,
        progress_callback: Optional[Callable] = None,
        workspace_root: Optional[str] = None,
    ):
        super().__init__(
            name="autonomous_mission_agent",
            description="Autonomous Security Mission Orchestrator with Dynamic Skill Discovery, Cognitive Reasoning, KnowledgeDB, and UI-Traffic Correlation",
            tool_manager=tool_manager,
            progress_callback=progress_callback,
        )
        self.workspace = WorkspaceManager(root=workspace_root) if workspace_root else WorkspaceManager()
        self.registry = SkillRegistry()
        self.evidence_mgr = EvidenceManager()
        self.reporter = MissionReporter(self.workspace, self.evidence_mgr)

    async def emit(self, event: str, data: dict):
        """بث الحدث عبر الـ callback الأساسي ولكل مستمعي الـ WebSocket المسجلين"""
        payload = {"agent": self.name, "event": event, "timestamp": time.time(), **data}
        await super().emit(event, data)

        session_id = data.get("session_id", "")
        if session_id and session_id in MISSION_EVENT_LISTENERS:
            for cb in list(MISSION_EVENT_LISTENERS[session_id]):
                try:
                    if asyncio.iscoroutinefunction(cb):
                        await cb(payload)
                    else:
                        cb(payload)
                except Exception:
                    pass

    async def run(self, task: AgentTask) -> AgentResult:
        target = task.target.strip()
        mode = task.mode or task.extra.get("mode", "full")
        session_id = task.session_id or str(int(time.time()))[-6:]
        total_mission_timeout = float(task.extra.get("total_timeout", 1800.0)) # 30 min default watchdog

        # Initialize or resume mission state
        ws_path = self.workspace.create_workspace(target, session_id)
        state_file = self.workspace.get_state_file(target, session_id)
        state = MissionState.load_or_create(state_file, target=target, mode=mode)
        state.session_id = session_id
        state.workspace_path = str(ws_path)

        # Initialize SQLite Knowledge Database (traffic.db)
        db_path = ws_path / "traffic.db"
        knowledge_db = KnowledgeDB(db_path)
        correlator = UITrafficCorrelator(knowledge_db)
        reasoning_engine = HypothesisReasoningEngine(knowledge_db)
        app_mapper = ApplicationMapper(knowledge_db)

        await self.emit("mission_started", {
            "target": target,
            "session_id": session_id,
            "mode": mode,
            "workspace": str(ws_path),
            "db_path": str(db_path)
        })

        # Discover skills
        self.registry.discover()
        planner = MissionPlanner(self.registry)

        max_iterations = task.extra.get("max_iterations", 30)
        iteration = 0

        try:
            # Global Watchdog wrapper
            async with asyncio.timeout(total_mission_timeout):
                while not planner.should_terminate(state) and iteration < max_iterations:
                    iteration += 1
                    ready_skills = planner.get_ready_skills(state)
                    if not ready_skills:
                        break

                    # Group independent ready skills into parallel batches (e.g. max 3 concurrent)
                    batches = planner.group_independent_skills(ready_skills, max_batch_size=3)

                    for batch in batches:
                        # Execute skills in current batch in parallel
                        tasks = [
                            self._execute_skill_resilient(skill_meta, state, target, session_id, mode, task.extra)
                            for skill_meta in batch
                        ]
                        results = await asyncio.gather(*tasks, return_exceptions=True)

                        # Process results, ingest into KnowledgeDB, and update state
                        for skill_meta, res in zip(batch, results):
                            if isinstance(res, Exception):
                                state.mark_skill_failed(skill_meta.name, str(res))
                                await self.emit("skill_failed", {
                                    "session_id": session_id,
                                    "skill": skill_meta.name,
                                    "errors": [str(res)]
                                })
                            elif isinstance(res, SkillResult):
                                if res.success:
                                    state.mark_skill_done(skill_meta.name, output_files=res.output_files)

                                    # Ingest discovered endpoints & parameters into KnowledgeDB
                                    self._ingest_skill_results_into_db(skill_meta.name, res, knowledge_db, target)

                                    for f in res.findings:
                                        # Calculate CVSS score
                                        vrt = VRTMapper.lookup(f.get("type", "general"))
                                        cvss_val = f.get("cvss_score") or CVSSCalculator.derive_from_vrt(vrt.vrt_id, f.get("severity", "Info"))
                                        f["cvss_score"] = cvss_val
                                        state.add_finding(f)

                                        self.evidence_mgr.add_evidence(
                                            title=f.get("title", f"Finding from {skill_meta.name}"),
                                            content=f.get("evidence", ""),
                                            tool=f.get("tool", skill_meta.name),
                                            severity=f.get("severity", "Info"),
                                            vuln_type=f.get("type", ""),
                                            target=target,
                                            url=f.get("url", ""),
                                            cvss_score=cvss_val
                                        )

                                    await self.emit("skill_completed", {
                                        "session_id": session_id,
                                        "skill": skill_meta.name,
                                        "findings_count": len(res.findings),
                                        "output_files": list(res.output_files.keys()),
                                        "duration": res.duration
                                    })
                                else:
                                    err_msg = "; ".join(res.errors) if res.errors else "Execution failed"
                                    state.mark_skill_failed(skill_meta.name, err_msg)
                                    await self.emit("skill_failed", {
                                        "session_id": session_id,
                                        "skill": skill_meta.name,
                                        "errors": res.errors
                                    })

                        # Trigger Observation -> Hypothesis generation cycle
                        with knowledge_db._get_conn() as conn:
                            eps = [dict(r) for r in conn.cursor().execute("SELECT * FROM endpoints").fetchall()]
                            params = [dict(r) for r in conn.cursor().execute("SELECT * FROM parameters").fetchall()]
                        reasoning_engine.generate_hypotheses_from_observations(target, eps, params, [])

                        # Save state after each batch
                        state.save(state_file)

        except asyncio.TimeoutError:
            state.status = "timeout"
            state.errors.append(f"Mission watchdog exceeded global timeout limit of {total_mission_timeout}s")
            logger.warning(f"[AutonomousMissionAgent] Global timeout reached ({total_mission_timeout}s)")
            await self.emit("mission_timeout", {
                "session_id": session_id,
                "target": target,
                "elapsed": state.total_elapsed
            })

        # Finalize mission & export Application Maps + Correlation Report
        if state.status != "timeout":
            state.status = "completed"
        state.save(state_file)

        # Generate Application Topology Maps
        app_mapper.export_all(ws_path, target)

        # Generate report
        report_path = self.reporter.generate_report(state)

        await self.emit("mission_completed", {
            "target": target,
            "session_id": session_id,
            "completed_skills": state.completed_skills,
            "failed_skills": state.failed_skills,
            "total_findings": state.findings_count,
            "health_score": state.health_score,
            "db_stats": knowledge_db.get_stats(),
            "report_path": str(report_path)
        })

        return AgentResult(
            agent_name=self.name,
            target=target,
            findings=state.findings,
            raw_output={"report": report_path.read_text(encoding="utf-8") if report_path.exists() else ""},
            errors=state.errors,
            success=len(state.completed_skills) > 0
        )

    async def _execute_skill_resilient(
        self,
        skill_meta: SkillMeta,
        state: MissionState,
        target: str,
        session_id: str,
        mode: str,
        extra: Dict[str, Any]
    ) -> SkillResult:
        """
        تنفيذ المهارة مع دعم إعادة المحاولة وتجربة الأدوات البديلة
        """
        skill_name = skill_meta.name
        max_retries = skill_meta.max_retries
        attempt = 0
        last_result: Optional[SkillResult] = None

        while attempt <= max_retries:
            skill_instance = skill_meta.instantiate()
            if not skill_instance:
                return SkillResult(skill_name=skill_name, success=False, errors=["Class instantiation failed"])

            await self.emit("skill_started", {
                "session_id": session_id,
                "skill": skill_name,
                "category": skill_meta.category,
                "target": target,
                "attempt": attempt + 1
            })

            ctx = SkillContext(
                target=target,
                session_id=session_id,
                workspace=self.workspace,
                tool_manager=self.mgr,
                state_files=state.files,
                mode=mode,
                extra=extra,
                retry_attempt=attempt
            )

            res = await skill_instance.run(ctx)
            if res.success:
                return res

            last_result = res
            attempt += 1
            if attempt <= max_retries:
                state.increment_retry(skill_name)
                logger.info(f"[{skill_name}] Attempt {attempt} failed, retrying...")
                await asyncio.sleep(1.0) # Backoff before retry

        return last_result or SkillResult(skill_name=skill_name, success=False, errors=["Retries exhausted"])

    def _ingest_skill_results_into_db(
        self,
        skill_name: str,
        result: SkillResult,
        db: KnowledgeDB,
        target: str
    ) -> None:
        """
        تغذية قاعدة بيانات المعرفة بالـ Endpoints والـ Parameters والـ Traffic المكتشفة من الـ Skill
        """
        import re
        try:
            for fname, fpath_str in result.output_files.items():
                p = Path(fpath_str)
                if not p.exists():
                    continue

                content = p.read_text(encoding="utf-8", errors="ignore")

                # Ingest Endpoints
                if fname in ("endpoints.txt", "urls.txt", "urls_alive.txt", "api_endpoints.txt", "links.txt"):
                    for line in content.splitlines():
                        line = line.strip()
                        if line and not line.startswith("#"):
                            # Handle "[METHOD] URL" format
                            method = "GET"
                            url = line
                            if line.startswith("[") and "]" in line:
                                method = line.split("]")[0].strip("[").strip()
                                url = line.split("]")[1].strip()
                            if url.startswith("http"):
                                ep_id = db.insert_endpoint(url=url, method=method, source_tool=skill_name)
                                # Extract query parameters if any
                                if "?" in url:
                                    query = url.split("?")[1]
                                    for param_pair in query.split("&"):
                                        if "=" in param_pair:
                                            p_name, p_val = param_pair.split("=", 1)
                                            is_id = p_name.lower() in ("id", "user_id", "uid", "account_id") or p_val.isdigit()
                                            db.insert_parameter(endpoint_id=ep_id, name=p_name, location="query", sample_value=p_val, is_identifier=is_id)

                # Ingest Parameters
                elif fname == "parameters.txt":
                    for line in content.splitlines():
                        line = line.strip()
                        if line and not line.startswith("#"):
                            param_name = line.split()[0]
                            is_id = param_name.lower() in ("id", "user_id", "uid", "account_id")
                            db.insert_parameter(endpoint_id=1, name=param_name, location="query", is_identifier=is_id)

                # Ingest Traffic Requests
                elif fname == "requests.txt":
                    for line in content.splitlines():
                        line = line.strip()
                        if line.startswith("[") and "]" in line:
                            parts = line.split("]")
                            method = parts[0].strip("[")
                            rest = parts[1].strip()
                            url_match = re.search(r"https?://\S+", rest)
                            if url_match:
                                req_url = url_match.group(0)
                                db.insert_traffic(method=method, url=req_url, resource_type="xhr", source_tool=skill_name)

        except Exception as exc:
            logger.debug(f"[AutonomousMissionAgent] Database ingestion warning: {exc}")

