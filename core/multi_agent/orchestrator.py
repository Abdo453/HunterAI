"""
HunterAI Multi-Agent Orchestrator
نظام المشرف والوكلاء المتخصصين — مقتبس من فكرة BlacksmithAI Agent Hierarchy

الهierarchy:
1. Orchestrator — مركز القيادة والتحكم، التخطيط للمهام، تفويض المهام، التقرير النهائي
2. Specialized Subagents — وكلاء متخصصين لكل مرحلة (Recon, Scan, Vuln, Exploit, Post-Exploit)

كل وكيل فرعي يخطط مهامه محليًا (Local Autonomy)، while the Orchestrator retains top-level control.
"""
from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum

from agents.base_agent import BaseAgent, AgentTask, AgentResult
from tools.tool_manager import ToolManager

log = logging.getLogger("hunter_ai.multi_agent")


class MissionStatus(str):
    PENDING = "pending"
    PLANNING = "planning"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"


class TaskStatus(str):
    PENDING = "pending"
    ASSIGNED = "assigned"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class SubAgentTask:
    task_id: str
    agent_type: str  # recon, scan, vuln, exploit, post_exploit, osint
    target: str
    extra: Dict[str, Any] = field(default_factory=dict)
    status: str = TaskStatus.PENDING
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    completed_at: Optional[float] = None

    def to_dict(self) -> dict:
        return {
            "task_id": self.task_id,
            "agent_type": self.agent_type,
            "target": self.target,
            "extra": self.extra,
            "status": self.status,
            "result": self.result,
            "error": self.error,
            "created_at": self.created_at,
            "completed_at": self.completed_at,
        }


@dataclass
class MissionPlan:
    mission_id: str
    target: str
    mission_type: str  # full, auth, bola, api, osint
    phases: List[str] = field(default_factory=list)
    tasks: List[SubAgentTask] = field(default_factory=list)
    status: str = MissionStatus.PENDING
    created_at: float = field(default_factory=time.time)
    completed_at: Optional[float] = None
    overall_risk_score: float = 0.0

    def to_dict(self) -> dict:
        return {
            "mission_id": self.mission_id,
            "target": self.target,
            "mission_type": self.mission_type,
            "phases": self.phases,
            "tasks": [t.to_dict() for t in self.tasks],
            "status": self.status,
            "created_at": self.created_at,
            "completed_at": self.completed_at,
            "overall_risk_score": self.overall_risk_score,
        }


class AgentOrchestrator(BaseAgent):
    """
    Orchestrator Agent — مركز القيادة والتحكم
    يحافظ على خطة المهمة العالية المستوى، يدير قائمة المهام، ي detail العمل للوكلاء المتخصصين،
    ويولد التقرير النهائي مع النتائج، الشدة، الأدلة، وإرشادات العلاج.
    """

    def __init__(self, mgr: ToolManager, cb=None):
        super().__init__(
            "orchestrator_agent",
            "Orchestrator — Multi-agent mission planning and delegation",
            mgr,
            cb,
        )
        self.missions: Dict[str, MissionPlan] = {}
        self.available_agents: Dict[str, BaseAgent] = {}

    def register_agent(self, agent_type: str, agent: BaseAgent):
        self.available_agents[agent_type] = agent
        log.info(f"[Orchestrator] Registered agent: {agent_type} -> {agent.name}")

    # ── واجهة رئيسية ──────────────────────────────────────────────

    async def create_mission(
        self,
        target: str,
        mission_type: str = "full",
        phases: Optional[List[str]] = None,
    ) -> MissionPlan:
        mission_id = f"mission_{uuid.uuid4().hex[:12]}"

        default_phases = {
            "full": ["recon", "scan", "vuln", "exploit", "post_exploit"],
            "auth": ["recon", "scan", "vuln"],
            "bola": ["recon", "scan", "vuln", "exploit"],
            "api": ["recon", "scan", "vuln"],
            "osint": ["recon", "osint"],
        }

        phases = phases or default_phases.get(mission_type, ["recon", "scan", "vuln"])

        plan = MissionPlan(
            mission_id=mission_id,
            target=target,
            mission_type=mission_type,
            phases=phases,
            status=MissionStatus.PLANNING,
        )

        self.missions[mission_id] = plan
        log.info(f"[Orchestrator] Created mission {mission_id} for {target} ({mission_type})")
        return plan

    async def execute_mission(
        self,
        mission_id: str,
    ) -> MissionPlan:
        plan = self.missions.get(mission_id)
        if not plan:
            raise ValueError(f"Mission {mission_id} not found")

        plan.status = MissionStatus.EXECUTING

        # تنفيذ المراحل بالترتيب
        for phase in plan.phases:
            await self._execute_phase(plan, phase)

        plan.status = MissionStatus.COMPLETED
        plan.completed_at = time.time()
        plan.overall_risk_score = self._calculate_mission_risk(plan)

        log.info(f"[Orchestrator] Mission {mission_id} completed. Risk score: {plan.overall_risk_score}")
        return plan

    async def _execute_phase(
        self,
        plan: MissionPlan,
        phase: str,
    ):
        log.info(f"[Orchestrator] Executing phase: {phase} for mission {plan.mission_id}")

        # تعيين المهمة للوكيل المتخصص
        agent = self.available_agents.get(phase)
        if not agent:
            log.warning(f"[Orchestrator] No agent registered for phase: {phase}")
            task = SubAgentTask(
                task_id=f"task_{uuid.uuid4().hex[:8]}",
                agent_type=phase,
                target=plan.target,
                status=TaskStatus.FAILED,
                error=f"No agent registered for {phase}",
            )
            plan.tasks.append(task)
            return

        task = SubAgentTask(
            task_id=f"task_{uuid.uuid4().hex[:8]}",
            agent_type=phase,
            target=plan.target,
            extra={"mission_id": plan.mission_id, "phase": phase},
            status=TaskStatus.ASSIGNED,
        )
        plan.tasks.append(task)

        try:
            agent_task = AgentTask(
                target=plan.target,
                extra=task.extra,
            )
            result = await agent.run(agent_task)

            task.status = TaskStatus.COMPLETED
            task.result = {
                "findings_count": len(result.findings),
                "findings": result.findings,
                "errors": result.errors,
                "success": result.success,
            }
            task.completed_at = time.time()

            log.info(
                f"[Orchestrator] Phase {phase} completed: {len(result.findings)} findings"
            )

        except Exception as e:
            log.exception(f"[Orchestrator] Phase {phase} failed")
            task.status = TaskStatus.FAILED
            task.error = str(e)
            task.completed_at = time.time()

    def _calculate_mission_risk(self, plan: MissionPlan) -> float:
        score = 0.0
        for task in plan.tasks:
            if task.result and task.status == TaskStatus.COMPLETED:
                findings = task.result.get("findings", [])
                for f in findings:
                    severity = f.get("severity", "Info").lower()
                    if severity == "critical":
                        score += 2.5
                    elif severity == "high":
                        score += 1.5
                    elif severity == "medium":
                        score += 1.0
                    elif severity == "low":
                        score += 0.5
                    else:
                        score += 0.2
        return min(round(score, 2), 10.0)

    def get_mission(self, mission_id: str) -> Optional[MissionPlan]:
        return self.missions.get(mission_id)

    def get_all_missions(self) -> List[MissionPlan]:
        return list(self.missions.values())

    # ── BaseAgent contract ────────────────────────────────────────

    async def run(self, task: AgentTask) -> AgentResult:
        target = task.target
        extra = task.extra or {}
        mission_type = extra.get("mission_type", "full")
        phases = extra.get("phases")

        r = AgentResult(agent_name=self.name, target=target)
        await self.emit("start", {"message": f"Orchestrator mission on {target}"})

        try:
            plan = await self.create_mission(target, mission_type, phases)
            completed_plan = await self.execute_mission(plan.mission_id)

            r.findings.append({
                "type": "mission_completed",
                "severity": "Info",
                "title": f"Mission {plan.mission_id} Completed",
                "evidence": f"Target: {target}, Type: {mission_type}, Risk Score: {completed_plan.overall_risk_score}",
                "tool": "OrchestratorAgent",
                "recommendation": "راجع نتائج الوكلاء الفرعية في التقرير النهائي.",
            })
            r.raw_output["mission"] = completed_plan.to_dict()

        except Exception as e:
            log.exception("Orchestrator mission failed")
            r.success = False
            r.errors.append(str(e))

        await self.emit("complete", {
            "findings": len(r.findings),
            "mission_id": plan.mission_id if 'plan' in locals() else None,
        })
        return r
