"""
Deterministic Task Planner & Evidence-Gating Engine (Inspired by PentestGPT & OpenHands)
محرك التخطيط الحتمي وقواعد التحقق الصارمة — يمنع القفز للاستغلال بدون دليل تجريبي
"""
import time
import uuid
from enum import Enum
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field


class TaskKind(str, Enum):
    DISCOVER = "discover"        # استكشاف الأصول والنطاقات
    ENUMERATE = "enumerate"      # فحص الخدمات والمنافذ والتقنيات
    TEST = "test"                # فحص واختبار الفرضيات والثغرات
    EXPLOIT = "exploit"          # تأكيد الثغرة واستخراج الدليل
    VERIFY = "verify"            # التحقق المستقل من صحة النتيجة
    REMEDIATE = "remediate"      # ترقيع وحل الثغرة برمجياً


class TaskStatus(str, Enum):
    PENDING = "pending"
    ACTIVE = "active"
    BLOCKED = "blocked"
    DONE = "done"
    FAILED = "failed"


@dataclass
class PentestTask:
    id: str
    kind: TaskKind
    target: str
    objective: str
    done_when: str
    status: TaskStatus = TaskStatus.PENDING
    basis_evidence_ids: List[str] = field(default_factory=list)
    depends_on_task_ids: List[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    completed_at: Optional[float] = None
    result_summary: str = ""


@dataclass
class ActionTrace:
    action_id: str
    action_type: str
    tool_or_model: str
    command_or_prompt: str
    observation: str
    thought: str
    timestamp: float = field(default_factory=time.time)


class TaskPlanner:
    """
    مخطط المهام المنضبط (Evidence-Gated Task Planner):
    - يمنع تنفيذ مهام EXPLOIT قبل وجود دليل مؤكد من مرحلة TEST
    - يحفظ Trace كامل لجميع الأفعال والملاحظات (Action / Observation / Thought)
    """

    def __init__(self, target: str):
        self.target = target
        self.tasks: Dict[str, PentestTask] = {}
        self.traces: List[ActionTrace] = []
        self.evidence_store: Dict[str, Dict[str, Any]] = {}
        self._initialize_default_plan()

    def _initialize_default_plan(self):
        """إنشاء خطة الانطلاق الافتراضية للهدف"""
        t1 = self.add_task(TaskKind.DISCOVER, self.target, "Enumerate all subdomains and DNS assets", "All OSINT sources queried")
        t2 = self.add_task(TaskKind.ENUMERATE, self.target, "Probe alive web services and WAFs", "Active HTTP services cataloged", depends_on=[t1.id])
        t3 = self.add_task(TaskKind.TEST, self.target, "Crawl URLs and test endpoints for vulnerabilities", "Vulnerability testing completed", depends_on=[t2.id])
        t4 = self.add_task(TaskKind.VERIFY, self.target, "Verify confirmed findings and calculate CVSS", "Consolidated report ready", depends_on=[t3.id])

    def add_task(self, kind: TaskKind, target: str, objective: str, done_when: str,
                 depends_on: Optional[List[str]] = None) -> PentestTask:
        tid = f"task_{kind.value}_{str(uuid.uuid4())[:6]}"
        task = PentestTask(
            id=tid,
            kind=kind,
            target=target,
            objective=objective,
            done_when=done_when,
            depends_on_task_ids=depends_on or []
        )
        self.tasks[tid] = task
        return task

    def add_evidence(self, title: str, raw_data: str, source_tool: str) -> str:
        eid = f"ev_{str(uuid.uuid4())[:6]}"
        self.evidence_store[eid] = {
            "id": eid,
            "title": title,
            "data": raw_data,
            "tool": source_tool,
            "timestamp": time.time()
        }
        return eid

    def record_trace(self, action_type: str, tool_or_model: str, command: str,
                     observation: str, thought: str):
        """تسجيل Trace فعل وملاحظة (نموذج OpenHands)"""
        trace = ActionTrace(
            action_id=f"act_{len(self.traces)+1}",
            action_type=action_type,
            tool_or_model=tool_or_model,
            command_or_prompt=command,
            observation=observation[:1000],
            thought=thought
        )
        self.traces.append(trace)

    def can_execute_task(self, task_id: str) -> Tuple[bool, str]:
        """التحقق الحتمي من إمكانية تنفيذ المهمة (Evidence Gating)"""
        task = self.tasks.get(task_id)
        if not task:
            return False, "Task not found"

        # Check dependencies
        for dep_id in task.depends_on_task_ids:
            dep_task = self.tasks.get(dep_id)
            if dep_task and dep_task.status != TaskStatus.DONE:
                return False, f"Blocked by dependency task: {dep_id} ({dep_task.objective})"

        # Gating rule: EXPLOIT tasks require evidence from TEST phase
        if task.kind == TaskKind.EXPLOIT:
            if not task.basis_evidence_ids:
                return False, "Evidence Gating Block: Cannot run EXPLOIT without verified evidence IDs from TEST phase."

        return True, "Ready for execution"

    def complete_task(self, task_id: str, summary: str, evidence_ids: Optional[List[str]] = None):
        if task_id in self.tasks:
            t = self.tasks[task_id]
            t.status = TaskStatus.DONE
            t.completed_at = time.time()
            t.result_summary = summary
            if evidence_ids:
                t.basis_evidence_ids.extend(evidence_ids)

    def get_plan_state(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "total_tasks": len(self.tasks),
            "completed_tasks": len([t for t in self.tasks.values() if t.status == TaskStatus.DONE]),
            "tasks": [
                {
                    "id": t.id,
                    "kind": t.kind.value,
                    "objective": t.objective,
                    "status": t.status.value,
                    "done_when": t.done_when,
                    "evidence_count": len(t.basis_evidence_ids)
                }
                for t in self.tasks.values()
            ],
            "traces_count": len(self.traces)
        }
