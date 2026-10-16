"""Tests لـ Multi-Agent Orchestrator"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.multi_agent.orchestrator import (
    AgentOrchestrator,
    MissionPlan,
    SubAgentTask,
    MissionStatus,
    TaskStatus,
)


def test_mission_creation():
    plan = MissionPlan(
        mission_id="mission_1",
        target="https://example.com",
        mission_type="full",
        phases=["recon", "scan"],
    )
    assert plan.mission_id == "mission_1"
    assert plan.target == "https://example.com"
    assert plan.status == MissionStatus.PENDING
    assert len(plan.phases) == 2
    print("[PASS] orchestrator mission creation")


def test_subagent_task():
    task = SubAgentTask(
        task_id="task_1",
        agent_type="recon",
        target="https://example.com",
    )
    d = task.to_dict()
    assert d["task_id"] == "task_1"
    assert d["agent_type"] == "recon"
    assert d["status"] == "pending"
    print("[PASS] orchestrator subagent task")


def test_risk_calculation():
    from core.multi_agent.orchestrator import AgentOrchestrator
    # لا يمكننا إنشاء وكيل حقيقي بدون ToolManager، لكن نختبر المنطق مباشرة
    orch = AgentOrchestrator.__new__(AgentOrchestrator)
    plan = MissionPlan(
        mission_id="m",
        target="t",
        mission_type="full",
        phases=[],
    )
    # إضافة نتائج وهمية
    task = SubAgentTask(
        task_id="t1",
        agent_type="vuln",
        target="t",
        status=TaskStatus.COMPLETED,
        result={"findings": [
            {"severity": "critical"},
            {"severity": "high"},
            {"severity": "info"},
        ]},
    )
    plan.tasks.append(task)
    score = orch._calculate_mission_risk(plan)
    assert score == 4.2  # 2.5 + 1.5 + 0.2
    print("[PASS] orchestrator risk calculation")


def test_agent_import():
    from core.multi_agent.orchestrator import AgentOrchestrator
    assert AgentOrchestrator is not None
    print("[PASS] orchestrator agent import")


if __name__ == "__main__":
    test_mission_creation()
    test_subagent_task()
    test_risk_calculation()
    test_agent_import()
    print("\n[INFO] جميع اختبارات Multi-Agent Orchestrator نجحت!")
