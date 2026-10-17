"""
LEDGER-023 (M4) — TaskScheduler governance invariants.

Covers the three defects documented in docs/IMPLEMENTATION_PLAN.md (M4):
  1. Auto-review must enforce the anti-self-grading guard.
  2. `add_task(parameters=...)` must reach the execution result.
  3. An unregistered action must NOT pass as a successful "simulated noop".
"""
from __future__ import annotations

from core.contracts.task_contracts import AgentTeam, TaskLifecycleStatus
from core.system.task_scheduler import TaskScheduler


def _scheduler(tmp_path) -> TaskScheduler:
    return TaskScheduler(
        tasks_file=tmp_path / "tasks.json",
        logs_dir=tmp_path / "task_logs",
        state_file=tmp_path / "state.json",
    )


def test_parameters_reach_execution_result(tmp_path):
    sched = _scheduler(tmp_path)
    task = sched.add_task(
        "Verify IDOR",
        "verify_finding",
        target="https://target.com/api/v1/users/456",
        team=AgentTeam.VERIFICATION,
        parameters={"vuln_class": "IDOR", "parameter": "id"},
    )
    assert task.parameters == {"vuln_class": "IDOR", "parameter": "id"}

    sched.register_handler("verify_finding", lambda task, context: {"verdict": "CONFIRMED"})
    sched.execute_task(task.task_id, owner_agent="Worker_1")

    assert task.result is not None
    assert task.result.parameters == {"vuln_class": "IDOR", "parameter": "id"}


def test_unregistered_action_is_not_reported_as_success(tmp_path):
    sched = _scheduler(tmp_path)
    task = sched.add_task("Ghost", "no_such_action", target="https://target.com")

    res = sched.execute_task(task.task_id, owner_agent="Worker_1")

    assert res["success"] is False
    assert task.status != TaskLifecycleStatus.DONE
    assert task.result is not None
    assert any("NO_HANDLER" in e for e in task.result.errors)


def test_independent_reviewer_seals_task_done(tmp_path):
    sched = _scheduler(tmp_path)
    task = sched.add_task("Recon", "recon", team=AgentTeam.RECON)
    sched.register_handler("recon", lambda task, context: {"hosts": ["a"]})

    res = sched.execute_task(task.task_id, owner_agent="Worker_1")

    assert res["success"] is True
    assert task.status == TaskLifecycleStatus.DONE
    assert task.reviewer_agent == "Reviewer_RECON"
    assert task.owner_agent == "Worker_1"


def test_owner_cannot_self_review_through_execute(tmp_path):
    sched = _scheduler(tmp_path)
    task = sched.add_task("Self Review", "recon", team=AgentTeam.RECON)
    sched.register_handler("recon", lambda task, context: {"ok": True})

    # Owner is exactly the auto-generated reviewer name.
    res = sched.execute_task(task.task_id, owner_agent="Reviewer_RECON")

    assert res["success"] is False
    assert task.status != TaskLifecycleStatus.DONE


def test_explicit_reviewer_is_used(tmp_path):
    sched = _scheduler(tmp_path)
    task = sched.add_task("Recon", "recon", team=AgentTeam.RECON)
    sched.register_handler("recon", lambda task, context: {"ok": True})

    res = sched.execute_task(
        task.task_id, owner_agent="Worker_1", reviewer_agent="HumanAuditor"
    )

    assert res["success"] is True
    assert task.reviewer_agent == "HumanAuditor"
