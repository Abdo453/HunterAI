"""Tests لـ Mission Planner"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.mission_planner.planner import (
    MissionPlanner,
    PlannerTask,
    TaskPriority,
    PlannerTaskStatus,
)


def test_add_and_get_task():
    planner = MissionPlanner("test_agent")
    task_id = planner.add_task("فحص المنافذ", "فحص جميع المنافذ المفتوحة", TaskPriority.HIGH)
    task = planner.get_task(task_id)
    assert task is not None
    assert task.title == "فحص المنافذ"
    assert task.priority == TaskPriority.HIGH
    assert task.status == PlannerTaskStatus.PENDING
    print("[PASS] planner add/get task")


def test_task_dependencies():
    planner = MissionPlanner("test_agent")
    t1_id = planner.add_task("الاستكشاف الأولي", "جمع المعلومات الأساسية", TaskPriority.HIGH)
    t2_id = planner.add_task("فحص الثغرات", "فحص الثغرات المكتشفة", TaskPriority.HIGH, dependencies=[t1_id])

    # t2 لا يمكن بدءها قبل t1
    ready = planner.get_ready_tasks()
    ready_ids = [t.task_id for t in ready]
    assert t1_id in ready_ids, f"{t1_id} not in {ready_ids}"
    assert t2_id not in ready_ids, f"{t2_id} should not be in {ready_ids}"

    # إكمال t1
    planner.start_task(t1_id)
    planner.complete_task(t1_id, {"result": "done"})

    # الآن t2 جاهزة
    ready = planner.get_ready_tasks()
    ready_ids = [t.task_id for t in ready]
    assert t2_id in ready_ids, f"{t2_id} should be in {ready_ids}"
    print("[PASS] planner task dependencies")


def test_task_priority_ordering():
    planner = MissionPlanner("test_agent")
    planner.add_task("منخفضة", "", TaskPriority.LOW)
    planner.add_task("عالية", "", TaskPriority.HIGH)
    planner.add_task("حرجة", "", TaskPriority.CRITICAL)
    planner.add_task("متوسطة", "", TaskPriority.MEDIUM)

    ready = planner.get_ready_tasks()
    priorities = [t.priority for t in ready]
    assert priorities[0] == TaskPriority.CRITICAL
    assert priorities[1] == TaskPriority.HIGH
    assert priorities[2] == TaskPriority.MEDIUM
    assert priorities[3] == TaskPriority.LOW
    print("[PASS] planner priority ordering")


def test_progress_tracking():
    planner = MissionPlanner("test_agent")
    planner.add_task("task1", "", TaskPriority.MEDIUM)
    planner.add_task("task2", "", TaskPriority.MEDIUM)
    planner.add_task("task3", "", TaskPriority.MEDIUM)

    progress = planner.get_progress()
    assert progress["total"] == 3
    assert progress["completed"] == 0
    assert progress["completion_percentage"] == 0.0

    planner.complete_task(list(planner.tasks.keys())[0], {})
    progress = planner.get_progress()
    assert progress["completed"] == 1
    assert progress["completion_percentage"] == 33.3
    print("[PASS] planner progress tracking")


def test_agent_import():
    from core.mission_planner.planner import MissionPlanner
    assert MissionPlanner is not None
    print("[PASS] planner import")


if __name__ == "__main__":
    test_add_and_get_task()
    test_task_dependencies()
    test_task_priority_ordering()
    test_progress_tracking()
    test_agent_import()
    print("\n[INFO] جميع اختبارات Mission Planner نجحت!")
