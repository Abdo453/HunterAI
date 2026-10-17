"""
واجهة المخطط المجردة (Planner Interface) — مرحلة C Teil من حزمة core.planner القائمة.

يُوفّر عقدة موحدة للتقسيم الهدف إلى مهام فرعية، يمكن تنفيذها بواسطة أي محرك تخطيط
(نموذج لغوي، فضاء حالات، قواعد ثابتة) دون التأثير على المنسق.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import Any, List, Optional


@dataclass
class SubTask:
    """مهمة فرعية ينتجها المخطط."""
    description: str
    target: str = ""
    role: Optional[str] = None        # الدور المفضل للعامل (مثل "web", "recon")
    dependencies: List[str] = field(default_factory=list)
    scope: dict = field(default_factory=dict)
    max_attempts: int = 3
    metadata: dict = field(default_factory=dict)


@dataclass
class Plan:
    """خطة تنفيذ لRun واحد."""
    run_id: str
    goal: str
    subtasks: List[SubTask] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)


class Planner(abc.ABC):
    """واجهة مخطط افتراضية."""

    @abc.abstractmethod
    def plan(self, *, run_id: str, goal: str,
             scope: Optional[dict] = None,
             context: Optional[dict] = None) -> Plan:
        raise NotImplementedError


class DefaultPlanner(Planner):
    """
    تخطيط افتراضي (تافه) — يُعيد مهمة واحدة بالهدف نفسه.
    يُستبدل لاحقًا بمنطيق تخطيط حقيقي (مثل StateSpacePlanner القائم).
    """

    def plan(self, *, run_id: str, goal: str,
             scope: Optional[dict] = None,
             context: Optional[dict] = None) -> Plan:
        return Plan(
            run_id=run_id, goal=goal,
            subtasks=[SubTask(
                description=goal,
                target=(scope or {}).get("target", ""),
                scope=dict(scope or {}))],
            metadata={"planner": "default-single-task"})
