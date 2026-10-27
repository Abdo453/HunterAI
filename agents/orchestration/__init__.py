"""
Pentest Scaffold — Orchestration Triad (Layer 3)
================================================
ثلاثة وكلاء بأدوار متكاملة على غرار MazeRunner:

- GlobalOrchestrator   : يدير TDG، يوزع المهام، ويقرر تغيير المسار.
- ContextIntensiveExecutor : ينفذ الأدوات ويجمع الملاحظات دون تلويث ذاكرة التخطيط.
- FailureOrientedReviewer : يحلل الفشل، يستخرج الدروس، ويعدل الخطة (backtracking).

يتم تنسيقهم عبر TriadCoordinator الذي يدير حلقة التخطيط → التنفيذ → المراجعة.
"""
from agents.orchestration.global_orchestrator import GlobalOrchestrator
from agents.orchestration.context_executor import ContextIntensiveExecutor
from agents.orchestration.failure_reviewer import FailureOrientedReviewer
from agents.orchestration.triad_coordinator import TriadCoordinator, CoordinationResult

__all__ = [
    "GlobalOrchestrator",
    "ContextIntensiveExecutor",
    "FailureOrientedReviewer",
    "TriadCoordinator",
    "CoordinationResult",
]
