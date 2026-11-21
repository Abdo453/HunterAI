"""
Task & Clue Cache — الكاش المشترك بين الوكلاء الثلاثة
=====================================================

يحتفظ بحالة كل مهمة (من TaskDependencyGraph) والدليل البيئي المرتبط بها
(mapping بين أدلة الاستكشاف والمهمات المستفيدة منها). يخدم كسوق معلّمات
共享 بين:

- Global Orchestrator  — يقرأ أولويات المهام وحالتها ويقرر المسار التالي.
- Context-Intensive Executor — يكتب ملاحظات التنفيذ وأوامر الأدوات ونواتجها.
- Failure-Oriented Reviewer — يقرأ الفشلات المسجلة ويحدث الخطة والدليل.

يعتمد على JSON خفيف للتح persistence الاختياري، ويتبع نفس نمط الذكريات
القائمة في هذا الحزمة.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from pathlib import Path
from typing import Dict, List, Any, Optional

from agents.security_intelligence.config import SecurityIntelligenceConfig

log = logging.getLogger("security_intelligence.task_clue_cache")


class ClueEntry:
    """قطعة دليل بيئي واحدة اكتُشفت أثناء التنفيذ"""
    def __init__(
        self,
        clue_id: Optional[str] = None,
        target: str = "",
        source_tool: str = "",
        clue_type: str = "",          # open_port | endpoint | parameter | technology | credential | cve | misconfig
        content: str = "",
        evidence_ref: Optional[List[str]] = None,
        related_task_ids: Optional[List[str]] = None,
        confidence: float = 0.0,
    ):
        self.id = clue_id or f"CLUE-{uuid.uuid4().hex[:8]}"
        self.target = target
        self.source_tool = source_tool
        self.clue_type = clue_type
        self.content = content
        self.evidence_ref = evidence_ref or []
        self.related_task_ids = related_task_ids or []
        self.confidence = max(0.0, min(1.0, confidence))
        self.discovered_at = time.time()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "target": self.target,
            "source_tool": self.source_tool,
            "clue_type": self.clue_type,
            "content": self.content,
            "evidence_ref": self.evidence_ref,
            "related_task_ids": self.related_task_ids,
            "confidence": self.confidence,
            "discovered_at": self.discovered_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ClueEntry":
        entry = cls(
            clue_id=data.get("id"),
            target=data.get("target", ""),
            source_tool=data.get("source_tool", ""),
            clue_type=data.get("clue_type", ""),
            content=data.get("content", ""),
            evidence_ref=data.get("evidence_ref", []),
            related_task_ids=data.get("related_task_ids", []),
            confidence=data.get("confidence", 0.0),
        )
        entry.discovered_at = data.get("discovered_at", entry.discovered_at)
        return entry


class TaskExecutionState:
    """حالة تنفيذ مهمة واحدة في الكاش"""
    def __init__(
        self,
        task_id: str,
        title: str = "",
        status: str = "pending",
        assigned_agent: Optional[str] = None,
        started_at: Optional[float] = None,
        completed_at: Optional[float] = None,
    ):
        self.task_id = task_id
        self.title = title
        self.status = status  # pending | in_progress | done | failed | blocked | skipped
        self.assigned_agent = assigned_agent
        self.started_at = started_at
        self.completed_at = completed_at
        self.notes: List[str] = []
        self.commands_run: List[str] = []
        self.clue_ids: List[str] = []
        self.failure_reason: Optional[str] = None
        self.last_updated = time.time()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "title": self.title,
            "status": self.status,
            "assigned_agent": self.assigned_agent,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "notes": self.notes,
            "commands_run": self.commands_run,
            "clue_ids": self.clue_ids,
            "failure_reason": self.failure_reason,
            "last_updated": self.last_updated,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TaskExecutionState":
        state = cls(
            task_id=data["task_id"],
            title=data.get("title", ""),
            status=data.get("status", "pending"),
            assigned_agent=data.get("assigned_agent"),
            started_at=data.get("started_at"),
            completed_at=data.get("completed_at"),
        )
        state.notes = data.get("notes", [])
        state.commands_run = data.get("commands_run", [])
        state.clue_ids = data.get("clue_ids", [])
        state.failure_reason = data.get("failure_reason")
        state.last_updated = data.get("last_updated", state.last_updated)
        return state


class TaskClueCache:
    """
    كاش مستمر للمهام والأدلة.
    - task_states: معرّف المهمة -> حالة التنفيذ
    - clues: معرّف الدليل -> ClueEntry
    - target_clues: الهدف -> [معرّفات الأدلة]
    - type_clues: نوع الدليل -> [معرّفات الأدلة]
    - task_clues: معرّف المهمة -> [معرّفات الأدلة المرتبطة]
    """

    def __init__(self, storage_file: Optional[str] = None, persist: bool = False):
        self.storage_file = storage_file or SecurityIntelligenceConfig.TASK_CLUE_CACHE_PATH
        self.persist = persist
        self.task_states: Dict[str, TaskExecutionState] = {}
        self.clues: Dict[str, ClueEntry] = {}
        self.target_clues: Dict[str, List[str]] = {}
        self.type_clues: Dict[str, List[str]] = {}
        self.task_clues: Dict[str, List[str]] = {}
        if self.persist:
            self._load()

    # ------------------------------------------------------------------ #
    # حالات المهام
    # ------------------------------------------------------------------ #
    def upsert_task_state(
        self,
        task_id: str,
        title: str = "",
        status: str = "pending",
        assigned_agent: Optional[str] = None,
    ) -> TaskExecutionState:
        if task_id in self.task_states:
            state = self.task_states[task_id]
            state.status = status
            if title:
                state.title = title
            if assigned_agent is not None:
                state.assigned_agent = assigned_agent
            state.last_updated = time.time()
        else:
            state = TaskExecutionState(
                task_id=task_id,
                title=title,
                status=status,
                assigned_agent=assigned_agent,
            )
            self.task_states[task_id] = state
        self._save()
        return state

    def get_task_state(self, task_id: str) -> Optional[TaskExecutionState]:
        return self.task_states.get(task_id)

    def add_task_note(self, task_id: str, note: str) -> None:
        state = self.task_states.get(task_id)
        if state:
            state.notes.append(note)
            state.last_updated = time.time()
            self._save()

    def add_task_command(self, task_id: str, command: str) -> None:
        state = self.task_states.get(task_id)
        if state:
            state.commands_run.append(command)
            state.last_updated = time.time()
            self._save()

    def mark_task_completed(self, task_id: str, summary: str = "") -> None:
        state = self.task_states.get(task_id)
        if state:
            state.status = "done"
            state.completed_at = time.time()
            state.last_updated = time.time()
            if summary:
                state.notes.append(f"[DONE] {summary}")
            self._save()

    def mark_task_failed(self, task_id: str, reason: str) -> None:
        state = self.task_states.get(task_id)
        if state:
            state.status = "failed"
            state.failure_reason = reason
            state.completed_at = time.time()
            state.last_updated = time.time()
            state.notes.append(f"[FAILED] {reason}")
            self._save()

    # ------------------------------------------------------------------ #
    # الأدلة (Clues)
    # ------------------------------------------------------------------ #
    def add_clue(
        self,
        target: str,
        source_tool: str,
        clue_type: str,
        content: str,
        evidence_ref: Optional[List[str]] = None,
        related_task_ids: Optional[List[str]] = None,
        confidence: float = 0.0,
    ) -> ClueEntry:
        entry = ClueEntry(
            target=target,
            source_tool=source_tool,
            clue_type=clue_type,
            content=content,
            evidence_ref=evidence_ref,
            related_task_ids=related_task_ids,
            confidence=confidence,
        )
        self.clues[entry.id] = entry
        self.target_clues.setdefault(target, []).append(entry.id)
        self.type_clues.setdefault(clue_type, []).append(entry.id)
        for tid in (related_task_ids or []):
            self.task_clues.setdefault(tid, []).append(entry.id)
        self._save()
        log.debug(f"[TCC] Clue {entry.id} ({clue_type}) for {target}: {content[:80]}")
        return entry

    def get_clue(self, clue_id: str) -> Optional[ClueEntry]:
        return self.clues.get(clue_id)

    def get_clues_for_target(self, target: str) -> List[ClueEntry]:
        return [self.clues[cid] for cid in self.target_clues.get(target, [])]

    def get_clues_by_type(self, clue_type: str) -> List[ClueEntry]:
        return [self.clues[cid] for cid in self.type_clues.get(clue_type, [])]

    def get_clues_for_task(self, task_id: str) -> List[ClueEntry]:
        return [self.clues[cid] for cid in self.task_clues.get(task_id, [])]

    def link_clue_to_task(self, clue_id: str, task_id: str) -> None:
        entry = self.clues.get(clue_id)
        if entry and task_id not in entry.related_task_ids:
            entry.related_task_ids.append(task_id)
            self.task_clues.setdefault(task_id, []).append(clue_id)
            self._save()

    # ------------------------------------------------------------------ #
    # استفسارات متقاطعة (للـ Reviewer و Orchestrator)
    # ------------------------------------------------------------------ #
    def find_related_clues(
        self,
        target: str,
        clue_types: Optional[List[str]] = None,
        min_confidence: float = 0.0,
    ) -> List[ClueEntry]:
        """أدلة مرتبطة بهدف معين، اختيارياً بتصفية حسب النوع والحد الأدنى من الثقة"""
        result = []
        for cid in self.target_clues.get(target, []):
            entry = self.clues[cid]
            if clue_types and entry.clue_type not in clue_types:
                continue
            if entry.confidence < min_confidence:
                continue
            result.append(entry)
        result.sort(key=lambda e: e.confidence, reverse=True)
        return result

    def get_failed_tasks(self) -> List[TaskExecutionState]:
        return [s for s in self.task_states.values() if s.status == "failed"]

    def get_in_progress_tasks(self) -> List[TaskExecutionState]:
        return [s for s in self.task_states.values() if s.status == "in_progress"]

    def get_pending_tasks(self) -> List[TaskExecutionState]:
        return [s for s in self.task_states.values() if s.status == "pending"]

    def recover_missing_prerequisites(self, task_id: str, target: str) -> Dict[str, Any]:
        """
        MazeRunner-style Failure-Oriented Review & Prerequisite Recovery:
        Inspects a failed task's failure_reason and searches distant clues
        in the persistent cache to recover missing prerequisites (e.g. tokens,
        parameters, endpoints, ports) and reschedule the task.
        """
        state = self.task_states.get(task_id)
        if not state:
            return {"recovered": False, "task_id": task_id, "reason": "Task not found"}

        reason_lower = (state.failure_reason or "").lower()
        needed_types: List[str] = []
        if any(k in reason_lower for k in ("401", "403", "auth", "token", "cookie", "credential", "session")):
            needed_types.extend(["credential", "token", "header", "technology"])
        if any(k in reason_lower for k in ("param", "400", "missing", "input", "field")):
            needed_types.extend(["parameter", "endpoint"])
        if any(k in reason_lower for k in ("404", "route", "path", "endpoint")):
            needed_types.extend(["endpoint", "open_port"])
        if not needed_types:
            needed_types = ["credential", "parameter", "endpoint", "technology", "open_port", "misconfig"]

        matching_clues = self.find_related_clues(target=target, clue_types=needed_types, min_confidence=0.2)
        if not matching_clues:
            # Also check all clues in cache if target string varied (e.g. URL vs hostname)
            for c in self.clues.values():
                if c.clue_type in needed_types and (target in c.target or c.target in target):
                    matching_clues.append(c)

        if not matching_clues:
            return {
                "recovered": False,
                "task_id": task_id,
                "needed_types": needed_types,
                "matched_clues": [],
            }

        recovered_clue_ids = []
        for clue in matching_clues[:5]:
            self.link_clue_to_task(clue.id, task_id)
            if clue.id not in state.clue_ids:
                state.clue_ids.append(clue.id)
            recovered_clue_ids.append(clue.id)

        state.status = "pending"
        state.notes.append(
            f"[RECOVERED_BY_REVIEWER] Linked {len(recovered_clue_ids)} distant clues ({', '.join(recovered_clue_ids)}) "
            f"to resolve failure: {state.failure_reason}"
        )
        state.last_updated = time.time()
        self._save()

        return {
            "recovered": True,
            "task_id": task_id,
            "needed_types": needed_types,
            "matched_clues": [c.to_dict() for c in matching_clues[:5]],
            "new_status": state.status,
        }

    def link_distant_clues(self, target: str) -> List[Dict[str, Any]]:
        """
        Connects distant clues across phases for the same target (e.g., linking
        discovered credentials/tokens or parameters to discovered endpoints/ports).
        """
        target_entries = self.get_clues_for_target(target)
        if not target_entries:
            target_entries = [c for c in self.clues.values() if target in c.target or c.target in target]

        endpoints = [c for c in target_entries if c.clue_type in ("endpoint", "open_port")]
        enablers = [c for c in target_entries if c.clue_type in ("credential", "token", "parameter", "cve", "misconfig")]

        links: List[Dict[str, Any]] = []
        for ep in endpoints:
            for en in enablers:
                if ep.id == en.id:
                    continue
                links.append({
                    "target": target,
                    "surface_clue_id": ep.id,
                    "surface_type": ep.clue_type,
                    "surface_content": ep.content,
                    "enabler_clue_id": en.id,
                    "enabler_type": en.clue_type,
                    "enabler_content": en.content,
                    "combined_confidence": round((ep.confidence + en.confidence) / 2.0, 3),
                })
        return links

    def save(self) -> None:
        """Explicitly persist cache to storage_file."""
        prev = self.persist
        self.persist = True
        self._save()
        self.persist = prev

    # ------------------------------------------------------------------ #
    # تصدير
    # ------------------------------------------------------------------ #
    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_states": {tid: s.to_dict() for tid, s in self.task_states.items()},
            "clues": {cid: c.to_dict() for cid, c in self.clues.items()},
            "target_clues": {k: v for k, v in self.target_clues.items()},
            "type_clues": {k: v for k, v in self.type_clues.items()},
            "task_clues": {k: v for k, v in self.task_clues.items()},
        }

    def _save(self):
        if not self.persist:
            return
        try:
            p = Path(self.storage_file)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(
                json.dumps(self.to_dict(), indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        except Exception as e:
            log.warning(f"Failed to save TaskClueCache: {e}")

    def _load(self):
        try:
            p = Path(self.storage_file)
            if p.exists():
                data = json.loads(p.read_text(encoding="utf-8"))
                for item in data.get("task_states", {}).values():
                    state = TaskExecutionState.from_dict(item)
                    self.task_states[state.task_id] = state
                for item in data.get("clues", {}).values():
                    entry = ClueEntry.from_dict(item)
                    self.clues[entry.id] = entry
                    self.target_clues.setdefault(entry.target, []).append(entry.id)
                    self.type_clues.setdefault(entry.clue_type, []).append(entry.id)
                    for tid in entry.related_task_ids:
                        self.task_clues.setdefault(tid, []).append(entry.id)
        except Exception as e:
            log.warning(f"Failed to load TaskClueCache: {e}")
