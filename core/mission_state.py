"""
Mission State — حالة المهمة المستمرة (Persistent JSON)
يحفظ تقدم الـ Mission في ملف JSON بحيث لو اتوقفت تكمل من نفس النقطة
"""
from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class MissionState:
    session_id: str
    target: str
    status: str = "running"          # running | paused | completed | failed
    completed_skills: List[str] = field(default_factory=list)
    failed_skills: List[str] = field(default_factory=list)
    skipped_skills: List[str] = field(default_factory=list)
    retry_counts: Dict[str, int] = field(default_factory=dict) # skill_name -> number of retries
    files: Dict[str, str] = field(default_factory=dict)       # skill_name -> output_file_path
    next_actions: List[str] = field(default_factory=list)     # Skills scheduled to run
    findings_count: int = 0
    findings: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    timeline: List[Dict[str, Any]] = field(default_factory=list) # List of event timestamps
    started_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    total_elapsed: float = 0.0
    health_score: float = 100.0      # 0.0 to 100.0 %
    mode: str = "full"               # full | recon_only | web_only | vuln_only | quick
    workspace_path: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    # ── Persistence ──────────────────────────────────────────────

    def save(self, path: Path) -> None:
        """حفظ الحالة في ملف JSON"""
        self.updated_at = time.time()
        self.total_elapsed = round(self.updated_at - self.started_at, 2)
        self.health_score = self.calculate_health_score()
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(asdict(self), fh, indent=2, ensure_ascii=False)

    @classmethod
    def load(cls, path: Path) -> "MissionState":
        """تحميل الحالة من ملف JSON"""
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return cls(**data)

    @classmethod
    def create_new(cls, target: str, mode: str = "full") -> "MissionState":
        """إنشاء Mission State جديد"""
        return cls(
            session_id=str(uuid.uuid4())[:8],
            target=target,
            mode=mode,
        )

    @classmethod
    def load_or_create(cls, state_file: Path, target: str, mode: str = "full") -> "MissionState":
        """يحمّل State موجود أو يعمل جديد"""
        if state_file.exists():
            try:
                state = cls.load(state_file)
                if state.target == target and state.status not in ("completed", "failed"):
                    return state
            except Exception:
                pass
        return cls.create_new(target, mode)

    # ── Skill tracking & Retries ──────────────────────────────────

    def mark_skill_done(self, skill_name: str, output_files: Dict[str, str] = None) -> None:
        if skill_name not in self.completed_skills:
            self.completed_skills.append(skill_name)
        if skill_name in self.failed_skills:
            self.failed_skills.remove(skill_name)
        if output_files:
            self.files.update(output_files)
        self.add_timeline_event("skill_completed", {"skill": skill_name})

    def mark_skill_failed(self, skill_name: str, error: str = "") -> None:
        if skill_name not in self.failed_skills:
            self.failed_skills.append(skill_name)
        if error:
            self.errors.append(f"[{skill_name}] {error}")
        self.add_timeline_event("skill_failed", {"skill": skill_name, "error": error})

    def mark_skill_skipped(self, skill_name: str) -> None:
        if skill_name not in self.skipped_skills:
            self.skipped_skills.append(skill_name)

    def get_retry_count(self, skill_name: str) -> int:
        return self.retry_counts.get(skill_name, 0)

    def increment_retry(self, skill_name: str) -> int:
        self.retry_counts[skill_name] = self.retry_counts.get(skill_name, 0) + 1
        self.add_timeline_event("skill_retry", {"skill": skill_name, "attempt": self.retry_counts[skill_name]})
        return self.retry_counts[skill_name]

    def is_skill_done(self, skill_name: str) -> bool:
        return skill_name in self.completed_skills

    def is_skill_failed(self, skill_name: str) -> bool:
        return skill_name in self.failed_skills

    def add_finding(self, finding: Dict[str, Any]) -> None:
        self.findings.append(finding)
        self.findings_count = len(self.findings)
        self.add_timeline_event("finding_added", {"title": finding.get("title", ""), "severity": finding.get("severity", "Info")})

    def add_timeline_event(self, event_type: str, details: Dict[str, Any] = None) -> None:
        self.timeline.append({
            "timestamp": time.time(),
            "time_str": time.strftime("%H:%M:%S"),
            "event": event_type,
            "details": details or {}
        })

    def calculate_health_score(self) -> float:
        """حساب درجة صحة وسلاسة المهمة (100% - خصم على الفشل والأخطاء المتكررة)"""
        total_attempted = len(self.completed_skills) + len(self.failed_skills)
        if total_attempted == 0:
            return 100.0
        success_ratio = len(self.completed_skills) / total_attempted
        retry_penalty = min(sum(self.retry_counts.values()) * 5.0, 30.0)
        score = (success_ratio * 100.0) - retry_penalty
        return round(max(min(score, 100.0), 0.0), 1)

    # ── Summary ───────────────────────────────────────────────────

    def summary(self) -> Dict[str, Any]:
        elapsed = time.time() - self.started_at
        return {
            "session_id": self.session_id,
            "target": self.target,
            "status": self.status,
            "mode": self.mode,
            "health_score": self.health_score,
            "completed_skills": len(self.completed_skills),
            "failed_skills": len(self.failed_skills),
            "skipped_skills": len(self.skipped_skills),
            "retry_counts": self.retry_counts,
            "findings_count": self.findings_count,
            "elapsed_seconds": round(elapsed, 1),
            "next_actions": self.next_actions,
            "timeline_events_count": len(self.timeline),
        }

    def __repr__(self) -> str:
        return (
            f"MissionState(session={self.session_id}, target={self.target}, "
            f"status={self.status}, done={len(self.completed_skills)}, "
            f"health={self.health_score}%, findings={self.findings_count})"
        )
