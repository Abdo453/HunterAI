"""
Readiness Artifact — حفظ تقرير الجاهزية كـ Artifact لكل جلسة
============================================================
التقرير يُكتب تحت مساحة عمل الجلسة (evidence) بحيث يمكن تدقيقه لاحقًا:
  workspace/<safe_target>/<session_id>/evidence/readiness_report.json
أو مسار مخصص عند الصفر.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

from core.readiness.checker import ReadinessReport

log = logging.getLogger("hunter_ai.readiness.artifact")

ARTIFACT_NAME = "readiness_report.json"


def default_artifact_dir() -> Path:
    """الافتراضي: data/readiness/ (عند عدم توفر target/session)."""
    return Path("data/readiness")


def target_session_dir(root: Path, target: str, session_id: str) -> Path:
    """مسار آمن للتقارير الخاصة بالهدف والجلسة."""
    from core.workspace_manager import WorkspaceManager
    safe = WorkspaceManager(root=root)._safe_name(target or "no_target")
    return root / safe / session_id / "evidence"


def save_readiness_artifact(
    report: ReadinessReport,
    workspace_root: Optional[Path] = None,
) -> Optional[Path]:
    """
    يحفظ التقرير كـ JSONL/JSON artifact ويُرجع مساره.
    - target+session موجودان → workspace/<safe>/<session>/evidence/
    - غير موجودين        → data/readiness/
    لا يفشل أبدًا بدء المهمة بسبب الحفظ — الأخطاء تُسجل فقط.
    """
    try:
        if workspace_root is not None and (report.target or report.session_id):
            out_dir = target_session_dir(workspace_root, report.target, report.session_id)
        else:
            out_dir = default_artifact_dir()
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / ARTIFACT_NAME
        out_path.write_text(report.to_json() + "\n", encoding="utf-8")
        log.info("[Readiness] artifact saved: %s", out_path)
        return out_path
    except Exception:
        log.exception("[Readiness] فشل حفظ artifact — لا يؤثر على المهمة")
        return None


def load_readiness_artifact(path: Path) -> dict:
    """يقرأ تقرير محفوظ سابقًا (للأدلة أو التدقيق)."""
    return json.loads(Path(path).read_text(encoding="utf-8"))
