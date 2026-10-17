"""
مسارات تشغيل التشغيلات (Runs API) — مرحلة H.

تُعَرِّض بيانات منسق المهام (Coordinator) ومتجر الأدلة الدائم (EvidenceStore)
عبر واجهة الويب الحالية، بحيث يصبح النظام الجديد جزءًا من التطبيق الفعلي:

  GET /api/runs/{run_id}/events     — تاريخ الأحداث runway لتشغيل معين
  GET /api/runs/{run_id}/evidence   — الأدلة المرتبطة بتشغيل معين
  GET /api/runs/{run_id}/findings   — النتائج المؤكدة (أدلة مثبتة/شاذات)

كل نقطة نهاية مُصادقة عبر نمط التطبيق الحالي وتُعيد بيانات مقصوصة (لا أسرار).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Path

from core.global_state import GLOBAL_COORDINATOR, GLOBAL_EVIDENCE_STORE

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/runs", tags=["runs"])


def _serialize_event(ev: Any) -> Dict[str, Any]:
    if isinstance(ev, dict):
        return {
            "event_id": ev.get("event_id"),
            "run_id": ev.get("run_id"),
            "event_type": ev.get("event_type"),
            "timestamp": ev.get("timestamp"),
            "payload": dict(ev.get("payload") or {}),
        }
    return {
        "event_id": ev.event_id,
        "run_id": ev.run_id,
        "event_type": ev.event_type,
        "timestamp": ev.timestamp,
        "payload": dict(ev.payload or {}),
    }


def _serialize_evidence(rec: Any) -> Dict[str, Any]:
    return {
        "evidence_id": rec.evidence_id,
        "run_id": rec.run_id,
        "source_worker": rec.source_worker,
        "source_tool": rec.source_tool,
        "evidence_type": rec.evidence_type,
        "sanitized_content": rec.sanitized_content,
        "content_hash": rec.content_hash,
        "provenance": rec.provenance,
        "confidence": rec.confidence,
        "verification_status": rec.verification_status,
        "created_at": rec.created_at,
        "metadata": dict(rec.metadata or {}),
    }


@router.get("/{run_id}/events")
async def run_events(
    run_id: str = Path(..., description="معرف التشغيل"),
) -> Dict[str, Any]:
    """إرجاع الأحداث المرتبة لتشغيل معين (تاريخ runway)."""
    events = GLOBAL_COORDINATOR.events(run_id)
    if not events:
        # قد يكون التشغيل موجودًا في run_control لكنه لا أحداث له بعد
        raise HTTPException(status_code=404, detail="تشغيل غير موجود أو لا أحداث له")
    return {
        "run_id": run_id,
        "count": len(events),
        "events": [_serialize_event(e) for e in events],
    }


@router.get("/{run_id}/evidence")
async def run_evidence(
    run_id: str = Path(..., description="معرف التشغيل"),
    min_confidence: Optional[float] = None,
) -> Dict[str, Any]:
    """إرجاع الأدلة المرتبطة بتشغيل معين."""
    evidence = GLOBAL_EVIDENCE_STORE.list_evidence(
        run_id=run_id, min_confidence=min_confidence
    )
    return {
        "run_id": run_id,
        "count": len(evidence),
        "evidence": [_serialize_evidence(e) for e in evidence],
    }


@router.get("/{run_id}/findings")
async def run_findings(
    run_id: str = Path(..., description="معرف التشغيل"),
) -> Dict[str, Any]:
    """
    إرجاع "النتائج" لتشغيل معين.

    تُستنتج النتائج من الأدلة التي وصلت إلى حالة التحقق:
    - evidence_type == "proof"  ⇒ نتيجة مؤكدة
    - evidence_type == "anomaly" و confidence >= 0.7 ⇒ مرشح للتحقيق
    - verification_status == "contradicted" ⇒ مرفوض (إيجابي كاذب)
    """
    evidence = GLOBAL_EVIDENCE_STORE.list_evidence(run_id=run_id)
    findings: List[Dict[str, Any]] = []
    rejected: List[Dict[str, Any]] = []

    for rec in evidence:
        item = {
            "evidence_id": rec.evidence_id,
            "title": f"{rec.evidence_type} على {rec.source_tool or 'غير محدد'}",
            "affected_asset": rec.metadata.get("target", ""),
            "category": rec.evidence_type,
            "confidence": rec.confidence,
            "verification_status": rec.verification_status,
            "evidence": rec.sanitized_content[:500],
            "provenance": rec.provenance,
        }
        if rec.verification_status == "contradicted":
            rejected.append(item)
        elif rec.evidence_type == "proof":
            findings.append(item)
        elif rec.evidence_type == "anomaly" and rec.confidence >= 0.7:
            findings.append({**item, "needs_verification": True})

    return {
        "run_id": run_id,
        "findings_count": len(findings),
        "findings": findings,
        "rejected_count": len(rejected),
        "rejected": rejected,
    }
