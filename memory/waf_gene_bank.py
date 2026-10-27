"""
WAF Gene Bank — بنك الجينات لتجاوز WAF
=======================================
يخزن نتائج كل محاولة تجاوز (نجاح/فشل) مع السياق الكامل حتى يبدأ الوكيل
المرة القادمة من حيث وقف، وليس من الصفر.

الهيكل المحفوظ لكل سجل:
{
  "target": "https://example.com",
  "waf_type": "ModSecurity",          # نوع WAF الذي تم بصمته
  "waf_version": "3.0.x",             # إصدار لو ظهر
  "technique_level": 1,               # درجة السلم (1-5)
  "technique_name": "encoding",       # اسم التقنية (encoding, tag, event, js, parser)
  "payload": "<svg onload=...>",
  "headers": {"Content-Type": "..."},
  "status_code": 200,
  "success": true/false,
  "failure_reason": "blocked | challenge | error | null",  # فقط لو 실패
  "timestamp": "2026-10-28T...",
  "attempts": 1,                      # عدد المرات التي جُربت فيها هذه التركيبة
  "success_rate": 1.0                 # 0.0 إلى 1.0
}
"""
from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class GeneRecord:
    target: str
    waf_type: str
    waf_version: Optional[str] = None
    technique_level: int = 0
    technique_name: str = ""
    payload: str = ""
    headers: Dict[str, str] = None
    status_code: Optional[int] = None
    success: bool = False
    failure_reason: Optional[str] = None
    timestamp: str = field(default_factory=now_iso)
    attempts: int = 1
    success_rate: float = 0.0

    def __post_init__(self):
        if self.headers is None:
            self.headers = {}


class WAFGeneBank:
    """
    بنك الجينات لتجاوز WAF.
    - يسجل كل محاولة (payload + WAF + النتيجة).
    - يعيد أفضل التركيبات المعروفة لنوع WAF معين.
    - يُحدّث نسبة النجاح لكل تركيبة مع التكرار.
    """

    def __init__(self, storage_dir: str = "data/waf_gene_bank"):
        self.dir = Path(storage_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._index: Dict[str, List[GeneRecord]] = {}
        self._load_all()

    # ------------------------------------------------------------------ #
    # internal persistence
    # ------------------------------------------------------------------ #
    def _file_for(self, waf_type: str) -> Path:
        safe = re_safe(waf_type)
        return self.dir / f"{safe}.json"

    def _load_all(self) -> None:
        self._index = {}
        for p in self.dir.glob("*.json"):
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                waf_type = p.stem
                records = [GeneRecord(**r) for r in data]
                self._index[waf_type] = records
            except Exception:
                continue

    def _persist(self, waf_type: str) -> None:
        with self._lock:
            p = self._file_for(waf_type)
            data = [asdict(r) for r in self._index.get(waf_type, [])]
            p.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

    # ------------------------------------------------------------------ #
    # public API
    # ------------------------------------------------------------------ #
    def record_attempt(
        self,
        target: str,
        waf_type: str,
        technique_level: int,
        technique_name: str,
        payload: str,
        success: bool,
        status_code: Optional[int] = None,
        headers: Optional[Dict[str, str]] = None,
        waf_version: Optional[str] = None,
        failure_reason: Optional[str] = None,
    ) -> None:
        """
        تسجيل محاولة تجاوز. لو التركيبة موجودة مسبقاً لنفس الهدف+NWAف، يُحدّد
        المحاولات ونسبة النجاح بدلاً من إنشاء سجل مكرر.
        """
        waf_key = waf_type or "unknown"
        records = self._index.setdefault(waf_key, [])

        # البحث عن سجل مماثل (نفس target + payload + technique)
        existing = None
        for r in records:
            if (
                r.target == target
                and r.payload == payload
                and r.technique_level == technique_level
                and r.technique_name == technique_name
            ):
                existing = r
                break

        now = now_iso()
        if existing:
            existing.attempts += 1
            if success:
                # معدل نجاح متحرك (إجمالي النجاحات / المحاولات)
                prev_successes = existing.success_rate * (existing.attempts - 1)
                existing.success_rate = (prev_successes + 1) / existing.attempts
            else:
                prev_successes = existing.success_rate * (existing.attempts - 1)
                existing.success_rate = prev_successes / existing.attempts
            existing.status_code = status_code if status_code is not None else existing.status_code
            existing.failure_reason = failure_reason or existing.failure_reason
            existing.timestamp = now
        else:
            rate = 1.0 if success else 0.0
            records.append(GeneRecord(
                target=target,
                waf_type=waf_key,
                waf_version=waf_version,
                technique_level=technique_level,
                technique_name=technique_name,
                payload=payload,
                headers=headers or {},
                status_code=status_code,
                success=success,
                failure_reason=failure_reason,
                timestamp=now,
                attempts=1,
                success_rate=rate,
            ))

        self._persist(waf_key)

    def get_best_payloads(
        self,
        waf_type: str,
        target: Optional[str] = None,
        min_success_rate: float = 0.0,
        limit: int = 10,
    ) -> List[GeneRecord]:
        """
        إرجاع أفضل payloads معروفة لنوع WAF معين، مرتبة حسب نسبة النجاح ثم عدد المحاولات.
        """
        waf_key = waf_type or "unknown"
        records = self._index.get(waf_key, [])

        filtered = [
            r for r in records
            if r.success_rate >= min_success_rate
            and (target is None or r.target == target)
        ]

        # ترتيب: نسبة النجاحdesc، ثم عدد المحاولات desc (الأكثر تجربةً أولاً)
        filtered.sort(key=lambda r: (r.success_rate, r.attempts), reverse=True)
        return filtered[:limit]

    def has_successful(self, waf_type: str, target: Optional[str] = None) -> bool:
        """هل هناك至少 payload ناجح واحد لنوع WAF هذا؟"""
        for r in self.get_best_payloads(waf_type, target=target, min_success_rate=0.5):
            if r.success:
                return True
        return False

    def summary(self) -> Dict[str, Any]:
        total = 0
        successes = 0
        by_waf: Dict[str, Dict[str, Any]] = {}
        for waf_type, records in self._index.items():
            total += len(records)
            succ = sum(1 for r in records if r.success)
            successes += succ
            by_waf[waf_type] = {
                "records": len(records),
                "successes": succ,
                "best_rate": max((r.success_rate for r in records), default=0.0),
            }
        return {
            "total_records": total,
            "total_successes": successes,
            "waf_types": len(by_waf),
            "by_waf": by_waf,
        }


def re_safe(name: str) -> str:
    """تحويل اسم WAF إلى اسم ملف آمن."""
    return "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in name).strip("_") or "unknown"


__all__ = ["WAFGeneBank", "GeneRecord"]
