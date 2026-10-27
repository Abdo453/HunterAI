"""
Failure Episodic Memory
=======================

ذاكرة الفشل العرضية (MAM-PT — الوحدة الثالثة).
تسجل كل محاولة فاشلة مع سبب الفشل، الأداة المستخدمة، الهدف، والسياق البيئي،
كما تحفظ "الدليل النافي" (negative evidence) لمنع الوكيل من تكرار نفس الغلطة
أو إعادة تجربة أمر محكوم عليه بالفشل في ظروف مماثلة.

التصميم يتبع نفس نمط ProjectMemory / TargetMemory / FalsePositiveMemory
للحفاظ على التوافق مع MemoryManager القائم.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Dict, List, Any, Optional

from agents.security_intelligence.config import SecurityIntelligenceConfig

log = logging.getLogger("security_intelligence.failure_episodic_memory")


# ── إعادة تعريف بدون pydantic للحفاظ على خفة التبعيات (مثل بقية الذكريات) ──
class FailureRecord:
    """سجل فشل واحد مع كل سياقات الاستدعاء"""
    def __init__(
        self,
        task_id: str,
        target: str,
        tool: str,
        command: str,
        reason: str,
        evidence: Optional[List[str]] = None,
        context: Optional[Dict[str, Any]] = None,
        fingerprint: Optional[str] = None,
    ):
        self.id = f"FAIL-{int(time.time()*1000)}-{abs(hash(command)) % 10000:04d}"
        self.task_id = task_id
        self.target = target
        self.tool = tool
        self.command = command
        self.reason = reason
        self.evidence = evidence or []
        self.context = context or {}
        self.fingerprint = fingerprint or self._compute_fingerprint()
        self.timestamp = time.time()
        self.repeat_count = 1

    def _compute_fingerprint(self) -> str:
        """بصمة موجهة للتطابق مع محاولات مماثلة (أداة + هدف + سبب ملخص)"""
        import hashlib
        raw = f"{self.tool}|{self.target}|{self.reason}|{self.context.get('port','')}|{self.context.get('endpoint','')}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "task_id": self.task_id,
            "target": self.target,
            "tool": self.tool,
            "command": self.command,
            "reason": self.reason,
            "evidence": self.evidence,
            "context": self.context,
            "fingerprint": self.fingerprint,
            "timestamp": self.timestamp,
            "repeat_count": self.repeat_count,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FailureRecord":
        rec = cls(
            task_id=data["task_id"],
            target=data["target"],
            tool=data["tool"],
            command=data["command"],
            reason=data["reason"],
            evidence=data.get("evidence", []),
            context=data.get("context", {}),
            fingerprint=data.get("fingerprint"),
        )
        rec.id = data.get("id", rec.id)
        rec.timestamp = data.get("timestamp", rec.timestamp)
        rec.repeat_count = data.get("repeat_count", 1)
        return rec


class FailureEpisodicMemory:
    """
    يخزن المحاولات الفاشلة ويتيح الاستفسار عنها قبل التنفيذ.
    يمكنه الإجابة: "هل جربنا هذا الأمر على هذا الهدف وفشل من قبل؟"
    """

    def __init__(self, storage_file: Optional[str] = None, persist: bool = False):
        self.storage_file = storage_file or SecurityIntelligenceConfig.FAILURE_MEMORY_PATH
        self.persist = persist
        self.failures: Dict[str, FailureRecord] = {}          # key = failure id
        self.by_fingerprint: Dict[str, str] = {}              # fingerprint -> failure id
        self.by_target: Dict[str, List[str]] = {}             # target -> [failure ids]
        self.by_tool: Dict[str, List[str]] = {}               # tool -> [failure ids]
        if self.persist:
            self._load()

    # ------------------------------------------------------------------ #
    # تسجيل الفشل
    # ------------------------------------------------------------------ #
    def record_failure(
        self,
        task_id: str,
        target: str,
        tool: str,
        command: str,
        reason: str,
        evidence: Optional[List[str]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> FailureRecord:
        """
        تسجيل محاولة فاشلة. إذا كانت هناك بصمة مماثلة موجودة، يتم تحديث
        repeat_count بدلاً من إنشاء سجل جديد (للتعرف على الأنماط المتكررة).
        """
        # التحقق من وجود بصمة مكررة لنفس الهدف والأداة والسبب
        existing_id = self._find_similar(target, tool, reason, context)
        if existing_id:
            rec = self.failures[existing_id]
            rec.repeat_count += 1
            rec.timestamp = time.time()
            if evidence:
                rec.evidence = list(dict.fromkeys(rec.evidence + evidence))
            self._save()
            log.info(
                f"[FAIL-EP] Repeated failure #{rec.repeat_count} for {tool} on {target}: {reason}"
            )
            return rec

        rec = FailureRecord(
            task_id=task_id,
            target=target,
            tool=tool,
            command=command,
            reason=reason,
            evidence=evidence,
            context=context,
        )
        self.failures[rec.id] = rec
        self.by_fingerprint[rec.fingerprint] = rec.id
        self.by_target.setdefault(target, []).append(rec.id)
        self.by_tool.setdefault(tool, []).append(rec.id)
        self._save()
        log.warning(f"[FAIL-EP] New failure recorded: {rec.id} — {tool} on {target}: {reason}")
        return rec

    def _find_similar(
        self,
        target: str,
        tool: str,
        reason: str,
        context: Optional[Dict[str, Any]],
    ) -> Optional[str]:
        """البحث عن فشل سابق مماثل لنفس المجموعة (أداة + هدف + سبب + سياق)"""
        # مطابقة مباشرة بالبصمة لو fanns سياق Port/Endpoint
        if context:
            import hashlib
            raw = f"{tool}|{target}|{reason}|{context.get('port','')}|{context.get('endpoint','')}"
            fp = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
            if fp in self.by_fingerprint:
                return self.by_fingerprint[fp]

        # مطابقة宽ة: نفس الأداة والهدف والسبب
        for fid in self.by_target.get(target, []):
            rec = self.failures[fid]
            if rec.tool == tool and rec.reason == reason:
                return fid
        return None

    # ------------------------------------------------------------------ #
    # استفسار قبل التنفيذ (الاستخدام الرئيسي من قبل Executor / Reviewer)
    # ------------------------------------------------------------------ #
    def is_known_failure(
        self,
        target: str,
        tool: str,
        command: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> Optional[FailureRecord]:
        """
        retornar السجل إذا كان هذا الأمر/الهدف قد فشل من قبل بنفس النمط.
        يُستدعى قبل تنفيذ أي أمر لتجنب تكرار الفشل الحتمي.
        """
        import hashlib
        # محاولة مطابقة السياق المحدد (Port/Endpoint)
        if context:
            raw = f"{tool}|{target}|{context.get('port','')}|{context.get('endpoint','')}"
            fp = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
            fid = self.by_fingerprint.get(fp)
            if fid:
                return self.failures[fid]

        # مطابقة واسعة علىsame tool + target عبر السجلات
        for fid in self.by_target.get(target, []):
            rec = self.failures[fid]
            if rec.tool == tool and rec.command == command:
                return rec
        return None

    def get_failures_for_target(self, target: str) -> List[FailureRecord]:
        return [self.failures[fid] for fid in self.by_target.get(target, [])]

    def get_failures_for_tool(self, tool: str) -> List[FailureRecord]:
        return [self.failures[fid] for fid in self.by_tool.get(tool, [])]

    def get_repeated_failures(self, min_repeats: int = 2) -> List[FailureRecord]:
        """سجلات الفشل التي تكررت min_repeats مرة أو أكثر — مرشحة لمراجعة Reviewer"""
        return [rec for rec in self.failures.values() if rec.repeat_count >= min_repeats]

    # ------------------------------------------------------------------ #
    # تصدير / استيراد
    # ------------------------------------------------------------------ #
    def to_dict(self) -> Dict[str, Any]:
        return {
            "failures": [rec.to_dict() for rec in self.failures.values()],
            "by_fingerprint": self.by_fingerprint,
            "by_target": {k: v for k, v in self.by_target.items()},
            "by_tool": {k: v for k, v in self.by_tool.items()},
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
            log.warning(f"Failed to save FailureEpisodicMemory: {e}")

    def _load(self):
        try:
            p = Path(self.storage_file)
            if p.exists():
                data = json.loads(p.read_text(encoding="utf-8"))
                for item in data.get("failures", []):
                    rec = FailureRecord.from_dict(item)
                    self.failures[rec.id] = rec
                    self.by_fingerprint[rec.fingerprint] = rec.id
                    self.by_target.setdefault(rec.target, []).append(rec.id)
                    self.by_tool.setdefault(rec.tool, []).append(rec.id)
        except Exception as e:
            log.warning(f"Failed to load FailureEpisodicMemory: {e}")
