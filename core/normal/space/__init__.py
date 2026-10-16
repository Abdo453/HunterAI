"""
HunterAI Negative Space Ledger (سجل المساحات السالبة)
توثيق كل ما لم يتم اختباره وأسبابه —-core invariant من HunterAI:
No Findings Reported ≠ Application is Secure
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum

log = logging.getLogger("hunter_ai.negative_space")


class SkipReason(str):
    SKIPPED_POLICY_RESTRICTION = "SKIPPED_POLICY_RESTRICTION"      # prohibido por constitución
    SKIPPED_AUTH_MISSING = "SKIPPED_AUTH_MISSING"                   # يحتاج مصادقة غير متوفرة
    SKIPPED_OPERATOR_APPROVAL = "SKIPPED_OPERATOR_APPROVAL"         # يحتاج موافقة المشغل
    SKIPPED_TOOL_UNAVAILABLE = "SKIPPED_TOOL_UNAVAILABLE"           # الأداة غير مثبتة
    SKIPPED_OUT_OF_SCOPE = "SKIPPED_OUT_OF_SCOPE"                  # خارج النطاق المصرح به
    SKIPPED_RATE_LIMIT = "SKIPPED_RATE_LIMIT"                       # حد معدل الأدوات
    SKIPPED_SAFE_MODE = "SKIPPED_SAFE_MODE"                         # وضع الآمان مفعّل
    SKIPPED_TECHNICAL_LIMITATION = "SKIPPED_TECHNICAL_LIMITATION"   # قيود تقنية


@dataclass
class UntestedItem:
    """عنصر واحد لم يتم اختباره مع سبب الت.skip"""
    item_id: str
    item_type: str  # route, parameter, state_transition, port, service, ...
    target: str
    description: str
    skip_reason: str
    skip_reason_detail: str
    severity_if_found: str = "unknown"  # low, medium, high, critical — إذا تم العثور على ثغرة هناك
    discovered_at: float = field(default_factory=time.time)
    last_reviewed: Optional[float] = None
    retry_eligible: bool = True  # هل يمكن إعادة المحاولة لاحقاً

    def to_dict(self) -> dict:
        return {
            "item_id": self.item_id,
            "item_type": self.item_type,
            "target": self.target,
            "description": self.description,
            "skip_reason": self.skip_reason,
            "skip_reason_detail": self.skip_reason_detail,
            "severity_if_found": self.severity_if_found,
            "discovered_at": self.discovered_at,
            "last_reviewed": self.last_reviewed,
            "retry_eligible": self.retry_eligible,
        }


class NegativeSpaceLedger:
    """
    سجل المساحات السالبة — يوثق كل ما لم يتم اختباره وأسبابه.
    هذا يضمن الشفافية الجذرية (Radical Epistemic Transparency):
    عدم وجود نتائج لا يعني أن التطبيق آمن.
    """

    def __init__(self):
        self.untested_items: Dict[str, UntestedItem] = {}
        self._item_counter = 0

    def add_untested(
        self,
        item_type: str,
        target: str,
        description: str,
        skip_reason: str,
        skip_reason_detail: str = "",
        severity_if_found: str = "unknown",
        retry_eligible: bool = True,
    ) -> str:
        """إضافة عنصر غير مختبر إلى السجل"""
        self._item_counter += 1
        item_id = f"ns_{self._item_counter:04d}"
        item = UntestedItem(
            item_id=item_id,
            item_type=item_type,
            target=target,
            description=description,
            skip_reason=skip_reason,
            skip_reason_detail=skip_reason_detail,
            severity_if_found=severity_if_found,
            retry_eligible=retry_eligible,
        )
        self.untested_items[item_id] = item
        log.debug(
            f"[NegativeSpace] Added {item_type} on {target}: {skip_reason} — {skip_reason_detail}"
        )
        return item_id

    def get_item(self, item_id: str) -> Optional[UntestedItem]:
        return self.untested_items.get(item_id)

    def list_all(self) -> List[UntestedItem]:
        return list(self.untested_items.values())

    def list_by_reason(self, skip_reason: str) -> List[UntestedItem]:
        return [i for i in self.untested_items.values() if i.skip_reason == skip_reason]

    def list_by_target(self, target: str) -> List[UntestedItem]:
        return [i for i in self.untested_items.values() if i.target == target]

    def list_retry_eligible(self) -> List[UntestedItem]:
        return [i for i in self.untested_items.values() if i.retry_eligible]

    def mark_reviewed(self, item_id: str):
        if item_id in self.untested_items:
            self.untested_items[item_id].last_reviewed = time.time()

    def remove_item(self, item_id: str) -> bool:
        if item_id in self.untested_items:
            del self.untested_items[item_id]
            return True
        return False

    def clear(self):
        self.untested_items.clear()
        self._item_counter = 0

    def summary(self) -> dict:
        total = len(self.untested_items)
        by_reason: Dict[str, int] = {}
        for item in self.untested_items.values():
            by_reason[item.skip_reason] = by_reason.get(item.skip_reason, 0) + 1
        by_target: Dict[str, int] = {}
        for item in self.untested_items.values():
            by_target[item.target] = by_target.get(item.target, 0) + 1
        retry_eligible = len(self.list_retry_eligible())

        return {
            "total_untested": total,
            "by_reason": by_reason,
            "by_target": by_target,
            "retry_eligible": retry_eligible,
        }


# مثيل افتراضي يمكن استخدامه في toda the system
negative_space_ledger: Optional[NegativeSpaceLedger] = None


def get_negative_space_ledger() -> NegativeSpaceLedger:
    global negative_space_ledger
    if negative_space_ledger is None:
        negative_space_ledger = NegativeSpaceLedger()
    return negative_space_ledger
