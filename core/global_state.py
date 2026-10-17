"""
حالة التطبيق المشتركة (Global State) — مرحلة H.

سواقل تطبيقية نظيفة لملحقات Phase C/D، تُحقن في الراوترات دون حالات عامة إلزامية
إجبارية على كل مكون (يمكن استبدالها في الاختبارات).
"""

from __future__ import annotations

from core.coordinator import Coordinator
from core.evidence_store import EvidenceStore

# نسخة مشتركة للمنسق — تُستخدم من واجهة التشغيل في الويب
GLOBAL_COORDINATOR = Coordinator()

# نسخة مشتركة لمتجر الأدلة الدائم — تُستخدم من واجهة الأدلة في الويب
GLOBAL_EVIDENCE_STORE = EvidenceStore()
