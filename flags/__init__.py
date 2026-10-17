"""نظام ترشيح وكتابة الفلوغات (CTF Flag Pipeline).

المرحلة 2 من خطة التكامل مع Muteki:
- extractor.py : استخراج مرشّحات فلوغات من نص عشوائي (مخرجات worker / logs)
- store.py     : مخزن مرشّحات مع dedupe + ranking + علامة false positive
- service.py   : خدمة موحدة: نص → تحقق من القالب → تخزين → كشف اكتمال multi-flag
"""
from flags.models import FlagCandidate, FlagStatus
from flags.extractor import extract_flag_candidates
from flags.store import FlagStore
from flags.service import FlagService

__all__ = [
    "FlagCandidate", "FlagStatus",
    "extract_flag_candidates", "FlagStore", "FlagService",
]
