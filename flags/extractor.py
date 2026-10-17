"""استخراج مرشّحات الفلوغات من نص عشوائي.

يعمل بثلاث طبقات:
1. قوالب صريحة (Flag format المُعلن من المستخدم: مثال `flag{...}`)
2. أنماط شائعة (HTB{...}, CTF{...}, FLAG{...} وغيرها)
3. مؤشرات سياق (كلمات مثل "flag is", "congratulations") ترفع الثقة
"""
from __future__ import annotations

import re
from typing import List, Optional

from flags.models import FlagCandidate

# أنماط شائعة — case-insensitive، تغطي أغلب المنصات
_GENERIC_PATTERNS = [
    re.compile(r"\bflag\{[^{}\n]{3,200}\}", re.IGNORECASE),
    re.compile(r"\bctf\{[^{}\n]{3,200}\}", re.IGNORECASE),
    re.compile(r"\bhtb\{[^{}\n]{3,200}\}", re.IGNORECASE),
    re.compile(r"\bpicoctf\{[^{}\n]{3,200}\}", re.IGNORECASE),
    re.compile(r"\bgctf\{[^{}\n]{3,200}\}", re.IGNORECASE),
    re.compile(r"\bFLAG_[A-Z0-9_]{8,80}\b"),
    re.compile(r"\b[a-z0-9]{3,10}ctf\{[^{}\n]{3,200}\}", re.IGNORECASE),
]

# مؤشرات سياق ترفع الثقة (تظهر عادةً قرب الفلوغ الصحيح)
_CONFIDENCE_CONTEXT = (
    "congratulations", "correct flag", "flag submitted", "well done",
    "solved", "accepted", "you got it", "right answer",
)

# عوامل خفض الثقة (شائعة في false positives)
_SUSPICIOUS_CONTEXT = (
    "example", "placeholder", "flag{...}", "flag{}", "your_flag_here",
    "xxxx", "todo", "format", "regex",
)


def _compile_custom(pattern: str) -> Optional[re.Pattern]:
    """تجميع قالب Flag مُعلن من المستخدم (regex)."""
    try:
        return re.compile(pattern)
    except re.error:
        return None


def _confidence_for(value: str, context: str, format_ok: bool) -> float:
    score = 0.45  # أساس للاكتشاف
    if format_ok:
        score += 0.25
    low = context.lower()
    if any(ind in low for ind in _CONFIDENCE_CONTEXT):
        score += 0.2
    if any(ind in low for ind in _SUSPICIOUS_CONTEXT):
        score -= 0.35
    # طول معقول = أقوى
    inner = len(value)
    if 8 <= inner <= 80:
        score += 0.1
    return max(0.0, min(1.0, score))


def extract_flag_candidates(
    text: str,
    *,
    flag_format: str = "",
    source: str = "",
    worker: str = "",
    max_candidates: int = 50,
) -> List[FlagCandidate]:
    """استخراج مرشّحات فلوغات من نص.

    flag_format: regex يصف قالب المسابقة (مثل `flag\\{[a-f0-9]{32}\\}`).
    يعود بمرشّحات مرتّبة تنازليًا بالثقة، بدون تكرار (dedupe بالقيمة).
    """
    if not text:
        return []

    patterns: List[re.Pattern] = []
    if flag_format:
        custom = _compile_custom(flag_format)
        if custom is not None:
            patterns.append(custom)
    patterns.extend(_GENERIC_PATTERNS)

    seen: set = set()
    candidates: List[FlagCandidate] = []

    for pat in patterns:
        for m in pat.finditer(text):
            value = m.group(0).strip()
            if not value or value in seen:
                continue
            seen.add(value)
            start = max(0, m.start() - 120)
            end = min(len(text), m.end() + 120)
            context = text[start:end]
            format_ok = bool(flag_format) and bool(
                _compile_custom(flag_format) and
                _compile_custom(flag_format).fullmatch(value))
            if not flag_format:
                format_ok = True  # لا يوجد قالب مُعلن ⇒ الأنماط الشائعة تكفي
            conf = _confidence_for(value, context, format_ok)
            candidates.append(FlagCandidate(
                value=value,
                format_ok=format_ok,
                confidence=conf,
                source=source,
                context=context.replace("\n", " ")[:240],
                worker=worker,
            ))
            if len(candidates) >= max_candidates:
                break
        if len(candidates) >= max_candidates:
            break

    candidates.sort(key=lambda c: c.confidence, reverse=True)
    return candidates
