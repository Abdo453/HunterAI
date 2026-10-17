"""نوع مشترك لمحركات الوكلاء (CLI Engine Workers).

محرك (Engine) = عميل CLI خارجي (Claude Code / Codex / OpenCode / غيرها)
يُستدعى كـ subprocess لتنفيذ مهمة أمنية واحدة، وتعاد نتائجه مُطبَّعة.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class LaunchContext:
    """سياق تشغيل موحّد يُترجم لكل محرك حسب لغته الخاصة.

    permission_mode / sandbox_mode: مُعرِّفات مجرّدة تتحقق من صحة المحرك
    (مثال: claude يقبل "acceptEdits" وcodex يقبل "danger-full-access").
    """

    model: str = ""
    permission_mode: str = ""
    sandbox_mode: str = ""
    interactive: bool = False
    cwd: str = ""
    extra_env: Dict[str, str] = field(default_factory=dict)


@dataclass
class StreamStep:
    """خطوة حيّة واحدة أثناء تنفيذ المحرك (نص / استدعاء أداة / نتيجة أداة)."""

    kind: str  # "text" | "tool_call" | "tool_result" | "status" | "error"
    text: str = ""
    tool_name: str = ""
    tool_input: Any = None
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass
class EngineResult:
    """نتيجة تنفيذ مُطبَّعة من أي محرك."""

    ok: bool
    exit_code: Optional[int] = None
    output_text: str = ""
    session_id: str = ""
    error: str = ""
    duration_s: float = 0.0
    # استهلاك يُبلغه المحرك نفسه إن وُجد (يُستخدم لاحقًا لمراقبة التكلفة)
    cost_usd: Optional[float] = None
    input_tokens: Optional[int] = None
    output_tokens: Optional[int] = None
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass
class HealthStatus:
    """نتيجة فحص صحة محرك."""

    healthy: bool
    detail: str = ""
    binary: str = ""
    version: str = ""


# القدرات التي يعلن بها المحرك عن نفسه للـ scheduler
CAP_SECURE_PROMPT = "secure_prompt"      # يستقبل prompt عبر stdin بدون حفظ الجلسة
CAP_STREAMING = "streaming"              # يبثّ خطوات JSON أثناء التنفيذ
CAP_WEB_ISOLATION = "web_isolation"      # يستطيع تعطيل أدوات الويب الداخلية
CAP_RESUME = "resume"                    # يستأنف جلسة سابقة
CAP_NATIVE_SANDBOX = "native_sandbox"    # يملك وضع عزل أصلي (e.g. codex --sandbox)

ENGINE_CAPABILITIES: Dict[str, List[str]] = {}
