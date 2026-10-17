"""
واجهة موفري النماذج اللغوية الموحدة (Agent Provider Interface) — Phase B.

تُطبَّق الفكرة من الوصف التصميمي لـ Muteki بأصلية كود MIT (لا نسخ من AGPL):
每 مزود نموذج يُwrap في محوّل (adapter) يُExpose عقدة موحدة،
حتى لا يعلم Divis scheduler تفاصيل أي مزود بعينه.

مبادئ أمنية:
- لا تُخزن مفاتيح API أو رموز المصادقة في هذه الطبقة؛ تُقرأ من المتغيرات
  البيئية أو من مدير الأسرار في وقت التنفيذ.
- لا تُطبع مفاتيح API / رؤوس المصادقة الكاملة في رسائل الخطأ أو السجلات.
- يدعم الإلغاء (cancel) والمهلة (timeout) والمحاولات المحدودة (bounded retries).
- كل مزود يعلن عن قدراته (tool-calling، streaming) عبر capabilities().
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ModelCapability:
    """إمكانية واحدة يدعمها المزود."""
    name: str                     # مثال: "tool_calling", "streaming", "json_mode"
    version: Optional[str] = None


@dataclass(frozen=True)
class ProviderCapabilities:
    """قدرات مزود نموذج — تُعلن وتُستعلم، لا تُفترض."""
    provider: str
    model: str
    supports_tool_calling: bool = False
    supports_streaming: bool = False
    supports_json_mode: bool = False
    max_tokens: Optional[int] = None
    extra: List[ModelCapability] = field(default_factory=list)

    def has(self, capability: str) -> bool:
        if capability == "tool_calling":
            return self.supports_tool_calling
        if capability == "streaming":
            return self.supports_streaming
        if capability == "json_mode":
            return self.supports_json_mode
        return any(c.name == capability for c in self.extra)


@dataclass
class ProviderRequest:
    """طلب موحد يُرسل إلى أي مزود."""
    model: str
    messages: List[Dict[str, str]]          # [{role, content}, ...]
    tools: Optional[List[Dict[str, Any]]] = None   # تعريفات الأدوات (موحّدة داخليًا)
    tool_choice: Optional[str] = None       # "required" | "auto" | "none"
    temperature: Optional[float] = None
    max_tokens: Optional[int] = None
    timeout_s: float = 120.0
    run_id: str = ""                        # للأudit والتتبع
    provider_ref: Optional[str] = None      # مرجع مصادقة (اسم، لا قيمة سرية)


@dataclass
class ProviderResponse:
    """رد موحد من أي مزود."""
    ok: bool
    content: str = ""
    tool_calls: List[Dict[str, Any]] = field(default_factory=list)
    finish_reason: Optional[str] = None
    model: str = ""
    provider: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    estimated_cost_usd: Optional[float] = None
    latency_s: float = 0.0
    error: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)   # internals للمزود (تُنقى قبل التسجيل)


@dataclass
class ProviderHealth:
    """نتيجة فحص صحة المزود."""
    healthy: bool
    provider: str
    model: str
    latency_s: float = 0.0
    error: Optional[str] = None
    checked_at: float = field(default_factory=time.time)


class AgentProvider(ABC):
    """
    واجهة مجردة لكل مزود نموذج لغوي.

    المطبقون يجب أن لا يفترضوا أن كل المزودين يدعمون نفس تنسيق tool-calling.
    كل سلوك مزوّد محدد يُخفي خلف محوّل (adapter) خاص به.
    """

    def __init__(self, provider: str, model: str, *,
                 timeout_s: float = 120.0,
                 max_retries: int = 2,
                 retry_backoff_s: float = 1.0,
                 provider_ref: Optional[str] = None):
        self.provider = provider
        self.model = model
        self.timeout_s = timeout_s
        self.max_retries = max_retries
        self.retry_backoff_s = retry_backoff_s
        self.provider_ref = provider_ref   # مرجع مصادقة (اسم فقط، لا سر)
        self._cancelled: Dict[str, asyncio.Event] = {}  # run_id -> Event

    # ── القدرات والفحص ────────────────────────────────────────────────────
    @abstractmethod
    def capabilities(self) -> ProviderCapabilities:
        """الإمكانيات التي يدعمها هذا المزود/النموذج."""

    @abstractmethod
    async def health_check(self) -> ProviderHealth:
        """فصلhether المزود可連 إلى الخدمة (باستخدام استعلام بسيط غير تدميري)."""

    # ── التنفيذ ───────────────────────────────────────────────────────────
    @abstractmethod
    async def execute(self, request: ProviderRequest) -> ProviderResponse:
        """إرسال طلب وحيد غير متدفق (non-streaming) والعودة بالنتيجة الموحّدة."""

    @abstractmethod
    async def stream(self, request: ProviderRequest,
                     on_chunk: Callable[[str], None]) -> ProviderResponse:
        """إرسال طلب مع بثّ الاستجابة مقطعة مقطعة عبر on_chunk."""

    @abstractmethod
    def cancel(self, run_id: str) -> bool:
        """طلب إلغاء تشغيل معرّف بـ run_id. يعود True إذا كان هناك ما يُلغى."""

    # ── مساعدة داخلية للمحوّلات ──────────────────────────────────────────
    def _mask_error(self, exc: Exception) -> str:
        """إرجاع رسالة خطأ آمنة للسجلات (بدون مفاتيح/رموز)."""
        text = str(exc)
        # إزالة أنماط مفاتيح API شائعة إن وُجدت في نص الخطأ
        import re
        text = re.sub(r"(sk-[A-Za-z0-9]{10,})", "sk-***", text)
        text = re.sub(r"(Bearer\s+[A-Za-z0-9._\-]{10,})", "Bearer ***", text)
        text = re.sub(r"(ghp_[A-Za-z0-9]{10,})", "ghp_***", text)
        return text[:300]

    def _register_cancel(self, run_id: str) -> asyncio.Event:
        ev = asyncio.Event()
        self._cancelled[run_id] = ev
        return ev

    def is_cancelled(self, run_id: str) -> bool:
        ev = self._cancelled.get(run_id)
        return bool(ev and ev.is_set())


# نسخة “لا شيء” للتطوير والاختبار حين لا يوجد مزود حقيقي مهيأ
class StubProvider(AgentProvider):
    """مزود وهمي لأغراض التطوير والاختبار فقط — لا يُستخدم في الإنتاج الحقيقي."""

    def __init__(self, provider: str = "stub", model: str = "stub-model"):
        super().__init__(provider, model)
        self._health = ProviderHealth(healthy=True, provider=provider, model=model)

    def capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(
            provider=self.provider, model=self.model,
            supports_tool_calling=False, supports_streaming=False,
            supports_json_mode=False)

    async def health_check(self) -> ProviderHealth:
        await asyncio.sleep(0)
        return self._health

    async def execute(self, request: ProviderRequest) -> ProviderResponse:
        await asyncio.sleep(0)
        return ProviderResponse(
            ok=True, content=f"[stub] received {len(request.messages)} message(s)",
            model=self.model, provider=self.provider)

    async def stream(self, request: ProviderRequest,
                     on_chunk: Callable[[str], None]) -> ProviderResponse:
        for word in ("[stub]", " response"):
            on_chunk(word)
            await asyncio.sleep(0)
        return ProviderResponse(ok=True, content="[stub] response",
                                model=self.model, provider=self.provider)

    def cancel(self, run_id: str) -> bool:
        return False


# سجل مزوّدين مشترك (يُحقن في الجدولة وليس حالة عامة إلزامية)
_PROVIDERS: Dict[str, AgentProvider] = {}


def register_provider(name: str, provider: AgentProvider) -> None:
    _PROVIDERS[name] = provider


def get_provider(name: str) -> Optional[AgentProvider]:
    return _PROVIDERS.get(name)


def list_providers() -> List[str]:
    return sorted(_PROVIDERS.keys())
