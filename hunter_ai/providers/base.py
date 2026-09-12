"""
HunterAI Base Model Provider Abstract Class
Standardizes interface across Local Ollama, Cloud APIs, and Deterministic engines.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Set

from hunter_ai.agents.capabilities import AgentCapability


class BaseModelProvider(ABC):
    """
    الواجهة المعيارية الموحدة لمزودي الذكاء الاصطناعي (Base Model Provider):
    - generate: توليد استجابة نصية حرة
    - analyze_structured: توليد كائن JSON منظم ومتحقق منه
    - health_check: فحص زمن الاستجابة وحالة الاتصال
    """

    def __init__(self, model_id: str, provider_name: str, context_window: int = 16384):
        self.model_id = model_id
        self.provider_name = provider_name
        self.context_window = context_window
        self.is_online = True
        self.last_latency_ms = 0.0

    @abstractmethod
    async def generate(self, prompt: str, system_prompt: str = "") -> str:
        """توليد رد نصي"""
        pass

    @abstractmethod
    async def analyze_structured(self, prompt: str, system_prompt: str = "") -> Dict[str, Any]:
        """تحليل واستخراج كائن بيانات منظم"""
        pass

    @abstractmethod
    async def health_check(self) -> Dict[str, Any]:
        """فحص حالة المزود وسرعته"""
        pass

    @abstractmethod
    def supported_capabilities(self) -> Set[AgentCapability]:
        """قائمة القدرات التي يدعمها هذا النموذج"""
        pass
