"""
استثناءات مخصصة لمشروع HunterAI
"""
from __future__ import annotations

from typing import Any, Optional


class HunterAIError(Exception):
    """الاستثناء الأساسي لجميع أخطاء HunterAI."""
    def __init__(self, message: str, code: str = "HUNTERAI_ERROR", details: Optional[dict] = None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.details = details or {}

    def to_dict(self) -> dict:
        return {
            "error": self.code,
            "message": self.message,
            "details": self.details,
        }


class ConfigurationError(HunterAIError):
    """أخطاء في إعدادات النظام."""
    def __init__(self, message: str, details: Optional[dict] = None):
        super().__init__(message, code="CONFIG_ERROR", details=details)


class ModelError(HunterAIError):
    """أخطاء في النماذج الذكية (Ollama, API providers)."""
    def __init__(self, message: str, model: Optional[str] = None, provider: Optional[str] = None, details: Optional[dict] = None):
        super().__init__(message, code="MODEL_ERROR", details=details or {})
        self.model = model
        self.provider = provider


class WAFError(HunterAIError):
    """أخطاء في تجاوز WAF."""
    def __init__(self, message: str, waf_type: Optional[str] = None, level: Optional[str] = None, details: Optional[dict] = None):
        super().__init__(message, code="WAF_ERROR", details=details or {})
        self.waf_type = waf_type
        self.level = level


class MemoryError(HunterAIError):
    """أخطاء في الذاكرة المنظمة."""
    def __init__(self, message: str, memory_type: Optional[str] = None, entry_id: Optional[str] = None, details: Optional[dict] = None):
        super().__init__(message, code="MEMORY_ERROR", details=details or {})
        self.memory_type = memory_type
        self.entry_id = entry_id


class TDGError(HunterAIError):
    """أخطاء في رسم بياني لتبعية المهام."""
    def __init__(self, message: str, task_id: Optional[str] = None, details: Optional[dict] = None):
        super().__init__(message, code="TDG_ERROR", details=details or {})
        self.task_id = task_id


class EvidenceCourtError(HunterAIError):
    """أخطاء في محكمة الأدلة."""
    def __init__(self, message: str, case_id: Optional[str] = None, details: Optional[dict] = None):
        super().__init__(message, code="EVIDENCE_COURT_ERROR", details=details or {})
        self.case_id = case_id


class OrchestratorError(HunterAIError):
    """أخطاء في منسق الوكلاء."""
    def __init__(self, message: str, agent_role: Optional[str] = None, details: Optional[dict] = None):
        super().__init__(message, code="ORCHESTRATOR_ERROR", details=details or {})
        self.agent_role = agent_role


class RAGError(HunterAIError):
    """أخطاء في محرك RAG."""
    def __init__(self, message: str, source: Optional[str] = None, details: Optional[dict] = None):
        super().__init__(message, code="RAG_ERROR", details=details or {})
        self.source = source
