"""
الإعدادات المركزية لمشروع HunterAI
جميع المتغيرات القابلة للتعديل في مكان واحد
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

from dotenv import load_dotenv

# تحميل متغيرات البيئة من ملف .env
load_dotenv()


@dataclass
class OllamaConfig:
    host: str = field(default_factory=lambda: os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434"))
    default_model: str = field(default_factory=lambda: os.getenv("HUNTER_AI_MODEL", "qwen2.5-coder:14b"))
    timeout: int = 30
    max_retries: int = 3


@dataclass
class WAFConfig:
    max_levels: int = 9
    timeout_seconds: int = 15
    follow_redirects: bool = False
    user_agent: str = "Mozilla/5.0 (compatible; HunterAI-WAF-Test/1.0)"


@dataclass
class MemoryConfig:
    storage_path: str = "data/memory/triple"
    failure_ttl_seconds: int = 86400 * 30  # 30 days
    working_ttl_seconds: int = 600  # 10 minutes


@dataclass
class TDGConfig:
    storage_path: str = "data/task_graphs"
    max_retries: int = 3


@dataclass
class RAGConfig:
    knowledge_dir: str = "data/knowledge_base"
    min_score: float = 0.1
    top_k: int = 5


@dataclass
class EvidenceCourtConfig:
    confidence_threshold: float = 0.5
    bypass_confidence_boost: float = 0.2


@dataclass
class HunterAIConfig:
    ollama: OllamaConfig = field(default_factory=OllamaConfig)
    waf: WAFConfig = field(default_factory=WAFConfig)
    memory: MemoryConfig = field(default_factory=MemoryConfig)
    tdg: TDGConfig = field(default_factory=TDGConfig)
    rag: RAGConfig = field(default_factory=RAGConfig)
    evidence_court: EvidenceCourtConfig = field(default_factory=EvidenceCourtConfig)
    debug: bool = field(default_factory=lambda: os.getenv("DEBUG", "false").lower() == "true")
    authorized: bool = field(default_factory=lambda: os.getenv("HUNTER_AUTHORIZED", "false").lower() == "true")

    @classmethod
    def from_env(cls) -> "HunterAIConfig":
        return cls()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ollama": {
                "host": self.ollama.host,
                "default_model": self.ollama.default_model,
                "timeout": self.ollama.timeout,
            },
            "waf": {
                "max_levels": self.waf.max_levels,
                "timeout_seconds": self.waf.timeout_seconds,
            },
            "memory": {
                "storage_path": self.memory.storage_path,
                "failure_ttl_seconds": self.memory.failure_ttl_seconds,
            },
            "debug": self.debug,
            "authorized": self.authorized,
        }


# مثيل عام للإعدادات
config = HunterAIConfig.from_env()
