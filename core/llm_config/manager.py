"""
HunterAI LLM Configuration System
إعدادات نموذج اللغة المرنة — مقتبس من فكرة BlacksmithAI config.json

يدعم مزودين متعددين (OpenAI, Anthropic, Gemini, OpenRouter, vLLM, Ollama, Groq, MiniMax...)
مع إمكانية تخصيص context_size, max_retries, max_tokens لكل مزود ونموذج
"""
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List
from pathlib import Path

log = logging.getLogger("hunter_ai.llm_config")


@dataclass
class ModelConfig:
    """إعدادات نموذج فردي"""
    model: str = "default"
    context_size: int = 200000
    max_retries: int = 3
    stream_usage: bool = True
    max_tokens: Optional[int] = None
    temperature: float = 0.7
    top_p: float = 0.9

    def to_dict(self) -> dict:
        return {
            "model": self.model,
            "context_size": self.context_size,
            "max_retries": self.max_retries,
            "stream_usage": self.stream_usage,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "top_p": self.top_p,
        }


@dataclass
class ProviderConfig:
    """إعدادات مزود LLM"""
    name: str
    base_url: str
    default_model: str
    default_embedding_model: str = "text-embedding-3-small"
    default_model_config: ModelConfig = field(default_factory=ModelConfig)
    default_embedding_model_config: ModelConfig = field(default_factory=ModelConfig)
    api_key_env: str = ""  # اسم متغير البيئة للمفتاح السري

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "base_url": self.base_url,
            "default_model": self.default_model,
            "default_embedding_model": self.default_embedding_model,
            "default_model_config": self.default_model_config.to_dict(),
            "default_embedding_model_config": self.default_embedding_model_config.to_dict(),
            "api_key_env": self.api_key_env,
        }


@dataclass
class LLMConfig:
    """الإعدادات الكاملة للنماذج اللغوية"""
    defaults: Dict[str, str] = field(default_factory=dict)
    providers: Dict[str, ProviderConfig] = field(default_factory=dict)

    def get_default_provider(self) -> str:
        return self.defaults.get("provider", "openrouter")

    def get_provider(self, name: str) -> Optional[ProviderConfig]:
        return self.providers.get(name)

    def get_default_model_config(self) -> Optional[ModelConfig]:
        provider_name = self.get_default_provider()
        provider = self.get_provider(provider_name)
        if provider:
            return provider.default_model_config
        return None

    def to_dict(self) -> dict:
        return {
            "defaults": self.defaults,
            "providers": {k: v.to_dict() for k, v in self.providers.items()},
        }

    @classmethod
    def from_dict(cls, data: dict) -> "LLMConfig":
        defaults = data.get("defaults", {})
        providers = {}
        for name, pdata in data.get("providers", {}).items():
            model_cfg = ModelConfig(**pdata.get("default_model_config", {}))
            embed_cfg = ModelConfig(**pdata.get("default_embedding_model_config", {}))
            providers[name] = ProviderConfig(
                name=name,
                base_url=pdata.get("base_url", ""),
                default_model=pdata.get("default_model", ""),
                default_embedding_model=pdata.get("default_embedding_model", "text-embedding-3-small"),
                default_model_config=model_cfg,
                default_embedding_model_config=embed_cfg,
                api_key_env=pdata.get("api_key_env", ""),
            )
        return cls(defaults=defaults, providers=providers)

    @classmethod
    def from_json_file(cls, path: str) -> "LLMConfig":
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls.from_dict(data)

    def save_to_json_file(self, path: str):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, ensure_ascii=False, indent=2)


# التكوين الافتراضي لـ HunterAI
DEFAULT_LLM_CONFIG = LLMConfig(
    defaults={
        "provider": "nvidia",
    },
    providers={
        "nvidia": ProviderConfig(
            name="nvidia",
            base_url="https://integrate.api.nvidia.com/v1",
            default_model="nvidia/z-ai/glm-5.3-flash",
            default_embedding_model="nvidia/nv-embedcode-7b-v1",
            default_model_config=ModelConfig(
                model="nvidia/z-ai/glm-5.3-flash",
                context_size=131072,
                max_retries=3,
                stream_usage=True,
                max_tokens=None,
                temperature=0.7,
            ),
            default_embedding_model_config=ModelConfig(
                model="nvidia/nv-embedcode-7b-v1",
                context_size=4096,
                max_retries=3,
            ),
            api_key_env="NVIDIA_API_KEY",
        ),
        "openrouter": ProviderConfig(
            name="openrouter",
            base_url="https://openrouter.ai/api/v1/chat/completions",
            default_model="mistralai/mistral-7b-instruct",
            default_embedding_model="openai/text-embedding-3-small",
            default_model_config=ModelConfig(
                model="mistralai/mistral-7b-instruct",
                context_size=32768,
                max_retries=3,
                stream_usage=True,
            ),
            api_key_env="OPENROUTER_API_KEY",
        ),
        "openai": ProviderConfig(
            name="openai",
            base_url="https://api.openai.com/v1/chat/completions",
            default_model="gpt-4o-mini",
            default_embedding_model="text-embedding-3-small",
            default_model_config=ModelConfig(
                model="gpt-4o-mini",
                context_size=128000,
                max_retries=3,
                stream_usage=True,
            ),
            api_key_env="OPENAI_API_KEY",
        ),
        "vllm": ProviderConfig(
            name="vllm",
            base_url="http://localhost:8000/v1/chat/completions",
            default_model="mistralai/mistral-7b-instruct",
            default_embedding_model="text-embedding-3-small",
            default_model_config=ModelConfig(
                model="mistralai/mistral-7b-instruct",
                context_size=32768,
                max_retries=3,
                stream_usage=True,
            ),
            api_key_env="VLLM_API_KEY",
        ),
        "anthropic": ProviderConfig(
            name="anthropic",
            base_url="https://api.anthropic.com/v1/messages",
            default_model="claude-3-5-sonnet-20241022",
            default_embedding_model="text-embedding-3-small",
            default_model_config=ModelConfig(
                model="claude-3-5-sonnet-20241022",
                context_size=200000,
                max_retries=3,
                stream_usage=True,
            ),
            api_key_env="ANTHROPIC_API_KEY",
        ),
        "gemini": ProviderConfig(
            name="gemini",
            base_url="https://generativelanguage.googleapis.com/v1beta/models",
            default_model="gemini-1.5-pro",
            default_embedding_model="text-embedding-004",
            default_model_config=ModelConfig(
                model="gemini-1.5-pro",
                context_size=1048576,
                max_retries=3,
                stream_usage=True,
            ),
            api_key_env="GEMINI_API_KEY",
        ),
        "groq": ProviderConfig(
            name="groq",
            base_url="https://api.groq.com/openai/v1/chat/completions",
            default_model="llama-3.1-70b-versatile",
            default_embedding_model="text-embedding-3-small",
            default_model_config=ModelConfig(
                model="llama-3.1-70b-versatile",
                context_size=131072,
                max_retries=3,
                stream_usage=True,
            ),
            api_key_env="GROQ_API_KEY",
        ),
    },
)


class LLMConfigManager:
    """
    مدير إعدادات النماذج اللغوية
    يحمل الإعدادات من ملف config.json أو المتغيرات البيئية
    """

    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or "config.json"
        self.config: LLMConfig = DEFAULT_LLM_CONFIG
        self._load_config()

    def _load_config(self):
        """يحمل الإعدادات من الملف إذا وجد، وإلا يستخدم الافتراضي"""
        if self.config_path and os.path.exists(self.config_path):
            try:
                self.config = LLMConfig.from_json_file(self.config_path)
                log.info(f"[LLMConfig] Loaded config from {self.config_path}")
            except Exception as e:
                log.warning(f"[LLMConfig] Failed to load config: {e}, using defaults")
                self.config = DEFAULT_LLM_CONFIG
        else:
            log.info(f"[LLMConfig] Config file not found, using defaults")

    def get_config(self) -> LLMConfig:
        return self.config

    def get_default_provider(self) -> str:
        return self.config.get_default_provider()

    def get_provider(self, name: str) -> Optional[ProviderConfig]:
        return self.config.get_provider(name)

    def get_api_key(self, provider_name: str) -> Optional[str]:
        """يجلب مفتاح API من متغير البيئة بناءً على اسم المزود"""
        provider = self.get_provider(provider_name)
        if not provider or not provider.api_key_env:
            return None
        return os.getenv(provider.api_key_env)

    def reload(self):
        self._load_config()


# مثيل افتراضي يمكن استخدامه في toute the system
llm_config = LLMConfigManager()
