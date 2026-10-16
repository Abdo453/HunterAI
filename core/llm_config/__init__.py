"""HunterAI LLM Configuration Package"""
from core.llm_config.manager import (
    LLMConfig, ModelConfig, ProviderConfig, LLMConfigManager, llm_config,
)

__all__ = [
    "LLMConfig",
    "ModelConfig",
    "ProviderConfig",
    "LLMConfigManager",
    "llm_config",
]
__version__ = "1.0.0"
