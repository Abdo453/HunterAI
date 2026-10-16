"""Tests لـ LLM Configuration System"""
import sys
import os
import json
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.llm_config.manager import (
    LLMConfig, ModelConfig, ProviderConfig, LLMConfigManager, llm_config,
)


def test_model_config():
    mc = ModelConfig(
        model="gpt-4o-mini",
        context_size=128000,
        max_retries=3,
        stream_usage=True,
    )
    d = mc.to_dict()
    assert d["model"] == "gpt-4o-mini"
    assert d["context_size"] == 128000
    assert d["max_retries"] == 3
    print("[PASS] llm model_config")


def test_provider_config():
    pc = ProviderConfig(
        name="openai",
        base_url="https://api.openai.com/v1/chat/completions",
        default_model="gpt-4o-mini",
        api_key_env="OPENAI_API_KEY",
    )
    d = pc.to_dict()
    assert d["name"] == "openai"
    assert d["api_key_env"] == "OPENAI_API_KEY"
    print("[PASS] llm provider_config")


def test_llm_config_from_dict():
    data = {
        "defaults": {"provider": "openai"},
        "providers": {
            "openai": {
                "name": "openai",
                "base_url": "https://api.openai.com/v1/chat/completions",
                "default_model": "gpt-4o-mini",
                "api_key_env": "OPENAI_API_KEY",
            }
        },
    }
    config = LLMConfig.from_dict(data)
    assert config.get_default_provider() == "openai"
    provider = config.get_provider("openai")
    assert provider is not None
    assert provider.base_url == "https://api.openai.com/v1/chat/completions"
    print("[PASS] llm config from_dict")


def test_config_save_load():
    config = LLMConfig(defaults={"provider": "vllm"})
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        config.save_to_json_file(f.name)
        tmp = f.name

    try:
        loaded = LLMConfig.from_json_file(tmp)
        assert loaded.get_default_provider() == "vllm"
        print("[PASS] llm config save/load")
    finally:
        os.unlink(tmp)


def test_global_config():
    assert llm_config is not None
    assert llm_config.get_default_provider() == "nvidia"
    provider = llm_config.get_provider("nvidia")
    assert provider is not None
    assert provider.name == "nvidia"
    print("[PASS] llm global config")


def test_api_key_retrieval():
    # لن نجد مفتاح API حقيقي، لكن نتحقق من المنطق
    provider = llm_config.get_provider("nvidia")
    if provider:
        key = llm_config.get_api_key("nvidia")
        # قد تكون None إذا لم يتم تعيين المتغير البيئي
        assert key is None or isinstance(key, str)
    print("[PASS] llm api_key retrieval")


if __name__ == "__main__":
    test_model_config()
    test_provider_config()
    test_llm_config_from_dict()
    test_config_save_load()
    test_global_config()
    test_api_key_retrieval()
    print("\n[INFO] جميع اختبارات LLM Configuration نجحت!")
