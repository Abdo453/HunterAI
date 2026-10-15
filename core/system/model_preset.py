"""
HunterAI Model Presets and Agent Profile Loader
================================================
Defines ModelPreset configuration classes and helpers to load
agent profiles from `profiles/` directory.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class ModelPreset:
    """
    Model configuration preset defining model identity, generation parameters,
    and capability flags.
    """
    model: str
    temperature: float = 0.2
    top_p: float = 0.95
    max_tokens: int = 4096
    context_length: int = 32768
    system_prompt: str = ""
    stop_sequences: List[str] = field(default_factory=list)
    timeout_seconds: float = 60.0
    fallback_models: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    BUILTIN_PRESETS: Dict[str, Dict[str, Any]] = field(default_factory=lambda: {
        "gpt-4": {
            "model": "gpt-4",
            "temperature": 0.2,
            "max_tokens": 4096,
            "context_length": 128000,
            "fallback_models": ["qwen3:8b", "qwen2.5-coder:14b-tools"],
        },
        "qwen3:8b": {
            "model": "qwen3:8b",
            "temperature": 0.2,
            "max_tokens": 4096,
            "context_length": 32768,
            "fallback_models": ["qwen2.5-coder:14b-tools"],
        },
        "qwen2.5-coder:14b-tools": {
            "model": "qwen2.5-coder:14b-tools",
            "temperature": 0.1,
            "max_tokens": 8192,
            "context_length": 32768,
            "fallback_models": ["qwen3:8b"],
        },
        "deterministic_verifier": {
            "model": "rule_based",
            "temperature": 0.0,
            "max_tokens": 2048,
            "context_length": 16384,
            "fallback_models": [],
        },
    })

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ModelPreset:
        model = data.get("model", "qwen3:8b")
        return cls(
            model=model,
            temperature=float(data.get("temperature", 0.2)),
            top_p=float(data.get("top_p", 0.95)),
            max_tokens=int(data.get("max_tokens", 4096)),
            context_length=int(data.get("context_length", 32768)),
            system_prompt=str(data.get("system_prompt", "")),
            stop_sequences=list(data.get("stop_sequences", [])),
            timeout_seconds=float(data.get("timeout_seconds", 60.0)),
            fallback_models=list(data.get("fallback_models", [])),
            metadata=dict(data.get("metadata", {})),
        )

    @classmethod
    def load_preset(cls, name_or_path: str) -> ModelPreset:
        """Loads by preset name or from a JSON file path"""
        p = Path(name_or_path)
        if p.exists() and p.is_file():
            data = json.loads(p.read_text(encoding="utf-8"))
            return cls.from_dict(data)

        # Check builtins
        dummy = cls(model="")
        if name_or_path in dummy.BUILTIN_PRESETS:
            return cls.from_dict(dummy.BUILTIN_PRESETS[name_or_path])

        # Default fallback
        return cls(model=name_or_path)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "model": self.model,
            "temperature": self.temperature,
            "top_p": self.top_p,
            "max_tokens": self.max_tokens,
            "context_length": self.context_length,
            "system_prompt": self.system_prompt,
            "stop_sequences": self.stop_sequences,
            "timeout_seconds": self.timeout_seconds,
            "fallback_models": self.fallback_models,
            "metadata": self.metadata,
        }


@dataclass
class AgentProfile:
    """
    Complete definition of an agent persona, skills, allowed tools, and model preset.
    """
    id: str
    name: str
    role: str
    preset: ModelPreset
    skills: List[str] = field(default_factory=list)
    allowed_tools: List[str] = field(default_factory=list)
    permissions: List[str] = field(default_factory=list)

    @classmethod
    def load_from_file(cls, path: str | Path) -> AgentProfile:
        p = Path(path)
        data = json.loads(p.read_text(encoding="utf-8"))
        preset_data = {
            "model": data.get("model", "qwen3:8b"),
            "temperature": data.get("temperature", 0.2),
            "system_prompt": data.get("system_prompt", ""),
        }
        return cls(
            id=data.get("id", p.stem),
            name=data.get("name", p.stem),
            role=data.get("role", "general"),
            preset=ModelPreset.from_dict(preset_data),
            skills=list(data.get("skills", [])),
            allowed_tools=list(data.get("allowed_tools", [])),
            permissions=list(data.get("permissions", [])),
        )

    @classmethod
    def load_all_profiles(cls, profiles_dir: str | Path = "profiles") -> Dict[str, AgentProfile]:
        dir_path = Path(profiles_dir)
        profiles = {}
        if dir_path.exists():
            for f in dir_path.glob("*.json"):
                try:
                    prof = cls.load_from_file(f)
                    profiles[prof.id] = prof
                except Exception:
                    pass
        return profiles
