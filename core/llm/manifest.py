"""Canonical Model Manifest, Hardware Profiles, and Per-Role Model Assignments.

Adapted from vxcontrol/pentagi ``backend/pkg/providers/pconfig/config.go``
(commit ``cffed9485aa1cca70762cd08a57ac62a80406258``, licensed under MIT;
see ``THIRD_PARTY_LICENSES/PENTAGI_MIT.txt`` and ``NOTICE``).

Provides:
- Single canonical source of truth for provider default models (eliminating
  conflicting Gemini ``3.8-flash`` / ``2.5`` / ``2.0`` / ``1.5-pro`` drift).
- Hardware profiles (``auto``, ``4GB``, ``8GB``, ``16GB+``, ``cpu_only``) with
  VRAM caps, context windows, ``keep_alive`` defaults, and model selections.
- Per-role model assignments (``triage``, ``fixer``, ``planner``,
  ``deep_analyst``, ``copilot``) validated with Pydantic.
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional, Tuple

from pydantic import BaseModel, ConfigDict, Field, field_validator

logger = logging.getLogger("hunter_ai.llm.manifest")

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST_PATH = REPO_ROOT / "model_manifest.json"

#: Unified canonical Gemini default model across the entire HunterAI platform.
DEFAULT_GEMINI_MODEL: str = "gemini-2.5-flash"
GEMINI_MODELS: Tuple[str, ...] = (
    "gemini-2.5-flash",
    "gemini-2.5-pro",
    "gemini-2.0-flash",
)

HardwareProfileName = Literal["auto", "4GB", "8GB", "16GB+", "cpu_only"]
AgentRoleName = Literal["triage", "fixer", "planner", "deep_analyst", "copilot"]

VALID_HARDWARE_PROFILES: Tuple[str, ...] = ("auto", "4GB", "8GB", "16GB+", "cpu_only")
VALID_ROLES: Tuple[str, ...] = ("triage", "fixer", "planner", "deep_analyst", "copilot")


def canonical_gemini_model() -> str:
    """Return the unified Gemini model ID, honoring explicit ``GEMINI_MODEL`` override."""
    override = (os.getenv("GEMINI_MODEL") or "").strip()
    return override or DEFAULT_GEMINI_MODEL


class ModelEntry(BaseModel):
    """Single model definition in ``model_manifest.json``."""

    model_config = ConfigDict(extra="allow")

    id: str
    alias: str = ""
    role: str = ""
    parameters: str = ""
    context_window: int = Field(default=8192, ge=512)
    max_output_tokens: int = Field(default=4096, ge=128)
    requires_gpu: bool = True
    min_vram_mb: int = Field(default=0, ge=0)
    responsibilities: List[str] = Field(default_factory=list)


class HardwareProfileConfig(BaseModel):
    """Hardware-tier execution limits and preferred local models."""

    model_config = ConfigDict(extra="allow")

    name: HardwareProfileName
    min_vram_mb: int = Field(default=0, ge=0)
    max_loaded_models: int = Field(default=1, ge=0)
    default_num_ctx: int = Field(default=8192, ge=1024)
    keep_alive_seconds: int = Field(default=0, ge=0)
    prefer_cloud_fallback: bool = False
    vram_pressure_unload_pct: float = Field(default=85.0, ge=50.0, le=99.0)
    role_models: Dict[str, str] = Field(default_factory=dict)


class RoleAssignment(BaseModel):
    """Per-role inference tuning adapted from PentAGI ``pconfig.AgentConfig``."""

    model_config = ConfigDict(extra="allow")

    role: AgentRoleName
    local_model: str
    cloud_provider: str = "gemini"
    cloud_model: str = DEFAULT_GEMINI_MODEL
    temperature: float = Field(default=0.2, ge=0.0, le=2.0)
    max_tokens: int = Field(default=4096, ge=128)
    context_window: int = Field(default=8192, ge=1024)
    uses_tools: bool = True
    priority: Literal["interactive", "background"] = "background"

    @field_validator("local_model", "cloud_model")
    @classmethod
    def _non_empty_model(cls, value: str) -> str:
        clean = value.strip()
        if not clean:
            raise ValueError("model name must not be empty")
        return clean


class ProviderDefaultEntry(BaseModel):
    """Canonical default model & model list for a cloud provider."""

    model_config = ConfigDict(extra="allow")

    default_model: str
    models: List[str] = Field(default_factory=list)
    context_window: int = Field(default=128000, ge=1024)


def default_provider_defaults() -> Dict[str, ProviderDefaultEntry]:
    return {
        "nvidia": ProviderDefaultEntry(
            default_model="nvidia/nemotron-3-ultra-550b-a55b",
            models=[
                "nvidia/nemotron-3-ultra-550b-a55b",
                "nvidia/nemotron-3-super-120b-a12b",
            ],
            context_window=131072,
        ),
        "gemini": ProviderDefaultEntry(
            default_model=DEFAULT_GEMINI_MODEL,
            models=list(GEMINI_MODELS),
            context_window=1048576,
        ),
        "deepseek": ProviderDefaultEntry(
            default_model="deepseek-chat",
            models=["deepseek-chat", "deepseek-reasoner"],
            context_window=131072,
        ),
        "anthropic": ProviderDefaultEntry(
            default_model="claude-3-5-sonnet-20241022",
            models=["claude-3-5-sonnet-20241022", "claude-3-5-haiku-20241022"],
            context_window=200000,
        ),
        "openai": ProviderDefaultEntry(
            default_model="gpt-4o",
            models=["gpt-4o", "gpt-4o-mini", "o3-mini"],
            context_window=128000,
        ),
        "groq": ProviderDefaultEntry(
            default_model="llama-3.3-70b-versatile",
            models=["llama-3.3-70b-versatile"],
            context_window=131072,
        ),
        "openrouter": ProviderDefaultEntry(
            default_model="anthropic/claude-3.5-sonnet",
            models=["anthropic/claude-3.5-sonnet", "google/gemini-2.5-flash"],
            context_window=200000,
        ),
        "taskade": ProviderDefaultEntry(
            default_model="taskade-ai",
            models=["taskade-ai"],
            context_window=32768,
        ),
    }


def default_hardware_profiles() -> Dict[str, HardwareProfileConfig]:
    return {
        "auto": HardwareProfileConfig(
            name="auto",
            min_vram_mb=0,
            max_loaded_models=1,
            default_num_ctx=8192,
            keep_alive_seconds=120,
            prefer_cloud_fallback=False,
            vram_pressure_unload_pct=85.0,
            role_models={},
        ),
        "cpu_only": HardwareProfileConfig(
            name="cpu_only",
            min_vram_mb=0,
            max_loaded_models=1,
            default_num_ctx=4096,
            keep_alive_seconds=0,
            prefer_cloud_fallback=True,
            vram_pressure_unload_pct=80.0,
            role_models={
                "triage": "xploiter/pentester:latest",
                "fixer": "qwen2.5-coder:3b",
                "planner": "xploiter/pentester:latest",
                "deep_analyst": "xploiter/pentester:latest",
                "copilot": "qwen2.5-coder:3b",
            },
        ),
        "4GB": HardwareProfileConfig(
            name="4GB",
            min_vram_mb=3500,
            max_loaded_models=1,
            default_num_ctx=4096,
            keep_alive_seconds=0,
            prefer_cloud_fallback=False,
            vram_pressure_unload_pct=82.0,
            role_models={
                "triage": "xploiter/pentester:latest",
                "fixer": "qwen2.5-coder:3b",
                "planner": "xploiter/pentester:latest",
                "deep_analyst": "xploiter/pentester:latest",
                "copilot": "qwen2.5-coder:3b",
            },
        ),
        "8GB": HardwareProfileConfig(
            name="8GB",
            min_vram_mb=7000,
            max_loaded_models=1,
            default_num_ctx=8192,
            keep_alive_seconds=120,
            prefer_cloud_fallback=False,
            vram_pressure_unload_pct=85.0,
            role_models={
                "triage": "xploiter/pentester:latest",
                "fixer": "qwen2.5-coder:7b",
                "planner": "qwen3:8b",
                "deep_analyst": "WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B:latest",
                "copilot": "qwen3:8b",
            },
        ),
        "16GB+": HardwareProfileConfig(
            name="16GB+",
            min_vram_mb=14000,
            max_loaded_models=1,
            default_num_ctx=16384,
            keep_alive_seconds=300,
            prefer_cloud_fallback=False,
            vram_pressure_unload_pct=88.0,
            role_models={
                "triage": "xploiter/pentester:latest",
                "fixer": "qwen2.5-coder:14b",
                "planner": "qwen3:8b",
                "deep_analyst": "WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B:latest",
                "copilot": "qwen2.5-coder:14b",
            },
        ),
    }


def default_role_assignments() -> Dict[str, RoleAssignment]:
    return {
        "triage": RoleAssignment(
            role="triage",
            local_model="xploiter/pentester:latest",
            cloud_provider="gemini",
            cloud_model=DEFAULT_GEMINI_MODEL,
            temperature=0.15,
            max_tokens=2048,
            context_window=8192,
            uses_tools=False,
            priority="background",
        ),
        "fixer": RoleAssignment(
            role="fixer",
            local_model="qwen2.5-coder:14b",
            cloud_provider="gemini",
            cloud_model=DEFAULT_GEMINI_MODEL,
            temperature=0.1,
            max_tokens=4096,
            context_window=16384,
            uses_tools=True,
            priority="background",
        ),
        "planner": RoleAssignment(
            role="planner",
            local_model="qwen3:8b",
            cloud_provider="gemini",
            cloud_model=DEFAULT_GEMINI_MODEL,
            temperature=0.2,
            max_tokens=4096,
            context_window=16384,
            uses_tools=True,
            priority="background",
        ),
        "deep_analyst": RoleAssignment(
            role="deep_analyst",
            local_model="WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B:latest",
            cloud_provider="gemini",
            cloud_model="gemini-2.5-pro",
            temperature=0.2,
            max_tokens=8192,
            context_window=32768,
            uses_tools=True,
            priority="background",
        ),
        "copilot": RoleAssignment(
            role="copilot",
            local_model="qwen2.5-coder:14b",
            cloud_provider="gemini",
            cloud_model=DEFAULT_GEMINI_MODEL,
            temperature=0.3,
            max_tokens=4096,
            context_window=16384,
            uses_tools=True,
            priority="interactive",
        ),
    }


class ModelManifest(BaseModel):
    """Canonical platform model manifest with hardware profiles & role configs."""

    model_config = ConfigDict(extra="allow")

    manifest_version: str = "2.0.0"
    inference_backend: str = "ollama"
    default_host: str = "http://127.0.0.1:11434"
    active_hardware_profile: HardwareProfileName = "auto"
    provider_defaults: Dict[str, ProviderDefaultEntry] = Field(default_factory=default_provider_defaults)
    hardware_profiles: Dict[str, HardwareProfileConfig] = Field(default_factory=default_hardware_profiles)
    roles: Dict[str, RoleAssignment] = Field(default_factory=default_role_assignments)
    models: List[ModelEntry] = Field(default_factory=list)

    @property
    def effective_ollama_host(self) -> str:
        from models.ollama_manager import normalize_ollama_host

        return normalize_ollama_host(os.getenv("OLLAMA_HOST") or self.default_host)

    def get_default_model(self, provider_id: str) -> str:
        """Return canonical default model for *provider_id*, honoring env overrides."""
        pid = (provider_id or "").strip().lower()
        env_override = (os.getenv(f"{pid.upper()}_MODEL") or "").strip()
        if env_override:
            return env_override
        entry = self.provider_defaults.get(pid)
        if entry:
            return entry.default_model
        if pid == "gemini":
            return DEFAULT_GEMINI_MODEL
        return ""

    def get_provider_models(self, provider_id: str) -> Tuple[str, ...]:
        pid = (provider_id or "").strip().lower()
        entry = self.provider_defaults.get(pid)
        if not entry:
            return ()
        ordered: List[str] = []
        default_m = self.get_default_model(pid)
        if default_m:
            ordered.append(default_m)
        for m in entry.models:
            if m not in ordered:
                ordered.append(m)
        return tuple(ordered)

    def resolve_hardware_profile(
        self,
        *,
        requested_profile: Optional[str] = None,
        vram_total_mb: Optional[int] = None,
        gpu_available: Optional[bool] = None,
    ) -> HardwareProfileConfig:
        """Resolve concrete hardware profile (evaluating ``auto`` against real VRAM)."""
        raw = (
            requested_profile
            or os.getenv("HUNTER_HARDWARE_PROFILE")
            or self.active_hardware_profile
            or "auto"
        ).strip()
        if raw in self.hardware_profiles and raw != "auto":
            return self.hardware_profiles[raw]

        # Auto-select based on real detected GPU/VRAM
        if gpu_available is False or vram_total_mb is None or vram_total_mb <= 0:
            return self.hardware_profiles.get("cpu_only", default_hardware_profiles()["cpu_only"])
        if vram_total_mb >= 14000:
            return self.hardware_profiles.get("16GB+", default_hardware_profiles()["16GB+"])
        if vram_total_mb >= 7000:
            return self.hardware_profiles.get("8GB", default_hardware_profiles()["8GB"])
        if vram_total_mb >= 3500:
            return self.hardware_profiles.get("4GB", default_hardware_profiles()["4GB"])
        return self.hardware_profiles.get("cpu_only", default_hardware_profiles()["cpu_only"])

    def get_role_config(
        self,
        role: str,
        *,
        profile: Optional[HardwareProfileConfig] = None,
    ) -> RoleAssignment:
        """Return effective role assignment, applying hardware-profile local model override."""
        role_key = (role or "copilot").strip().lower()
        base = self.roles.get(role_key) or default_role_assignments().get(
            role_key,
            default_role_assignments()["copilot"],
        )
        if profile is None:
            return base
        override_local = profile.role_models.get(role_key)
        ctx = min(base.context_window, profile.default_num_ctx) if profile.default_num_ctx else base.context_window
        return base.model_copy(
            update={
                "local_model": override_local or base.local_model,
                "context_window": max(1024, ctx),
            }
        )

    def context_window_for(self, model_name: str, default: int = 8192) -> int:
        target = (model_name or "").strip().lower()
        for entry in self.models:
            if target and (
                entry.id.lower() == target
                or (entry.alias and entry.alias.lower() == target)
                or target in entry.id.lower()
            ):
                return entry.context_window
        for entry in self.provider_defaults.values():
            if target == entry.default_model.lower() or any(target == m.lower() for m in entry.models):
                return entry.context_window
        return default

    @classmethod
    def load(cls, path: Optional[str | Path] = None) -> "ModelManifest":
        target = Path(path) if path is not None else DEFAULT_MANIFEST_PATH
        if not target.is_file():
            logger.debug("[ModelManifest] %s not found; using built-in defaults", target)
            return cls()
        try:
            raw = json.loads(target.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                return cls()
            # Merge defaults so partial legacy manifests upgrade seamlessly
            merged = cls().model_dump()
            for key in ("manifest_version", "inference_backend", "default_host", "active_hardware_profile", "models"):
                if key in raw:
                    merged[key] = raw[key]
            for map_key in ("provider_defaults", "hardware_profiles", "roles"):
                if isinstance(raw.get(map_key), dict):
                    merged[map_key].update(raw[map_key])
            return cls.model_validate(merged)
        except Exception as exc:  # noqa: BLE001
            logger.warning("[ModelManifest] Failed parsing %s (%s); using defaults", target, exc)
            return cls()


_manifest_cache: Optional[Tuple[Path, float, ModelManifest]] = None


def get_model_manifest(path: Optional[str | Path] = None, *, force_reload: bool = False) -> ModelManifest:
    """Return cached ``ModelManifest`` (auto-reloaded if file mtime changes)."""
    global _manifest_cache
    target = Path(path) if path is not None else DEFAULT_MANIFEST_PATH
    try:
        mtime = target.stat().st_mtime if target.is_file() else -1.0
    except OSError:
        mtime = -1.0
    if (
        not force_reload
        and _manifest_cache is not None
        and _manifest_cache[0] == target
        and _manifest_cache[1] == mtime
    ):
        return _manifest_cache[2]
    loaded = ModelManifest.load(target)
    _manifest_cache = (target, mtime, loaded)
    return loaded


__all__ = [
    "AgentRoleName",
    "DEFAULT_GEMINI_MODEL",
    "DEFAULT_MANIFEST_PATH",
    "GEMINI_MODELS",
    "HardwareProfileConfig",
    "HardwareProfileName",
    "ModelEntry",
    "ModelManifest",
    "ProviderDefaultEntry",
    "RoleAssignment",
    "VALID_HARDWARE_PROFILES",
    "VALID_ROLES",
    "canonical_gemini_model",
    "default_hardware_profiles",
    "default_provider_defaults",
    "default_role_assignments",
    "get_model_manifest",
]
