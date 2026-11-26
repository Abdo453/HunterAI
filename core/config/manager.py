"""Unified Configuration Manager for HunterAI.

Consolidates configuration from:
1. Environment variables (``.env`` and ``os.environ``) — highest precedence
2. Signed authorization policy (``permissions.json`` + verified HMAC grant)
3. Settings store (``data/control_settings.json`` and optional ``PlatformStore``)
4. Explicit declarative assessment file (``hunter.yaml``)
5. Safe platform defaults — lowest precedence

Precedence order:
    ``env > signed policy > settings store > hunter.yaml > defaults``

Secrets are masked on export/snapshot and settings writes use crash-safe atomic
file replacement via ``core.persist.atomic_file``.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

import yaml

from core.persist.atomic_file import atomic_write_json
from core.policy.red_team import AuthorizationGrant, ForbiddenAction, Profile, load_grant
from core.secret_sanitizer import SecretSanitizer

logger = logging.getLogger("hunter_ai.config.manager")

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent

DEFAULT_SETTINGS: Dict[str, Any] = {
    "upstream_proxy": "",
    "burp_agent_port": 8085,
    "max_concurrent_agents": 5,
    "safe_boundaries_enforced": True,
    "llm_policy": "balanced",
    "default_provider": "ollama",
    "default_model": "qwen2.5:14b",
    "ollama_host": "http://127.0.0.1:11434",
    "artex_url": "http://127.0.0.1:7071",
    "web_port": 8000,
    "rate_limit_rps": 10.0,
    "max_runtime_minutes": 30,
    "max_requests": 5000,
    "profile": "standard",
    "mode": "passive",
    "high_risk_approval": "manual",
    "debug": False,
}

# Mapping from canonical config key -> (env_var_name, caster)
_ENV_KEY_MAP: Dict[str, Tuple[str, type]] = {
    "upstream_proxy": ("HUNTER_UPSTREAM_PROXY", str),
    "burp_agent_port": ("HUNTER_BURP_AGENT_PORT", int),
    "max_concurrent_agents": ("HUNTER_MAX_CONCURRENT_AGENTS", int),
    "safe_boundaries_enforced": ("HUNTER_SAFE_BOUNDARIES", bool),
    "llm_policy": ("HUNTER_LLM_POLICY", str),
    "default_provider": ("HUNTER_DEFAULT_PROVIDER", str),
    "default_model": ("HUNTER_DEFAULT_MODEL", str),
    "ollama_host": ("OLLAMA_HOST", str),
    "artex_url": ("HUNTERAI_ARTEX_URL", str),
    "web_port": ("WEB_PORT", int),
    "rate_limit_rps": ("HUNTER_RATE_LIMIT_RPS", float),
    "max_runtime_minutes": ("HUNTER_MAX_RUNTIME_MINUTES", int),
    "max_requests": ("HUNTER_MAX_REQUESTS", int),
    "profile": ("HUNTER_POLICY_PROFILE", str),
    "mode": ("HUNTER_ASSESSMENT_MODE", str),
    "high_risk_approval": ("HUNTER_HIGH_RISK_APPROVAL", str),
    "debug": ("DEBUG", bool),
}

_SECRET_MARKERS = ("key", "secret", "token", "password", "passwd", "auth", "cookie")


def _parse_bool(raw: Any) -> bool:
    if isinstance(raw, bool):
        return raw
    return str(raw).strip().lower() in {"1", "true", "yes", "on"}


def _cast_env_value(raw: str, target_type: type) -> Any:
    text = raw.strip()
    if target_type is bool:
        return _parse_bool(text)
    if target_type is int:
        return int(text)
    if target_type is float:
        return float(text)
    return text


def _parse_dotenv_file(path: Path) -> Dict[str, str]:
    """Parse a ``.env`` file safely without mutating global ``os.environ``."""
    out: Dict[str, str] = {}
    if not path.is_file():
        return out
    try:
        for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            if line.startswith("export "):
                line = line[7:].strip()
            key, val = line.split("=", 1)
            k = key.strip()
            v = val.strip()
            if len(v) >= 2 and v[0] == v[-1] and v[0] in {"'", '"'}:
                v = v[1:-1]
            if k:
                out[k] = v
    except OSError as exc:
        logger.warning("Failed reading .env file %s: %s", path, exc)
    return out


@dataclass(frozen=True)
class ResolvedConfigValue:
    key: str
    value: Any
    source: str  # "env" | "dotenv" | "signed_policy" | "settings_store" | "hunter_yaml" | "default"


class ConfigManager:
    """Single source of truth unifying env, signed policy, settings store, and hunter.yaml."""

    def __init__(
        self,
        *,
        base_dir: Optional[str | Path] = None,
        env_path: Optional[str | Path] = None,
        settings_path: Optional[str | Path] = None,
        permissions_path: Optional[str | Path] = None,
        hunter_yaml_path: Optional[str | Path] = None,
        grant_path: Optional[str | Path] = None,
        policy_secret: Optional[bytes] = None,
        environ: Optional[Mapping[str, str]] = None,
    ) -> None:
        self.base_dir = Path(base_dir) if base_dir is not None else _REPO_ROOT
        self.env_path = Path(env_path) if env_path is not None else (self.base_dir / ".env")
        self.settings_path = (
            Path(settings_path)
            if settings_path is not None
            else (self.base_dir / "data" / "control_settings.json")
        )
        self.permissions_path = (
            Path(permissions_path)
            if permissions_path is not None
            else (self.base_dir / "permissions.json")
        )
        self.hunter_yaml_path = (
            Path(hunter_yaml_path)
            if hunter_yaml_path is not None
            else (self.base_dir / "hunter.yaml")
        )
        self.grant_path = (
            Path(grant_path)
            if grant_path is not None
            else (self.base_dir / "data" / "root_controller" / "grant.json")
        )
        self._explicit_policy_secret = policy_secret
        self._environ_override = environ
        self._lock = threading.RLock()

        self._dotenv: Dict[str, str] = {}
        self._settings_store: Dict[str, Any] = {}
        self._permissions: Dict[str, Any] = {}
        self._hunter_yaml: Dict[str, Any] = {}
        self._signed_grant: Optional[AuthorizationGrant] = None
        self._signed_grant_valid: bool = False
        self._signed_policy_overrides: Dict[str, Any] = {}
        self.reload()

    def _effective_environ(self) -> Mapping[str, str]:
        return self._environ_override if self._environ_override is not None else os.environ

    def _resolve_policy_secret(self) -> Optional[bytes]:
        if self._explicit_policy_secret:
            return self._explicit_policy_secret
        env = self._effective_environ()
        raw = (env.get("HUNTERAI_POLICY_SECRET") or self._dotenv.get("HUNTERAI_POLICY_SECRET") or "").strip()
        if raw:
            return raw.encode("utf-8")
        secret_file = self.grant_path.parent / ".policy_secret"
        if secret_file.is_file():
            try:
                content = secret_file.read_text(encoding="utf-8").strip()
                if content:
                    return content.encode("utf-8")
            except OSError as exc:
                logger.warning("Unable to read policy secret file %s: %s", secret_file, exc)
        return None

    def reload(self) -> None:
        """Reload all backing config sources from disk and environment."""
        with self._lock:
            self._dotenv = _parse_dotenv_file(self.env_path)
            self._settings_store = self._load_json_dict(self.settings_path)
            self._permissions = self._load_json_dict(self.permissions_path)
            self._hunter_yaml = self._load_hunter_yaml(self.hunter_yaml_path)
            self._signed_grant, self._signed_grant_valid, self._signed_policy_overrides = (
                self._load_signed_policy()
            )

    @staticmethod
    def _load_json_dict(path: Path) -> Dict[str, Any]:
        if not path.is_file():
            return {}
        try:
            parsed = json.loads(path.read_text(encoding="utf-8"))
            return parsed if isinstance(parsed, dict) else {}
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("Failed loading JSON config %s: %s", path, exc)
            return {}

    @staticmethod
    def _load_hunter_yaml(path: Path) -> Dict[str, Any]:
        if not path.is_file():
            return {}
        try:
            raw = path.read_text(encoding="utf-8")
            parsed = yaml.safe_load(raw)
            if not isinstance(parsed, dict):
                return {}
            # Normalize known declarative fields cleanly
            scope_raw = parsed.get("scope") if isinstance(parsed.get("scope"), dict) else {}
            limits_raw = parsed.get("limits") if isinstance(parsed.get("limits"), dict) else {}
            approval_raw = parsed.get("approval") if isinstance(parsed.get("approval"), dict) else {}
            normalized: Dict[str, Any] = {
                "target": str(parsed.get("target") or "").strip(),
                "assessment_profile": str(parsed.get("profile") or "generic_web").strip(),
                "mode": str(parsed.get("mode") or "passive").strip().lower(),
                "scope": {
                    "allow": [str(x).strip() for x in (scope_raw.get("allow") or []) if str(x).strip()],
                    "deny": [str(x).strip() for x in (scope_raw.get("deny") or []) if str(x).strip()],
                    "excluded_paths": [
                        str(x).strip() for x in (scope_raw.get("excluded_paths") or []) if str(x).strip()
                    ],
                },
                "limits": {
                    "requests_per_second": float(limits_raw.get("requests_per_second", 2.0)),
                    "max_runtime_minutes": int(limits_raw.get("max_runtime_minutes", 30)),
                    "max_requests": int(limits_raw.get("max_requests", 5000)),
                },
                "approval": {
                    "high_risk_actions": str(approval_raw.get("high_risk_actions") or "manual").strip().lower(),
                },
            }
            return normalized
        except (OSError, yaml.YAMLError, ValueError, TypeError) as exc:
            logger.warning("Failed parsing hunter.yaml at %s: %s", path, exc)
            return {}

    def _load_signed_policy(self) -> Tuple[Optional[AuthorizationGrant], bool, Dict[str, Any]]:
        overrides: Dict[str, Any] = {}
        # Static fail-closed defaults from permissions.json
        if self._permissions.get("fail_closed") is True:
            overrides["safe_boundaries_enforced"] = True

        if not self.grant_path.is_file():
            return None, False, overrides

        try:
            grant = load_grant(str(self.grant_path))
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            logger.warning("Failed reading authorization grant %s: %s", self.grant_path, exc)
            return None, False, overrides

        secret = self._resolve_policy_secret()
        valid = bool(secret and grant.verify(secret) and grant.active_at(time.time()))
        if valid:
            if grant.allows_profile(Profile.RED_TEAM):
                overrides["profile"] = Profile.RED_TEAM.value
            elif grant.allows_profile(Profile.STANDARD):
                overrides["profile"] = Profile.STANDARD.value
            else:
                overrides["profile"] = Profile.SAFE.value
            overrides["authorized_scope"] = [s.value for s in grant.scope]
            overrides["grant_id"] = grant.grant_id
        return grant, valid, overrides

    def _yaml_value(self, key: str) -> Tuple[bool, Any]:
        if not self._hunter_yaml:
            return False, None
        if key == "mode" and self._hunter_yaml.get("mode"):
            return True, self._hunter_yaml["mode"]
        if key == "rate_limit_rps":
            limits = self._hunter_yaml.get("limits") or {}
            if "requests_per_second" in limits:
                return True, float(limits["requests_per_second"])
        if key == "max_runtime_minutes":
            limits = self._hunter_yaml.get("limits") or {}
            if "max_runtime_minutes" in limits:
                return True, int(limits["max_runtime_minutes"])
        if key == "max_requests":
            limits = self._hunter_yaml.get("limits") or {}
            if "max_requests" in limits:
                return True, int(limits["max_requests"])
        if key == "high_risk_approval":
            appr = self._hunter_yaml.get("approval") or {}
            if "high_risk_actions" in appr:
                return True, str(appr["high_risk_actions"])
        if key in self._hunter_yaml:
            return True, self._hunter_yaml[key]
        return False, None

    def resolve_with_source(self, key: str, default: Any = None) -> ResolvedConfigValue:
        """Resolve *key* according to ``env > signed policy > settings store > hunter.yaml > defaults``."""
        with self._lock:
            env = self._effective_environ()
            env_spec = _ENV_KEY_MAP.get(key)
            if env_spec is not None:
                env_name, caster = env_spec
                if env_name in env and str(env[env_name]).strip() != "":
                    return ResolvedConfigValue(key, _cast_env_value(env[env_name], caster), "env")
                if env_name in self._dotenv and self._dotenv[env_name].strip() != "":
                    return ResolvedConfigValue(key, _cast_env_value(self._dotenv[env_name], caster), "dotenv")
            else:
                upper = key.upper()
                if upper in env and str(env[upper]).strip() != "":
                    return ResolvedConfigValue(key, env[upper], "env")
                if upper in self._dotenv and self._dotenv[upper].strip() != "":
                    return ResolvedConfigValue(key, self._dotenv[upper], "dotenv")

            if key in self._signed_policy_overrides:
                return ResolvedConfigValue(key, self._signed_policy_overrides[key], "signed_policy")

            if key in self._settings_store and self._settings_store[key] is not None:
                return ResolvedConfigValue(key, self._settings_store[key], "settings_store")

            found_yaml, yaml_val = self._yaml_value(key)
            if found_yaml:
                return ResolvedConfigValue(key, yaml_val, "hunter_yaml")

            if key in DEFAULT_SETTINGS:
                return ResolvedConfigValue(key, DEFAULT_SETTINGS[key], "default")
            return ResolvedConfigValue(key, default, "default")

    def get(self, key: str, default: Any = None) -> Any:
        return self.resolve_with_source(key, default=default).value

    def get_int(self, key: str, default: int = 0) -> int:
        val = self.get(key, default)
        try:
            return int(val)
        except (TypeError, ValueError):
            return default

    def get_float(self, key: str, default: float = 0.0) -> float:
        val = self.get(key, default)
        try:
            return float(val)
        except (TypeError, ValueError):
            return default

    def get_bool(self, key: str, default: bool = False) -> bool:
        val = self.get(key, default)
        if val is None:
            return default
        return _parse_bool(val)

    def get_assessment_config(self) -> Dict[str, Any]:
        """Return explicit parsed ``hunter.yaml`` declarative assessment configuration."""
        with self._lock:
            return json.loads(json.dumps(self._hunter_yaml))

    def get_permissions_policy(self) -> Dict[str, Any]:
        """Return parsed ``permissions.json`` capability and invariant specification."""
        with self._lock:
            return json.loads(json.dumps(self._permissions))

    def get_hard_invariants(self) -> List[Dict[str, str]]:
        """Return non-overridable hard invariants from ``permissions.json`` / ``ForbiddenAction``."""
        with self._lock:
            hi = self._permissions.get("hard_invariants") if isinstance(self._permissions, dict) else None
            if isinstance(hi, dict) and isinstance(hi.get("denied"), list):
                examples = hi.get("examples") if isinstance(hi.get("examples"), dict) else {}
                return [
                    {
                        "action": str(act).upper(),
                        "desc": str(examples.get(act) or f"Never authorized: {act}"),
                    }
                    for act in hi["denied"]
                ]
            return [
                {"action": fa.value.upper(), "desc": f"Never authorized in any profile: {fa.value}"}
                for fa in ForbiddenAction
            ]

    def get_signed_grant(self) -> Tuple[Optional[AuthorizationGrant], bool]:
        with self._lock:
            return self._signed_grant, self._signed_grant_valid

    def update_settings(self, updates: Dict[str, Any]) -> Dict[str, Any]:
        """Atomically persist settings into ``control_settings.json`` and refresh in-memory state."""
        with self._lock:
            merged = dict(self._settings_store)
            for k, v in updates.items():
                if v is not None:
                    merged[str(k)] = v
            atomic_write_json(self.settings_path, merged)
            self._settings_store = merged
            return self.resolved_settings()

    def resolved_settings(self) -> Dict[str, Any]:
        """Return all canonical keys resolved with full precedence."""
        with self._lock:
            keys = set(DEFAULT_SETTINGS.keys()) | set(self._settings_store.keys())
            return {k: self.resolve_with_source(k).value for k in sorted(keys)}

    def snapshot(self, *, redact_secrets: bool = True) -> Dict[str, Any]:
        """Return an inspectable configuration snapshot with source provenance and optional secret masking."""
        with self._lock:
            keys = sorted(
                set(DEFAULT_SETTINGS.keys())
                | set(self._settings_store.keys())
                | set(self._signed_policy_overrides.keys())
            )
            values: Dict[str, Any] = {}
            sources: Dict[str, str] = {}
            for k in keys:
                res = self.resolve_with_source(k)
                val = res.value
                if redact_secrets and isinstance(val, str) and any(m in k.lower() for m in _SECRET_MARKERS):
                    val = SecretSanitizer.mask_string(val, prefix_len=3, suffix_len=2) if val else ""
                values[k] = val
                sources[k] = res.source
            return {
                "values": values,
                "sources": sources,
                "hunter_yaml": self.get_assessment_config(),
                "signed_grant_active": self._signed_grant_valid,
                "permissions_fail_closed": bool(self._permissions.get("fail_closed", True)),
            }


_GLOBAL_CONFIG_MANAGER: Optional[ConfigManager] = None
_CONFIG_LOCK = threading.Lock()


def get_config_manager(*, reload: bool = False) -> ConfigManager:
    """Return process-wide singleton ``ConfigManager``."""
    global _GLOBAL_CONFIG_MANAGER
    with _CONFIG_LOCK:
        if _GLOBAL_CONFIG_MANAGER is None:
            _GLOBAL_CONFIG_MANAGER = ConfigManager()
        elif reload:
            _GLOBAL_CONFIG_MANAGER.reload()
        return _GLOBAL_CONFIG_MANAGER
