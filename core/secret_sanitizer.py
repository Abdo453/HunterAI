"""
Secret Sanitizer & Credential Masking Engine
Prevents leakage of sensitive credentials, API keys, JWTs, cookies, PEM keys,
and configured runtime secrets in raw logs, reports, disk persistence, and
cloud-egress boundaries while leaving operational in-memory values untouched.
"""
from __future__ import annotations

import os
import re
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple


_COOKIE_ATTR_NAMES: Set[str] = {
    "path",
    "domain",
    "expires",
    "max-age",
    "samesite",
    "priority",
    "httponly",
    "secure",
    "partitioned",
}

_SENSITIVE_HEADER_KEYS: Set[str] = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-hunter-token",
    "x-goog-api-key",
    "x-session-token",
    "api-key",
}

_CONFIGURED_SECRET_ENV_SUFFIXES: Tuple[str, ...] = (
    "_API_KEY",
    "_SECRET",
    "_SECRET_KEY",
    "_ACCESS_TOKEN",
    "_AUTH_TOKEN",
    "_PASSWORD",
    "_PRIVATE_KEY",
)

_CONFIGURED_SECRET_ENV_EXACT: Set[str] = {
    "GITHUB_TOKEN",
    "HUNTER_API_TOKEN",
    "ARTEX_API_TOKEN",
    "HUNTERAI_POLICY_SECRET",
    "HUNTER_A2A_SECRET",
    "GEMINI_API_KEY",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "NVIDIA_API_KEY",
    "DEEPSEEK_API_KEY",
    "GROQ_API_KEY",
    "OPENROUTER_API_KEY",
    "TASKADE_API_KEY",
}


class SecretSanitizer:
    """
    Scrubs and masks sensitive tokens across text, JSON structures, and reports.
    Preserves verifiable prefixes/suffixes where helpful while protecting
    confidential payloads. Never mutates caller-owned objects in place.
    Example: sk_live_1234567890abcdef -> sk_live_••••••••cdef
    """

    MASK_BULLET = "••••••••"
    _registered_secrets: Set[str] = set()

    @classmethod
    def register_secret(cls, secret: str) -> None:
        """Register an explicit runtime/configured secret literal for scrubbing."""
        if isinstance(secret, str):
            val = secret.strip()
            if len(val) >= 8:
                cls._registered_secrets.add(val)

    @classmethod
    def clear_registered_secrets(cls) -> None:
        """Clear dynamically registered secret literals (used in tests/session reset)."""
        cls._registered_secrets.clear()

    @classmethod
    def _collect_configured_secrets(cls, extra_secrets: Optional[Iterable[str]] = None) -> List[str]:
        """Collect configured secret literals from registered values, extras, and env."""
        literals: Set[str] = set(cls._registered_secrets)
        if extra_secrets:
            for item in extra_secrets:
                if isinstance(item, str) and len(item.strip()) >= 8:
                    literals.add(item.strip())
        for env_key, env_val in os.environ.items():
            if not env_val:
                continue
            upper_key = env_key.upper()
            if upper_key in _CONFIGURED_SECRET_ENV_EXACT or upper_key.endswith(_CONFIGURED_SECRET_ENV_SUFFIXES):
                cleaned = env_val.strip()
                if len(cleaned) >= 8:
                    literals.add(cleaned)
        # Replace longest secrets first to prevent partial-substring collisions
        return sorted(literals, key=len, reverse=True)

    @classmethod
    def _mask_cookie_header_value(cls, raw_value: str) -> str:
        """Mask cookie values inside a Cookie or Set-Cookie header value."""
        parts = raw_value.split(";")
        masked_parts: List[str] = []
        for part in parts:
            stripped = part.strip()
            if not stripped:
                continue
            if "=" in stripped:
                k, _, v = stripped.partition("=")
                k_clean = k.strip()
                if k_clean.lower() in _COOKIE_ATTR_NAMES:
                    masked_parts.append(f"{k_clean}={v.strip()}")
                else:
                    masked_parts.append(f"{k_clean}={cls.MASK_BULLET}")
            else:
                masked_parts.append(stripped)
        return "; ".join(masked_parts)

    @classmethod
    def mask_string(cls, secret_str: str, prefix_len: int = 4, suffix_len: int = 4) -> str:
        """Masks a generic sensitive string leaving only small prefix and suffix"""
        if not secret_str:
            return ""
        if len(secret_str) <= prefix_len + suffix_len:
            return cls.MASK_BULLET
        return f"{secret_str[:prefix_len]}{cls.MASK_BULLET}{secret_str[-suffix_len:]}"

    @classmethod
    def sanitize_text(cls, text: str, extra_secrets: Optional[Iterable[str]] = None) -> str:
        """Applies regex and configured-literal masking to sensitive tokens within text."""
        if not text or not isinstance(text, str):
            return text

        scrubbed = text

        # 0. Dynamic configured-secret literals (env + explicitly registered secrets)
        for literal in cls._collect_configured_secrets(extra_secrets=extra_secrets):
            if literal in scrubbed:
                scrubbed = scrubbed.replace(literal, cls.MASK_BULLET)

        # 1. PEM Private Keys (RSA, EC, DSA, OPENSSH, PGP, PKCS8)
        scrubbed = re.sub(
            r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----",
            f"-----BEGIN PRIVATE KEY-----\n{cls.MASK_BULLET}[REDACTED_PEM_KEY]\n-----END PRIVATE KEY-----",
            scrubbed,
        )

        # 2. AWS Access Keys
        scrubbed = re.sub(
            r"\b((?:AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{4})[A-Z0-9]{8}([A-Z0-9]{4})\b",
            r"\1" + cls.MASK_BULLET + r"\2",
            scrubbed,
        )

        # 3. Stripe & payment keys
        scrubbed = re.sub(
            r"\b((?:sk|pk|rk)_(?:live|test)_[a-zA-Z0-9]{4})[a-zA-Z0-9]{12,}([a-zA-Z0-9]{4})\b",
            r"\1" + cls.MASK_BULLET + r"\2",
            scrubbed,
        )

        # 4. OpenAI / Anthropic sk-* keys
        scrubbed = re.sub(
            r"\b(sk-(?:proj-|svcacct-|ant-api\d*-|ant-)?[A-Za-z0-9]{3})[A-Za-z0-9_\-]{12,}([A-Za-z0-9]{4})\b",
            r"\1" + cls.MASK_BULLET + r"\2",
            scrubbed,
        )

        # 5. NVIDIA NIM keys (nvapi-*)
        scrubbed = re.sub(
            r"\b(nvapi-[A-Za-z0-9_\-]{4})[A-Za-z0-9_\-]{12,}([A-Za-z0-9_\-]{4})\b",
            r"\1" + cls.MASK_BULLET + r"\2",
            scrubbed,
        )

        # 6. Google API keys (AIza*)
        scrubbed = re.sub(
            r"\b(AIza[0-9A-Za-z_\-]{4})[0-9A-Za-z_\-]{18,}([0-9A-Za-z_\-]{4})\b",
            r"\1" + cls.MASK_BULLET + r"\2",
            scrubbed,
        )

        # 7. Slack tokens (xoxb/xoxp/xoxa/xoxr/xoxs/xapp)
        scrubbed = re.sub(
            r"\b((?:xox[baprs]|xapp)-[A-Za-z0-9\-]{4})[A-Za-z0-9\-]{8,}([A-Za-z0-9]{4})\b",
            r"\1" + cls.MASK_BULLET + r"\2",
            scrubbed,
        )

        # 8. GitHub personal / fine-grained access tokens
        scrubbed = re.sub(
            r"\b((?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{4})[a-zA-Z0-9]{24,}([a-zA-Z0-9]{4})\b",
            r"\1" + cls.MASK_BULLET + r"\2",
            scrubbed,
        )
        scrubbed = re.sub(
            r"\b(github_pat_[A-Za-z0-9_]{4})[A-Za-z0-9_]{20,}([A-Za-z0-9_]{4})\b",
            r"\1" + cls.MASK_BULLET + r"\2",
            scrubbed,
        )

        # 9. Full JWT Tokens (header.payload.signature — redact payload & signature completely)
        scrubbed = re.sub(
            r"\b(eyJ[A-Za-z0-9_\-]{4,})\.[A-Za-z0-9_\-]{4,}\.[A-Za-z0-9_\-=]*\b",
            "eyJ" + cls.MASK_BULLET,
            scrubbed,
        )

        # 10. Authorization: Bearer / Basic headers and standalone Bearer/Basic tokens
        scrubbed = re.sub(
            r"(?i)((?:proxy-)?authorization\s*[:=]\s*bearer\s+)([^\s\"',;}{]+)",
            r"\1" + cls.MASK_BULLET,
            scrubbed,
        )
        scrubbed = re.sub(
            r"(?i)((?:proxy-)?authorization\s*[:=]\s*basic\s+)([A-Za-z0-9+/=]{4,})",
            r"\1" + cls.MASK_BULLET,
            scrubbed,
        )
        scrubbed = re.sub(
            r"(?i)\b(bearer\s+)([A-Za-z0-9_\-\.~+/=]{8,})",
            r"\1" + cls.MASK_BULLET,
            scrubbed,
        )
        scrubbed = re.sub(
            r"(?i)\b(basic\s+)([A-Za-z0-9+/=]{8,})",
            r"\1" + cls.MASK_BULLET,
            scrubbed,
        )

        # 11. Cookie / Set-Cookie headers
        scrubbed = re.sub(
            r"(?i)\b((?:set-)?cookie\s*:\s*)([^\r\n]+)",
            lambda m: f"{m.group(1)}{cls._mask_cookie_header_value(m.group(2))}",
            scrubbed,
        )

        # 12. Slack Webhooks
        scrubbed = re.sub(
            r"(https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+)/[a-zA-Z0-9_]{16,}",
            r"\1/" + cls.MASK_BULLET,
            scrubbed,
        )

        # 13. Generic API params: api_key=..., token=...
        scrubbed = re.sub(
            r"(?i)((?:api[_-]?key|access[_-]?token|secret[_-]?key|auth[_-]?token)[\"\'\s:=]+[\"\']?)([a-zA-Z0-9_\-]{3})[a-zA-Z0-9_\-]{10,}([a-zA-Z0-9_\-]{3})([\"\'\s&]|$)",
            r"\1\2" + cls.MASK_BULLET + r"\3\4",
            scrubbed,
        )

        # 14. Password fields
        scrubbed = re.sub(
            r"(?i)((?:password|passwd|pwd)[\"\'\s:=]+[\"\']?)([^\"\'\s&]{2})[^\"\'\s&]{4,}([^\"\'\s&]{2})([\"\'\s&]|$)",
            r"\1\2" + cls.MASK_BULLET + r"\3\4",
            scrubbed,
        )

        # 15. Credential-bearing connection URIs (ANY scheme): user:password@host
        scrubbed = re.sub(
            r"([a-zA-Z][a-zA-Z0-9+.\-]*://[^:/@\s]+:)([^@\s]+)(@)",
            r"\1" + cls.MASK_BULLET + r"\3",
            scrubbed,
        )

        return scrubbed

    @classmethod
    def _sanitize_header_value(cls, key_lower: str, val: Any, extra_secrets: Optional[Iterable[str]] = None) -> Any:
        if isinstance(val, list):
            return [cls._sanitize_header_value(key_lower, item, extra_secrets=extra_secrets) for item in val]
        if not isinstance(val, str):
            return cls.sanitize_data(val, extra_secrets=extra_secrets)
        stripped = val.strip()
        if key_lower in ("authorization", "proxy-authorization"):
            low = stripped.lower()
            if low.startswith("bearer "):
                return f"Bearer {cls.MASK_BULLET}"
            if low.startswith("basic "):
                return f"Basic {cls.MASK_BULLET}"
            return cls.MASK_BULLET if stripped else ""
        if key_lower in ("cookie", "set-cookie"):
            return cls._mask_cookie_header_value(stripped) if stripped else ""
        return cls.MASK_BULLET if stripped else ""

    @classmethod
    def sanitize_data(cls, data: Any, extra_secrets: Optional[Iterable[str]] = None) -> Any:
        """Recursively scrubs sensitive data in dictionaries, lists, and strings without mutating inputs."""
        if isinstance(data, str):
            return cls.sanitize_text(data, extra_secrets=extra_secrets)
        elif isinstance(data, dict):
            out: Dict[Any, Any] = {}
            for k, v in data.items():
                k_low = str(k).lower() if isinstance(k, str) else ""
                if k_low in _SENSITIVE_HEADER_KEYS:
                    out[k] = cls._sanitize_header_value(k_low, v, extra_secrets=extra_secrets)
                elif k_low == "cookies" and isinstance(v, dict):
                    out[k] = {ck: cls.MASK_BULLET for ck in v}
                elif k_low in ("token_prefix", "token_snippet", "candidate_value") and isinstance(v, str) and v:
                    out[k] = cls.MASK_BULLET
                else:
                    out[k] = cls.sanitize_data(v, extra_secrets=extra_secrets)
            return out
        elif isinstance(data, list):
            return [cls.sanitize_data(item, extra_secrets=extra_secrets) for item in data]
        elif isinstance(data, tuple):
            return tuple(cls.sanitize_data(item, extra_secrets=extra_secrets) for item in data)
        elif isinstance(data, set):
            return {cls.sanitize_data(item, extra_secrets=extra_secrets) for item in data}
        return data
