"""Persistent runtime secret helpers for HunterAI backend."""

from __future__ import annotations

import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def get_or_create_secret(
    env_var: str,
    rel_path: str,
    *,
    nbytes: int = 32,
) -> str:
    """Return a secret from *env_var* or load/persist a random secret on disk."""
    env_val = os.environ.get(env_var, "").strip()
    if env_val:
        return env_val

    secret_path = BASE_DIR / rel_path
    try:
        if secret_path.is_file():
            stored = secret_path.read_text(encoding="utf-8").strip()
            if len(stored) >= 32:
                return stored
    except OSError:
        pass

    generated = secrets.token_hex(nbytes)
    try:
        secret_path.parent.mkdir(parents=True, exist_ok=True)
        secret_path.write_text(generated, encoding="utf-8")
        try:
            os.chmod(secret_path, 0o600)
        except OSError:
            pass
    except OSError:
        pass
    return generated


def get_or_create_policy_secret() -> str:
    """Return the RedTeam grant HMAC signing secret without hardcoded fallbacks."""
    return get_or_create_secret(
        "HUNTERAI_POLICY_SECRET",
        "data/root_controller/.policy_secret",
        nbytes=32,
    )
