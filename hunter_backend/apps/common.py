"""Shared request parsing, security guards, path safety, subprocess, and AI helpers."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
from pathlib import Path
import re
import shlex
import shutil
import socket
from typing import Any, Dict, Iterable, List, Optional, Tuple, Type, TypeVar
from urllib.parse import urlparse

from django.http import JsonResponse
from pydantic import BaseModel, ValidationError
from rest_framework.response import Response

from core.copilot_service import (
    _StrictScopeGuardAdapter,
    evaluate_action_policy,
)
from core.scope_engine import (
    HARD_BLOCKED_HOSTS,
    INVIOLABLE_IPV4_SUBNETS,
    normalize_ip_literal,
)
from core.scope_guard import ScopeGuard
from hunter_backend.runtime import (
    BASE_DIR,
    check_target_policy,
    resolve_effective_scope,
)

logger = logging.getLogger("hunter_backend.apps.common")

TModel = TypeVar("TModel", bound=BaseModel)

SECTION_ALLOWLIST_RE = re.compile(r"^[a-zA-Z0-9_-]{1,32}$")
SKILL_NAME_RE = re.compile(r"^[a-zA-Z0-9._-]{1,64}$")
_SHELL_META_TOKENS = ("&&", "||", ";", "|", "`", "$(", "${", ">", "<", "\n", "\r")
_BLOCKED_SENSITIVE_FILENAMES = {
    ".env",
    ".env.local",
    ".env.production",
    ".env.development",
    "id_rsa",
    "id_ed25519",
    "credentials.json",
    ".policy_secret",
    ".django_secret",
    "secrets.json",
}
_SECRET_MASK_SUFFIXES = ("_API_KEY", "_TOKEN", "_SECRET", "_PASSWORD")


def ok_json(data: Any, status: int = 200) -> Response:
    """Return a DRF JSON Response."""
    return Response(data, status=status)


def err_json(
    message: str,
    status: int = 400,
    *,
    extra: Optional[Dict[str, Any]] = None,
) -> Response:
    """Return a consistent DRF JSON error payload."""
    body: Dict[str, Any] = {"error": message, "detail": message}
    if extra:
        body.update(extra)
    return Response(body, status=status)


def drf_validation_response(verr: JsonResponse) -> Response:
    """Preserve Pydantic/FastAPI error structure inside a DRF Response."""
    try:
        payload = json.loads(verr.content.decode("utf-8"))
    except Exception:
        payload = {"detail": "Validation failed"}
    return Response(payload, status=verr.status_code)


def django_json(data: Any, status: int = 200) -> JsonResponse:
    """Return a Django JsonResponse (safe for async views)."""
    return JsonResponse(data, status=status, safe=isinstance(data, dict))


def django_err(
    message: str,
    status: int = 400,
    *,
    extra: Optional[Dict[str, Any]] = None,
) -> JsonResponse:
    """Return a Django JsonResponse error payload (safe for async views)."""
    body: Dict[str, Any] = {"error": message, "detail": message}
    if extra:
        body.update(extra)
    return JsonResponse(body, status=status)


def parse_json_body(request: Any) -> Tuple[Dict[str, Any], Optional[JsonResponse]]:
    """Extract a JSON object dict from either a DRF Request or Django HttpRequest."""
    if hasattr(request, "data"):
        data = request.data
        if data is None or data == "":
            return {}, None
        if isinstance(data, dict):
            return dict(data), None
        return {}, django_err("Request body must be a JSON object", status=400)

    raw = request.body or b""
    if not raw.strip():
        return {}, None
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except Exception:
        return {}, django_err("Invalid JSON request body", status=400)
    if not isinstance(parsed, dict):
        return {}, django_err("Request body must be a JSON object", status=400)
    return parsed, None


def validate_model(
    model_cls: Type[TModel],
    data: Dict[str, Any],
    *,
    error_status: int = 400,
) -> Tuple[Optional[TModel], Optional[JsonResponse]]:
    """Validate *data* against a Pydantic BaseModel without losing FastAPI error parity."""
    try:
        return model_cls(**(data or {})), None
    except ValidationError as exc:
        return None, JsonResponse(
            {"detail": exc.errors(), "error": str(exc)},
            status=error_status,
        )


def parse_query_bool(value: Optional[str], default: bool = False) -> bool:
    """Parse boolean HTTP query parameter cleanly."""
    if value is None or value == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def parse_query_int(
    value: Optional[str],
    default: int,
    *,
    min_value: int = 1,
    max_value: int = 1000,
) -> int:
    """Parse bounded integer HTTP query parameter cleanly."""
    if value is None or value == "":
        return default
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return max(min_value, min(parsed, max_value))


def parse_query_float(value: Optional[str], default: float) -> float:
    """Parse float HTTP query parameter cleanly."""
    if value is None or value == "":
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def format_sse(
    event_name: str,
    data: Any,
    *,
    event_id: Optional[Any] = None,
) -> bytes:
    """Encode an SSE frame safely for async StreamingHttpResponse."""
    payload_str = data if isinstance(data, str) else json.dumps(data, default=str)
    lines: List[str] = []
    if event_id is not None:
        lines.append(f"id: {event_id}")
    if event_name:
        lines.append(f"event: {event_name}")
    for line in payload_str.splitlines() or [""]:
        lines.append(f"data: {line}")
    return ("\n".join(lines) + "\n\n").encode("utf-8")


# ---------------------------------------------------------------------------
# Strict Path & Secret File Protections
# ---------------------------------------------------------------------------


def has_windows_ads_or_nul(raw_path: str) -> bool:
    """Detect NUL bytes or Windows Alternate Data Stream ':' colons beyond drive letter."""
    if "\x00" in raw_path:
        return True
    cleaned = raw_path
    if len(cleaned) >= 2 and cleaned[1] == ":" and cleaned[0].isalpha():
        cleaned = cleaned[2:]
    return ":" in cleaned


def is_blocked_sensitive_path(path: Path) -> bool:
    """Reject access to sensitive secrets, dotfiles (.env*), .git, and key material."""
    parts = [p.lower() for p in path.parts]
    name = path.name.lower()
    if name in _BLOCKED_SENSITIVE_FILENAMES or name.startswith(".env"):
        return True
    if ".git" in parts or "data/root_controller" in "/".join(parts):
        return True
    if name.endswith((".pem", ".key", ".p12", ".pfx", ".kdbx")):
        return True
    return False


def safe_resolve_path(
    user_path: str,
    allowed_roots: Iterable[Path],
    *,
    must_exist: bool = False,
) -> Path:
    """Resolve *user_path* and enforce strict containment under *allowed_roots*."""
    raw = (user_path or "").strip()
    if not raw or has_windows_ads_or_nul(raw):
        raise PermissionError("Invalid or unsafe file path")

    roots = [Path(r).resolve() for r in allowed_roots]
    candidate_input = Path(raw)

    resolved_targets: List[Path] = []
    if candidate_input.is_absolute():
        resolved_targets.append(candidate_input.resolve())
    else:
        for root in roots:
            resolved_targets.append((root / raw).resolve())

    for cand in resolved_targets:
        for root in roots:
            if cand.is_relative_to(root):
                if is_blocked_sensitive_path(cand):
                    raise PermissionError("Access to sensitive credential/secret file is denied")
                if must_exist and not cand.exists():
                    raise FileNotFoundError(f"Path not found: {raw}")
                return cand

    raise PermissionError("Path escapes allowed workspace directory")


def validate_skill_name(name: str) -> str:
    """Validate skill/checklist identifier against traversal characters."""
    cleaned = (name or "").strip()
    if not SKILL_NAME_RE.match(cleaned) or cleaned in {".", ".."}:
        raise PermissionError(f"Invalid skill identifier: {name!r}")
    return cleaned


# ---------------------------------------------------------------------------
# SSRF + ScopeGuard Target Validation
# ---------------------------------------------------------------------------


def _is_forbidden_ip_or_host(host: str) -> Optional[str]:
    clean = (host or "").strip().strip("[]").lower()
    if not clean:
        return "Target host is empty"
    if clean in HARD_BLOCKED_HOSTS:
        return f"Host {clean!r} is strictly forbidden (internal/metadata host)"

    ip_norm = normalize_ip_literal(clean) or clean
    try:
        addr = ipaddress.ip_address(ip_norm)
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
            addr = addr.ipv4_mapped
        if (
            addr.is_loopback
            or addr.is_private
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_unspecified
            or addr.is_reserved
        ):
            return f"IP address {addr} belongs to a forbidden non-public/internal subnet"
        if isinstance(addr, ipaddress.IPv4Address):
            for subnet in INVIOLABLE_IPV4_SUBNETS:
                if addr in subnet:
                    return f"IP address {addr} belongs to inviolable subnet {subnet}"
    except ValueError:
        pass
    return None


def validate_http_url_ssrf_and_scope(
    url: str,
    *,
    scope: Any = None,
    out_of_scope: Any = None,
    engagement_id: Optional[str] = None,
    action_type: str = "repeater_send",
) -> Tuple[bool, str, Dict[str, Any]]:
    """Enforce http/https scheme, anti-SSRF IP/host blocks, and ScopeGuard scope check."""
    raw = (url or "").strip()
    if not raw:
        return False, "URL is required", {"status": "BLOCKED_INVALID_URL"}

    parsed = urlparse(raw)
    if parsed.scheme.lower() not in {"http", "https"}:
        return (
            False,
            f"Unsupported or unsafe URL scheme {parsed.scheme!r}; only http/https allowed",
            {"status": "BLOCKED_SCHEME"},
        )
    host = parsed.hostname or ""
    ip_reason = _is_forbidden_ip_or_host(host)
    if ip_reason:
        return False, ip_reason, {"status": "BLOCKED_SSRF"}

    # Best-effort DNS resolution check so external aliases resolving to 127.0.0.1 / 169.254.169.254 are stopped.
    try:
        infos = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80), proto=socket.IPPROTO_TCP)
        for info in infos:
            resolved_ip = info[4][0]
            dns_reason = _is_forbidden_ip_or_host(resolved_ip)
            if dns_reason:
                return (
                    False,
                    f"Resolved target IP blocked ({dns_reason})",
                    {"status": "BLOCKED_SSRF_DNS"},
                )
    except OSError:
        # Unresolvable hostnames (e.g. unit-test targets) still pass DNS step to ScopeGuard.
        pass

    in_list, out_list = resolve_effective_scope(
        scope=scope,
        out_of_scope=out_of_scope,
        engagement_id=engagement_id,
    )
    sg = ScopeGuard(in_scope=in_list or None, out_of_scope=out_list or None)
    allowed_sg, reason_sg = sg.is_allowed(raw)
    policy = evaluate_action_policy(
        action_type=action_type,
        target=raw,
        in_scope=in_list or None,
        out_of_scope=out_list or None,
    )

    if not (allowed_sg and policy.get("allowed", False)):
        reason = policy.get("reason") or reason_sg or "Target blocked by ScopeGuard"
        return False, reason, policy
    return True, "Allowed", policy


def validate_scan_target(
    target: str,
    *,
    scope: Any = None,
    out_of_scope: Any = None,
    engagement_id: Optional[str] = None,
    action_type: str = "scan",
) -> Tuple[bool, str, Dict[str, Any]]:
    """Validate scan target hostname/URL via ScopeGuard and policy invariants."""
    clean = (target or "").strip()
    if not clean:
        return False, "Target is required", {"status": "BLOCKED_EMPTY"}

    if "://" in clean:
        return validate_http_url_ssrf_and_scope(
            clean,
            scope=scope,
            out_of_scope=out_of_scope,
            engagement_id=engagement_id,
            action_type=action_type,
        )

    ip_reason = _is_forbidden_ip_or_host(clean)
    if ip_reason:
        return False, ip_reason, {"status": "BLOCKED_SSRF"}

    in_list, out_list = resolve_effective_scope(
        scope=scope,
        out_of_scope=out_of_scope,
        engagement_id=engagement_id,
    )
    policy = check_target_policy(
        clean,
        action_type=action_type,
        scope=in_list or None,
        out_of_scope=out_list or None,
        engagement_id=engagement_id,
    )
    if not policy.get("allowed", False):
        return False, policy.get("reason", "Target blocked by ScopeGuard"), policy
    return True, "Allowed", policy


# ---------------------------------------------------------------------------
# Shell-Free Subprocess Execution
# ---------------------------------------------------------------------------


async def run_command_no_shell(
    command: str | List[str],
    *,
    timeout_s: float = 60.0,
    cwd: Optional[Path] = None,
) -> Dict[str, Any]:
    """Execute a command strictly via ``asyncio.create_subprocess_exec`` (no shell)."""
    if isinstance(command, str):
        raw = command.strip()
        if not raw:
            raise ValueError("Empty command")
        for tok in _SHELL_META_TOKENS:
            if tok in raw:
                raise PermissionError(f"Shell operator {tok!r} is forbidden in subprocess execution")
        tokens = shlex.split(raw, posix=(os.name != "nt"))
    elif isinstance(command, list):
        tokens = [str(item) for item in command if str(item) != ""]
    else:
        raise ValueError("command must be a string or list of arguments")

    if not tokens:
        raise ValueError("No command arguments parsed")

    exe = shutil.which(tokens[0])
    if exe is None and Path(tokens[0]).is_file():
        exe = tokens[0]
    if exe is None:
        return {
            "returncode": 127,
            "stdout": "",
            "stderr": f"Executable not found on PATH: {tokens[0]}",
            "command": tokens,
        }

    proc = await asyncio.create_subprocess_exec(
        exe,
        *tokens[1:],
        cwd=str(cwd or BASE_DIR),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout_s)
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:
            pass
        return {
            "returncode": -1,
            "stdout": "",
            "stderr": f"Command timed out after {timeout_s}s",
            "command": tokens,
            "timed_out": True,
        }

    return {
        "returncode": proc.returncode,
        "stdout": stdout_b.decode("utf-8", errors="replace"),
        "stderr": stderr_b.decode("utf-8", errors="replace"),
        "command": tokens,
    }


# ---------------------------------------------------------------------------
# .env & AI Provider Helpers
# ---------------------------------------------------------------------------


def read_env_file(env_path: Optional[Path] = None) -> Dict[str, str]:
    """Read key=value entries from repo ``.env`` without shell evaluation."""
    target = env_path or (BASE_DIR / ".env")
    values: Dict[str, str] = {}
    if not target.is_file():
        return values
    try:
        for line in target.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            k, v = stripped.split("=", 1)
            key = k.strip()
            val = v.strip().strip('"').strip("'")
            if key:
                values[key] = val
    except OSError:
        pass
    return values


def write_env_file(updates: Dict[str, str], env_path: Optional[Path] = None) -> None:
    """Safely update allowlisted keys in ``.env`` with newline stripping."""
    target = env_path or (BASE_DIR / ".env")
    existing = read_env_file(target)
    for key, val in updates.items():
        clean_k = re.sub(r"[^A-Za-z0-9_]", "", str(key))
        if not clean_k:
            continue
        clean_v = str(val).replace("\r", "").replace("\n", "")
        existing[clean_k] = clean_v
        os.environ[clean_k] = clean_v

    lines = [f"{k}={v}" for k, v in sorted(existing.items())]
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")


def mask_secret(value: str) -> str:
    """Mask an API secret preserving only a short suffix hint."""
    if not value:
        return ""
    if len(value) <= 6:
        return "*" * len(value)
    return f"{'*' * 8}{value[-4:]}"


def redact_settings_map(mapping: Dict[str, str]) -> Dict[str, Any]:
    """Return UI-safe settings with secret fields masked."""
    out: Dict[str, Any] = {}
    for k, v in mapping.items():
        upper = k.upper()
        if any(upper.endswith(sfx) for sfx in _SECRET_MASK_SUFFIXES):
            out[k] = mask_secret(v)
            out[f"{k}_SET"] = bool(v)
        else:
            out[k] = v
    return out


def call_provider_sync(
    prompt: str,
    *,
    provider: Optional[str] = None,
    model: Optional[str] = None,
    system_prompt: str = "",
) -> str:
    """Best-effort synchronous LLM provider invocation using core.llm_router."""
    try:
        from core.llm_router import get_llm_router

        router = get_llm_router()
        resp = router.chat(
            prompt=prompt,
            system=system_prompt or "You are HunterAI Bug Bounty Assistant.",
            provider=provider,
            model=model,
        )
        if isinstance(resp, dict):
            return str(resp.get("content") or resp.get("response") or resp)
        return str(resp)
    except Exception as exc:
        return f"AI provider unavailable ({exc}). Check Settings / Ollama or API key."


async def call_ai(
    prompt: str,
    *,
    provider: Optional[str] = None,
    model: Optional[str] = None,
    system_prompt: str = "",
) -> str:
    """Async wrapper around ``call_provider_sync`` for native async views."""
    return await asyncio.to_thread(
        call_provider_sync,
        prompt,
        provider=provider,
        model=model,
        system_prompt=system_prompt,
    )


def load_agent_context(max_chars: int = 3500) -> str:
    """Load AGENTS.md context excerpt safely for agent prompts."""
    agents_file = BASE_DIR / "AGENTS.md"
    if not agents_file.is_file():
        return ""
    try:
        return agents_file.read_text(encoding="utf-8")[:max_chars]
    except OSError:
        return ""
