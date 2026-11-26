"""SSRF-gated LLM wire-protocol detection, tool-support probing, and Ollama context inspection.

Adapted from PentesterFlow/agent ``src/llm/wireDetect.ts`` and ``src/llm/probe.ts``
(commit ``0759d873a07350a70283c9751f7d136905f777c7``, licensed under Apache-2.0;
see ``THIRD_PARTY_LICENSES/PENTESTERFLOW_APACHE2.txt`` and ``NOTICE``).

Security hardening for HunterAI:
- Every outbound probe against a custom ``base_url`` is gated by
  ``validate_probe_base_url()`` enforcing HunterAI SSRF invariants:
  * Blocks non-HTTP(S) schemes, cloud metadata endpoints, link-local, multicast,
    unspecified, and RFC1918 private LAN addresses (unless explicitly opted in).
  * Allows explicit loopback Ollama (``:11434``) and LM Studio (``:1234``)
    endpoints ONLY (plus explicit loopback ports configured via
    ``OLLAMA_HOST`` / ``LM_STUDIO_HOST``), blocking arbitrary loopback services.
  * Disables HTTP redirects (``follow_redirects=False``) and proxy env leaks
    (``trust_env=False``) on all probes.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
import ipaddress
import logging
import os
import socket
from typing import Any, Awaitable, Callable, Dict, Iterable, Literal, Optional, Set, Tuple
from urllib.parse import urlparse

import httpx

from core.copilot_service import (
    check_target_scheme_and_syntax,
    classify_host_security,
    extract_target_host,
    is_private_lab_enabled,
)
from core.scope_engine import normalize_ip_literal

logger = logging.getLogger("hunter_ai.llm.probe")

WireKind = Literal["ollama", "openai-compat", "unknown"]
ToolSupport = Literal["yes", "no", "unknown"]

PING_TOOL_NAME = "__hunterai_probe_ping"
DEFAULT_PROBE_TIMEOUT_S = 4.0
DEFAULT_TOOL_PROBE_TIMEOUT_S = 8.0
DEFAULT_CTX_PROBE_TIMEOUT_S = 5.0

#: Default loopback ports permitted for local Ollama and LM Studio servers.
DEFAULT_ALLOWED_LOOPBACK_PORTS = frozenset({11434, 1234})


@dataclass(frozen=True)
class WireProbeResult:
    """Result of probing a base URL for Ollama vs OpenAI-compatible wire API."""

    kind: WireKind
    detail: str
    blocked: bool = False


@dataclass(frozen=True)
class ToolProbeResult:
    """Result of probing whether a model emits native structured tool calls."""

    tool_support: ToolSupport
    detail: str = ""


@dataclass(frozen=True)
class OllamaContextInfo:
    """Effective context window discovered from Ollama ``/api/show``."""

    num_ctx: int
    source: Literal["parameter", "metadata", "default"]


def _configured_loopback_ports() -> Set[int]:
    """Return allowed loopback ports (Ollama/LM Studio defaults + configured env hosts)."""
    ports: Set[int] = set(DEFAULT_ALLOWED_LOOPBACK_PORTS)
    for env_name, fallback_port in (("OLLAMA_HOST", 11434), ("LM_STUDIO_HOST", 1234)):
        raw = (os.getenv(env_name) or "").strip()
        if not raw:
            continue
        candidate = raw if "://" in raw else f"http://{raw}"
        try:
            parsed = urlparse(candidate)
            host = extract_target_host(candidate)
            if classify_host_security(host)[0] == "loopback":
                ports.add(parsed.port or fallback_port)
        except ValueError:
            continue
    return ports


def _resolve_and_check_dns_ssrf(host: str) -> Optional[str]:
    """Reject public hostnames that resolve to metadata/loopback/private IPs."""
    if normalize_ip_literal(host) is not None:
        return None
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError:
        # Unresolvable host will fail cleanly at transport time; don't crash SSRF check
        return None
    for _fam, _type, _proto, _canon, sockaddr in infos:
        resolved_ip = str(sockaddr[0]).split("%", 1)[0]
        cat, reason = classify_host_security(resolved_ip)
        if cat != "public":
            return (
                reason
                or f"SSRF_BLOCKED: Host '{host}' resolves to restricted address {resolved_ip} ({cat})"
            )
    return None


def validate_probe_base_url(
    base_url: str,
    *,
    allowed_loopback_ports: Optional[Iterable[int]] = None,
    allowed_private_hosts: Optional[Iterable[str]] = None,
    check_dns: bool = True,
) -> Tuple[bool, str]:
    """Validate an LLM probe ``base_url`` against HunterAI SSRF policy.

    Allows:
    - Explicit loopback Ollama (``:11434``) and LM Studio (``:1234``) endpoints
      (plus any port explicitly configured via ``OLLAMA_HOST`` / ``LM_STUDIO_HOST``
      or ``allowed_loopback_ports``).
    - Public HTTP(S) LLM API endpoints (with optional DNS rebinding check).

    Blocks:
    - Non-HTTP(S) schemes, control characters, malformed authorities.
    - Cloud metadata / link-local / multicast / unspecified addresses.
    - RFC1918 / CGNAT / ULA private LAN addresses (unless
      ``HUNTER_ALLOW_PRIVATE_LAB_SCOPE=1`` AND host is explicitly in
      ``allowed_private_hosts``).
    - Arbitrary loopback ports (e.g. Redis 6379, PostgreSQL 5432, internal APIs).
    """
    raw = (base_url or "").strip()
    if not raw:
        return False, "SSRF_BLOCKED: empty base_url"
    if "://" not in raw:
        return False, "SSRF_BLOCKED: base_url must include explicit http:// or https:// scheme"

    syntax_err = check_target_scheme_and_syntax(raw)
    if syntax_err:
        return False, f"SSRF_BLOCKED: {syntax_err}"

    parsed = urlparse(raw)
    if parsed.username or parsed.password:
        return False, "SSRF_BLOCKED: credentials in URL authority are not allowed"

    host = extract_target_host(raw)
    category, sec_reason = classify_host_security(host)

    if category == "non_overridable":
        return False, sec_reason or f"SSRF_BLOCKED: host '{host}' is strictly forbidden"

    if category == "loopback":
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        allowed_ports = _configured_loopback_ports()
        if allowed_loopback_ports is not None:
            allowed_ports.update(int(p) for p in allowed_loopback_ports)
        if port not in allowed_ports:
            return (
                False,
                f"SSRF_BLOCKED: loopback port {port} is not an approved local LLM port "
                f"(allowed: {sorted(allowed_ports)})",
            )
        return True, f"Allowed explicit loopback LLM endpoint {host}:{port}"

    if category == "private_lab":
        if is_private_lab_enabled() and allowed_private_hosts:
            norm_allowed = {extract_target_host(str(h)) for h in allowed_private_hosts if str(h).strip()}
            if host in norm_allowed:
                return True, f"Allowed explicitly authorized private lab LLM host {host}"
            target_ip = normalize_ip_literal(host)
            if target_ip is not None:
                for entry in allowed_private_hosts:
                    if "/" in str(entry):
                        try:
                            net = ipaddress.ip_network(str(entry).strip("[]"), strict=False)
                            if target_ip.version == net.version and target_ip in net:
                                return True, f"Allowed explicitly authorized private lab subnet {entry}"
                        except ValueError:
                            continue
        return (
            False,
            sec_reason
            or f"SSRF_BLOCKED: private/LAN host '{host}' is blocked by LLM probe SSRF policy",
        )

    if check_dns:
        dns_err = _resolve_and_check_dns_ssrf(host)
        if dns_err:
            return False, dns_err

    return True, f"Allowed public LLM endpoint {host}"


async def _probe_ok(
    url: str,
    *,
    client: Optional[httpx.AsyncClient],
    timeout_s: float,
) -> bool:
    try:
        if client is not None:
            resp = await client.get(url, timeout=timeout_s, follow_redirects=False)
            return 200 <= resp.status_code < 300
        async with httpx.AsyncClient(
            timeout=timeout_s,
            follow_redirects=False,
            trust_env=False,
        ) as owned:
            resp = await owned.get(url)
            return 200 <= resp.status_code < 300
    except Exception:  # noqa: BLE001 - probe failure is non-fatal
        return False


async def detect_wire_kind(
    base_url: str,
    *,
    client: Optional[httpx.AsyncClient] = None,
    timeout_s: float = DEFAULT_PROBE_TIMEOUT_S,
    allowed_loopback_ports: Optional[Iterable[int]] = None,
    allowed_private_hosts: Optional[Iterable[str]] = None,
    check_dns: bool = True,
) -> WireProbeResult:
    """Probe ``base_url`` concurrently on ``/api/tags`` vs ``/v1/models``.

    Prefers native Ollama when both respond OK (local default). Every custom
    ``base_url`` is first validated through ``validate_probe_base_url``.
    """
    base = (base_url or "").strip().rstrip("/")
    if not base:
        return WireProbeResult(kind="unknown", detail="empty base_url", blocked=True)

    # Skip live DNS lookup only when an in-memory mock transport is injected.
    effective_dns_check = check_dns and client is None
    allowed, reason = validate_probe_base_url(
        base,
        allowed_loopback_ports=allowed_loopback_ports,
        allowed_private_hosts=allowed_private_hosts,
        check_dns=effective_dns_check,
    )
    if not allowed:
        logger.warning("[LLMProbe] Blocked wire probe to %s: %s", base, reason)
        return WireProbeResult(kind="unknown", detail=reason, blocked=True)

    ollama_ok, openai_ok = await asyncio.gather(
        _probe_ok(f"{base}/api/tags", client=client, timeout_s=timeout_s),
        _probe_ok(f"{base}/v1/models", client=client, timeout_s=timeout_s),
    )

    if ollama_ok and openai_ok:
        return WireProbeResult(
            kind="ollama",
            detail="both /api/tags and /v1/models respond — using native ollama",
        )
    if ollama_ok:
        return WireProbeResult(kind="ollama", detail="/api/tags ok")
    if openai_ok:
        return WireProbeResult(
            kind="openai-compat",
            detail="/v1/models ok but /api/tags failed — use openai-compat, not ollama",
        )
    return WireProbeResult(
        kind="unknown",
        detail="neither /api/tags nor /v1/models responded OK",
    )


async def suggest_backend_for_ollama_url(
    base_url: str,
    *,
    client: Optional[httpx.AsyncClient] = None,
    timeout_s: float = DEFAULT_PROBE_TIMEOUT_S,
) -> Optional[Literal["openai-compat"]]:
    """Return ``'openai-compat'`` when an Ollama URL actually speaks OpenAI ``/v1`` only."""
    res = await detect_wire_kind(base_url, client=client, timeout_s=timeout_s)
    return "openai-compat" if res.kind == "openai-compat" else None


def build_tool_probe_request(model: str) -> Dict[str, Any]:
    """Build the minimal tool-calling probe request payload."""
    ping_tool = {
        "type": "function",
        "function": {
            "name": PING_TOOL_NAME,
            "description": "Echo back the value you receive. Used to verify tool-calling works.",
            "parameters": {
                "type": "object",
                "properties": {
                    "value": {
                        "type": "string",
                        "description": "Echo this string back verbatim.",
                    }
                },
                "required": ["value"],
            },
        },
    }
    return {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": (
                    f"You are a tool-calling probe. Your ONLY response must be a call to "
                    f"the `{PING_TOOL_NAME}` tool with value=\"ok\". Do not produce any text. "
                    "Do not call any other tool."
                ),
            },
            {"role": "user", "content": "probe"},
        ],
        "tools": [ping_tool],
    }


def _extract_called_tool_names(resp: Any) -> Set[str]:
    names: Set[str] = set()
    if resp is None:
        return names
    tool_calls = None
    if isinstance(resp, dict):
        tool_calls = resp.get("tool_calls") or resp.get("toolCalls")
        if tool_calls is None and isinstance(resp.get("message"), dict):
            tool_calls = resp["message"].get("tool_calls") or resp["message"].get("toolCalls")
        if tool_calls is None and isinstance(resp.get("choices"), list) and resp["choices"]:
            msg = resp["choices"][0].get("message", {})
            if isinstance(msg, dict):
                tool_calls = msg.get("tool_calls") or msg.get("toolCalls")
    else:
        tool_calls = getattr(resp, "tool_calls", None) or getattr(resp, "toolCalls", None)
        if tool_calls is None:
            msg_attr = getattr(resp, "message", None)
            if msg_attr is not None:
                tool_calls = getattr(msg_attr, "tool_calls", None) or getattr(msg_attr, "toolCalls", None)

    for tc in tool_calls or []:
        if isinstance(tc, dict):
            fn = tc.get("function")
            if isinstance(fn, dict) and fn.get("name"):
                names.add(str(fn["name"]))
            elif tc.get("name"):
                names.add(str(tc["name"]))
        else:
            fn = getattr(tc, "function", None)
            if fn is not None and getattr(fn, "name", None):
                names.add(str(fn.name))
            elif getattr(tc, "name", None):
                names.add(str(tc.name))
    return names


async def probe_tool_support(
    caller: Callable[[Dict[str, Any]], Awaitable[Any]] | Any,
    *,
    model: str = "",
    timeout_s: float = DEFAULT_TOOL_PROBE_TIMEOUT_S,
) -> ToolProbeResult:
    """Send a minimal probe forcing ``__hunterai_probe_ping`` to verify native tool support.

    ``caller`` may be an async callable ``(req_dict) -> resp`` or an object exposing
    an async ``chat(req_dict)`` method.
    """
    eff_model = model or getattr(caller, "model", None) or getattr(caller, "model_name", "") or "default"
    if callable(eff_model):
        eff_model = str(eff_model())
    req = build_tool_probe_request(str(eff_model))

    async def _invoke() -> Any:
        if callable(caller):
            return await caller(req)
        chat_fn = getattr(caller, "chat", None)
        if callable(chat_fn):
            return await chat_fn(req)
        raise TypeError("caller must be an async callable or expose an async chat() method")

    try:
        resp = await asyncio.wait_for(_invoke(), timeout=timeout_s)
        names = _extract_called_tool_names(resp)
        if PING_TOOL_NAME in names:
            return ToolProbeResult(tool_support="yes", detail="model emitted native probe tool_call")
        return ToolProbeResult(
            tool_support="no",
            detail=(
                "model returned text instead of a tool_call — pick a function-calling "
                "model (e.g. qwen2.5-coder, llama3.1+, gemini-2.5-flash)."
            ),
        )
    except Exception as exc:  # noqa: BLE001 - best-effort startup probe
        msg_lower = str(exc).lower()
        if any(
            sig in msg_lower
            for sig in (
                "does not support tools",
                "tools are not supported",
                "tool use is not supported",
                "tool calling is not supported",
                "function calling is not supported",
            )
        ):
            return ToolProbeResult(tool_support="no", detail=str(exc))
        logger.warning("[LLMProbe] tool support probe failed: %s", exc)
        return ToolProbeResult(tool_support="unknown", detail=str(exc))


def parse_ollama_context_info(body: Dict[str, Any]) -> OllamaContextInfo:
    """Parse effective ``num_ctx`` from Ollama ``/api/show`` JSON payload.

    Priority:
    1. Explicit ``PARAMETER num_ctx <n>`` line in ``parameters`` string.
    2. Architecture metadata ``*.context_length`` in ``model_info``.
    3. Ollama default ``2048``.
    """
    params = body.get("parameters")
    if isinstance(params, str):
        for line in params.splitlines():
            trimmed = line.strip()
            if not trimmed.startswith("num_ctx"):
                continue
            parts = trimmed.split()
            if len(parts) >= 2:
                try:
                    n = int(parts[1])
                    if n > 0:
                        return OllamaContextInfo(num_ctx=n, source="parameter")
                except ValueError:
                    continue

    model_info = body.get("model_info")
    if isinstance(model_info, dict):
        for key, val in model_info.items():
            if not str(key).endswith(".context_length"):
                continue
            try:
                n = int(val)
                if n > 0:
                    return OllamaContextInfo(num_ctx=n, source="metadata")
            except (TypeError, ValueError):
                continue

    return OllamaContextInfo(num_ctx=2048, source="default")


async def detect_ollama_context_window(
    base_url: str,
    model: str,
    *,
    client: Optional[httpx.AsyncClient] = None,
    timeout_s: float = DEFAULT_CTX_PROBE_TIMEOUT_S,
    allowed_loopback_ports: Optional[Iterable[int]] = None,
    allowed_private_hosts: Optional[Iterable[str]] = None,
    check_dns: bool = True,
) -> Optional[OllamaContextInfo]:
    """Query Ollama ``POST /api/show`` for ``model``'s effective context window.

    Gated by ``validate_probe_base_url``; returns ``None`` if blocked or unreachable.
    """
    base = (base_url or "").strip().rstrip("/")
    if not base or not (model or "").strip():
        return None

    effective_dns_check = check_dns and client is None
    allowed, reason = validate_probe_base_url(
        base,
        allowed_loopback_ports=allowed_loopback_ports,
        allowed_private_hosts=allowed_private_hosts,
        check_dns=effective_dns_check,
    )
    if not allowed:
        logger.warning("[LLMProbe] Blocked Ollama /api/show probe to %s: %s", base, reason)
        return None

    url = f"{base}/api/show"
    payload = {"name": model}
    try:
        if client is not None:
            resp = await client.post(url, json=payload, timeout=timeout_s, follow_redirects=False)
        else:
            async with httpx.AsyncClient(
                timeout=timeout_s,
                follow_redirects=False,
                trust_env=False,
            ) as owned:
                resp = await owned.post(url, json=payload)
        if resp.status_code != 200:
            return None
        data = resp.json()
        if not isinstance(data, dict):
            return None
        return parse_ollama_context_info(data)
    except Exception as exc:  # noqa: BLE001 - best-effort probe
        logger.debug("[LLMProbe] Ollama context probe failed for %s: %s", model, exc)
        return None


__all__ = [
    "DEFAULT_ALLOWED_LOOPBACK_PORTS",
    "OllamaContextInfo",
    "PING_TOOL_NAME",
    "ToolProbeResult",
    "ToolSupport",
    "WireKind",
    "WireProbeResult",
    "build_tool_probe_request",
    "detect_ollama_context_window",
    "detect_wire_kind",
    "parse_ollama_context_info",
    "probe_tool_support",
    "suggest_backend_for_ollama_url",
    "validate_probe_base_url",
]
