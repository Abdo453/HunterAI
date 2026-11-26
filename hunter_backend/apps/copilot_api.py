"""Copilot conversations, SSE chat stream, /api/chat, models, status, and settings."""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import logging
import os
import re
import shlex
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from asgiref.sync import async_to_sync
from django.http import HttpRequest, JsonResponse, StreamingHttpResponse
from django.views.decorators.http import require_GET, require_http_methods
from pydantic import BaseModel, Field
from rest_framework.views import APIView

from core.copilot_service import (
    MAX_ATTACHMENT_BYTES,
    MAX_ATTACHMENT_EXCERPT_CHARS,
    CopilotService,
    classify_host_security,
    collect_live_context,
    detect_live_providers,
    evaluate_action_policy,
    extract_target_host,
    is_tcp_reachable,
)
from core.llm_router import get_llm_router
from core.platform_store import get_platform_store, new_id
from core.scope_engine import normalize_ip_literal
from core.security_mode import web_governance_enforced
from hunter_backend.apps.common import (
    call_ai,
    django_err,
    django_json,
    drf_validation_response,
    err_json,
    format_sse,
    mask_secret,
    ok_json,
    parse_json_body,
    parse_query_int,
    read_env_file,
    run_command_no_shell,
    validate_model,
    validate_subprocess_command,
    write_env_file,
)
from hunter_backend.auth import get_request_auth
from hunter_backend.runtime import (
    BASE_DIR,
    DATA_DIR,
    ensure_platform_wiring,
    get_copilot_service,
)

logger = logging.getLogger("hunter_backend.apps.copilot_api")

ATTACHMENTS_DIR = DATA_DIR / "copilot_attachments"


def _get_attachments_dir() -> Path:
    env_dir = (os.environ.get("HUNTER_COPILOT_ATTACHMENTS_DIR") or "").strip()
    return Path(env_dir) if env_dir else ATTACHMENTS_DIR

PROVIDER_ENV_KEYS: Dict[str, str] = {
    "ollama": "",
    "nvidia": "NVIDIA_API_KEY",
    "gemini": "GEMINI_API_KEY",
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "groq": "GROQ_API_KEY",
    "deepseek": "DEEPSEEK_API_KEY",
    "openrouter": "OPENROUTER_API_KEY",
    "taskade": "TASKADE_API_KEY",
    "huggingface": "HUGGINGFACE_API_KEY",
    "mistral": "MISTRAL_API_KEY",
}

DEFAULT_MODELS: Dict[str, str] = {
    "ollama": "qwen2.5:14b",
    "nvidia": "meta/llama-3.3-70b-instruct",
    "gemini": "gemini-2.5-flash",
    "openai": "gpt-4o",
    "anthropic": "claude-sonnet-4-20250514",
    "groq": "llama-3.3-70b-versatile",
    "deepseek": "deepseek-chat",
    "openrouter": "anthropic/claude-3.5-sonnet",
    "taskade": "gpt-4o-mini",
    "huggingface": "Qwen/Qwen2.5-72B-Instruct",
    "mistral": "mistral-large-latest",
}


class ConversationCreateRequest(BaseModel):
    title: str = "New Investigation"
    engagement_id: Optional[str] = None
    run_id: Optional[str] = None
    mode: str = "analyst"
    model: str = "auto"
    set_active: bool = True


class ConversationPatchRequest(BaseModel):
    title: Optional[str] = None
    engagement_id: Optional[str] = None
    run_id: Optional[str] = None
    mode: Optional[str] = None
    model: Optional[str] = None


class ChatStreamRequest(BaseModel):
    message: str = Field(..., min_length=1)
    conversation_id: Optional[str] = None
    engagement_id: Optional[str] = None
    run_id: Optional[str] = None
    model: Optional[str] = None
    mode: Optional[str] = None
    attachment_ids: List[str] = Field(default_factory=list)


class CopilotConversationsView(APIView):
    """GET / POST /api/copilot/conversations."""

    def get(self, request: Any) -> Any:
        store = ensure_platform_wiring()
        items = store.list_conversations(
            engagement_id=request.GET.get("engagement_id") or None,
            run_id=request.GET.get("run_id") or None,
            limit=parse_query_int(request.GET.get("limit"), 100),
        )
        return ok_json({"conversations": items, "count": len(items)})

    def post(self, request: Any) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        req, verr = validate_model(ConversationCreateRequest, data, error_status=422)
        if verr is not None:
            return err_json("Invalid conversation payload", status=422, extra=json.loads(verr.content))
        store = ensure_platform_wiring()
        conv = store.create_conversation(
            title=req.title,
            engagement_id=req.engagement_id,
            run_id=req.run_id,
            mode=req.mode,
            model=req.model,
        )
        if req.set_active:
            store.update_context(active_conversation_id=conv["conversation_id"])
        return ok_json({"conversation": conv, **conv}, status=201)


class CopilotConversationDetailView(APIView):
    """GET / PATCH / DELETE /api/copilot/conversations/<cid>."""

    def get(self, request: Any, cid: str) -> Any:
        store = ensure_platform_wiring()
        conv = store.get_conversation(cid)
        if not conv:
            return err_json(f"Conversation {cid} not found", status=404)
        messages = store.list_messages(cid, limit=300)
        approval_cache: Dict[str, Optional[Dict[str, Any]]] = {}
        for msg in messages:
            aid = msg.get("approval_id")
            if not aid and isinstance(msg.get("refs"), list):
                for ref in msg["refs"]:
                    if isinstance(ref, dict) and ref.get("kind") == "approval" and ref.get("id"):
                        aid = str(ref["id"])
                        break
            if aid:
                aid_str = str(aid)
                if aid_str not in approval_cache:
                    approval_cache[aid_str] = store.get_approval(aid_str)
                ap = approval_cache[aid_str]
                if ap:
                    if not msg.get("approvalNotice"):
                        msg["approvalNotice"] = ap
                    if not msg.get("approval"):
                        msg["approval"] = ap
            meta = msg.get("metadata")
            if isinstance(meta, dict) and not msg.get("policyNotice"):
                pol = meta.get("policy_outcome")
                if isinstance(pol, dict) and pol.get("allowed") is False:
                    msg["policyNotice"] = {
                        "allowed": False,
                        "status": str(pol.get("status") or "BLOCKED"),
                        "reason": str(pol.get("reason") or "Blocked by PolicyEngine"),
                        "risk_tier": str(pol.get("risk_tier") or ""),
                    }
        return ok_json({"conversation": conv, "messages": messages})

    def patch(self, request: Any, cid: str) -> Any:
        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON body", status=400)
        req, verr = validate_model(ConversationPatchRequest, data, error_status=422)
        if verr is not None:
            return err_json("Invalid patch payload", status=422, extra=json.loads(verr.content))
        store = ensure_platform_wiring()
        kwargs: Dict[str, Any] = {}
        if req.title is not None:
            kwargs["title"] = req.title
        if req.engagement_id is not None:
            kwargs["engagement_id"] = req.engagement_id
        if req.run_id is not None:
            kwargs["run_id"] = req.run_id
        if req.mode is not None:
            kwargs["mode"] = req.mode
        if req.model is not None:
            kwargs["model"] = req.model
        updated = store.update_conversation(cid, **kwargs)
        if not updated:
            return err_json(f"Conversation {cid} not found", status=404)
        return ok_json({"conversation": updated, **updated})

    def delete(self, request: Any, cid: str) -> Any:
        store = ensure_platform_wiring()
        ok = store.delete_conversation(cid)
        if not ok:
            return err_json(f"Conversation {cid} not found", status=404)
        return ok_json({"ok": True, "deleted": cid})


@require_http_methods(["POST"])
async def copilot_upload_attachment_view(request: HttpRequest) -> JsonResponse:
    """POST /api/copilot/attachments: multipart file or JSON text upload reconciled with CopilotService limits."""
    ensure_platform_wiring()
    conv_id = (request.GET.get("conversation_id") or request.POST.get("conversation_id") or "").strip() or None

    raw_bytes = b""
    filename = "attachment.txt"
    content_type = "text/plain"

    uploaded = request.FILES.get("file") if hasattr(request, "FILES") else None
    if uploaded is not None:
        filename = Path(uploaded.name or "attachment.bin").name
        content_type = uploaded.content_type or "application/octet-stream"
        raw_bytes = uploaded.read()
    else:
        data, err = parse_json_body(request)
        if err is not None:
            return err
        filename = Path(str(data.get("filename") or "snippet.txt")).name
        content_type = str(data.get("content_type") or "text/plain")
        text_content = str(data.get("content") or data.get("text") or "")
        if not text_content:
            return django_err("Missing file upload or content field", status=400)
        conv_id = conv_id or data.get("conversation_id")
        raw_bytes = text_content.encode("utf-8", errors="replace")

    if len(raw_bytes) > MAX_ATTACHMENT_BYTES:
        return django_err(
            f"Attachment exceeds {MAX_ATTACHMENT_BYTES // (1024 * 1024)} MB limit",
            status=413,
        )

    svc = get_copilot_service()
    try:
        record = await asyncio.to_thread(
            svc.store_attachment,
            filename=filename,
            raw_bytes=raw_bytes,
            content_type=content_type,
            conversation_id=conv_id,
        )
    except ValueError as exc:
        return django_err(str(exc), status=413)
    return django_json(
        {
            "ok": True,
            "attachment": record,
            "max_bytes": MAX_ATTACHMENT_BYTES,
            "max_excerpt_chars": MAX_ATTACHMENT_EXCERPT_CHARS,
            **record,
        },
        status=201,
    )


@require_http_methods(["POST"])
async def copilot_chat_stream_view(request: HttpRequest) -> StreamingHttpResponse | JsonResponse:
    """POST /api/copilot/chat/stream: native async SSE streaming cancelling stream_task on disconnect."""
    data, err = parse_json_body(request)
    if err is not None:
        return err
    req, verr = validate_model(ChatStreamRequest, data, error_status=422)
    if verr is not None:
        return verr
    assert req is not None

    ensure_platform_wiring()
    svc: CopilotService = get_copilot_service()

    async def event_stream():
        queue: asyncio.Queue[Optional[bytes]] = asyncio.Queue(maxsize=256)
        turn_gen = svc.stream_turn(
            message=req.message,
            conversation_id=req.conversation_id,
            engagement_id=req.engagement_id,
            run_id=req.run_id,
            model=req.model,
            mode=req.mode,
            attachment_ids=req.attachment_ids,
        )

        async def _pump() -> None:
            try:
                async for item in turn_gen:
                    if isinstance(item, bytes):
                        chunk = item
                    elif isinstance(item, str):
                        chunk = item.encode("utf-8")
                    elif isinstance(item, (tuple, list)) and len(item) == 2:
                        ev_name, payload = item
                        chunk = format_sse(
                            str(ev_name or "message"),
                            payload if isinstance(payload, dict) else {"content": payload},
                        )
                    elif isinstance(item, dict):
                        ev_name = str(item.get("event") or item.get("type") or "message")
                        chunk = format_sse(ev_name, item)
                    else:
                        chunk = format_sse("message", {"content": str(item)})
                    await queue.put(chunk)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.exception("Copilot stream failed")
                await queue.put(format_sse("error", {"error": str(exc)}))
            finally:
                try:
                    await turn_gen.aclose()
                except Exception as close_exc:
                    logger.debug("Copilot turn generator close note: %s", close_exc)
                await queue.put(None)

        stream_task = asyncio.create_task(_pump())
        try:
            while True:
                chunk = await queue.get()
                if chunk is None:
                    break
                yield chunk
        except (asyncio.CancelledError, GeneratorExit):
            return
        finally:
            if not stream_task.done():
                stream_task.cancel()
                try:
                    await stream_task
                except asyncio.CancelledError:
                    logger.debug("Copilot SSE stream_task cancelled on client disconnect")
                except Exception as cancel_exc:
                    logger.warning("Copilot SSE stream_task shutdown error: %s", cancel_exc)

    resp = StreamingHttpResponse(event_stream(), content_type="text/event-stream")
    resp["Cache-Control"] = "no-cache, no-transform"
    resp["X-Accel-Buffering"] = "no"
    return resp


_BASH_FENCE_RE = re.compile(r"```(?:bash|sh|shell|zsh)?\s*\n(.*?)```", re.DOTALL | re.IGNORECASE)
_SHELL_META_CHAT_RE = re.compile(r"[;&|`$<>()\n\r\x00]|&&|\|\||\$\(")
_FORBIDDEN_CHAT_TOOLS = {
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "csh",
    "fish",
    "cmd",
    "powershell",
    "pwsh",
    "nc",
    "ncat",
    "netcat",
    "socat",
    "python",
    "python2",
    "python3",
    "py",
    "node",
    "nodejs",
    "deno",
    "bun",
    "curl",
    "wget",
    "perl",
    "ruby",
    "php",
}
_DOMAIN_TOKEN_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")
_LOCAL_EXTS = {".py", ".js", ".ts", ".txt", ".json", ".yaml", ".yml", ".md", ".xml", ".csv", ".log"}


def _parse_bool_flag(raw: Any, default: bool = False) -> bool:
    if isinstance(raw, bool):
        return raw
    if raw is None:
        return default
    return str(raw).strip().lower() in {"1", "true", "yes", "on"}


def _extract_chat_commands(text: str) -> List[str]:
    cmds: List[str] = []
    for block in _BASH_FENCE_RE.findall(text or ""):
        for line in block.splitlines():
            clean = line.strip()
            if clean and not clean.startswith("#"):
                cmds.append(clean)
    return cmds


def _resolve_chat_scope(
    store: Any,
    target: str,
    scope: Any,
    out_of_scope: Any,
    engagement_id: Optional[str],
) -> Tuple[str, List[str], List[str]]:
    in_scope = [str(s).strip() for s in scope if str(s).strip()] if isinstance(scope, list) else []
    oos = [str(s).strip() for s in out_of_scope if str(s).strip()] if isinstance(out_of_scope, list) else []
    eff_target = target.strip()
    eng = store.get_engagement(engagement_id) if engagement_id else None
    if not eng:
        active_id = (store.get_context() or {}).get("active_engagement_id")
        if active_id:
            eng = store.get_engagement(active_id)
    if eng:
        if not in_scope:
            in_scope = [str(s).strip() for s in (eng.get("in_scope") or []) if str(s).strip()]
        if not oos:
            oos = [str(s).strip() for s in (eng.get("out_of_scope") or []) if str(s).strip()]
        if not eff_target:
            eff_target = str(eng.get("target") or "").strip()
    return eff_target, in_scope, oos


def _extract_targets_from_tokens(tokens: List[str]) -> List[str]:
    targets: List[str] = []
    for raw in tokens[1:]:
        cand = raw.split("=", 1)[1] if raw.startswith("-") and "=" in raw else ("" if raw.startswith("-") else raw)
        cand = cand.strip("'\",;)")
        if not cand:
            continue
        if "://" in cand:
            targets.append(cand)
            continue
        host_part = cand.split("/", 1)[0].split(":", 1)[0].lower()
        if host_part == "localhost":
            targets.append(cand)
        elif not (host_part.isdigit() and int(host_part) <= 65535) and normalize_ip_literal(host_part) is not None:
            targets.append(cand)
        elif _DOMAIN_TOKEN_RE.fullmatch(host_part) and Path(host_part).suffix.lower() not in _LOCAL_EXTS:
            targets.append(cand)
    return targets


def _evaluate_chat_command(
    cmd: str,
    *,
    effective_target: str,
    in_scope: List[str],
    out_of_scope: List[str],
) -> Tuple[bool, str, str]:
    if not in_scope and web_governance_enforced():
        return False, "BLOCKED_SCOPE", "No authorized target scope configured (empty scope fails closed)."
    if _SHELL_META_CHAT_RE.search(cmd):
        return False, "BLOCKED_INVARIANT", "Shell metacharacters are forbidden in executed commands."
    try:
        tokens = shlex.split(cmd)
    except ValueError as exc:
        return False, "BLOCKED_RISK", f"Malformed command quoting: {exc}"
    if not tokens:
        return False, "BLOCKED_RISK", "Empty command."
    tool_name = Path(tokens[0]).name.lower().removesuffix(".exe")
    if tool_name in _FORBIDDEN_CHAT_TOOLS:
        return False, "BLOCKED_INVARIANT", f"Shell tool '{tool_name}' is prohibited."
    targets = _extract_targets_from_tokens(tokens) or ([effective_target] if effective_target else [""])
    for tgt in targets:
        host = extract_target_host(tgt)
        category, sec_reason = classify_host_security(host)
        if category == "non_overridable":
            return False, "BLOCKED_INVARIANT", sec_reason or f"Forbidden internal/metadata target '{host}'."
        pol = evaluate_action_policy(
            action_type="CLI_TOOL",
            target=tgt,
            tool_name=tool_name,
            command_args=cmd,
            in_scope=in_scope,
            out_of_scope=out_of_scope,
            allow_active_tests=True,
            rationale="Requested via /api/chat",
        )
        if not pol.get("allowed"):
            return False, str(pol.get("status") or "BLOCKED_SCOPE"), str(pol.get("reason") or "Blocked by PolicyEngine")
    return True, "APPROVED", "Verified"


@require_http_methods(["POST"])
async def legacy_api_chat_view(request: HttpRequest) -> JsonResponse:
    """POST /api/chat: AI chat with fail-closed approval-queue gating (never auto-executes LLM bash blocks)."""
    data, err = parse_json_body(request)
    if err is not None:
        return err
    message = str(data.get("message") or data.get("prompt") or "").strip()
    if not message:
        return django_err("message is required", status=400)

    provider = str(data.get("provider") or "").strip() or None
    model = str(data.get("model") or "").strip() or None
    allow_exec = _parse_bool_flag(data.get("allow_exec"), False)
    authorized = _parse_bool_flag(data.get("authorized"), False)
    target = str(data.get("target") or "").strip()
    engagement_id = data.get("engagement_id")
    run_id = data.get("run_id")

    store = ensure_platform_wiring()
    ctx = await asyncio.to_thread(
        collect_live_context,
        store,
        engagement_id=engagement_id,
        run_id=run_id,
        query_hint=message,
    )
    system = (
        "You are HunterAI Bug Bounty Copilot. Never fabricate findings. "
        f"Live context keys: {list(ctx.keys())}."
    )
    reply = await call_ai(message, provider=provider, model=model, system_prompt=system)

    commands = _extract_chat_commands(reply)
    executed_results: List[Dict[str, Any]] = []
    blocked_results: List[Dict[str, Any]] = []
    queued_approvals: List[Dict[str, Any]] = []
    terminal_parts: List[str] = []

    if allow_exec and authorized and commands:
        eff_target, in_scope, oos = await asyncio.to_thread(
            _resolve_chat_scope,
            store,
            target,
            data.get("scope"),
            data.get("out_of_scope"),
            engagement_id,
        )
        for cmd in commands:
            ok, status, reason = _evaluate_chat_command(
                cmd, effective_target=eff_target, in_scope=in_scope, out_of_scope=oos
            )
            if not ok:
                blocked_results.append({"command": cmd, "status": status, "reason": reason})
                terminal_parts.append(f"[!] BLOCKED ({status}): {cmd} — {reason}")
                continue
            try:
                validated_tokens = validate_subprocess_command(cmd)
            except (PermissionError, ValueError) as exc:
                blocked_results.append({"command": cmd, "status": "BLOCKED_INVARIANT", "reason": str(exc)})
                terminal_parts.append(f"[!] BLOCKED: {cmd} — {exc}")
                continue

            # NEVER auto-execute LLM-generated bash blocks; route to explicit HITL approval queue.
            tool_name = validated_tokens[0]
            cmd_args = " ".join(validated_tokens[1:])
            apr = await asyncio.to_thread(
                store.create_approval,
                action_type="RUN_TOOL",
                target=eff_target or (validated_tokens[-1] if len(validated_tokens) > 1 else ""),
                tool_name=tool_name,
                command_args=cmd_args,
                risk_tier="TIER_2_PROBE",
                rationale="LLM-proposed command via /api/chat requires explicit operator approval",
                payload={"source": "legacy_api_chat", "proposed_command": cmd},
                engagement_id=engagement_id,
                run_id=run_id,
                scope=in_scope,
            )
            queued_approvals.append(apr)
            terminal_parts.append(
                f"[?] APPROVAL_REQUIRED ({apr['approval_id']}): {cmd} queued for operator decision"
            )

    resolved_provider = provider or os.getenv("HUNTER_DEFAULT_PROVIDER", "auto")
    resolved_model = model or DEFAULT_MODELS.get(resolved_provider, os.getenv("HUNTER_DEFAULT_MODEL", "auto"))
    return django_json(
        {
            "response": reply,
            "reply": reply,
            "provider": resolved_provider,
            "model": resolved_model,
            "model_used": resolved_model,
            "allow_exec": allow_exec,
            "authorized": authorized,
            "executed": executed_results,
            "commands": executed_results,
            "queued_approvals": queued_approvals,
            "blocked": blocked_results,
            "terminal_output": "\n".join(terminal_parts),
            "context_summary": {
                "engagement_id": (ctx.get("engagement") or {}).get("engagement_id")
                if isinstance(ctx.get("engagement"), dict)
                else None,
                "run_id": (ctx.get("run") or {}).get("run_id")
                if isinstance(ctx.get("run"), dict)
                else None,
            },
        }
    )


@require_GET
async def status_view(request: HttpRequest) -> JsonResponse:
    """GET /api/status: Ollama / GPU / provider status."""
    from models.ollama_manager import normalize_ollama_host

    ollama_host = normalize_ollama_host(os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434"))
    local_models: List[str] = []
    loaded_models: List[str] = []

    try:
        import httpx

        async with httpx.AsyncClient(timeout=2.5) as client:
            r_tags = await client.get(f"{ollama_host}/api/tags")
            if r_tags.status_code == 200:
                local_models = [m["name"] for m in r_tags.json().get("models", []) if isinstance(m, dict) and "name" in m]
            r_ps = await client.get(f"{ollama_host}/api/ps")
            if r_ps.status_code == 200:
                loaded_models = [m["name"] for m in r_ps.json().get("models", []) if isinstance(m, dict) and "name" in m]
    except Exception:
        pass

    env = read_env_file()
    api_keys = {
        prov: bool(env.get(key) or os.getenv(key))
        for prov, key in PROVIDER_ENV_KEYS.items()
        if key
    }
    return django_json(
        {
            "local_models": local_models,
            "loaded_models": loaded_models,
            "api_keys": api_keys,
            "ollama_host": ollama_host,
        }
    )


class SettingsGetView(APIView):
    """GET /api/settings: masked AI provider configuration."""

    def get(self, request: Any) -> Any:
        env = read_env_file()
        keys: Dict[str, Any] = {}
        provider_status: Dict[str, bool] = {}
        for prov, env_key in PROVIDER_ENV_KEYS.items():
            val = (env.get(env_key) or os.getenv(env_key)) if env_key else None
            configured = bool(val) if env_key else False
            if prov == "ollama" and not configured:
                configured = is_tcp_reachable("127.0.0.1", 11434, timeout=0.4)
            keys[prov] = {
                "configured": configured,
                "key_masked": ("***" + val[-4:]) if val and len(val) > 4 else ("***" if val else None),
            }
            provider_status[prov] = configured

        default_provider = (
            env.get("HUNTER_DEFAULT_PROVIDER")
            or os.getenv("HUNTER_DEFAULT_PROVIDER")
            or "nvidia"
        ).strip().lower()
        if default_provider not in PROVIDER_ENV_KEYS:
            default_provider = "nvidia"
        default_model = (
            env.get("HUNTER_DEFAULT_MODEL")
            or os.getenv("HUNTER_DEFAULT_MODEL")
            or DEFAULT_MODELS.get(default_provider, "")
        ).strip()
        allow_exec = os.getenv("HUNTER_ALLOW_EXEC", "1").strip().lower() not in (
            "0",
            "false",
            "no",
            "off",
        )
        return ok_json(
            {
                "providers": list(PROVIDER_ENV_KEYS.keys()),
                "provider_status": provider_status,
                "default_provider": default_provider,
                "default_model": default_model,
                "default_models": DEFAULT_MODELS,
                "allow_exec": allow_exec,
                "keys": keys,
            }
        )


def _validate_ollama_host_url(raw_url: str) -> Tuple[bool, str]:
    """Validate OLLAMA_HOST URL against SSRF, scheme injection, and metadata targets."""
    cleaned = (raw_url or "").strip()
    if not cleaned:
        return False, "ollama_host must not be empty"
    if any(ch in cleaned for ch in ("\r", "\n", "\x00", " ", "\t")):
        return False, "ollama_host contains disallowed whitespace or control characters"
    parsed = urlparse(cleaned)
    scheme = (parsed.scheme or "").lower()
    if scheme not in {"http", "https"}:
        return False, f"Invalid ollama_host scheme {scheme!r}; only http/https allowed"
    if parsed.username or parsed.password or not parsed.hostname:
        return False, "Invalid ollama_host authority"
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        return False, "ollama_host must not include path, query, or fragment"
    try:
        port = parsed.port
    except ValueError:
        return False, "Invalid ollama_host port"
    if port is not None and not (1 <= port <= 65535):
        return False, "ollama_host port out of range"

    host = parsed.hostname.strip().rstrip(".").lower()
    category, reason = classify_host_security(host)
    if category == "non_overridable":
        return False, f"ollama_host blocked ({reason})"

    allow_remote = os.environ.get("HUNTER_ALLOW_REMOTE_OLLAMA", "0").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    if category != "loopback" and not allow_remote:
        return (
            False,
            "ollama_host must target loopback (127.0.0.1/localhost/::1) unless HUNTER_ALLOW_REMOTE_OLLAMA=1",
        )
    return True, "Allowed"


class SettingsSaveView(APIView):
    """POST /api/settings/save: operator-tier update of allowlisted provider keys/models in .env."""

    def post(self, request: Any) -> Any:
        auth_ctx = get_request_auth(request)
        if not auth_ctx.authenticated:
            return err_json("Authentication required", status=401, extra={"ok": False})
        if not auth_ctx.is_user_tier:
            return err_json(
                "Operator userTier authentication required to modify settings",
                status=403,
                extra={"ok": False, "error": "operator_tier_required"},
            )

        data, err = parse_json_body(request)
        if err is not None:
            return err_json("Invalid JSON payload", status=400, extra={"ok": False})

        updates: Dict[str, str] = {}
        for prov, env_key in PROVIDER_ENV_KEYS.items():
            if not env_key:
                continue
            val = str(data.get(prov) or data.get(env_key) or "").strip()
            if val and not val.startswith("***"):
                updates[env_key] = val

        req_provider = str(data.get("provider") or "").strip().lower()
        req_api_key = str(data.get("api_key") or "").strip()
        req_model = str(data.get("model") or "").strip()

        if req_provider:
            if req_provider not in PROVIDER_ENV_KEYS:
                return err_json(
                    f"Unknown provider '{req_provider}'",
                    status=400,
                    extra={"ok": False},
                )
            env_key = PROVIDER_ENV_KEYS[req_provider]
            if req_api_key and env_key and not req_api_key.startswith("***"):
                updates[env_key] = req_api_key
            updates["HUNTER_DEFAULT_PROVIDER"] = req_provider
            if req_model:
                updates["HUNTER_DEFAULT_MODEL"] = req_model
                DEFAULT_MODELS[req_provider] = req_model

        if "default_provider" in data and str(data["default_provider"]).strip().lower() in PROVIDER_ENV_KEYS:
            updates["HUNTER_DEFAULT_PROVIDER"] = str(data["default_provider"]).strip().lower()
        if "default_model" in data and str(data["default_model"]).strip():
            updates["HUNTER_DEFAULT_MODEL"] = str(data["default_model"]).strip()
        if "ollama_host" in data and str(data["ollama_host"]).strip():
            raw_ollama = str(data["ollama_host"]).strip()
            ok_host, reason_host = _validate_ollama_host_url(raw_ollama)
            if not ok_host:
                return err_json(
                    reason_host,
                    status=400,
                    extra={"ok": False, "error": "invalid_ollama_host"},
                )
            updates["OLLAMA_HOST"] = raw_ollama.rstrip("/")

        if updates:
            write_env_file(updates)
        return ok_json(
            {
                "ok": True,
                "updated_keys": [k for k in updates if not k.endswith("_KEY")],
                "masked_secrets": {k: mask_secret(v) for k, v in updates.items() if k.endswith("_KEY")},
            }
        )


class GlobalSkillsView(APIView):
    """GET /api/global-skills."""

    def get(self, request: Any) -> Any:
        try:
            from core.global_skills import global_skills_status

            return ok_json(global_skills_status())
        except Exception as exc:
            return ok_json({"skills": [], "error": str(exc)})


class AiDiagnosticsView(APIView):
    """GET /api/ai/diagnostics."""

    def get(self, request: Any) -> Any:
        try:
            from core.ai_diagnostics import run_full_ai_diagnostics

            diag = async_to_sync(run_full_ai_diagnostics)(verbose=False)
            return ok_json(diag)
        except Exception as exc:
            return ok_json({"ok": False, "error": str(exc)})


class ModelsCatalogView(APIView):
    """GET /api/models/catalog."""

    def get(self, request: Any) -> Any:
        catalog: Dict[str, Any] = {}
        try:
            catalog = async_to_sync(get_llm_router().catalog)()
        except Exception as exc:
            logger.debug("LLMRouter.catalog failed: %s", exc)
            catalog = {"policy": "balanced", "choices": [], "local": {"available": False, "models": []}, "cloud": []}
        try:
            providers = detect_live_providers()
        except Exception:
            providers = {}
        return ok_json(
            {
                **catalog,
                "providers": providers,
                "default_models": DEFAULT_MODELS,
                "provider_keys": list(PROVIDER_ENV_KEYS.keys()),
            }
        )


class AiModesView(APIView):
    """GET /api/ai/modes."""

    def get(self, request: Any) -> Any:
        try:
            from core.master_prompts import MasterPromptOrchestrator

            orch = MasterPromptOrchestrator()
            modes = getattr(orch, "list_modes", lambda: {})()
            return ok_json({"modes": modes})
        except Exception:
            return ok_json(
                {
                    "modes": [
                        {"id": "analyst", "name": "Analyst", "description": "Evidence-backed vulnerability analysis"},
                        {"id": "triage", "name": "Triage", "description": "7-Question Gate & severity validation"},
                        {"id": "planner", "name": "Planner", "description": "Attack path and recon planning"},
                        {"id": "reporter", "name": "Reporter", "description": "HackerOne/Bugcrowd report drafting"},
                    ]
                }
            )
