"""Pure ASGI 3.0 WebSocket router and Origin-validated connection adapter."""

from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import Any, Callable, Dict, Optional
from urllib.parse import parse_qs

from django.conf import settings

from core.run_control import GLOBAL_RUN_CONTROLLER
from hunter_backend.apps.common import call_ai
from hunter_backend.auth import ANONYMOUS_AUTH, AuthContext, authenticate_headers
from hunter_backend.runtime import (
    EVENT_BUS,
    _ACTIVE_MASTER_MISSIONS,
    copilot_state,
    ensure_platform_wiring,
)

logger = logging.getLogger("hunter_backend.websocket")

_MISSION_WS_RE = re.compile(r"^/ws/mission/(?P<session_id>[^/]+)/?$")


def _extract_headers(scope: Dict[str, Any]) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    for k, v in scope.get("headers") or ():
        headers[k.decode("latin-1").lower()] = v.decode("latin-1")
    return headers


def is_ws_origin_allowed(origin: Optional[str], *, has_valid_bearer: bool = False) -> bool:
    """Enforce fail-closed WS Origin allowlist; missing Origin requires valid bearer auth."""
    if origin is None:
        return bool(has_valid_bearer)
    cleaned = origin.strip().rstrip("/").lower()
    if not cleaned or cleaned == "null":
        return False
    allowed = {
        str(item).strip().rstrip("/").lower()
        for item in getattr(settings, "WS_ALLOWED_ORIGINS", ())
        if item
    }
    return cleaned in allowed


class WSConnection:
    """Minimal ASGI 3.0 WebSocket helper with send_json / receive_json."""

    def __init__(
        self,
        scope: Dict[str, Any],
        receive: Callable[..., Any],
        send: Callable[..., Any],
        *,
        auth: AuthContext = ANONYMOUS_AUTH,
    ) -> None:
        self.scope = scope
        self._receive = receive
        self._send = send
        self.auth = auth
        self.closed = False
        self.query = parse_qs(
            (scope.get("query_string") or b"").decode("utf-8", errors="replace")
        )

    async def accept(self, subprotocol: Optional[str] = None) -> None:
        msg: Dict[str, Any] = {"type": "websocket.accept"}
        if subprotocol:
            msg["subprotocol"] = subprotocol
        await self._send(msg)

    async def close(self, code: int = 1000, reason: str = "") -> None:
        if self.closed:
            return
        self.closed = True
        await self._send({"type": "websocket.close", "code": code, "reason": reason})

    async def send_text(self, text: str) -> None:
        if not self.closed:
            await self._send({"type": "websocket.send", "text": text})

    async def send_json(self, data: Any) -> None:
        await self.send_text(json.dumps(data, default=str))

    async def receive_raw(self) -> Dict[str, Any]:
        msg = await self._receive()
        if msg.get("type") == "websocket.disconnect":
            self.closed = True
        return msg

    async def receive_json(self) -> Optional[Dict[str, Any]]:
        msg = await self.receive_raw()
        if msg.get("type") != "websocket.receive":
            return None
        text = msg.get("text")
        if text is None and msg.get("bytes") is not None:
            text = msg["bytes"].decode("utf-8", errors="replace")
        if not text:
            return {}
        try:
            parsed = json.loads(text)
            return parsed if isinstance(parsed, dict) else {"message": str(parsed)}
        except Exception:
            return {"message": text}


async def _handle_ws_platform(ws: WSConnection) -> None:
    store = ensure_platform_wiring()
    await ws.accept()

    raw_since = (ws.query.get("since_seq") or [None])[0]
    since_seq = int(raw_since) if raw_since and raw_since.lstrip("-").isdigit() else None
    run_filter = (ws.query.get("run_id") or [None])[0]
    eng_filter = (ws.query.get("engagement_id") or [None])[0]

    q = EVENT_BUS.subscribe()
    try:
        backlog = EVENT_BUS.backlog_since(
            since_seq, run_id=run_filter, engagement_id=eng_filter, limit=100
        )
        for ev in backlog:
            await ws.send_json({"type": "event", "event": ev})

        await ws.send_json(
            {"type": "ready", "latest_seq": store.latest_seq(), "context": store.get_context()}
        )

        recv_task = asyncio.create_task(ws.receive_raw())
        q_task = asyncio.create_task(q.get())
        try:
            while not ws.closed:
                done, _ = await asyncio.wait(
                    {recv_task, q_task},
                    timeout=20.0,
                    return_when=asyncio.FIRST_COMPLETED,
                )
                if not done:
                    await ws.send_json({"type": "ping"})
                    continue

                if q_task in done:
                    ev = q_task.result()
                    if (not run_filter or ev.get("run_id") == run_filter) and (
                        not eng_filter or ev.get("engagement_id") == eng_filter
                    ):
                        await ws.send_json({"type": "event", "event": ev})
                    q_task = asyncio.create_task(q.get())

                if recv_task in done:
                    raw_msg = recv_task.result()
                    if raw_msg.get("type") == "websocket.disconnect":
                        break
                    text = raw_msg.get("text") or ""
                    try:
                        cmd = json.loads(text) if text else {}
                    except Exception:
                        cmd = {}
                    action = str(cmd.get("action") or cmd.get("type") or "").lower()
                    if action == "ping":
                        await ws.send_json({"type": "pong"})
                    elif action in {"pause", "resume", "stop"} and cmd.get("run_id"):
                        if not ws.auth.is_user_tier:
                            await ws.send_json(
                                {
                                    "type": "error",
                                    "error": "operator_tier_required",
                                    "detail": "Operator authentication is required for run control actions.",
                                }
                            )
                            recv_task = asyncio.create_task(ws.receive_raw())
                            continue
                        rid = str(cmd["run_id"])
                        ok = False
                        if action == "pause":
                            ok = GLOBAL_RUN_CONTROLLER.pause(rid)
                        elif action == "resume":
                            ok = GLOBAL_RUN_CONTROLLER.resume(rid)
                        elif action == "stop":
                            ok = await GLOBAL_RUN_CONTROLLER.stop(rid, force=True)
                        await ws.send_json({"type": "control_ack", "action": action, "run_id": rid, "ok": ok})
                    recv_task = asyncio.create_task(ws.receive_raw())
        finally:
            for t in (recv_task, q_task):
                if not t.done():
                    t.cancel()
    except asyncio.CancelledError:
        pass
    finally:
        EVENT_BUS.unsubscribe(q)
        await ws.close()


async def _handle_ws_chat(ws: WSConnection) -> None:
    await ws.accept()
    copilot_state.setdefault("connected_ws", []).append(ws)
    await ws.send_json({"type": "ready", "channel": "chat"})
    try:
        while not ws.closed:
            payload = await ws.receive_json()
            if payload is None:
                break
            if payload.get("type") == "ping" or payload.get("action") == "ping":
                await ws.send_json({"type": "pong"})
                continue
            message = str(payload.get("message") or payload.get("prompt") or "").strip()
            if not message:
                continue
            reply = await call_ai(
                message,
                provider=payload.get("provider"),
                model=payload.get("model"),
            )
            await ws.send_json({"type": "response", "content": reply, "done": True})
    except asyncio.CancelledError:
        pass
    finally:
        try:
            copilot_state.get("connected_ws", []).remove(ws)
        except ValueError:
            pass
        await ws.close()


async def _handle_ws_scan(ws: WSConnection) -> None:
    await ws.accept()
    q = EVENT_BUS.subscribe()
    await ws.send_json({"type": "ready", "channel": "scan"})
    recv_task = asyncio.create_task(ws.receive_raw())
    q_task = asyncio.create_task(q.get())
    try:
        while not ws.closed:
            done, _ = await asyncio.wait(
                {recv_task, q_task},
                timeout=20.0,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if not done:
                await ws.send_json({"type": "ping"})
                continue
            if q_task in done:
                ev = q_task.result()
                await ws.send_json({"type": "scan_event", "event": ev})
                q_task = asyncio.create_task(q.get())
            if recv_task in done:
                raw_msg = recv_task.result()
                if raw_msg.get("type") == "websocket.disconnect":
                    break
                await ws.send_json({"type": "ack"})
                recv_task = asyncio.create_task(ws.receive_raw())
    except asyncio.CancelledError:
        pass
    finally:
        for t in (recv_task, q_task):
            if not t.done():
                t.cancel()
        EVENT_BUS.unsubscribe(q)
        await ws.close()


async def _handle_ws_mission(ws: WSConnection, session_id: str) -> None:
    await ws.accept()
    mission = _ACTIVE_MASTER_MISSIONS.get(session_id) or {"session_id": session_id, "status": "unknown"}
    await ws.send_json({"type": "mission_state", "session_id": session_id, "mission": mission})
    q = EVENT_BUS.subscribe()
    recv_task = asyncio.create_task(ws.receive_raw())
    q_task = asyncio.create_task(q.get())
    try:
        while not ws.closed:
            done, _ = await asyncio.wait(
                {recv_task, q_task},
                timeout=20.0,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if not done:
                await ws.send_json({"type": "ping"})
                continue
            if q_task in done:
                ev = q_task.result()
                if ev.get("run_id") in {session_id, mission.get("run_id")}:
                    await ws.send_json({"type": "mission_event", "event": ev})
                q_task = asyncio.create_task(q.get())
            if recv_task in done:
                raw_msg = recv_task.result()
                if raw_msg.get("type") == "websocket.disconnect":
                    break
                recv_task = asyncio.create_task(ws.receive_raw())
    except asyncio.CancelledError:
        pass
    finally:
        for t in (recv_task, q_task):
            if not t.done():
                t.cancel()
        EVENT_BUS.unsubscribe(q)
        await ws.close()


async def _handle_ws_learn(ws: WSConnection) -> None:
    await ws.accept()
    await ws.send_json({"type": "ready", "channel": "learn", "topics": copilot_state.get("learning_topics", [])})
    try:
        while not ws.closed:
            payload = await ws.receive_json()
            if payload is None:
                break
            if payload.get("action") == "ping" or payload.get("type") == "ping":
                await ws.send_json({"type": "pong"})
                continue
            topic = str(payload.get("topic") or "").strip()
            await ws.send_json({"type": "learn_status", "topic": topic, "status": "acknowledged"})
    except asyncio.CancelledError:
        pass
    finally:
        await ws.close()


async def websocket_application(
    scope: Dict[str, Any],
    receive: Callable[..., Any],
    send: Callable[..., Any],
) -> None:
    """Pure ASGI WebSocket dispatcher enforcing fail-closed CSWSH Origin & bearer checks."""
    headers = _extract_headers(scope)
    auth_ctx, creds_supplied = authenticate_headers(headers)
    if creds_supplied and not auth_ctx.authenticated:
        logger.warning("Rejected WebSocket upgrade with invalid credentials")
        await send({"type": "websocket.close", "code": 4401})
        return

    origin = headers.get("origin")
    has_valid_bearer = bool(auth_ctx.authenticated and auth_ctx.is_bearer)
    if not is_ws_origin_allowed(origin, has_valid_bearer=has_valid_bearer):
        logger.warning("Rejected WebSocket upgrade with missing/untrusted Origin: %r", origin)
        await send({"type": "websocket.close", "code": 4403})
        return

    if not auth_ctx.authenticated:
        logger.warning("Rejected unauthenticated WebSocket upgrade on %r", scope.get("path"))
        await send({"type": "websocket.close", "code": 4401})
        return

    path = (scope.get("path") or "").rstrip("/") or "/"
    ws = WSConnection(scope, receive, send, auth=auth_ctx)

    if path == "/ws/platform":
        await _handle_ws_platform(ws)
    elif path == "/ws/chat":
        await _handle_ws_chat(ws)
    elif path == "/ws/scan":
        await _handle_ws_scan(ws)
    elif path == "/ws/learn":
        await _handle_ws_learn(ws)
    else:
        match = _MISSION_WS_RE.match(scope.get("path") or "")
        if match:
            await _handle_ws_mission(ws, match.group("session_id"))
        else:
            await send({"type": "websocket.close", "code": 4404})
