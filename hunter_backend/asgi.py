"""Pure ASGI 3.0 entrypoint wrapping Django HTTP, WebSockets, and ASGI lifespan."""

from __future__ import annotations

import logging
import os
from typing import Any, Callable, Dict

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "hunter_backend.settings")

from django.core.asgi import get_asgi_application

from hunter_backend.runtime import shutdown_runtime, startup_runtime
from hunter_backend.websocket import websocket_application

logger = logging.getLogger("hunter_backend.asgi")

_django_http_app = get_asgi_application()


async def _handle_lifespan(
    scope: Dict[str, Any],
    receive: Callable[..., Any],
    send: Callable[..., Any],
) -> None:
    """Handle ASGI lifespan.startup and lifespan.shutdown cleanly."""
    while True:
        message = await receive()
        msg_type = message.get("type")
        if msg_type == "lifespan.startup":
            try:
                await startup_runtime()
                await send({"type": "lifespan.startup.complete"})
            except Exception as exc:
                logger.exception("ASGI lifespan startup failed")
                await send({"type": "lifespan.startup.failed", "message": str(exc)})
                return
        elif msg_type == "lifespan.shutdown":
            try:
                await shutdown_runtime()
            except Exception:
                logger.exception("ASGI lifespan shutdown failed")
            await send({"type": "lifespan.shutdown.complete"})
            return


async def application(
    scope: Dict[str, Any],
    receive: Callable[..., Any],
    send: Callable[..., Any],
) -> None:
    """Top-level ASGI 3.0 dispatcher for lifespan, WebSockets, and Django HTTP."""
    scope_type = scope.get("type")
    if scope_type == "lifespan":
        await _handle_lifespan(scope, receive, send)
        return
    if scope_type == "websocket":
        await websocket_application(scope, receive, send)
        return
    if scope_type == "http":
        await _django_http_app(scope, receive, send)
        return
    raise NotImplementedError(f"Unsupported ASGI scope type: {scope_type!r}")
