"""Top-level HTML redirect and API capability index views."""

from __future__ import annotations

import os
from urllib.parse import quote

from django.http import HttpRequest, HttpResponseRedirect, JsonResponse
from django.views.decorators.http import require_GET

from hunter_backend.apps.common import SECTION_ALLOWLIST_RE

FRONTEND_URL = os.environ.get("HUNTERAI_FRONTEND_URL", "http://127.0.0.1:3000").rstrip("/")


def _wants_json(request: HttpRequest) -> bool:
    accept = (request.META.get("HTTP_ACCEPT") or "").lower()
    fmt = (request.GET.get("format") or "").strip().lower()
    return fmt == "json" or (
        "application/json" in accept and "text/html" not in accept
    )


@require_GET
async def index_view(request: HttpRequest) -> HttpResponseRedirect | JsonResponse:
    """Redirect browser navigation to Next.js UI or return API JSON metadata."""
    raw_section = (request.GET.get("section") or "").strip()
    safe_section = (
        raw_section if SECTION_ALLOWLIST_RE.fullmatch(raw_section) else ""
    )

    if _wants_json(request):
        return JsonResponse(
            {
                "service": "hunter-ai-django-asgi",
                "backend": "django-asgi",
                "status": "online",
                "frontend_url": FRONTEND_URL,
                "section": safe_section or "overview",
                "routes": {
                    "overview": "/",
                    "chat": "/chat",
                    "command": "/command",
                    "opencode": "/opencode",
                    "studio": "/studio",
                },
                "endpoints": {
                    "overview": "/api/platform/overview",
                    "csrf": "/api/csrf",
                    "stream": "/api/platform/stream",
                    "ws_platform": "/ws/platform",
                    "ws_chat": "/ws/chat",
                },
            }
        )

    suffix = f"/?section={quote(safe_section)}" if safe_section else "/"
    return HttpResponseRedirect(f"{FRONTEND_URL}{suffix}")


@require_GET
async def opencode_redirect_view(request: HttpRequest) -> HttpResponseRedirect | JsonResponse:
    """Redirect /opencode to Next.js Studio page (or return JSON metadata)."""
    target = f"{FRONTEND_URL}/studio"
    if _wants_json(request):
        return JsonResponse(
            {
                "service": "hunter-ai-django-asgi",
                "status": "online",
                "route": "/opencode",
                "redirect_to": target,
            }
        )
    return HttpResponseRedirect(target)


@require_GET
async def chat_redirect_view(request: HttpRequest) -> HttpResponseRedirect | JsonResponse:
    """Redirect /chat to Next.js Copilot panel (or return JSON metadata)."""
    target = f"{FRONTEND_URL}/?copilot=open"
    if _wants_json(request):
        return JsonResponse(
            {
                "service": "hunter-ai-django-asgi",
                "status": "online",
                "route": "/chat",
                "redirect_to": target,
            }
        )
    return HttpResponseRedirect(target)


@require_GET
async def command_redirect_view(request: HttpRequest) -> HttpResponseRedirect | JsonResponse:
    """Redirect /command to Next.js home command surface (or return JSON metadata)."""
    target = f"{FRONTEND_URL}/"
    if _wants_json(request):
        return JsonResponse(
            {
                "service": "hunter-ai-django-asgi",
                "status": "online",
                "route": "/command",
                "redirect_to": target,
            }
        )
    return HttpResponseRedirect(target)
