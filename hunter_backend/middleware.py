"""Async-capable Django 5.2 middlewares for CSP, static assets, and API CSRF guard."""

from __future__ import annotations

import asyncio
from typing import Any, Callable
from urllib.parse import urlparse

from asgiref.sync import iscoroutinefunction, markcoroutinefunction
from django.conf import settings
from django.http import JsonResponse, StreamingHttpResponse
from django.middleware.csrf import _check_token_format, _does_token_match, get_token
from django.utils.cache import patch_vary_headers
from django.utils.crypto import constant_time_compare
from django.utils.decorators import sync_and_async_middleware
from whitenoise.middleware import WhiteNoiseMiddleware

_MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_MULTIPART_ALLOWED_PATHS = {"/api/copilot/attachments"}
_BLOCKED_NOCORS_CONTENT_TYPES = {
    "text/plain",
    "application/x-www-form-urlencoded",
}


def _origin_matches_trusted(origin: str, request: Any) -> bool:
    """Return True if *origin* is explicitly trusted or matches the request host."""
    normalized = (origin or "").strip().rstrip("/")
    if not normalized or normalized.lower() == "null":
        return False

    trusted = {
        str(item).strip().rstrip("/")
        for item in (
            *getattr(settings, "CSRF_TRUSTED_ORIGINS", ()),
            *getattr(settings, "CORS_ALLOWED_ORIGINS", ()),
        )
        if item
    }
    if normalized in trusted:
        return True

    try:
        parsed = urlparse(normalized)
        req_host = request.get_host()
        req_scheme = "https" if request.is_secure() else "http"
        return bool(
            parsed.scheme == req_scheme
            and parsed.netloc
            and parsed.netloc.lower() == req_host.lower()
        )
    except Exception:
        return False


def _has_valid_csrf_header(request: Any) -> bool:
    """Validate double-submit CSRF cookie + X-CSRFToken header using Django helpers."""
    cookie_name = getattr(settings, "CSRF_COOKIE_NAME", "csrftoken")
    csrf_cookie = request.COOKIES.get(cookie_name, "")
    header_token = request.META.get("HTTP_X_CSRFTOKEN", "")
    if not csrf_cookie or not header_token:
        return False
    try:
        _check_token_format(csrf_cookie)
        _check_token_format(header_token)
        if len(header_token) == len(csrf_cookie) and constant_time_compare(header_token, csrf_cookie):
            return True
        return _does_token_match(header_token, csrf_cookie)
    except Exception:
        return False


def _check_mutation_security(request: Any) -> JsonResponse | None:
    """Enforce origin, Sec-Fetch-Site, CSRF token, and JSON content-type guards."""
    if request.method not in _MUTATING_METHODS:
        return None

    origin = request.META.get("HTTP_ORIGIN")
    if origin is not None and not _origin_matches_trusted(origin, request):
        return JsonResponse(
            {"detail": "Untrusted Origin rejected.", "error": "csrf_origin_rejected"},
            status=403,
        )

    sec_fetch_site = (request.META.get("HTTP_SEC_FETCH_SITE") or "").strip().lower()
    if sec_fetch_site == "cross-site":
        return JsonResponse(
            {"detail": "Cross-site mutation rejected.", "error": "csrf_cross_site"},
            status=403,
        )

    # Whenever X-CSRFToken header is supplied, ensure it strictly matches the cookie.
    header_token = request.META.get("HTTP_X_CSRFTOKEN")
    csrf_valid = _has_valid_csrf_header(request)
    if header_token is not None and not csrf_valid:
        return JsonResponse(
            {"detail": "Invalid or missing CSRF token.", "error": "csrf_invalid"},
            status=403,
        )

    raw_ct = request.META.get("CONTENT_TYPE", "")
    content_type = raw_ct.split(";", 1)[0].strip().lower()

    # Block browser no-cors / HTML form content types unless a verified CSRF token is present.
    if content_type in _BLOCKED_NOCORS_CONTENT_TYPES:
        return JsonResponse(
            {
                "detail": "Simple form/text Content-Type is rejected to prevent no-cors CSRF; use application/json.",
                "error": "csrf_content_type_rejected",
            },
            status=403,
        )

    if content_type == "multipart/form-data":
        if request.path_info.rstrip("/") not in _MULTIPART_ALLOWED_PATHS:
            return JsonResponse(
                {
                    "detail": "Multipart payload is not permitted on this endpoint.",
                    "error": "csrf_multipart_rejected",
                },
                status=403,
            )
        return None

    # Empty-body mutations (e.g., /api/platform/runs/<id>/pause) are allowed for trusted
    # same-origin / non-cross-site browser calls (already origin + Sec-Fetch-Site checked)
    # and local CLI/test clients.
    try:
        body_len = len(request.body)
    except Exception:
        body_len = int(request.META.get("CONTENT_LENGTH") or 0)

    if body_len == 0 and not content_type:
        if origin is not None and request.COOKIES and not csrf_valid and not _origin_matches_trusted(origin, request):
            return JsonResponse(
                {"detail": "CSRF validation failed.", "error": "csrf_failed"},
                status=403,
            )
        return None

    # Browser requests (Origin present) carrying a payload must use application/json or valid CSRF token.
    if origin is not None and content_type != "application/json" and not csrf_valid:
        return JsonResponse(
            {
                "detail": "Mutating browser requests must send application/json or valid X-CSRFToken.",
                "error": "csrf_json_required",
            },
            status=403,
        )

    return None


@sync_and_async_middleware
def SecurityHeadersMiddleware(get_response: Callable[..., Any]) -> Callable[..., Any]:
    """Attach CSP and defensive browser security headers on all HTTP responses."""
    csp = getattr(settings, "CSP_POLICY", "")

    def _apply_headers(response: Any) -> Any:
        if csp and "Content-Security-Policy" not in response:
            response["Content-Security-Policy"] = csp
        response.setdefault("X-Content-Type-Options", "nosniff")
        response.setdefault("X-Frame-Options", "SAMEORIGIN")
        response.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        return response

    if iscoroutinefunction(get_response):

        async def middleware(request: Any) -> Any:
            response = await get_response(request)
            return _apply_headers(response)

        markcoroutinefunction(middleware)
        return middleware

    def middleware(request: Any) -> Any:
        response = get_response(request)
        return _apply_headers(response)

    return middleware


@sync_and_async_middleware
def ApiCsrfAndJsonGuardMiddleware(
    get_response: Callable[..., Any],
) -> Callable[..., Any]:
    """Reject cross-site/no-cors browser mutations while preserving API & cookie CSRF flows."""

    def _prepare_csrf_cookie(request: Any) -> None:
        cookie_name = getattr(settings, "CSRF_COOKIE_NAME", "csrftoken")
        existing_cookie = request.COOKIES.get(cookie_name, "")
        if existing_cookie and "CSRF_COOKIE" not in request.META:
            try:
                _check_token_format(existing_cookie)
                request.META["CSRF_COOKIE"] = existing_cookie
            except Exception:
                pass
        if request.path_info == "/api/csrf" or (
            request.method == "GET" and not existing_cookie
        ):
            get_token(request)

    def _finalize_csrf_cookie(request: Any, response: Any) -> Any:
        if request.META.get("CSRF_COOKIE_NEEDS_UPDATE") and request.META.get("CSRF_COOKIE"):
            cookie_name = getattr(settings, "CSRF_COOKIE_NAME", "csrftoken")
            response.set_cookie(
                cookie_name,
                request.META["CSRF_COOKIE"],
                max_age=getattr(settings, "CSRF_COOKIE_AGE", 31449600),
                domain=getattr(settings, "CSRF_COOKIE_DOMAIN", None),
                path=getattr(settings, "CSRF_COOKIE_PATH", "/"),
                secure=getattr(settings, "CSRF_COOKIE_SECURE", False),
                httponly=getattr(settings, "CSRF_COOKIE_HTTPONLY", False),
                samesite=getattr(settings, "CSRF_COOKIE_SAMESITE", "Lax"),
            )
            patch_vary_headers(response, ("Cookie",))
        return response

    if iscoroutinefunction(get_response):

        async def middleware(request: Any) -> Any:
            _prepare_csrf_cookie(request)
            blocked = _check_mutation_security(request)
            if blocked is not None:
                return blocked
            response = await get_response(request)
            return _finalize_csrf_cookie(request, response)

        markcoroutinefunction(middleware)
        return middleware

    def middleware(request: Any) -> Any:
        _prepare_csrf_cookie(request)
        blocked = _check_mutation_security(request)
        if blocked is not None:
            return blocked
        response = get_response(request)
        return _finalize_csrf_cookie(request, response)

    return middleware


class AsyncWhiteNoiseMiddleware(WhiteNoiseMiddleware):
    """Async-capable WhiteNoise wrapper so ASGI SSE/async views never fall back to sync."""

    sync_capable = True
    async_capable = True

    def __init__(self, get_response: Callable[..., Any] | None = None, settings: Any = settings) -> None:
        super().__init__(get_response=get_response, settings=settings)
        self._is_async = bool(get_response and iscoroutinefunction(get_response))
        if self._is_async:
            markcoroutinefunction(self)

    def __call__(self, request: Any) -> Any:
        if self._is_async:
            return self._acall(request)
        if self.autorefresh:
            static_file = self.find_file(request.path_info)
        else:
            static_file = self.files.get(request.path_info)
        if static_file is not None:
            return self.serve(static_file, request)
        return self.get_response(request)

    async def _acall(self, request: Any) -> Any:
        if self.autorefresh:
            static_file = await asyncio.to_thread(self.find_file, request.path_info)
        else:
            static_file = self.files.get(request.path_info)
        if static_file is not None:
            resp = await asyncio.to_thread(self.serve, static_file, request)
            if isinstance(resp, StreamingHttpResponse) and not hasattr(resp.streaming_content, "__aiter__"):
                sync_iter = resp.streaming_content

                async def _async_chunks():
                    try:
                        for chunk in sync_iter:
                            yield chunk
                    finally:
                        close_fn = getattr(sync_iter, "close", None)
                        if callable(close_fn):
                            close_fn()

                resp.streaming_content = _async_chunks()
            return resp
        return await self.get_response(request)
