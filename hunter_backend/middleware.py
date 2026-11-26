"""Async-capable Django 5.2 middlewares for CSP, local auth, static assets, and API CSRF guard."""

from __future__ import annotations

import asyncio
import logging
import re
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

from hunter_backend.auth import (
    ANONYMOUS_AUTH,
    LOGIN_GUARD,
    USER_TIER,
    authenticate_request,
    extract_client_ip,
)

logger = logging.getLogger("hunter_backend.middleware")

_MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
_MULTIPART_ALLOWED_PATHS = {"/api/copilot/attachments"}
_BLOCKED_NOCORS_CONTENT_TYPES = {
    "text/plain",
    "application/x-www-form-urlencoded",
}

# Unauthenticated read-only paths (strictly GET/HEAD/OPTIONS)
_PUBLIC_READ_PATHS = {
    "/",
    "/chat",
    "/command",
    "/opencode",
    "/api/health",
    "/api/csrf",
    "/api/platform/artex/health",
}
# Auth login exchange endpoint validates credentials itself
_PUBLIC_AUTH_EXCHANGE_PATHS = {
    "/api/auth/session",
}

# Operator-only privileged mutation paths requiring authenticated userTier
_USER_TIER_EXACT_PATHS = {
    "/api/settings/save",
    "/api/control/settings",
    "/api/control/redteam-policy/issue",
    "/api/control/redteam-policy/revoke",
    "/api/editor/file/save",
    "/api/editor/file/create",
    "/api/opencode/skill-file/save",
    "/api/auth/revoke",
}
_USER_TIER_PATH_REGEXES = (
    re.compile(r"^/api/platform/approvals/[^/]+/decide/?$"),
)


def _normalized_path(request: Any) -> str:
    raw = str(getattr(request, "path_info", "") or "/")
    stripped = raw.rstrip("/")
    return stripped or "/"


def _is_public_route(request: Any) -> bool:
    path = _normalized_path(request)
    if request.method in _SAFE_METHODS:
        if path in _PUBLIC_READ_PATHS or path.startswith("/static/"):
            return True
    if request.method == "POST" and path in _PUBLIC_AUTH_EXCHANGE_PATHS:
        return True
    return False


def _requires_user_tier(request: Any) -> bool:
    if request.method not in _MUTATING_METHODS:
        return False
    path = _normalized_path(request)
    if path in _USER_TIER_EXACT_PATHS:
        return True
    return any(rx.match(path) for rx in _USER_TIER_PATH_REGEXES)


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
    except Exception as exc:
        logger.debug("Origin parsing failed for %r: %s", origin, exc)
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
    except Exception as exc:
        logger.debug("CSRF token verification failed: %s", exc)
        return False


def _has_valid_bearer_auth(request: Any) -> bool:
    attached = getattr(request, "hunter_auth", None)
    if attached is not None:
        return bool(attached.authenticated and attached.is_bearer)
    ctx, _supplied = authenticate_request(request)
    return bool(ctx.authenticated and ctx.is_bearer)


def _check_local_auth(request: Any) -> JsonResponse | None:
    """Authenticate caller, enforce LoginGuard rate-limiting, and check tier boundaries."""
    if request.method == "OPTIONS":
        request.hunter_auth = ANONYMOUS_AUTH
        return None

    client_ip = extract_client_ip(request)
    blocked, retry_after = LOGIN_GUARD.is_blocked(client_ip)
    if blocked and not _is_public_route(request):
        resp = JsonResponse(
            {
                "detail": "Too many failed authentication attempts. Try again later.",
                "error": "auth_rate_limited",
                "retry_after": retry_after,
            },
            status=429,
        )
        resp["Retry-After"] = str(retry_after)
        return resp

    auth_ctx, creds_supplied = authenticate_request(request)
    request.hunter_auth = auth_ctx

    if creds_supplied and not auth_ctx.authenticated:
        locked, lock_retry = LOGIN_GUARD.record_failure(client_ip)
        if locked:
            resp = JsonResponse(
                {
                    "detail": "Too many failed authentication attempts. Account locked temporarily.",
                    "error": "auth_rate_limited",
                    "retry_after": lock_retry,
                },
                status=429,
            )
            resp["Retry-After"] = str(lock_retry)
            return resp
        return JsonResponse(
            {"detail": "Invalid authentication credentials.", "error": "auth_invalid"},
            status=401,
        )

    if auth_ctx.authenticated:
        LOGIN_GUARD.record_success(client_ip)

    if _is_public_route(request):
        return None

    if not auth_ctx.authenticated:
        # Preserve explicit 403 for cross-site / evil-Origin / no-cors browser mutation attempts
        if request.method in _MUTATING_METHODS:
            origin = request.META.get("HTTP_ORIGIN")
            sec_fetch_site = (request.META.get("HTTP_SEC_FETCH_SITE") or "").strip().lower()
            raw_ct = request.META.get("CONTENT_TYPE", "")
            content_type = raw_ct.split(";", 1)[0].strip().lower()
            if origin is not None and not _origin_matches_trusted(origin, request):
                return JsonResponse(
                    {"detail": "Untrusted Origin rejected.", "error": "csrf_origin_rejected"},
                    status=403,
                )
            if sec_fetch_site == "cross-site":
                return JsonResponse(
                    {"detail": "Cross-site mutation rejected.", "error": "csrf_cross_site"},
                    status=403,
                )
            if content_type in _BLOCKED_NOCORS_CONTENT_TYPES:
                return JsonResponse(
                    {
                        "detail": "Simple form/text Content-Type is rejected to prevent no-cors CSRF; use application/json.",
                        "error": "csrf_content_type_rejected",
                    },
                    status=403,
                )
        return JsonResponse(
            {
                "detail": "Authentication required. Supply Authorization: Bearer <token> or valid session.",
                "error": "auth_required",
            },
            status=401,
        )

    if _requires_user_tier(request) and auth_ctx.tier != USER_TIER:
        return JsonResponse(
            {
                "detail": "Operator userTier authentication is required for this endpoint.",
                "error": "operator_tier_required",
            },
            status=403,
        )

    return None


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

    # Block browser no-cors / HTML form content types on all mutations.
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

    has_valid_bearer = _has_valid_bearer_auth(request)
    if has_valid_bearer:
        return None

    # Allow /api/auth/session login exchange with trusted Origin (or direct local CLI token exchange)
    if _normalized_path(request) in _PUBLIC_AUTH_EXCHANGE_PATHS:
        if origin is not None and not _origin_matches_trusted(origin, request):
            return JsonResponse(
                {"detail": "Untrusted Origin rejected.", "error": "csrf_origin_rejected"},
                status=403,
            )
        return None

    # Non-bearer state-changing requests MUST provide a trusted Origin AND valid X-CSRFToken
    # (closes JSON POST CSRF bypass and missing-Origin browser bypass).
    if origin is None or not _origin_matches_trusted(origin, request):
        return JsonResponse(
            {
                "detail": "Trusted Origin header is required for non-bearer state-changing requests.",
                "error": "csrf_origin_required",
            },
            status=403,
        )

    if not csrf_valid:
        return JsonResponse(
            {
                "detail": "Valid X-CSRFToken header matching csrftoken cookie is required for non-bearer mutations.",
                "error": "csrf_token_required",
            },
            status=403,
        )

    return None


@sync_and_async_middleware
def LocalAuthMiddleware(get_response: Callable[..., Any]) -> Callable[..., Any]:
    """Authenticate requests via local bearer token or signed session cookie."""
    if iscoroutinefunction(get_response):

        async def middleware(request: Any) -> Any:
            blocked = _check_local_auth(request)
            if blocked is not None:
                return blocked
            return await get_response(request)

        markcoroutinefunction(middleware)
        return middleware

    def middleware(request: Any) -> Any:
        blocked = _check_local_auth(request)
        if blocked is not None:
            return blocked
        return get_response(request)

    return middleware


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
