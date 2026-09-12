"""
Application State Detector
==========================
Analyzes DOM content, page title, URL patterns, tokens, and cookies to classify
the semantic state of the web application (LOGIN, AUTHENTICATED, DASHBOARD, etc.).
"""
from __future__ import annotations

import logging
import re
from enum import Enum
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

logger = logging.getLogger("hunter_ai.state_detector")


class SemanticAppState(str, Enum):
    GUEST = "GUEST"
    LOGIN_PAGE = "LOGIN_PAGE"
    REGISTRATION_PAGE = "REGISTRATION_PAGE"
    AUTHENTICATED = "AUTHENTICATED"
    DASHBOARD = "DASHBOARD"
    USER_PROFILE = "USER_PROFILE"
    SETTINGS = "SETTINGS"
    ADMIN_PORTAL = "ADMIN_PORTAL"
    UPLOAD_SURFACE = "UPLOAD_SURFACE"
    ERROR_PAGE = "ERROR_PAGE"
    MODAL_ACTIVE = "MODAL_ACTIVE"


class StateDetector:
    """Classifies application states based on DOM indicators and URL heuristics"""

    AUTH_KEYWORDS = ("logout", "sign out", "log out", "my account", "signout", "dashboard", "logged in as")
    LOGIN_KEYWORDS = ("login", "sign in", "signin", "log in", "enter credentials", "authenticate")
    REGISTER_KEYWORDS = ("register", "sign up", "signup", "create account", "join")
    ADMIN_KEYWORDS = ("/admin", "/wp-admin", "/console", "/manage", "/cpanel", "administrator")
    UPLOAD_KEYWORDS = ("upload", "multipart/form-data", 'type="file"', "type='file'", "choose file")

    @classmethod
    def detect_state(
        cls,
        url: str,
        html: str,
        cookies: Optional[List[Dict[str, Any]]] = None,
        local_storage: Optional[Dict[str, str]] = None,
    ) -> SemanticAppState:
        lower_html = (html or "").lower()
        parsed_url = urlparse(url)
        path = parsed_url.path.lower()

        # Check for error pages
        if any(err in lower_html for err in ("404 not found", "500 internal server error", "access denied", "forbidden")):
            return SemanticAppState.ERROR_PAGE

        # Check for active modal
        if any(kw in lower_html for kw in ("role=\"dialog\"", "class=\"modal show\"", "aria-modal=\"true\"", "<dialog open")):
            return SemanticAppState.MODAL_ACTIVE

        # Check for admin portal
        if any(ak in path for ak in cls.ADMIN_KEYWORDS) or "admin panel" in lower_html:
            return SemanticAppState.ADMIN_PORTAL

        # Check for upload surface
        if any(uk in lower_html for uk in cls.UPLOAD_KEYWORDS):
            return SemanticAppState.UPLOAD_SURFACE

        # Check for user profile / settings
        if "/settings" in path or "/account/settings" in path:
            return SemanticAppState.SETTINGS
        if "/profile" in path or "/user/" in path:
            return SemanticAppState.USER_PROFILE
        if "/dashboard" in path or "/home" in path:
            return SemanticAppState.DASHBOARD

        # Check for authenticated session indicators (cookies/tokens/logout button)
        has_auth_cookie = bool(cookies and any(
            c.get("name", "").lower() in ("session", "token", "jwt", "auth", "logged_in", "connect.sid")
            for c in cookies
        ))
        has_auth_token = bool(local_storage and any(
            "token" in k.lower() or "jwt" in k.lower() or "auth" in k.lower()
            for k in local_storage.keys()
        ))
        has_logout_text = any(kw in lower_html for kw in cls.AUTH_KEYWORDS)

        if has_logout_text or has_auth_token:
            return SemanticAppState.AUTHENTICATED

        # Check for login form
        if any(lk in path for lk in ("login", "signin")) or (
            any(lk in lower_html for lk in cls.LOGIN_KEYWORDS) and 'type="password"' in lower_html
        ):
            return SemanticAppState.LOGIN_PAGE

        # Check for registration
        if any(rk in path for rk in ("register", "signup")) or (
            any(rk in lower_html for rk in cls.REGISTER_KEYWORDS) and 'type="password"' in lower_html
        ):
            return SemanticAppState.REGISTRATION_PAGE

        return SemanticAppState.GUEST
