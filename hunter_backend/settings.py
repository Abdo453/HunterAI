"""Django 5.2 settings for the unified HunterAI ASGI backend."""

from __future__ import annotations

import os
from pathlib import Path

from corsheaders.defaults import default_headers

from hunter_backend.secrets_util import get_or_create_secret

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = get_or_create_secret(
    "HUNTERAI_DJANGO_SECRET",
    "data/root_controller/.django_secret",
    nbytes=32,
)

DEBUG = os.environ.get("HUNTERAI_DEBUG", "0").strip().lower() in {
    "1",
    "true",
    "yes",
}

APPEND_SLASH = False

_DEFAULT_ALLOWED_HOSTS = [
    "127.0.0.1",
    "localhost",
    "testserver",
    "test",
    "[::1]",
    "::1",
]
_EXTRA_ALLOWED_HOSTS = [
    h.strip()
    for h in os.environ.get("HUNTERAI_ALLOWED_HOSTS", "").split(",")
    if h.strip()
]
ALLOWED_HOSTS = list(dict.fromkeys([*_DEFAULT_ALLOWED_HOSTS, *_EXTRA_ALLOWED_HOSTS]))

INSTALLED_APPS = [
    "corsheaders",
    "rest_framework",
    "django.contrib.staticfiles",
]

MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",
    "hunter_backend.middleware.SecurityHeadersMiddleware",
    "hunter_backend.middleware.AsyncWhiteNoiseMiddleware",
    "django.middleware.common.CommonMiddleware",
    "hunter_backend.middleware.ApiCsrfAndJsonGuardMiddleware",
]

ROOT_URLCONF = "hunter_backend.urls"
ASGI_APPLICATION = "hunter_backend.asgi.application"

DATABASES = {}

# Local browser frontend + same-origin origins
_LOCAL_ORIGINS = [
    "http://127.0.0.1:3000",
    "http://localhost:3000",
    "http://127.0.0.1:8000",
    "http://localhost:8000",
]
_EXTRA_ORIGINS = [
    o.strip().rstrip("/")
    for o in os.environ.get("HUNTERAI_TRUSTED_ORIGINS", "").split(",")
    if o.strip()
]
_TRUSTED_ORIGINS = list(dict.fromkeys([*_LOCAL_ORIGINS, *_EXTRA_ORIGINS]))

CORS_ALLOWED_ORIGINS = _TRUSTED_ORIGINS
CORS_ALLOW_CREDENTIALS = True
CORS_ALLOW_HEADERS = list(
    dict.fromkeys([*default_headers, "last-event-id", "x-csrftoken"])
)

CSRF_TRUSTED_ORIGINS = _TRUSTED_ORIGINS
CSRF_COOKIE_NAME = "csrftoken"
CSRF_COOKIE_HTTPONLY = False
CSRF_COOKIE_SAMESITE = "Lax"

WS_ALLOWED_ORIGINS = {
    "http://127.0.0.1:3000",
    "http://localhost:3000",
    "http://127.0.0.1:8000",
    "http://localhost:8000",
}

CSP_POLICY = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' 'unsafe-eval' blob:; "
    "style-src 'self' 'unsafe-inline'; "
    "font-src 'self' data:; "
    "img-src 'self' data: blob:; "
    "worker-src 'self' blob:; "
    "connect-src 'self' ws: wss: http://127.0.0.1:8000 http://localhost:8000 "
    "http://127.0.0.1:3000 http://localhost:3000; "
    "frame-ancestors 'self'; "
    "base-uri 'self'; "
    "object-src 'none'"
)

STATIC_URL = "/static/"
STATIC_ROOT = str(BASE_DIR / "data" / "staticfiles")
STATICFILES_DIRS = [
    str(p)
    for p in (
        BASE_DIR / "ui" / "web" / "static",
        BASE_DIR / "hunter_backend" / "static",
    )
    if p.is_dir()
]
WHITENOISE_USE_FINDERS = True
WHITENOISE_AUTOREFRESH = True

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [],
    "DEFAULT_PERMISSION_CLASSES": [],
    "UNAUTHENTICATED_USER": None,
    "DEFAULT_PARSER_CLASSES": [
        "rest_framework.parsers.JSONParser",
    ],
    "DEFAULT_RENDERER_CLASSES": [
        "rest_framework.renderers.JSONRenderer",
    ],
}

DATA_UPLOAD_MAX_MEMORY_SIZE = 20 * 1024 * 1024  # 20 MB

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = False
USE_TZ = True

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {
        "console": {"class": "logging.StreamHandler"},
    },
    "root": {
        "handlers": ["console"],
        "level": os.environ.get("HUNTERAI_LOG_LEVEL", "INFO"),
    },
}
