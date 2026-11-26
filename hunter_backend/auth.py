"""Local operator/agent authentication, PBKDF2-SHA512 KDF, sgn revocation, and LoginGuard.

Provides fail-closed local API authentication for the HunterAI Django ASGI control plane:
- Startup-generated CSPRNG local bearer token (``HUNTER_API_TOKEN`` or
  ``data/root_controller/.api_token`` with ``0o600`` permissions).
- PBKDF2-SHA512 domain-separated key derivation for signing/verifying local session
  tokens and tiered credentials without reusing raw secret material across domains.
- Monotonic session generation (``sgn``) revocation so operator logout/revocation
  immediately invalidates all previously issued session cookies/tokens.
- Tier separation between ``userTier`` (human operator session or operator bearer)
  and ``tokenTier`` (scoped read/agent bearer token).
- Sliding-window ``LoginGuard`` rate limiting keyed by trusted-proxy-validated client IP.
"""

from __future__ import annotations

import base64
from collections import OrderedDict, deque
from dataclasses import dataclass
import hashlib
import hmac
import ipaddress
import json
import logging
import os
from pathlib import Path
import secrets
import threading
import time
from typing import Any, Deque, Dict, Iterable, Mapping, Optional, Tuple

from django.conf import settings

logger = logging.getLogger("hunter_backend.auth")

BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_API_TOKEN_REL_PATH = "data/root_controller/.api_token"
DEFAULT_SGN_REL_PATH = "data/root_controller/.session_gen"

USER_TIER = "userTier"
TOKEN_TIER = "tokenTier"
ANON_TIER = "anonymous"

SESSION_COOKIE_NAME = "hunter_session"
_SIGNED_TOKEN_PREFIX = "hnt1"
_PBKDF2_ITERATIONS = 120_000
_DERIVED_KEY_CACHE_MAX = 32

_KDF_LOCK = threading.Lock()
_DERIVED_KEY_CACHE: "OrderedDict[Tuple[str, str, bytes, int, int], bytes]" = OrderedDict()

_TOKEN_LOCK = threading.Lock()
_CACHED_FILE_TOKEN: Optional[str] = None

_SGN_LOCK = threading.RLock()
_SESSION_GENERATION: Optional[int] = None


@dataclass(frozen=True)
class AuthContext:
    """Authenticated caller identity and privilege tier attached to requests."""

    authenticated: bool
    principal: str
    tier: str
    auth_method: str
    is_bearer: bool = False
    sgn: int = 0

    @property
    def is_user_tier(self) -> bool:
        return self.authenticated and self.tier == USER_TIER


ANONYMOUS_AUTH = AuthContext(
    authenticated=False,
    principal="anonymous",
    tier=ANON_TIER,
    auth_method="none",
    is_bearer=False,
    sgn=0,
)


def _write_restricted_file(path: Path, content: str) -> None:
    """Persist secret/state file with owner-only ``0o600`` permissions."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(content)
        finally:
            try:
                os.chmod(path, 0o600)
            except OSError as exc:
                logger.warning("Unable to chmod 0600 on %s: %s", path, exc)
    else:
        path.write_text(content, encoding="utf-8")
        try:
            os.chmod(path, 0o600)
        except OSError as exc:
            logger.debug("chmod 0600 note on Windows for %s: %s", path, exc)


def get_api_token_path() -> Path:
    custom = (os.environ.get("HUNTER_API_TOKEN_FILE") or "").strip()
    if custom:
        return Path(custom)
    return BASE_DIR / DEFAULT_API_TOKEN_REL_PATH


def get_session_gen_path() -> Path:
    custom = (os.environ.get("HUNTER_SESSION_GEN_FILE") or "").strip()
    if custom:
        return Path(custom)
    return BASE_DIR / DEFAULT_SGN_REL_PATH


def get_or_create_api_token() -> str:
    """Return the active local operator bearer token (env -> 0o600 file -> CSPRNG)."""
    global _CACHED_FILE_TOKEN

    env_val = (os.environ.get("HUNTER_API_TOKEN") or "").strip()
    if env_val:
        return env_val

    with _TOKEN_LOCK:
        token_path = get_api_token_path()
        if token_path.is_file():
            try:
                stored = token_path.read_text(encoding="utf-8").strip()
                if len(stored) >= 32:
                    _CACHED_FILE_TOKEN = stored
                    return stored
            except OSError as exc:
                logger.warning("Failed reading API token file %s: %s", token_path, exc)

        if _CACHED_FILE_TOKEN and len(_CACHED_FILE_TOKEN) >= 32:
            return _CACHED_FILE_TOKEN

        generated = secrets.token_hex(32)
        try:
            _write_restricted_file(token_path, generated)
        except OSError as exc:
            logger.warning("Failed persisting API token to %s: %s", token_path, exc)
        _CACHED_FILE_TOKEN = generated
        return generated


def get_agent_api_token() -> str:
    """Return optional scoped agent/read-tier bearer token (``HUNTER_AGENT_TOKEN``)."""
    return (os.environ.get("HUNTER_AGENT_TOKEN") or "").strip()


def derive_domain_key(
    secret: str,
    domain: str,
    *,
    salt: bytes = b"",
    iterations: int = _PBKDF2_ITERATIONS,
    dklen: int = 32,
) -> bytes:
    """Derive a domain-separated key using PBKDF2-HMAC-SHA512 with bounded caching."""
    if not secret:
        raise ValueError("secret is required for key derivation")
    if not domain:
        raise ValueError("domain is required for domain separation")

    cache_key = (secret, domain, salt, iterations, dklen)
    with _KDF_LOCK:
        cached = _DERIVED_KEY_CACHE.get(cache_key)
        if cached is not None:
            _DERIVED_KEY_CACHE.move_to_end(cache_key)
            return cached

    domain_salt = b"hunterai.auth.v1:" + domain.encode("utf-8") + (b":" + salt if salt else b"")
    derived = hashlib.pbkdf2_hmac(
        "sha512",
        secret.encode("utf-8"),
        domain_salt,
        iterations,
        dklen=dklen,
    )

    with _KDF_LOCK:
        _DERIVED_KEY_CACHE[cache_key] = derived
        if len(_DERIVED_KEY_CACHE) > _DERIVED_KEY_CACHE_MAX:
            _DERIVED_KEY_CACHE.popitem(last=False)
    return derived


def get_session_generation() -> int:
    """Return the current monotonic session generation (``sgn``)."""
    global _SESSION_GENERATION
    with _SGN_LOCK:
        if _SESSION_GENERATION is not None:
            return _SESSION_GENERATION
        sgn_path = get_session_gen_path()
        if sgn_path.is_file():
            try:
                raw = sgn_path.read_text(encoding="utf-8").strip()
                parsed = int(raw)
                if parsed >= 1:
                    _SESSION_GENERATION = parsed
                    return _SESSION_GENERATION
            except (OSError, ValueError) as exc:
                logger.warning("Unable to parse session generation file %s: %s", sgn_path, exc)
        _SESSION_GENERATION = 1
        return _SESSION_GENERATION


def revoke_all_sessions() -> int:
    """Increment ``sgn`` to revoke all previously issued session/signed tokens."""
    global _SESSION_GENERATION
    with _SGN_LOCK:
        current = get_session_generation()
        next_gen = current + 1
        _SESSION_GENERATION = next_gen
        sgn_path = get_session_gen_path()
        try:
            _write_restricted_file(sgn_path, str(next_gen))
        except OSError as exc:
            logger.warning("Failed persisting session generation to %s: %s", sgn_path, exc)
        return next_gen


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64url_decode(encoded: str) -> bytes:
    pad = "=" * (-len(encoded) % 4)
    return base64.urlsafe_b64decode(encoded + pad)


def issue_session_token(
    *,
    principal: str = "operator",
    tier: str = USER_TIER,
    ttl_seconds: int = 8 * 3600,
) -> str:
    """Issue a signed, ``sgn``-bound session or tiered bearer token."""
    if tier not in {USER_TIER, TOKEN_TIER}:
        raise ValueError(f"Unsupported auth tier: {tier!r}")
    secret = get_or_create_api_token()
    domain = "operator_session_signing" if tier == USER_TIER else "agent_token_signing"
    signing_key = derive_domain_key(secret, domain)
    now = int(time.time())
    payload = {
        "sub": str(principal or "operator").strip()[:64],
        "tier": tier,
        "sgn": get_session_generation(),
        "iat": now,
        "exp": now + max(60, int(ttl_seconds)),
    }
    payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    payload_b64 = _b64url_encode(payload_bytes)
    signing_input = f"{_SIGNED_TOKEN_PREFIX}.{domain}.{payload_b64}".encode("ascii")
    sig = hmac.new(signing_key, signing_input, hashlib.sha256).digest()
    return f"{_SIGNED_TOKEN_PREFIX}.{payload_b64}.{_b64url_encode(sig)}"


def verify_session_token(
    token: str,
    *,
    is_bearer: bool = False,
) -> Optional[AuthContext]:
    """Verify a signed ``hnt1.<payload>.<sig>`` token against PBKDF2 key, expiry, and ``sgn``."""
    raw = (token or "").strip()
    parts = raw.split(".")
    if len(parts) != 3 or parts[0] != _SIGNED_TOKEN_PREFIX:
        return None
    _, payload_b64, sig_b64 = parts
    try:
        payload_bytes = _b64url_decode(payload_b64)
        payload = json.loads(payload_bytes.decode("utf-8"))
        provided_sig = _b64url_decode(sig_b64)
    except Exception as exc:
        logger.debug("Malformed signed auth token rejected: %s", exc)
        return None

    if not isinstance(payload, dict):
        return None
    tier = str(payload.get("tier") or "")
    if tier not in {USER_TIER, TOKEN_TIER}:
        return None
    domain = "operator_session_signing" if tier == USER_TIER else "agent_token_signing"
    secret = get_or_create_api_token()
    signing_key = derive_domain_key(secret, domain)
    signing_input = f"{_SIGNED_TOKEN_PREFIX}.{domain}.{payload_b64}".encode("ascii")
    expected_sig = hmac.new(signing_key, signing_input, hashlib.sha256).digest()
    if not hmac.compare_digest(provided_sig, expected_sig):
        return None

    try:
        exp = int(payload.get("exp") or 0)
        sgn = int(payload.get("sgn") or 0)
    except (TypeError, ValueError):
        return None

    if exp <= int(time.time()):
        return None
    if sgn != get_session_generation():
        return None

    principal = str(payload.get("sub") or ("operator" if tier == USER_TIER else "agent")).strip()
    method = (
        ("bearer_signed_user" if tier == USER_TIER else "bearer_signed_token")
        if is_bearer
        else "session_cookie"
    )
    return AuthContext(
        authenticated=True,
        principal=principal or "operator",
        tier=tier,
        auth_method=method,
        is_bearer=is_bearer,
        sgn=sgn,
    )


def verify_bearer_token(raw_token: str) -> Optional[AuthContext]:
    """Verify a bearer credential (operator token, agent token, or signed ``hnt1`` token)."""
    candidate = (raw_token or "").strip()
    if not candidate:
        return None

    if candidate.startswith(f"{_SIGNED_TOKEN_PREFIX}."):
        return verify_session_token(candidate, is_bearer=True)

    operator_token = get_or_create_api_token()
    op_verifier = derive_domain_key(operator_token, "api_token_verifier")
    cand_mac = hmac.new(op_verifier, candidate.encode("utf-8"), hashlib.sha256).digest()
    op_mac = hmac.new(op_verifier, operator_token.encode("utf-8"), hashlib.sha256).digest()
    if hmac.compare_digest(cand_mac, op_mac):
        return AuthContext(
            authenticated=True,
            principal="operator",
            tier=USER_TIER,
            auth_method="bearer_operator",
            is_bearer=True,
            sgn=get_session_generation(),
        )

    agent_token = get_agent_api_token()
    if agent_token:
        ag_verifier = derive_domain_key(agent_token, "agent_token_verifier")
        cand_ag_mac = hmac.new(ag_verifier, candidate.encode("utf-8"), hashlib.sha256).digest()
        ag_mac = hmac.new(ag_verifier, agent_token.encode("utf-8"), hashlib.sha256).digest()
        if hmac.compare_digest(cand_ag_mac, ag_mac):
            return AuthContext(
                authenticated=True,
                principal="agent",
                tier=TOKEN_TIER,
                auth_method="bearer_agent",
                is_bearer=True,
                sgn=get_session_generation(),
            )

    return None


def extract_bearer_from_headers(headers: Mapping[str, str]) -> Optional[str]:
    """Extract bearer credential from ``Authorization: Bearer`` or ``X-Hunter-Token``."""
    lower = {str(k).lower(): str(v) for k, v in headers.items()}
    auth_hdr = (lower.get("authorization") or "").strip()
    if auth_hdr:
        parts = auth_hdr.split(None, 1)
        if len(parts) == 2 and parts[0].lower() == "bearer":
            return parts[1].strip()
        # Non-empty malformed Authorization header must still trigger invalid-credential rejection
        return "__invalid_auth_header__"
    x_tok = (lower.get("x-hunter-token") or "").strip()
    if x_tok:
        return x_tok
    return None


def _parse_cookie_header(cookie_header: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for chunk in (cookie_header or "").split(";"):
        if "=" in chunk:
            k, v = chunk.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def authenticate_headers(
    headers: Mapping[str, str],
    cookies: Optional[Mapping[str, str]] = None,
) -> Tuple[AuthContext, bool]:
    """Authenticate from raw HTTP/WebSocket headers & cookies.

    Returns ``(auth_context, credentials_supplied)`` so callers can distinguish
    missing credentials from invalid credentials (and trigger ``LoginGuard``).
    """
    bearer = extract_bearer_from_headers(headers)
    if bearer is not None:
        if bearer == "__invalid_auth_header__":
            return ANONYMOUS_AUTH, True
        ctx = verify_bearer_token(bearer)
        return (ctx or ANONYMOUS_AUTH), True

    cookie_map: Mapping[str, str]
    if cookies is not None:
        cookie_map = cookies
    else:
        lower = {str(k).lower(): str(v) for k, v in headers.items()}
        cookie_map = _parse_cookie_header(lower.get("cookie", ""))

    cookie_name = getattr(settings, "HUNTER_SESSION_COOKIE_NAME", SESSION_COOKIE_NAME)
    sess_cookie = (cookie_map.get(cookie_name) or "").strip()
    if sess_cookie:
        ctx = verify_session_token(sess_cookie, is_bearer=False)
        return (ctx or ANONYMOUS_AUTH), True

    return ANONYMOUS_AUTH, False


def authenticate_request(request: Any) -> Tuple[AuthContext, bool]:
    """Authenticate a Django/DRF HttpRequest."""
    headers: Dict[str, str] = {}
    auth_hdr = request.META.get("HTTP_AUTHORIZATION")
    if auth_hdr is not None:
        headers["authorization"] = str(auth_hdr)
    x_tok = request.META.get("HTTP_X_HUNTER_TOKEN")
    if x_tok is not None:
        headers["x-hunter-token"] = str(x_tok)
    return authenticate_headers(headers, cookies=getattr(request, "COOKIES", None) or {})


def get_request_auth(request: Any) -> AuthContext:
    """Return the ``AuthContext`` attached by middleware (or resolve on demand)."""
    attached = getattr(request, "hunter_auth", None)
    if isinstance(attached, AuthContext):
        return attached
    ctx, _supplied = authenticate_request(request)
    return ctx


def _ip_matches_trusted_proxies(remote_addr: str, trusted_proxies: Iterable[str]) -> bool:
    if not remote_addr:
        return False
    try:
        remote_ip = ipaddress.ip_address(remote_addr.strip().strip("[]"))
    except ValueError:
        return False
    for raw in trusted_proxies:
        entry = str(raw or "").strip()
        if not entry:
            continue
        try:
            if "/" in entry:
                if remote_ip in ipaddress.ip_network(entry, strict=False):
                    return True
            else:
                if remote_ip == ipaddress.ip_address(entry.strip("[]")):
                    return True
        except ValueError:
            continue
    return False


def extract_client_ip(
    request: Any,
    *,
    trusted_proxies: Optional[Iterable[str]] = None,
) -> str:
    """Extract client IP honoring ``X-Forwarded-For`` ONLY from explicit trusted proxies."""
    remote_addr = str(request.META.get("REMOTE_ADDR") or "127.0.0.1").strip()
    proxies = (
        list(trusted_proxies)
        if trusted_proxies is not None
        else list(getattr(settings, "TRUSTED_PROXIES", ()))
    )
    if proxies and _ip_matches_trusted_proxies(remote_addr, proxies):
        xff = str(request.META.get("HTTP_X_FORWARDED_FOR") or "").strip()
        if xff:
            # Walk right-to-left skipping trusted hops to select the first untrusted client IP
            hops = [h.strip() for h in xff.split(",") if h.strip()]
            for hop in reversed(hops):
                if not _ip_matches_trusted_proxies(hop, proxies):
                    return hop
            if hops:
                return hops[0]
        xri = str(request.META.get("HTTP_X_REAL_IP") or "").strip()
        if xri:
            return xri
    return remote_addr or "127.0.0.1"


class LoginGuard:
    """Thread-safe sliding-window authentication failure rate limiter."""

    def __init__(
        self,
        *,
        max_failures: int = 10,
        window_seconds: float = 300.0,
        lockout_seconds: float = 300.0,
    ) -> None:
        self.max_failures = max(1, int(max_failures))
        self.window_seconds = max(1.0, float(window_seconds))
        self.lockout_seconds = max(1.0, float(lockout_seconds))
        self._lock = threading.Lock()
        self._failures: Dict[str, Deque[float]] = {}
        self._locked_until: Dict[str, float] = {}

    def _prune(self, key: str, now: float) -> Deque[float]:
        bucket = self._failures.get(key)
        if bucket is None:
            bucket = deque()
            self._failures[key] = bucket
        cutoff = now - self.window_seconds
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        return bucket

    def is_blocked(self, client_key: str, *, now: Optional[float] = None) -> Tuple[bool, int]:
        ts = time.monotonic() if now is None else now
        with self._lock:
            until = self._locked_until.get(client_key, 0.0)
            if until > ts:
                return True, max(1, int(until - ts) + 1)
            if client_key in self._locked_until:
                del self._locked_until[client_key]
            return False, 0

    def record_failure(self, client_key: str, *, now: Optional[float] = None) -> Tuple[bool, int]:
        ts = time.monotonic() if now is None else now
        with self._lock:
            bucket = self._prune(client_key, ts)
            bucket.append(ts)
            if len(bucket) >= self.max_failures:
                until = ts + self.lockout_seconds
                self._locked_until[client_key] = until
                bucket.clear()
                return True, int(self.lockout_seconds)
            return False, 0

    def record_success(self, client_key: str) -> None:
        with self._lock:
            self._failures.pop(client_key, None)
            self._locked_until.pop(client_key, None)

    def reset(self) -> None:
        with self._lock:
            self._failures.clear()
            self._locked_until.clear()


LOGIN_GUARD = LoginGuard(
    max_failures=int(os.environ.get("HUNTER_AUTH_MAX_FAILURES", "10")),
    window_seconds=float(os.environ.get("HUNTER_AUTH_WINDOW_SECONDS", "300")),
    lockout_seconds=float(os.environ.get("HUNTER_AUTH_LOCKOUT_SECONDS", "300")),
)
