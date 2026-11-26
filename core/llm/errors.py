"""Structured LLM backend error classification and diagnostics.

Adapted from:
- PentesterFlow/agent ``src/llm/errors.ts``
  (commit ``0759d873a07350a70283c9751f7d136905f777c7``, licensed under Apache-2.0;
  see ``THIRD_PARTY_LICENSES/PENTESTERFLOW_APACHE2.txt`` and ``NOTICE``).
- vxcontrol/pentagi ``backend/pkg/providers/retry.go``
  (commit ``cffed9485aa1cca70762cd08a57ac62a80406258``, licensed under MIT;
  see ``THIRD_PARTY_LICENSES/PENTAGI_MIT.txt`` and ``NOTICE``).
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import json
import re
import time
from typing import Any, Dict, Literal, Optional, Union

ErrorCategory = Literal[
    "model-not-loaded",
    "model-not-found",
    "backend-down",
    "endpoint-not-found",
    "auth-failed",
    "rate-limited",
    "content-refusal",
    "bad-request",
    "timeout",
    "server-error",
    "unknown",
]

TRANSIENT_STATUS_CODES = frozenset({408, 429, 502, 503, 504, 529})
DETERMINISTIC_CLIENT_STATUS_CODES = frozenset({400, 401, 402, 403, 404, 405, 406, 409, 410, 413, 415, 422})

_BACKEND_MSG_STATUS_RE = re.compile(r"^([\w.-]+)\s+error\s+(\d{3}):\s*(.*)$", re.IGNORECASE)
_BACKEND_MSG_PLAIN_RE = re.compile(r"^([\w.-]+):\s*(.*)$", re.IGNORECASE)
_VENDOR_STATUS_RE = re.compile(r"(?:HTTP|status(?:\s+code)?)\s*[:=]?\s*(\d{3})", re.IGNORECASE)

_REFUSAL_ERR_SIGNATURES = (
    "content_filter",
    "content filter",
    "content_policy",
    "content policy",
    "safety filter",
    "blocked by safety",
    "policy violation",
    "refused",
)

_TRANSPORT_DOWN_SIGNATURES = (
    "econnrefused",
    "connection refused",
    "enotfound",
    "no such host",
    "etimedout",
    "i/o timeout",
    "network is unreachable",
    "socket hang up",
    "fetch failed",
    "connecterror",
    "connecttimeout",
    "name or service not known",
    "getaddrinfo failed",
    "actively refused",
    "winerror 10061",
)


class BackendError(Exception):
    """Structured diagnostic error returned by an LLM backend."""

    def __init__(
        self,
        backend: str,
        category: ErrorCategory,
        status_code: int,
        detail: str,
        *,
        retry_after_s: Optional[float] = None,
        is_refusal: bool = False,
    ) -> None:
        msg = (
            f"{backend} error {status_code}: {detail}"
            if status_code != 0
            else f"{backend}: {detail}"
        )
        super().__init__(msg)
        self.backend: str = backend
        self.category: ErrorCategory = category
        self.status_code: int = int(status_code)
        self.detail: str = detail
        self.retry_after_s: Optional[float] = retry_after_s
        self.is_refusal: bool = is_refusal or category == "content-refusal"

    @property
    def retry_after_ms(self) -> Optional[int]:
        if self.retry_after_s is None:
            return None
        return int(round(self.retry_after_s * 1000))

    def to_diagnostic(self) -> "StructuredDiagnostic":
        return StructuredDiagnostic(
            backend=self.backend,
            category=self.category,
            status_code=self.status_code,
            detail=clean_detail(self.detail),
            transient=is_transient(self),
            deterministic=is_deterministic_error(self),
            is_refusal=self.is_refusal,
            retry_after_s=self.retry_after_s,
            actionable_fix=fix_line(self.backend, self.category, self.status_code),
        )


@dataclass(frozen=True)
class StructuredDiagnostic:
    """JSON-serializable backend failure report for logs, telemetry, and UI."""

    backend: str
    category: ErrorCategory
    status_code: int
    detail: str
    transient: bool
    deterministic: bool
    is_refusal: bool
    retry_after_s: Optional[float]
    actionable_fix: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "backend": self.backend,
            "category": self.category,
            "status_code": self.status_code,
            "detail": self.detail,
            "transient": self.transient,
            "deterministic": self.deterministic,
            "is_refusal": self.is_refusal,
            "retry_after_s": self.retry_after_s,
            "actionable_fix": self.actionable_fix,
        }


def is_refusal_error(err: BaseException) -> bool:
    """Return True if *err* represents a model/provider safety or policy refusal."""
    if isinstance(err, BackendError):
        if err.is_refusal or err.category == "content-refusal":
            return True
        text = err.detail.lower()
    else:
        text = str(err).lower()
    return any(sig in text for sig in _REFUSAL_ERR_SIGNATURES)


def is_transient(err: BaseException) -> bool:
    """True for retryable errors (408/429/502/503/504/529, backend-down, timeout).

    A plain HTTP 500 or deterministic 4xx (except 408/429) or refusal is NOT
    considered transient for automatic retry.
    """
    if isinstance(err, BackendError):
        if err.is_refusal or err.category == "content-refusal":
            return False
        if err.category in ("backend-down", "timeout", "rate-limited"):
            return True
        return err.status_code in TRANSIENT_STATUS_CODES
    if isinstance(err, (TimeoutError, ConnectionError)):
        return True
    name = type(err).__name__.lower()
    if any(k in name for k in ("timeout", "connecterror", "networkerror", "remoteprotocolerror")):
        return True
    return False


def is_deterministic_error(err: BaseException) -> bool:
    """True if repeating or failing over the exact request cannot succeed safely.

    Adapted from PentAGI's ``isDeterministicError``: covers refusals, content
    filters, local parameter/config rejections, and non-408/429 4xx statuses.
    """
    if is_refusal_error(err):
        return True
    if isinstance(err, BackendError):
        if err.category in (
            "auth-failed",
            "bad-request",
            "content-refusal",
            "model-not-found",
            "model-not-loaded",
            "endpoint-not-found",
        ):
            return True
        if err.status_code in DETERMINISTIC_CLIENT_STATUS_CODES:
            return True
        if 400 <= err.status_code < 500 and err.status_code not in (408, 429):
            return True
        return False

    if isinstance(err, (ValueError, TypeError, PermissionError)):
        return True

    match = _VENDOR_STATUS_RE.search(str(err))
    if match:
        code = int(match.group(1))
        if 400 <= code < 500 and code not in (408, 429):
            return True
    return False


def parse_retry_after(
    header: Optional[str],
    *,
    now: Optional[float] = None,
) -> Optional[float]:
    """Parse an HTTP ``Retry-After`` header (delta-seconds or HTTP-date) into seconds."""
    if not header:
        return None
    trimmed = str(header).strip()
    if not trimmed:
        return None
    if re.fullmatch(r"\d+(?:\.\d+)?", trimmed):
        return max(0.0, float(trimmed))
    try:
        dt = parsedate_to_datetime(trimmed)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        now_ts = time.time() if now is None else float(now)
        return max(0.0, dt.timestamp() - now_ts)
    except (TypeError, ValueError, OverflowError):
        return None


def classify_backend(
    backend: str,
    transport_err: Optional[BaseException] = None,
    status_code: int = 0,
    body: Optional[str] = None,
    *,
    retry_after_header: Optional[str] = None,
) -> BackendError:
    """Classify a transport error or non-2xx HTTP response into a ``BackendError``."""
    retry_after_s = parse_retry_after(retry_after_header)

    if transport_err is not None:
        if isinstance(transport_err, BackendError):
            return transport_err
        msg = str(transport_err) or type(transport_err).__name__
        lower = f"{type(transport_err).__name__}: {msg}".lower()
        if "timeout" in lower or isinstance(transport_err, TimeoutError):
            return BackendError(backend, "timeout", 408, msg, retry_after_s=retry_after_s)
        if any(sig in lower for sig in _TRANSPORT_DOWN_SIGNATURES):
            return BackendError(backend, "backend-down", 0, msg, retry_after_s=retry_after_s)
        return BackendError(backend, "unknown", 0, msg, retry_after_s=retry_after_s)

    msg = (body or "").strip()
    if body:
        try:
            parsed = json.loads(body)
            if isinstance(parsed, dict):
                err_val = parsed.get("error")
                if isinstance(err_val, str) and err_val.strip():
                    msg = err_val.strip()
                elif isinstance(err_val, dict) and err_val.get("message"):
                    msg = str(err_val["message"]).strip()
                elif isinstance(parsed.get("message"), str) and parsed["message"].strip():
                    msg = parsed["message"].strip()
        except (ValueError, TypeError):
            pass

    lower = msg.lower()

    if any(sig in lower for sig in _REFUSAL_ERR_SIGNATURES):
        return BackendError(
            backend, "content-refusal", status_code, msg, retry_after_s=None, is_refusal=True
        )

    if (
        status_code == 429
        or "rate limit" in lower
        or "rate_limit" in lower
        or "too many requests" in lower
        or "quota exceeded" in lower
    ):
        eff_code = 429 if status_code < 400 else status_code
        return BackendError(backend, "rate-limited", eff_code, msg or "rate limited", retry_after_s=retry_after_s)

    if (
        "no models loaded" in lower
        or "no model loaded" in lower
        or "model not loaded" in lower
        or "please load a model" in lower
    ):
        return BackendError(backend, "model-not-loaded", status_code, msg)

    if (
        "try pulling it first" in lower
        or "model not found" in lower
        or "unknown model" in lower
        or ("model" in lower and "not found" in lower)
        or ("model" in lower and "does not exist" in lower)
    ):
        return BackendError(backend, "model-not-found", status_code, msg)

    if status_code == 404:
        detail = msg or "empty 404 response — base_url may be wrong, or the proxy/server is down"
        return BackendError(backend, "endpoint-not-found", 404, detail)

    if status_code in (401, 403):
        return BackendError(backend, "auth-failed", status_code, msg or "unauthorized")

    if status_code == 408 or "timeout" in lower:
        return BackendError(backend, "timeout", status_code or 408, msg or "request timed out", retry_after_s=retry_after_s)

    if 400 <= status_code < 500:
        return BackendError(backend, "bad-request", status_code, msg or f"client error {status_code}")

    if status_code >= 500:
        return BackendError(backend, "server-error", status_code, msg or f"server error {status_code}", retry_after_s=retry_after_s)

    return BackendError(backend, "unknown", status_code, msg or "unknown backend error", retry_after_s=retry_after_s)


def clean_detail(detail: str) -> str:
    """Strip redundant leading 'error:' prefixes and collapse whitespace."""
    cleaned = re.sub(r"^error:\s*", "", detail or "", flags=re.IGNORECASE)
    return re.sub(r"\s+", " ", cleaned).strip()


def display_backend(backend: str) -> str:
    trimmed = (backend or "").strip()
    if not trimmed:
        return "backend"
    if trimmed == "openai-compat":
        return "OpenAI-compat"
    if trimmed in ("lmstudio", "lm-studio", "lm_studio"):
        return "LM Studio"
    return trimmed


def fix_line(backend: str, category: ErrorCategory, status_code: int = 0) -> str:
    b = (backend or "").lower()
    if category == "model-not-found":
        if "ollama" in b:
            return "Run `ollama pull <model>` or pick an installed model in Settings."
        return "Verify the model ID exists for this provider in model_manifest.json."
    if category == "model-not-loaded":
        return "Load a model in the local inference UI (e.g. LM Studio) and retry."
    if category == "endpoint-not-found":
        return "Verify base_url / OLLAMA_HOST and probe /api/tags or /v1/models."
    if category == "backend-down":
        if "ollama" in b:
            return "Start Ollama (`ollama serve`) and verify OLLAMA_HOST is reachable."
        if "lmstudio" in b or "lm-studio" in b or "lm_studio" in b:
            return "Start the LM Studio local server on 127.0.0.1:1234."
        return "Check network reachability and provider endpoint configuration."
    if category == "auth-failed" or status_code in (401, 403):
        return "Verify the provider API key is configured and authorized for this model."
    if category == "rate-limited" or status_code == 429:
        return "Back off briefly or switch to a backup provider/local model."
    if category == "content-refusal":
        return "Reframe prompt context or route through an authorized local security model."
    if category == "timeout" or status_code == 408:
        return "Retry with a smaller context window or faster model."
    if category == "server-error" or status_code >= 500:
        return "Retry shortly or fail over to a healthy backup provider."
    return "Inspect diagnostics and provider settings."


def parse_backend_error_message(message: str) -> Optional[BackendError]:
    m = _BACKEND_MSG_STATUS_RE.match((message or "").strip())
    if m:
        return classify_backend(m.group(1), None, int(m.group(2)), m.group(3).strip() or None)
    m2 = _BACKEND_MSG_PLAIN_RE.match((message or "").strip())
    if m2 and any(sig in (m2.group(2) or "").lower() for sig in _TRANSPORT_DOWN_SIGNATURES):
        return BackendError(m2.group(1), "backend-down", 0, m2.group(2).strip())
    return None


def format_user_error(err: Union[BaseException, str]) -> str:
    """Format an error into actionable, multi-line operator diagnostics."""
    be: Optional[BackendError] = None
    if isinstance(err, BackendError):
        be = err
    else:
        raw = str(err)
        be = parse_backend_error_message(raw)
        if be is None:
            return raw.strip() or "unknown error"

    backend = display_backend(be.backend)
    detail = clean_detail(be.detail)
    fix = fix_line(be.backend, be.category, be.status_code)

    headers: Dict[ErrorCategory, str] = {
        "model-not-found": f"Model not found on {backend}",
        "model-not-loaded": f"No model loaded on {backend}",
        "backend-down": f"Cannot reach {backend}",
        "endpoint-not-found": f"Endpoint not found on {backend} (404)",
        "auth-failed": f"Authentication failed on {backend} ({be.status_code})",
        "rate-limited": f"Rate limited by {backend} ({be.status_code or 429})",
        "content-refusal": f"Request refused by {backend}",
        "timeout": f"Request timed out on {backend}",
        "bad-request": f"Invalid request rejected by {backend} ({be.status_code})",
        "server-error": f"{backend} server error ({be.status_code})",
        "unknown": f"{backend} error" + (f" ({be.status_code})" if be.status_code else ""),
    }
    headline = headers.get(be.category, f"{backend} error")
    return "\n".join([headline, detail or "Request failed.", f"-> {fix}"])


def diagnose_error(backend: str, err: BaseException) -> StructuredDiagnostic:
    """Convert any exception into a ``StructuredDiagnostic``."""
    be = err if isinstance(err, BackendError) else classify_backend(backend, transport_err=err)
    return be.to_diagnostic()


__all__ = [
    "BackendError",
    "DETERMINISTIC_CLIENT_STATUS_CODES",
    "ErrorCategory",
    "StructuredDiagnostic",
    "TRANSIENT_STATUS_CODES",
    "classify_backend",
    "clean_detail",
    "diagnose_error",
    "display_backend",
    "fix_line",
    "format_user_error",
    "is_deterministic_error",
    "is_refusal_error",
    "is_transient",
    "parse_backend_error_message",
    "parse_retry_after",
]
