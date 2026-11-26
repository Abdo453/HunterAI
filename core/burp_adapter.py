"""
محول بورب (Burp Adapter) — مرحلة F + Phase 5 Sensory Triad Alignment.

محول ثابت (stable interface) للتكامل مع Burp Suite، يُحلق فوق البنية القائمة في
``core/burp_gateway/`` (البوابة المحلية 127.0.0.1:8085، مخزن الحركات، مصدّر النتائج،
محرك المصدر).

المسارات المعتمدة (Aligned with BurpGateway):
- ``GET /health``
- ``GET/POST /api/traffic`` و ``GET /api/traffic/{tx_id}``
- ``GET/POST /api/tasks`` و ``GET /api/tasks/{task_id}``
- ``GET/POST /api/scope``
- ``GET/POST /api/issues/burp`` و ``GET /api/issues/export``
- ``GET/POST /api/cases`` و ``GET /api/cases/{case_id}``
- ``POST /api/research/{replay,repeater,queue,experiment}``, ``GET /api/research/queue``,
  ``DELETE /api/research/queue/{exp_id}``

ضوابط أمنية:
- تمرير رمز المصادقة المحلي (Phase 1) عبر ``X-Hunter-Token`` و ``Authorization: Bearer``.
- تُنشق كوكيز ورؤوس Authorization والتوكنز قبل إرسال أي حركة إلى نموذج خارجي.
- تُسجل المنشأ (provenance) لكل نتيجة مستوردة من بورب.
- لا يُدعى أن نتيجة "مؤكدة" إلا إذا دعمتها عملية أو أداة حقيقية من بورب.
- جميع العمليات تخضع لفحص النطاق (ScopeEnforcer) قبل استرجاع أو إرسال حركة خارجية.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import os
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from core.scope_enforcer import ScopeEnforcer
from core.scope_guard import ScopeGuard

logger = logging.getLogger(__name__)

# رؤوس يُنشق منها قبل الإرسال للنماذج الخارجية
SENSITIVE_HEADERS = {
    "authorization", "cookie", "set-cookie", "x-api-key", "proxy-authorization",
    "www-authenticate", "token", "access-token", "x-hunter-token",
}

# أنماط السر
_SECRET_PATTERNS = [
    re.compile(r"(sk-[A-Za-z0-9]{10,})"),
    re.compile(r"(Bearer\s+[A-Za-z0-9._\-]{10,})"),
    re.compile(r"(ghp_[A-Za-z0-9]{10,})"),
    re.compile(r"(password\s*[:=]\s*\S+)", re.IGNORECASE),
    re.compile(r"(api[_-]?key\s*[:=]\s*\S+)", re.IGNORECASE),
]

_JOB_TYPE_TO_TASK_ACTION = {
    "scan": "SCAN",
    "passive_scan": "SCAN",
    "active_scan": "SCAN",
    "plan": "PLAN",
    "attack_plan": "PLAN",
    "probe": "PROBE",
    "repeater": "PROBE",
    "add_scope": "ADD_SCOPE",
    "scope": "ADD_SCOPE",
}


def _redact_secrets(text: str) -> str:
    for pat in _SECRET_PATTERNS:
        text = pat.sub("***", text)
    return text


def _redact_headers(headers: Optional[Dict[str, str]]) -> Dict[str, str]:
    if not headers:
        return {}
    out: Dict[str, str] = {}
    for k, v in (headers or {}).items():
        kl = str(k).lower()
        if kl in SENSITIVE_HEADERS:
            out[str(k)] = "***"
        else:
            out[str(k)] = _redact_secrets(str(v))
    return out


def _callable_accepts_kwarg(fn: Any, kwarg: str) -> bool:
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        return True
    for param in sig.parameters.values():
        if param.kind == inspect.Parameter.VAR_KEYWORD or param.name == kwarg:
            return True
    return False


@dataclass
class BurpTransaction:
    """حركة HTTP ملتقطة من بورب (مقصوصة ومُنَظَّفة)."""
    tx_id: str
    target_host: str
    method: str
    url: str
    status_code: int
    req_headers: Dict[str, str]          # مُنشَّقة
    req_body: str                        # مُنشَّقة
    resp_headers: Dict[str, str]         # مُنشَّقة
    resp_body: str                       # مُنشَّقة
    tool_source: str = "proxy"
    timestamp: float = field(default_factory=time.time)
    provenance: str = "burp_gateway"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tx_id": self.tx_id, "target_host": self.target_host,
            "method": self.method, "url": self.url,
            "status_code": self.status_code,
            "req_headers": dict(self.req_headers),
            "req_body": self.req_body,
            "resp_headers": dict(self.resp_headers),
            "resp_body": self.resp_body,
            "tool_source": self.tool_source,
            "timestamp": self.timestamp,
            "provenance": self.provenance,
        }


@dataclass
class BurpFinding:
    """نتيجة مؤثرة من بورب مع مصدر صريح."""
    finding_id: str
    target: str
    issue_name: str
    severity: str
    confidence: str
    evidence: str
    remediation: str
    provenance: str = "burp_extension"
    verified_by_burp: bool = False      # True فقط إذا أداة بورب أكدت فعليًا
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id, "target": self.target,
            "issue_name": self.issue_name, "severity": self.severity,
            "confidence": self.confidence, "evidence": self.evidence,
            "remediation": self.remediation, "provenance": self.provenance,
            "verified_by_burp": self.verified_by_burp,
            "created_at": self.created_at,
        }


@dataclass
class BurpAdapterConfig:
    """إعداد محول بورب."""
    gateway_base_url: str = "http://127.0.0.1:8085"
    api_token: Optional[str] = None
    timeout_s: float = 10.0
    max_retries: int = 2
    retry_backoff_s: float = 1.0
    max_request_size_bytes: int = 2_000_000
    max_response_size_bytes: int = 2_000_000
    enabled: bool = True


class BurpAdapterError(Exception):
    def __init__(self, message: str, category: str = "BURP_ERROR"):
        super().__init__(message)
        self.category = category


class BurpAdapter:
    """
    محول بورب ثابت.

    يتصل ببوابة HunterAI المحلية (`BurpGateway`) عبر المسارات الحقيقية `/api/*`
    مع تمرير رمز المصادقة المحلي (`X-Hunter-Token` و `Authorization: Bearer`).
    إذا لم يتوفر البورب/الإضافة، يعمل بوضع تدهور لطيف (degraded).
    """

    def __init__(
        self,
        config: Optional[BurpAdapterConfig] = None,
        scope_enforcer: Optional[ScopeEnforcer] = None,
        http_client: Optional[Any] = None,   # حقن للاختبار (httpx.AsyncClient)
    ):
        self.config = config or BurpAdapterConfig()
        self.scope_enforcer = scope_enforcer or ScopeEnforcer(
            ScopeGuard(in_scope=[], out_of_scope=[])
        )
        self._http = http_client
        self._owned_client = False
        self._status = "disconnected"   # disconnected | connected | degraded
        self._last_error: Optional[str] = None
        self._audit: List[Dict[str, Any]] = []

    def _resolve_auth_token(self) -> Optional[str]:
        token = (
            (self.config.api_token or "").strip()
            or (os.environ.get("HUNTER_BURP_GATEWAY_TOKEN") or "").strip()
            or (os.environ.get("HUNTER_API_TOKEN") or "").strip()
        )
        return token or None

    def _auth_headers(self) -> Dict[str, str]:
        token = self._resolve_auth_token()
        if not token:
            return {}
        return {
            "X-Hunter-Token": token,
            "Authorization": f"Bearer {token}",
        }

    async def _call_client(
        self,
        client: Any,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
    ) -> Any:
        url = f"{self.config.gateway_base_url.rstrip('/')}{path}"
        fn = getattr(client, method.lower())
        kwargs: Dict[str, Any] = {}
        if params is not None and _callable_accepts_kwarg(fn, "params"):
            kwargs["params"] = params
        if json_body is not None and _callable_accepts_kwarg(fn, "json"):
            kwargs["json"] = json_body
        auth_headers = self._auth_headers()
        if auth_headers and _callable_accepts_kwarg(fn, "headers"):
            kwargs["headers"] = auth_headers
        if _callable_accepts_kwarg(fn, "timeout"):
            kwargs["timeout"] = self.config.timeout_s
        return await asyncio.wait_for(fn(url, **kwargs), timeout=self.config.timeout_s)

    @staticmethod
    def _raise_if_auth_or_scope_error(resp: Any, context: str) -> None:
        status_code = int(getattr(resp, "status_code", 0) or 0)
        if status_code == 401:
            raise BurpAdapterError(
                f"Unauthorized during {context}: valid X-Hunter-Token or Authorization: Bearer token required",
                category="UNAUTHORIZED",
            )
        if status_code == 403:
            detail = ""
            try:
                body = resp.json()
                if isinstance(body, dict):
                    detail = str(body.get("reason") or body.get("detail") or body.get("status") or "")
            except Exception:
                detail = ""
            raise BurpAdapterError(
                f"Scope/policy rejected during {context}: {detail or '403 Forbidden'}",
                category="SCOPE_VIOLATION",
            )

    # ── الاتصال والفحص ────────────────────────────────────────────────

    async def health_check(self) -> Dict[str, Any]:
        """
        فحص ما إذا كانت بوابة بورب قابلة للوصول والاستجابة.
        يعيد حالة متصلة / غير متصلة / تدهور لطيف بدون انهيار.
        """
        start = time.time()
        self._audit.append({
            "event": "health_check",
            "timestamp": start,
        })
        if not self.config.enabled:
            self._status = "degraded"
            self._last_error = "Burp integration disabled by configuration"
            return {
                "status": "degraded",
                "available": False,
                "reason": self._last_error,
                "latency_s": round(time.time() - start, 3),
            }

        client = await self._get_client()
        if client is None:
            self._status = "degraded"
            self._last_error = "HTTP client unavailable"
            return {
                "status": "degraded",
                "available": False,
                "reason": self._last_error,
                "latency_s": round(time.time() - start, 3),
            }

        try:
            resp = await self._call_client(client, "get", "/health")
            if not resp.is_success:
                self._status = "degraded"
                self._last_error = f"Burp gateway returned HTTP {resp.status_code}"
                return {
                    "status": "degraded",
                    "available": False,
                    "reason": self._last_error,
                    "latency_s": round(time.time() - start, 3),
                }
            data = resp.json()
            self._status = "connected"
            self._last_error = None
            return {
                "status": "connected",
                "available": True,
                "reason": "Burp gateway reachable",
                "latency_s": round(time.time() - start, 3),
                "gateway": data,
            }
        except asyncio.TimeoutError:
            self._status = "degraded"
            self._last_error = "Burp gateway timeout"
            return {
                "status": "degraded",
                "available": False,
                "reason": self._last_error,
                "latency_s": round(time.time() - start, 3),
            }
        except Exception as exc:  # noqa: BLE001
            self._status = "degraded"
            self._last_error = f"Burp gateway unreachable: {exc}"
            return {
                "status": "degraded",
                "available": False,
                "reason": self._last_error,
                "latency_s": round(time.time() - start, 3),
            }

    async def get_available_capabilities(self) -> Dict[str, Any]:
        """
        اكتشاف القدرات المدعومة من تكامل بورب الحالي.
        لا يدّعي قدرات غير مدعومة فعلاً.
        """
        health = await self.health_check()
        avail = bool(health["available"])
        base = {
            "adapter": "hunterai_burp_adapter",
            "integration_mode": "burp_extension_to_local_gateway",
            "note": (
                "Burp Suite no official public REST API. Integration via BApp extension "
                "forwarding traffic to HunterAI local gateway (127.0.0.1:8085)."
            ),
            "available": avail,
            "operations": {
                "health_check": True,
                "get_available_capabilities": True,
                "retrieve_authorized_http_history": avail,
                "retrieve_request": avail,
                "retrieve_response": avail,
                "ingest_traffic": avail,
                "submit_supported_analysis_job": avail,
                "retrieve_analysis_results": avail,
                "get_scope": avail,
                "update_scope": avail,
                "import_supported_findings": avail,
                "export_supported_findings": True,
                "fetch_exported_issues": avail,
                "list_cases": avail,
                "upsert_case": avail,
                "research_replay": avail,
                "research_send_to_repeater": avail,
                "research_queue_experiment": avail,
            },
        }
        if health.get("gateway"):
            base["gateway_summary"] = health["gateway"]
        return base

    # ── استرجاع وإدخال الحركة المرخصة (/api/traffic) ──────────────────

    async def retrieve_authorized_http_history(
        self,
        *,
        target: Optional[str] = None,
        limit: int = 50,
    ) -> List[BurpTransaction]:
        """
        استرجاع حركة HTTP المرخصة فقط (بعد فحص النطاق) عبر ``GET /api/traffic``.
        تُنشف الأسرار قبل الإرجاع.
        """
        if not await self._ensure_connected():
            raise BurpAdapterError(
                "Burp integration unavailable (degraded mode)",
                category="NOT_CONNECTED",
            )

        client = await self._get_client()
        if client is None:
            raise BurpAdapterError("HTTP client unavailable", category="NOT_CONNECTED")

        if target:
            allowed, reason = self.scope_enforcer.enforce_target(target)
            if not allowed:
                logger.warning("Burp history request denied by scope: %s (%s)", target, reason)
                return []

        try:
            params: Dict[str, Any] = {"limit": limit}
            if target:
                parsed_target = urlparse(target if "://" in target else f"https://{target}")
                if parsed_target.hostname:
                    params["host"] = parsed_target.hostname
            resp = await self._call_client(client, "get", "/api/traffic", params=params)
            self._raise_if_auth_or_scope_error(resp, "retrieve_authorized_http_history")
            raw = resp.json() if resp.is_success else {}
            transactions = self._parse_transactions(raw)
            if target:
                transactions = [
                    t for t in transactions
                    if self.scope_enforcer.enforce_target(t.url or t.target_host)[0]
                ]
            return transactions[:limit]
        except asyncio.TimeoutError:
            raise BurpAdapterError("Burp history timeout", category="TIMEOUT")
        except BurpAdapterError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise BurpAdapterError(str(exc), category="EXECUTION_ERROR")

    async def ingest_traffic(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """إرسال حركة HTTP إلى ``POST /api/traffic`` بعد التحقق من النطاق."""
        if not await self._ensure_connected():
            raise BurpAdapterError("Burp integration unavailable", category="NOT_CONNECTED")
        target_ref = str(payload.get("url") or payload.get("host") or "")
        if target_ref:
            allowed, reason = self.scope_enforcer.enforce_target(target_ref)
            if not allowed:
                raise BurpAdapterError(
                    f"Traffic target outside scope: {target_ref} ({reason})",
                    category="SCOPE_VIOLATION",
                )
        client = await self._get_client()
        if client is None:
            raise BurpAdapterError("HTTP client unavailable", category="NOT_CONNECTED")
        try:
            resp = await self._call_client(client, "post", "/api/traffic", json_body=payload)
            self._raise_if_auth_or_scope_error(resp, "ingest_traffic")
            return resp.json() if resp.is_success else {"status": "ERROR", "http_status": resp.status_code}
        except asyncio.TimeoutError:
            raise BurpAdapterError("Burp traffic ingest timeout", category="TIMEOUT")
        except BurpAdapterError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise BurpAdapterError(str(exc), category="EXECUTION_ERROR")

    async def retrieve_request(self, tx_id: str) -> Optional[BurpTransaction]:
        """استرجاع طلب حركة معينة (مُنشّق)."""
        return await self._retrieve_transaction(tx_id, part="request")

    async def retrieve_response(self, tx_id: str) -> Optional[BurpTransaction]:
        """استرجاع استجابة حركة معينة (مُنشّق)."""
        return await self._retrieve_transaction(tx_id, part="response")

    async def _retrieve_transaction(self, tx_id: str, part: str) -> Optional[BurpTransaction]:
        if not await self._ensure_connected():
            raise BurpAdapterError("Burp integration unavailable", category="NOT_CONNECTED")
        client = await self._get_client()
        if client is None:
            raise BurpAdapterError("HTTP client unavailable", category="NOT_CONNECTED")
        try:
            resp = await self._call_client(client, "get", f"/api/traffic/{tx_id}")
            self._raise_if_auth_or_scope_error(resp, f"retrieve_{part}")
            if not resp.is_success:
                return None
            raw = resp.json()
            tx = self._normalize_transaction(raw)
            return tx if tx else None
        except asyncio.TimeoutError:
            raise BurpAdapterError("Burp transaction timeout", category="TIMEOUT")
        except BurpAdapterError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise BurpAdapterError(str(exc), category="EXECUTION_ERROR")

    # ── مهام التحليل (/api/tasks) ────────────────────────────────────

    async def submit_supported_analysis_job(
        self,
        *,
        target: str,
        job_type: str = "passive_scan",
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        إرسال مهمة تحليل مدعومة إلى ``POST /api/tasks``.
        لا يُنفذ أي عملية تدميرية تلقائيًا.
        """
        if not await self._ensure_connected():
            raise BurpAdapterError("Burp integration unavailable", category="NOT_CONNECTED")

        allowed, reason = self.scope_enforcer.enforce_target(target)
        if not allowed:
            raise BurpAdapterError(
                f"Target outside scope: {target} ({reason})",
                category="SCOPE_VIOLATION",
            )

        client = await self._get_client()
        if client is None:
            raise BurpAdapterError("HTTP client unavailable", category="NOT_CONNECTED")

        action = _JOB_TYPE_TO_TASK_ACTION.get(str(job_type or "").strip().lower(), "SCAN")
        payload = {
            "action": action,
            "target_url": target,
            "payload": {
                "job_type": job_type,
                "options": options or {},
                "provenance": "hunterai_burp_adapter",
                "submitted_at": time.time(),
            },
        }
        try:
            resp = await self._call_client(client, "post", "/api/tasks", json_body=payload)
            self._raise_if_auth_or_scope_error(resp, "submit_supported_analysis_job")
            data = resp.json() if resp.is_success else {}
            task_id = data.get("task_id") or data.get("job_id") or f"task-{uuid.uuid4().hex[:8]}"
            self._audit.append({
                "event": "submit_analysis_job",
                "target": target,
                "job_type": job_type,
                "task_id": task_id,
                "timestamp": time.time(),
            })
            return {
                "accepted": resp.is_success,
                "job_id": task_id,
                "task_id": task_id,
                "status": data.get("status", "QUEUED"),
                "gateway_response": data,
            }
        except asyncio.TimeoutError:
            raise BurpAdapterError("Analysis job timeout", category="TIMEOUT")
        except BurpAdapterError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise BurpAdapterError(str(exc), category="EXECUTION_ERROR")

    async def retrieve_analysis_results(
        self,
        job_id: str,
    ) -> Dict[str, Any]:
        """استرجاع حالة/نتائج مهمة عبر ``GET /api/tasks/{job_id}``."""
        if not await self._ensure_connected():
            raise BurpAdapterError("Burp integration unavailable", category="NOT_CONNECTED")
        client = await self._get_client()
        if client is None:
            raise BurpAdapterError("HTTP client unavailable", category="NOT_CONNECTED")
        try:
            resp = await self._call_client(client, "get", f"/api/tasks/{job_id}")
            self._raise_if_auth_or_scope_error(resp, "retrieve_analysis_results")
            if not resp.is_success:
                return {"found": False, "job_id": job_id, "status": "not_found"}
            data = resp.json()
            return {
                "found": True,
                "job_id": data.get("task_id") or job_id,
                "task_id": data.get("task_id") or job_id,
                "status": data.get("status", "unknown"),
                "results": data.get("result") if data.get("result") is not None else data.get("results", {}),
                "task": data,
                "provenance": "burp_gateway",
            }
        except asyncio.TimeoutError:
            raise BurpAdapterError("Analysis results timeout", category="TIMEOUT")
        except BurpAdapterError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise BurpAdapterError(str(exc), category="EXECUTION_ERROR")

    async def list_tasks(self) -> List[Dict[str, Any]]:
        """استعراض قائمة المهام عبر ``GET /api/tasks``."""
        if not await self._ensure_connected():
            raise BurpAdapterError("Burp integration unavailable", category="NOT_CONNECTED")
        client = await self._get_client()
        if client is None:
            raise BurpAdapterError("HTTP client unavailable", category="NOT_CONNECTED")
        try:
            resp = await self._call_client(client, "get", "/api/tasks")
            self._raise_if_auth_or_scope_error(resp, "list_tasks")
            data = resp.json() if resp.is_success else {}
            return list(data.get("tasks", [])) if isinstance(data, dict) else []
        except asyncio.TimeoutError:
            raise BurpAdapterError("List tasks timeout", category="TIMEOUT")
        except BurpAdapterError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise BurpAdapterError(str(exc), category="EXECUTION_ERROR")

    # ── إدارة النطاق (/api/scope) ────────────────────────────────────

    async def get_scope(self) -> Dict[str, List[str]]:
        """قراءة النطاق النشط من ``GET /api/scope``."""
        if not await self._ensure_connected():
            raise BurpAdapterError("Burp integration unavailable", category="NOT_CONNECTED")
        client = await self._get_client()
        if client is None:
            raise BurpAdapterError("HTTP client unavailable", category="NOT_CONNECTED")
        try:
            resp = await self._call_client(client, "get", "/api/scope")
            self._raise_if_auth_or_scope_error(resp, "get_scope")
            data = resp.json() if resp.is_success else {}
            return {
                "include": list(data.get("include", [])),
                "exclude": list(data.get("exclude", [])),
            }
        except asyncio.TimeoutError:
            raise BurpAdapterError("Get scope timeout", category="TIMEOUT")
        except BurpAdapterError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise BurpAdapterError(str(exc), category="EXECUTION_ERROR")

    async def update_scope(
        self,
        *,
        include: Optional[List[str]] = None,
        exclude: Optional[List[str]] = None,
        host: Optional[str] = None,
        action: str = "include",
    ) -> Dict[str, Any]:
        """تحديث النطاق في ``POST /api/scope``."""
        if not await self._ensure_connected():
            raise BurpAdapterError("Burp integration unavailable", category="NOT_CONNECTED")
        client = await self._get_client()
        if client is None:
            raise BurpAdapterError("HTTP client unavailable", category="NOT_CONNECTED")
        body: Dict[str, Any] = {}
        if include is not None:
            body["include"] = list(include)
        if exclude is not None:
            body["exclude"] = list(exclude)
        if host is not None:
            body["host"] = host
            body["action"] = action
        try:
            resp = await self._call_client(client, "post", "/api/scope", json_body=body)
            self._raise_if_auth_or_scope_error(resp, "update_scope")
            return resp.json() if resp.is_success else {"status": "ERROR", "http_status": resp.status_code}
        except asyncio.TimeoutError:
            raise BurpAdapterError("Update scope timeout", category="TIMEOUT")
        except BurpAdapterError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise BurpAdapterError(str(exc), category="EXECUTION_ERROR")

    # ── استيراد / تصدير النتائج (/api/issues/*) ───────────────────────

    async def import_supported_findings(
        self,
        *,
        source: str = "burp_scanner",
        limit: int = 100,
    ) -> List[BurpFinding]:
        """
        استيراد النتائج المدعومة من بورب عبر ``GET /api/issues/burp`` مع تسجيل المنشأ.
        لا يُدعى أن نتيجة "مؤكدة" إلا إذا أكدت أداة بورب فعلاً.
        """
        if not await self._ensure_connected():
            raise BurpAdapterError("Burp integration unavailable", category="NOT_CONNECTED")
        client = await self._get_client()
        if client is None:
            raise BurpAdapterError("HTTP client unavailable", category="NOT_CONNECTED")
        try:
            resp = await self._call_client(
                client,
                "get",
                "/api/issues/burp",
                params={"source": source, "limit": limit},
            )
            self._raise_if_auth_or_scope_error(resp, "import_supported_findings")
            body = resp.json() if resp.is_success else {}
            raw_findings = body.get("issues") or body.get("findings") or []
        except asyncio.TimeoutError:
            raise BurpAdapterError("Findings import timeout", category="TIMEOUT")
        except BurpAdapterError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise BurpAdapterError(str(exc), category="EXECUTION_ERROR")

        findings: List[BurpFinding] = []
        for f in raw_findings[:limit]:
            findings.append(BurpFinding(
                finding_id=f.get("finding_id") or f.get("id") or f"finding-{uuid.uuid4().hex[:8]}",
                target=f.get("target") or f.get("url") or f.get("host") or "",
                issue_name=f.get("issue_name") or f.get("name") or f.get("title") or "Burp finding",
                severity=f.get("severity", "Medium"),
                confidence=f.get("confidence", "Tentative"),
                evidence=_redact_secrets(str(f.get("evidence") or f.get("detail") or "")),
                remediation=_redact_secrets(str(f.get("remediation") or "")),
                provenance=str(f.get("provenance") or "burp_extension"),
                verified_by_burp=bool(f.get("verified_by_burp", False)),
            ))
            self._audit.append({
                "event": "import_finding",
                "finding_id": findings[-1].finding_id,
                "target": findings[-1].target,
                "timestamp": time.time(),
            })
        return findings

    async def submit_burp_issue(self, issue: Dict[str, Any]) -> Dict[str, Any]:
        """تسجيل نتيجة من Burp Scanner عبر ``POST /api/issues/burp``."""
        if not await self._ensure_connected():
            raise BurpAdapterError("Burp integration unavailable", category="NOT_CONNECTED")
        client = await self._get_client()
        if client is None:
            raise BurpAdapterError("HTTP client unavailable", category="NOT_CONNECTED")
        try:
            resp = await self._call_client(client, "post", "/api/issues/burp", json_body=issue)
            self._raise_if_auth_or_scope_error(resp, "submit_burp_issue")
            return resp.json() if resp.is_success else {"status": "ERROR", "http_status": resp.status_code}
        except asyncio.TimeoutError:
            raise BurpAdapterError("Submit burp issue timeout", category="TIMEOUT")
        except BurpAdapterError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise BurpAdapterError(str(exc), category="EXECUTION_ERROR")

    async def fetch_exported_issues(self) -> Dict[str, Any]:
        """جلب النتائج المؤكدة المصدرة لبورب عبر ``GET /api/issues/export``."""
        if not await self._ensure_connected():
            raise BurpAdapterError("Burp integration unavailable", category="NOT_CONNECTED")
        client = await self._get_client()
        if client is None:
            raise BurpAdapterError("HTTP client unavailable", category="NOT_CONNECTED")
        try:
            resp = await self._call_client(client, "get", "/api/issues/export")
            self._raise_if_auth_or_scope_error(resp, "fetch_exported_issues")
            return resp.json() if resp.is_success else {"issues_count": 0, "issues": []}
        except asyncio.TimeoutError:
            raise BurpAdapterError("Export issues timeout", category="TIMEOUT")
        except BurpAdapterError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise BurpAdapterError(str(exc), category="EXECUTION_ERROR")

    async def export_supported_findings(
        self,
        findings: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        تصدير نتائج إلى تنسيق متوافق مع بورب (IScanIssue JSON) للاستيراد في Target tab.
        لا يُنفذ أي عملية في بورب فعليًا؛ يُعيد صيغة التصدير فقط.
        """
        from core.burp_gateway.issue_exporter import BurpIssueExporter
        exported = []
        for f in findings:
            exported.append(BurpIssueExporter.format_finding_for_burp(f))
        self._audit.append({
            "event": "export_findings",
            "count": len(exported),
            "timestamp": time.time(),
        })
        return {
            "exported_count": len(exported),
            "format": "burp_iscan_issue_json",
            "findings": exported,
            "provenance": "hunterai_burp_adapter",
            "note": "Use Burp Suite Extension API (IScanIssue) to import into Target Issues tab.",
        }

    # ── حالات التحقيق (/api/cases) ───────────────────────────────────

    async def list_cases(self) -> List[Dict[str, Any]]:
        """استعراض حالات التحقيق عبر ``GET /api/cases``."""
        if not await self._ensure_connected():
            raise BurpAdapterError("Burp integration unavailable", category="NOT_CONNECTED")
        client = await self._get_client()
        if client is None:
            raise BurpAdapterError("HTTP client unavailable", category="NOT_CONNECTED")
        try:
            resp = await self._call_client(client, "get", "/api/cases")
            self._raise_if_auth_or_scope_error(resp, "list_cases")
            data = resp.json() if resp.is_success else {}
            return list(data.get("cases", [])) if isinstance(data, dict) else []
        except asyncio.TimeoutError:
            raise BurpAdapterError("List cases timeout", category="TIMEOUT")
        except BurpAdapterError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise BurpAdapterError(str(exc), category="EXECUTION_ERROR")

    async def get_case(self, case_id: str) -> Optional[Dict[str, Any]]:
        """استرجاع حالة تحقيق عبر ``GET /api/cases/{case_id}``."""
        if not await self._ensure_connected():
            raise BurpAdapterError("Burp integration unavailable", category="NOT_CONNECTED")
        client = await self._get_client()
        if client is None:
            raise BurpAdapterError("HTTP client unavailable", category="NOT_CONNECTED")
        try:
            resp = await self._call_client(client, "get", f"/api/cases/{case_id}")
            self._raise_if_auth_or_scope_error(resp, "get_case")
            if not resp.is_success:
                return None
            return resp.json()
        except asyncio.TimeoutError:
            raise BurpAdapterError("Get case timeout", category="TIMEOUT")
        except BurpAdapterError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise BurpAdapterError(str(exc), category="EXECUTION_ERROR")

    async def upsert_case(self, case_payload: Dict[str, Any]) -> Dict[str, Any]:
        """إنشاء أو تحديث حالة تحقيق عبر ``POST /api/cases``."""
        if not await self._ensure_connected():
            raise BurpAdapterError("Burp integration unavailable", category="NOT_CONNECTED")
        client = await self._get_client()
        if client is None:
            raise BurpAdapterError("HTTP client unavailable", category="NOT_CONNECTED")
        try:
            resp = await self._call_client(client, "post", "/api/cases", json_body=case_payload)
            self._raise_if_auth_or_scope_error(resp, "upsert_case")
            return resp.json() if resp.is_success else {"status": "ERROR", "http_status": resp.status_code}
        except asyncio.TimeoutError:
            raise BurpAdapterError("Upsert case timeout", category="TIMEOUT")
        except BurpAdapterError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise BurpAdapterError(str(exc), category="EXECUTION_ERROR")

    # ── عمليات البحث النشط (/api/research/*) ─────────────────────────

    async def research_replay(
        self,
        *,
        request_id: str,
        mutation: Optional[Dict[str, Any]] = None,
        reason: str = "Adapter Replay",
    ) -> Dict[str, Any]:
        """تنفيذ إعادة تشغيل عبر ``POST /api/research/replay``."""
        if not await self._ensure_connected():
            raise BurpAdapterError("Burp integration unavailable", category="NOT_CONNECTED")
        client = await self._get_client()
        if client is None:
            raise BurpAdapterError("HTTP client unavailable", category="NOT_CONNECTED")
        payload = {"request_id": request_id, "mutation": mutation, "reason": reason}
        try:
            resp = await self._call_client(client, "post", "/api/research/replay", json_body=payload)
            self._raise_if_auth_or_scope_error(resp, "research_replay")
            return resp.json() if resp.is_success else {"status": "ERROR", "http_status": resp.status_code}
        except asyncio.TimeoutError:
            raise BurpAdapterError("Research replay timeout", category="TIMEOUT")
        except BurpAdapterError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise BurpAdapterError(str(exc), category="EXECUTION_ERROR")

    async def research_send_to_repeater(
        self,
        *,
        request_id: Optional[str] = None,
        url: Optional[str] = None,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        body: str = "",
        tab_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """تهيئة تبويب Repeater عبر ``POST /api/research/repeater``."""
        if not await self._ensure_connected():
            raise BurpAdapterError("Burp integration unavailable", category="NOT_CONNECTED")
        if url:
            allowed, reason = self.scope_enforcer.enforce_target(url)
            if not allowed:
                raise BurpAdapterError(f"Target outside scope: {url} ({reason})", category="SCOPE_VIOLATION")
        client = await self._get_client()
        if client is None:
            raise BurpAdapterError("HTTP client unavailable", category="NOT_CONNECTED")
        payload: Dict[str, Any] = {"tab_name": tab_name}
        if request_id:
            payload["request_id"] = request_id
        elif url:
            payload.update({"url": url, "method": method, "headers": headers or {}, "body": body})
        try:
            resp = await self._call_client(client, "post", "/api/research/repeater", json_body=payload)
            self._raise_if_auth_or_scope_error(resp, "research_send_to_repeater")
            return resp.json() if resp.is_success else {"status": "ERROR", "http_status": resp.status_code}
        except asyncio.TimeoutError:
            raise BurpAdapterError("Research repeater timeout", category="TIMEOUT")
        except BurpAdapterError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise BurpAdapterError(str(exc), category="EXECUTION_ERROR")

    async def research_queue_experiment(
        self,
        *,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        body: str = "",
        priority: int = 5,
        eig: float = 0.5,
        risk_tier: str = "LOW_RISK",
    ) -> Dict[str, Any]:
        """إدراج تجربة في صف البحث عبر ``POST /api/research/queue``."""
        if not await self._ensure_connected():
            raise BurpAdapterError("Burp integration unavailable", category="NOT_CONNECTED")
        allowed, reason = self.scope_enforcer.enforce_target(url)
        if not allowed:
            raise BurpAdapterError(f"Target outside scope: {url} ({reason})", category="SCOPE_VIOLATION")
        client = await self._get_client()
        if client is None:
            raise BurpAdapterError("HTTP client unavailable", category="NOT_CONNECTED")
        payload = {
            "url": url,
            "method": method,
            "headers": headers or {},
            "body": body,
            "priority": priority,
            "eig": eig,
            "risk_tier": risk_tier,
        }
        try:
            resp = await self._call_client(client, "post", "/api/research/queue", json_body=payload)
            self._raise_if_auth_or_scope_error(resp, "research_queue_experiment")
            return resp.json() if resp.is_success else {"status": "ERROR", "http_status": resp.status_code}
        except asyncio.TimeoutError:
            raise BurpAdapterError("Research queue timeout", category="TIMEOUT")
        except BurpAdapterError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise BurpAdapterError(str(exc), category="EXECUTION_ERROR")

    async def research_list_queue(self) -> Dict[str, Any]:
        """استعراض صف تجارب البحث عبر ``GET /api/research/queue``."""
        if not await self._ensure_connected():
            raise BurpAdapterError("Burp integration unavailable", category="NOT_CONNECTED")
        client = await self._get_client()
        if client is None:
            raise BurpAdapterError("HTTP client unavailable", category="NOT_CONNECTED")
        try:
            resp = await self._call_client(client, "get", "/api/research/queue")
            self._raise_if_auth_or_scope_error(resp, "research_list_queue")
            return resp.json() if resp.is_success else {"metrics": {}, "items": []}
        except asyncio.TimeoutError:
            raise BurpAdapterError("Research list queue timeout", category="TIMEOUT")
        except BurpAdapterError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise BurpAdapterError(str(exc), category="EXECUTION_ERROR")

    async def research_cancel_experiment(self, exp_id: str) -> Dict[str, Any]:
        """إلغاء تجربة عبر ``DELETE /api/research/queue/{exp_id}``."""
        if not await self._ensure_connected():
            raise BurpAdapterError("Burp integration unavailable", category="NOT_CONNECTED")
        client = await self._get_client()
        if client is None:
            raise BurpAdapterError("HTTP client unavailable", category="NOT_CONNECTED")
        try:
            resp = await self._call_client(client, "delete", f"/api/research/queue/{exp_id}")
            self._raise_if_auth_or_scope_error(resp, "research_cancel_experiment")
            return resp.json() if resp.is_success else {"status": "NOT_FOUND", "experiment_id": exp_id}
        except asyncio.TimeoutError:
            raise BurpAdapterError("Research cancel timeout", category="TIMEOUT")
        except BurpAdapterError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise BurpAdapterError(str(exc), category="EXECUTION_ERROR")

    async def research_submit_experiment(self, contract: Dict[str, Any]) -> Dict[str, Any]:
        """تنفيذ عقد تجربة عبر ``POST /api/research/experiment``."""
        if not await self._ensure_connected():
            raise BurpAdapterError("Burp integration unavailable", category="NOT_CONNECTED")
        target_ep = str(contract.get("target_endpoint") or "")
        if target_ep:
            allowed, reason = self.scope_enforcer.enforce_target(target_ep)
            if not allowed:
                raise BurpAdapterError(f"Target outside scope: {target_ep} ({reason})", category="SCOPE_VIOLATION")
        client = await self._get_client()
        if client is None:
            raise BurpAdapterError("HTTP client unavailable", category="NOT_CONNECTED")
        try:
            resp = await self._call_client(client, "post", "/api/research/experiment", json_body=contract)
            self._raise_if_auth_or_scope_error(resp, "research_submit_experiment")
            return resp.json() if resp.is_success else {"status": "ERROR", "http_status": resp.status_code}
        except asyncio.TimeoutError:
            raise BurpAdapterError("Research experiment timeout", category="TIMEOUT")
        except BurpAdapterError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise BurpAdapterError(str(exc), category="EXECUTION_ERROR")

    # ── الحالة والتدقيق ──────────────────────────────────────────────

    def status(self) -> str:
        return self._status

    def last_error(self) -> Optional[str]:
        return self._last_error

    def audit_log(self) -> List[Dict[str, Any]]:
        return list(self._audit)

    def snapshot(self) -> Dict[str, Any]:
        return {
            "config": {
                "gateway_base_url": self.config.gateway_base_url,
                "timeout_s": self.config.timeout_s,
                "enabled": self.config.enabled,
                "auth_configured": bool(self._resolve_auth_token()),
            },
            "status": self._status,
            "last_error": self._last_error,
            "audit_count": len(self._audit),
        }

    # ── المساعدة الداخلية ─────────────────────────────────────────────

    def _is_available(self) -> bool:
        return self._status == "connected"

    async def _ensure_connected(self) -> bool:
        """يضمن الاتصال قبل تنفيذ العملية؛ يُجري health_check إذا لزم الأمر."""
        if self._status == "connected":
            return True
        await self.health_check()
        return self._status == "connected"

    async def _get_client(self):
        if self._http is not None:
            return self._http
        if self._owned_client and self._http is None:
            return None
        try:
            import httpx  # type: ignore
            self._http = httpx.AsyncClient(
                timeout=self.config.timeout_s,
                headers=self._auth_headers(),
            )
            self._owned_client = True
            return self._http
        except ImportError:
            logger.warning("httpx غير مثبت؛ محول بورب لا يمكنه الاتصال بالبوابة")
            return None

    async def aclose(self) -> None:
        if self._owned_client and self._http is not None:
            await self._http.aclose()
            self._http = None
            self._owned_client = False

    def _parse_transactions(self, raw: Any) -> List[BurpTransaction]:
        if isinstance(raw, list):
            items = raw
        elif isinstance(raw, dict):
            items = raw.get("transactions") or raw.get("traffic") or raw.get("items") or []
        else:
            items = []
        out: List[BurpTransaction] = []
        for t in items:
            if isinstance(t, dict):
                out.append(self._normalize_transaction(t))
        return out

    def _normalize_transaction(self, raw: Dict[str, Any]) -> BurpTransaction:
        host = raw.get("target_host") or raw.get("host") or ""
        url = raw.get("url") or ""
        if not url and host:
            path = raw.get("path") or "/"
            url = f"https://{host}{path if str(path).startswith('/') else '/' + str(path)}"
        status_val = (
            raw.get("status_code")
            if raw.get("status_code") is not None
            else raw.get("response_status")
            if raw.get("response_status") is not None
            else raw.get("status", 200)
        )
        req_headers = raw.get("req_headers") or raw.get("request_headers") or raw.get("headers") or {}
        resp_headers = raw.get("resp_headers") or raw.get("response_headers") or {}
        ts_val = raw.get("timestamp")
        if ts_val is None:
            raw_time = raw.get("time")
            ts_val = raw_time if isinstance(raw_time, (int, float)) else time.time()
        return BurpTransaction(
            tx_id=str(raw.get("tx_id") or raw.get("id") or f"tx-{uuid.uuid4().hex[:8]}"),
            target_host=str(host),
            method=str(raw.get("method") or "GET"),
            url=str(url),
            status_code=int(status_val or 200),
            req_headers=_redact_headers(req_headers if isinstance(req_headers, dict) else {}),
            req_body=_redact_secrets(str(raw.get("req_body") or ""))[:self.config.max_request_size_bytes],
            resp_headers=_redact_headers(resp_headers if isinstance(resp_headers, dict) else {}),
            resp_body=_redact_secrets(str(raw.get("resp_body") or ""))[:self.config.max_response_size_bytes],
            tool_source=str(raw.get("tool_source") or raw.get("source") or "proxy"),
            timestamp=float(ts_val),
            provenance="burp_gateway",
        )


# ---------------------------------------------------------------------------
# نسخة مشتركة (تُحقن في المنسق / واجهة الويب)
# ---------------------------------------------------------------------------

GLOBAL_BURP_ADAPTER = BurpAdapter()


def create_burp_adapter(
    *,
    gateway_base_url: Optional[str] = None,
    api_token: Optional[str] = None,
    scope_enforcer: Optional[ScopeEnforcer] = None,
    enabled: bool = True,
) -> BurpAdapter:
    cfg = BurpAdapterConfig()
    if gateway_base_url:
        cfg.gateway_base_url = gateway_base_url
    if api_token:
        cfg.api_token = api_token
    cfg.enabled = enabled
    return BurpAdapter(config=cfg, scope_enforcer=scope_enforcer)
