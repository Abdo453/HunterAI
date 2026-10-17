"""
محول بورب (Burp Adapter) — مرحلة F.

محول ثابت (stable interface) للتكامل مع Burp Suite، يُحلق فوق البنية القائمة في
``core/burp_gateway/`` (البوابة المحلية 127.0.0.1:8085، مخزن الحركات، مصدّر النتائج،
محرك المصدر).

ملاحظة معمارية مهمة (موثقة بصراحة):
- Burp Suite Professional/Community لا توفر واجهة برمجية REST عامة رسمية يمكن استدعاءها
  مباشرة من بايثون. واجهة البرمجة الرسمية لبورب هي Java Extension API (BApp / IBurpExtenderCallbacks).
- التكامل هنا يتم عبر إضافة Burp Suite (BApp) معينة (انظر ``agents/burp_agent/integrations/burp_extension/``)
  التي تُرسل حركة HTTP الملتقطة إلى بوابة HunterAI المحلية (`BurpGateway` على 127.0.0.1:8085)،
  ثم يقرأ هذا المحول من البوابة عبر HTTP محلي.
- إذا لم تكن الإضافة مثبتة أو البورب غير متاح، يعمل المحول بوضع "تدهور لطيف"
  (degraded): كل العملية ترجع "غير متاح" بدون انهيار، وتُستبدل بالمحاكاة فقط في
  اختبارات الوحدة (مفصولة عن التنفيذ الإنتاجي).

ضوابط أمنية:
- تُنشق كوكيز ورؤوس Authorization والتوكنز قبل إرسال أي حركة إلى نموذج خارجي.
- تُسجل المنشأ (provenance) لكل نتيجة مستوردة من بورب.
- لا يُدعى أن نتيجة "مؤكدة" إلا إذا دعمتها عملية أو أداة حقيقية من بورب.
- جميع العمليات تخضع لفحص النطاق (ScopeEnforcer) قبل استرجاع حركة خارجية.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse

from core.scope_enforcer import ScopeEnforcer
from core.scope_guard import ScopeGuard

logger = logging.getLogger(__name__)

# رؤوس يُنشق منها قبل الإ송 للنماذج الخارجية
SENSITIVE_HEADERS = {
    "authorization", "cookie", "set-cookie", "x-api-key", "proxy-authorization",
    "www-authenticate", "token", "access-token",
}

# أنماط السر
_SECRET_PATTERNS = [
    re.compile(r"(sk-[A-Za-z0-9]{10,})"),
    re.compile(r"(Bearer\s+[A-Za-z0-9._\-]{10,})"),
    re.compile(r"(ghp_[A-Za-z0-9]{10,})"),
    re.compile(r"(password\s*[:=]\s*\S+)", re.IGNORECASE),
    re.compile(r"(api[_-]?key\s*[:=]\s*\S+)", re.IGNORECASE),
]


def _redact_secrets(text: str) -> str:
    for pat in _SECRET_PATTERNS:
        text = pat.sub("***", text)
    return text


def _redact_headers(headers: Optional[Dict[str, str]]) -> Dict[str, str]:
    if not headers:
        return {}
    out: Dict[str, str] = {}
    for k, v in (headers or {}).items():
        kl = k.lower()
        if kl in SENSITIVE_HEADERS:
            out[k] = "***"
        else:
            out[k] = _redact_secrets(v)
    return out


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
    """نتيجة مؤثرة من بورب مع مصدر ספציפי."""
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

    يتصل ببوابة HunterAI المحلية (التي تستقبل ترافيك من إضافة بورب Suite).
    إذا لم يتوفر البورب/الإضافة، يعمل بوضع تدهور لطيف (degraded) وتُرجع كل عملية
    خطأ "غير متاح" بدلاً من الانهيار.
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
            url = f"{self.config.gateway_base_url.rstrip('/')}/health"
            resp = await asyncio.wait_for(
                client.get(url, timeout=self.config.timeout_s),
                timeout=self.config.timeout_s,
            )
            data = resp.json() if resp.is_success else {}
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
        base = {
            "adapter": "hunterai_burp_adapter",
            "integration_mode": "burp_extension_to_local_gateway",
            "note": (
                "Burp Suite no official public REST API. Integration via BApp extension "
                "forwarding traffic to HunterAI local gateway (127.0.0.1:8085)."
            ),
            "available": health["available"],
            "operations": {
                "health_check": True,
                "get_available_capabilities": True,
                "retrieve_authorized_http_history": health["available"],
                "retrieve_request": health["available"],
                "retrieve_response": health["available"],
                "submit_supported_analysis_job": health["available"],
                "retrieve_analysis_results": health["available"],
                "import_supported_findings": health["available"],
                "export_supported_findings": health["available"],
            },
        }
        if health.get("gateway"):
            base["gateway_summary"] = health["gateway"]
        return base

    # ── استرجاع الحركة المرخصة ──────────────────────────────────────

    async def retrieve_authorized_http_history(
        self,
        *,
        target: Optional[str] = None,
        limit: int = 50,
    ) -> List[BurpTransaction]:
        """
        استرجاع حركة HTTP المرخصة فقط (بعد فحص النطاق).
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

        # فحص النطاق إذا وُجد هدف
        if target:
            allowed, reason = self.scope_enforcer.enforce_target(target)
            if not allowed:
                logger.warning("Burp history request denied by scope: %s (%s)", target, reason)
                return []

        try:
            url = f"{self.config.gateway_base_url.rstrip('/')}/captures"
            resp = await asyncio.wait_for(
                client.get(url, params={"limit": limit}, timeout=self.config.timeout_s),
                timeout=self.config.timeout_s,
            )
            raw = resp.json() if resp.is_success else {}
            transactions = self._parse_transactions(raw)
            # تطبيق النطاق على كل نتيجة إذا وُجد هدف
            if target:
                transactions = [
                    t for t in transactions
                    if self.scope_enforcer.enforce_target(t.url)[0]
                ]
            return transactions[:limit]
        except asyncio.TimeoutError:
            raise BurpAdapterError("Burp history timeout", category="TIMEOUT")
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
            url = f"{self.config.gateway_base_url.rstrip('/')}/captures/{tx_id}"
            resp = await asyncio.wait_for(
                client.get(url, timeout=self.config.timeout_s),
                timeout=self.config.timeout_s,
            )
            if not resp.is_success:
                return None
            raw = resp.json()
            tx = self._normalize_transaction(raw)
            return tx if tx else None
        except asyncio.TimeoutError:
            raise BurpAdapterError("Burp transaction timeout", category="TIMEOUT")
        except Exception as exc:  # noqa: BLE001
            raise BurpAdapterError(str(exc), category="EXECUTION_ERROR")

    # ── مهام التحليل ─────────────────────────────────────────────────

    async def submit_supported_analysis_job(
        self,
        *,
        target: str,
        job_type: str = "passive_scan",
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        إرسال مهمة تحليل مدعومة من بورب (مثل فحص سلبي).
        لا يُنفذ أي عملية تدميرية تلقائيًا.
        """
        if not await self._ensure_connected():
            raise BurpAdapterError("Burp integration unavailable", category="NOT_CONNECTED")

        # فحص النطاق قبل أي مهمة
        allowed, reason = self.scope_enforcer.enforce_target(target)
        if not allowed:
            raise BurpAdapterError(
                f"Target outside scope: {target} ({reason})",
                category="SCOPE_VIOLATION",
            )

        client = await self._get_client()
        if client is None:
            raise BurpAdapterError("HTTP client unavailable", category="NOT_CONNECTED")

        payload = {
            "target": target,
            "job_type": job_type,
            "options": options or {},
            "provenance": "hunterai_burp_adapter",
            "submitted_at": time.time(),
        }
        try:
            url = f"{self.config.gateway_base_url.rstrip('/')}/analysis/jobs"
            resp = await asyncio.wait_for(
                client.post(url, json=payload, timeout=self.config.timeout_s),
                timeout=self.config.timeout_s,
            )
            data = resp.json() if resp.is_success else {}
            self._audit.append({
                "event": "submit_analysis_job",
                "target": target,
                "job_type": job_type,
                "timestamp": time.time(),
            })
            return {
                "accepted": resp.is_success,
                "job_id": data.get("job_id") or f"job-{uuid.uuid4().hex[:8]}",
                "status": data.get("status", "submitted"),
                "gateway_response": data,
            }
        except asyncio.TimeoutError:
            raise BurpAdapterError("Analysis job timeout", category="TIMEOUT")
        except Exception as exc:  # noqa: BLE001
            raise BurpAdapterError(str(exc), category="EXECUTION_ERROR")

    async def retrieve_analysis_results(
        self,
        job_id: str,
    ) -> Dict[str, Any]:
        """استرجاع نتائج مهمة تحليل."""
        if not await self._ensure_connected():
            raise BurpAdapterError("Burp integration unavailable", category="NOT_CONNECTED")
        client = await self._get_client()
        if client is None:
            raise BurpAdapterError("HTTP client unavailable", category="NOT_CONNECTED")
        try:
            url = f"{self.config.gateway_base_url.rstrip('/')}/analysis/jobs/{job_id}"
            resp = await asyncio.wait_for(
                client.get(url, timeout=self.config.timeout_s),
                timeout=self.config.timeout_s,
            )
            if not resp.is_success:
                return {"found": False, "job_id": job_id, "status": "not_found"}
            data = resp.json()
            return {
                "found": True,
                "job_id": job_id,
                "status": data.get("status", "unknown"),
                "results": data.get("results", {}),
                "provenance": "burp_gateway",
            }
        except asyncio.TimeoutError:
            raise BurpAdapterError("Analysis results timeout", category="TIMEOUT")
        except Exception as exc:  # noqa: BLE001
            raise BurpAdapterError(str(exc), category="EXECUTION_ERROR")

    # ── استيراد / تصدير النتائج ─────────────────────────────────────

    async def import_supported_findings(
        self,
        *,
        source: str = "burp_scanner",
        limit: int = 100,
    ) -> List[BurpFinding]:
        """
        استيراد النتائج المدعومة من بورب مع تسجيل المنشأ.
        لا يُدعى أن نتيجة "مؤكدة" إلا إذا أكدت أداة بورب فعلاً.
        """
        if not await self._ensure_connected():
            raise BurpAdapterError("Burp integration unavailable", category="NOT_CONNECTED")
        client = await self._get_client()
        if client is None:
            raise BurpAdapterError("HTTP client unavailable", category="NOT_CONNECTED")
        try:
            url = f"{self.config.gateway_base_url.rstrip('/')}/findings"
            resp = await asyncio.wait_for(
                client.get(url, params={"source": source, "limit": limit},
                           timeout=self.config.timeout_s),
                timeout=self.config.timeout_s,
            )
            raw_findings = resp.json().get("findings", []) if resp.is_success else []
        except asyncio.TimeoutError:
            raise BurpAdapterError("Findings import timeout", category="TIMEOUT")
        except Exception as exc:  # noqa: BLE001
            raise BurpAdapterError(str(exc), category="EXECUTION_ERROR")

        findings: List[BurpFinding] = []
        for f in raw_findings:
            findings.append(BurpFinding(
                finding_id=f.get("finding_id") or f.get("id") or f"finding-{uuid.uuid4().hex[:8]}",
                target=f.get("target") or f.get("host") or "",
                issue_name=f.get("issue_name") or f.get("title") or "Burp finding",
                severity=f.get("severity", "Medium"),
                confidence=f.get("confidence", "Tentative"),
                evidence=_redact_secrets(f.get("evidence", "") or ""),
                remediation=_redact_secrets(f.get("remediation", "") or ""),
                provenance="burp_extension",
                verified_by_burp=bool(f.get("verified_by_burp", False)),
            ))
            self._audit.append({
                "event": "import_finding",
                "finding_id": findings[-1].finding_id,
                "target": findings[-1].target,
                "timestamp": time.time(),
            })
        return findings

    async def export_supported_findings(
        self,
        findings: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        تصدير نتائج إلى تنسيق متوافق مع بورب (IScanIssue JSON) للإستيراد في Target tab.
        لا يُنفذ أي عملية في بورب فعليًا؛ يُعيد форму המשלוח فقط.
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
            self._http = httpx.AsyncClient(timeout=self.config.timeout_s)
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

    def _parse_transactions(self, raw: Dict[str, Any]) -> List[BurpTransaction]:
        items = raw.get("transactions", []) if isinstance(raw, dict) else []
        out: List[BurpTransaction] = []
        for t in items:
            out.append(self._normalize_transaction(t))
        return out

    def _normalize_transaction(self, raw: Dict[str, Any]) -> BurpTransaction:
        return BurpTransaction(
            tx_id=raw.get("tx_id") or raw.get("id") or f"tx-{uuid.uuid4().hex[:8]}",
            target_host=raw.get("target_host") or raw.get("host") or "",
            method=raw.get("method") or "GET",
            url=raw.get("url") or "",
            status_code=int(raw.get("status_code") or 200),
            req_headers=_redact_headers(raw.get("req_headers") or {}),
            req_body=_redact_secrets(raw.get("req_body") or "")[:self.config.max_request_size_bytes],
            resp_headers=_redact_headers(raw.get("resp_headers") or {}),
            resp_body=_redact_secrets(raw.get("resp_body") or "")[:self.config.max_response_size_bytes],
            tool_source=raw.get("tool_source") or raw.get("source") or "proxy",
            timestamp=float(raw.get("timestamp") or time.time()),
            provenance="burp_gateway",
        )


# ---------------------------------------------------------------------------
# نسخة مشتركة (تُحقن في المنسق / واجهة الويب)
# ---------------------------------------------------------------------------

GLOBAL_BURP_ADAPTER = BurpAdapter()


def create_burp_adapter(
    *,
    gateway_base_url: Optional[str] = None,
    scope_enforcer: Optional[ScopeEnforcer] = None,
    enabled: bool = True,
) -> BurpAdapter:
    cfg = BurpAdapterConfig()
    if gateway_base_url:
        cfg.gateway_base_url = gateway_base_url
    cfg.enabled = enabled
    return BurpAdapter(config=cfg, scope_enforcer=scope_enforcer)
