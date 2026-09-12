"""
WAF-Aware Architecture & Rate-Limit Governor
Provides safe, defensive, and non-evasive handling of Web Application Firewalls (WAF) and API Gateways:
1. Safe Gateway Response Classification (distinguishes WAF blocks from application errors).
2. Centralized Rate-Limit Governor (token bucket with backoff on 429, stopping on repeated 403s without evasion).
3. Baseline Comparison (verifies behavior against baseline before probing).
4. Strict Result Classification (waf_block, application_error, interesting_behavior, confirmed_vulnerability).
5. Defensive WAF Auditing (checks origin protection, informative block pages, and logging coverage).
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

WAF_SAFETY_POLICY = """
WAF Safety Policy:
- Never bypass, evade, disable, or fingerprint a WAF for evasion purposes.
- Never rotate IPs, spoof trusted headers, abuse proxy chains, or mutate payloads to defeat filtering.
- If a request is blocked, classify it as blocked and stop that test path.
- Do not interpret a WAF response as proof of a vulnerability.
- Use only benign canary values approved for the authorized program.
- Do not attempt WAF denial-of-service, parser differentials, request smuggling,
  cache poisoning, or desynchronization tests unless explicitly authorized.
- Escalate blocked or ambiguous cases for manual review.
- Keep all testing within the declared scope and request budget.
"""


class GatewayClassification(str, Enum):
    RATE_LIMITED = "rate_limited"
    BLOCKED_OR_FILTERED = "blocked_or_filtered"
    UPSTREAM_OR_GATEWAY_ERROR = "upstream_or_gateway_error"
    CHALLENGE = "challenge"
    APPLICATION_RESPONSE = "application_response"


class ResultClassification(str, Enum):
    WAF_BLOCK = "waf_block"
    APPLICATION_ERROR = "application_error"
    INTERESTING_BEHAVIOR = "interesting_behavior"
    CONFIRMED_VULNERABILITY = "confirmed_vulnerability"


@dataclass
class BaselineProfile:
    endpoint_url: str
    method: str
    status_code: int
    content_length: int
    title: str
    headers: Dict[str, str]
    response_time_ms: float
    timestamp: float = field(default_factory=time.time)


@dataclass
class FindingTriageResult:
    url: str
    parameter: str
    observation: str
    classification: ResultClassification
    confidence: float
    vulnerability_confirmed: bool
    next_action: str  # "stop_and_request_manual_review", "investigate_safely", "report", "discard"
    details: str = ""


class WAFAwareGovernor:
    """
    محرك الوعي بالـ WAF وضابط معدل الطلبات (WAF-Aware Governor):
    - يلتزم بسياسة الأمان وعدم التحايل (Non-Evasive Safety Policy).
    - يميّز بين استجابات بوابات الحماية (WAF/CDN) واستجابات التطبيق الحقيقية.
    - يدير معدل الطلبات ويوقف المسار المحظور للمراجعة اليدوية دون محاولات تدوير أو تزوير.
    """

    def __init__(self, requests_per_second: float = 2.0, max_consecutive_blocks: int = 3):
        self.rps = max(0.1, requests_per_second)
        self.interval = 1.0 / self.rps
        self.max_consecutive_blocks = max_consecutive_blocks

        self.last_request_time: float = 0.0
        self.consecutive_blocks: int = 0
        self.is_cool_down_active: bool = False
        self.baselines: Dict[str, BaselineProfile] = {}

    # ── 1. Gateway Response Classification ───────────────────────────
    @classmethod
    def classify_gateway_response(
        cls,
        status_code: int,
        response_headers: Dict[str, str],
        response_body: str
    ) -> GatewayClassification:
        """
        تصنيف طبيعة استجابة البوابة (Gateway/WAF Response):
        - 429 -> معدل الطلبات تجاوز الحد
        - 403, 406 -> حظر أو فلترة من الجدار الناري
        - 502, 503, 504 -> خطأ في خادم البوابة أو مزود الخدمة
        - كابتشا / تحدي -> صفحة تحدي
        - خلاف ذلك -> استجابة التطبيق العادية
        """
        body_lower = response_body.lower()
        headers_lower = {k.lower(): v.lower() for k, v in response_headers.items()}

        if status_code == 429 or "retry-after" in headers_lower:
            return GatewayClassification.RATE_LIMITED

        if "captcha" in body_lower or "turnstile" in body_lower or "just a moment..." in body_lower:
            return GatewayClassification.CHALLENGE

        if status_code in (403, 406):
            return GatewayClassification.BLOCKED_OR_FILTERED

        if status_code in (502, 503, 504):
            return GatewayClassification.UPSTREAM_OR_GATEWAY_ERROR

        return GatewayClassification.APPLICATION_RESPONSE

    # ── 2. Rate-Limit Governor ───────────────────────────────────────
    def enforce_rate_limit(self):
        """تطبيق حارس معدل الطلبات المركزي (Token Bucket / Interval)"""
        now = time.time()
        elapsed = now - self.last_request_time
        if elapsed < self.interval:
            sleep_sec = self.interval - elapsed
            time.sleep(sleep_sec)
        self.last_request_time = time.time()

    def handle_rate_limit_feedback(self, status_code: int) -> Tuple[bool, str]:
        """
        التعامل المسؤول مع استجابات الـ WAF والـ Rate Limiting:
        - عند 429: تفعيل فترة انتظار مضاعفة (Backoff).
        - عند تكرار 403: إيقاف مسار الاختبار للمراجعة اليدوية وعدم محاولة التحايل.
        """
        if status_code == 429:
            self.interval = min(self.interval * 2.0, 10.0)  # Slow down
            logger.warning(f"[WAFGovernor] 429 Rate Limit encountered. Increased interval to {self.interval:.2f}s.")
            time.sleep(2.0)  # Immediate safety pause
            return False, "Rate limited: Increased backoff interval."

        if status_code in (403, 406):
            self.consecutive_blocks += 1
            if self.consecutive_blocks >= self.max_consecutive_blocks:
                logger.warning(
                    f"[WAFGovernor] Reached {self.consecutive_blocks} consecutive blocks. "
                    f"STOPPING current test path to respect protection boundaries."
                )
                return False, "STOP_TEST_PATH: Repeated WAF blocks detected. Escalating to manual review."
            return True, f"WAF Block count: {self.consecutive_blocks}/{self.max_consecutive_blocks}"

        # Reset consecutive block counter on legitimate application response
        self.consecutive_blocks = 0
        return True, "Normal"

    # ── 3. Baseline Comparison ───────────────────────────────────────
    def record_baseline(
        self,
        endpoint_url: str,
        method: str,
        status_code: int,
        response_body: str,
        response_headers: Dict[str, str],
        response_time_ms: float
    ) -> BaselineProfile:
        """تسجيل الاستجابة الطبيعية الأساسية قبل إجراء أي فحص"""
        title_match = re.search(r"<title>(.*?)</title>", response_body, re.IGNORECASE)
        title = title_match.group(1).strip() if title_match else ""

        key = f"{method.upper()}:{endpoint_url.split('?')[0]}"
        profile = BaselineProfile(
            endpoint_url=endpoint_url,
            method=method.upper(),
            status_code=status_code,
            content_length=len(response_body),
            title=title,
            headers=response_headers,
            response_time_ms=response_time_ms
        )
        self.baselines[key] = profile
        return profile

    def compare_with_baseline(
        self,
        endpoint_url: str,
        method: str,
        probe_status: int,
        probe_body: str,
        probe_headers: Dict[str, str],
        probe_time_ms: float
    ) -> Dict[str, Any]:
        """مقارنة دقيقة بين نتيجة الفحص والـ Baseline لتفادي الخلط بين الحظر والثغرة"""
        key = f"{method.upper()}:{endpoint_url.split('?')[0]}"
        base = self.baselines.get(key)

        if not base:
            return {
                "has_baseline": False,
                "status_changed": False,
                "length_delta": 0,
                "note": "No prior baseline recorded."
            }

        title_match = re.search(r"<title>(.*?)</title>", probe_body, re.IGNORECASE)
        probe_title = title_match.group(1).strip() if title_match else ""

        status_changed = probe_status != base.status_code
        length_delta = len(probe_body) - base.content_length
        title_changed = probe_title != base.title

        return {
            "has_baseline": True,
            "baseline_status": base.status_code,
            "probe_status": probe_status,
            "status_changed": status_changed,
            "length_delta": length_delta,
            "title_changed": title_changed,
            "latency_delta_ms": round(probe_time_ms - base.response_time_ms, 1)
        }

    # ── 4. Strict Result Classification ──────────────────────────────
    def classify_test_result(
        self,
        target_url: str,
        parameter_name: str,
        probe_status: int,
        probe_headers: Dict[str, str],
        probe_body: str,
        benign_canary_reflected: bool = False,
        proven_differential: bool = False
    ) -> FindingTriageResult:
        """
        تصنيف النتيجة بصرامة علمية وأخلاقية:
        - لا يعتبر الـ 403 أو تغير حجم الصفحة دليلاً على ثغرة إطلاقاً.
        - يصنف حظر الـ WAF كـ waf_block ويوقف المسار للمراجعة اليدوية.
        """
        gateway_type = self.classify_gateway_response(probe_status, probe_headers, probe_body)

        if gateway_type in (GatewayClassification.BLOCKED_OR_FILTERED, GatewayClassification.CHALLENGE):
            return FindingTriageResult(
                url=target_url,
                parameter=parameter_name,
                observation=f"Request returned HTTP {probe_status} matching gateway filtering rule.",
                classification=ResultClassification.WAF_BLOCK,
                confidence=0.95,
                vulnerability_confirmed=False,
                next_action="stop_and_request_manual_review",
                details="WAF/Gateway filtered input parameter. Test path ceased without evasion attempts."
            )

        if probe_status in (500, 502, 503):
            return FindingTriageResult(
                url=target_url,
                parameter=parameter_name,
                observation=f"Request returned HTTP {probe_status} server error.",
                classification=ResultClassification.APPLICATION_ERROR,
                confidence=0.70,
                vulnerability_confirmed=False,
                next_action="investigate_safely",
                details="Server internal error encountered; requires safe non-destructive differential verification."
            )

        if proven_differential and benign_canary_reflected:
            return FindingTriageResult(
                url=target_url,
                parameter=parameter_name,
                observation="Safe non-destructive canary evaluated and verified with clear differential.",
                classification=ResultClassification.CONFIRMED_VULNERABILITY,
                confidence=0.95,
                vulnerability_confirmed=True,
                next_action="report",
                details="Verified vulnerability with clean reproducible proof without harm."
            )

        return FindingTriageResult(
            url=target_url,
            parameter=parameter_name,
            observation="Normal application response matching expected behavior.",
            classification=ResultClassification.INTERESTING_BEHAVIOR,
            confidence=0.60,
            vulnerability_confirmed=False,
            next_action="discard",
            details="Input evaluated normally by application."
        )

    # ── 5. Defensive WAF Auditing Heuristics ──────────────────────────
    @classmethod
    def audit_waf_defensive_coverage(
        cls,
        domain: str,
        subdomains: List[str],
        waf_detected_per_sub: Dict[str, bool],
        origin_ip_exposed: bool = False
    ) -> Dict[str, Any]:
        """
        فحوصات الـ WAF الدفاعية المصرح بها لمالك التطبيق:
        - هل الـ WAF أمام كل الأصول أم بعض الـ subdomains فقط؟
        - هل الـ Origin IP مكشوف مباشرة مما يسمح بتخطي الحماية عبر الـ IP؟
        """
        unprotected = [s for s in subdomains if not waf_detected_per_sub.get(s, False)]
        recommendations = []

        if unprotected:
            recommendations.append(f"WAF coverage gap: Subdomains {unprotected} are not behind WAF/CDN.")

        if origin_ip_exposed:
            recommendations.append(f"Origin Exposure: The direct origin IP for {domain} is publicly reachable.")

        return {
            "domain": domain,
            "total_subdomains": len(subdomains),
            "protected_subdomains": len(subdomains) - len(unprotected),
            "unprotected_subdomains": unprotected,
            "origin_ip_exposed": origin_ip_exposed,
            "hardening_recommendations": recommendations
        }
