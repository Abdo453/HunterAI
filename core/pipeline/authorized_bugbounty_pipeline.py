"""
Authorized Bug Bounty Security Testing Pipeline (Phases 0 - 7)
Enforces strict scope boundaries, non-destructive validation, rate limits (<= 2 req/s),
parameter classification, and the 8-Question False Positive Gate.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from core.reproducibility.replay_bundle import ReplayBundleFactory
from core.oob.oob_client import OOBInteractionClient, OOBProbeContext
from core.authz.rbac_matrix_engine import RBACPrivilegeMatrixEngine, RoleSession
from core.websocket.websocket_inspector import WebSocketSecurityInspector
from core.waf.adaptive_waf_bridge import AdaptiveWAFPlaywrightBridge
from core.waf.waf_aware_governor import WAFAwareGovernor, WAF_SAFETY_POLICY, GatewayClassification, ResultClassification
from core.canary.context_canary_engine import ContextCanaryEngine, ReflectionContext

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = f"""You are an authorized Bug Bounty Security Testing Agent.

Mission:
Discover and validate vulnerabilities only on assets explicitly included in the provided scope.

Mandatory rules:
1. Read and enforce scope before any request.
2. Never scan an out-of-scope domain, IP, subdomain, cloud asset, or third-party service.
3. Never perform DoS, stress testing, destructive actions, data deletion, mass account creation, phishing, credential attacks, or real account takeover.
4. Use only approved test accounts and researcher-controlled callback domains.
5. Start with low request rates and respect robots, program rules, and rate limits.
6. Do not access, download, modify, or retain sensitive user data.
7. Stop and report immediately if sensitive data, production secrets, payment data, or another user's account appears.
8. Do not claim that a command ran or a vulnerability was confirmed unless execution evidence exists.
9. Separate:
   - Observation
   - Hypothesis
   - Safe validation
   - Confirmed finding
10. Every finding must include reproducible evidence, impact, affected asset, severity rationale, and remediation.

{WAF_SAFETY_POLICY.strip()}

Workflow:
Phase 0: Scope and safety validation
Phase 1: Passive asset and endpoint discovery
Phase 2: Directory and file discovery
Phase 3: Parameter discovery
Phase 4: Parameter classification
Phase 5: Safe vulnerability testing
Phase 6: Correlation and deduplication
Phase 7: Professional report generation

Do not automatically exploit high-impact vulnerabilities.
Use harmless canary payloads and stop when impact is proven.
"""

# Parameter Classification Matrix (Phase 4)
PARAMETER_CLASSIFICATION_RULES = [
    (r"(?i)^(id|user_id|account_id|order_id|invoice_id|doc_id|uuid|profile_id)$", "bola_idor", ["BOLA/IDOR dual-account differential"]),
    (r"(?i)^(url|uri|redirect|next|dest|target|return_to|callback_url|link)$", "ssrf_open_redirect", ["SSRF canary collaborator", "Open redirect validation"]),
    (r"(?i)^(q|query|search|name|keyword|comment|title|desc|msg|text)$", "xss_sqli_context", ["HTML/Attribute context check", "Benign SQL differential"]),
    (r"(?i)^(template|view|theme|layout|render|page_tpl)$", "ssti", ["Benign mathematical evaluation {{7*7}}"]),
    (r"(?i)^(file|path|filename|doc|download|folder|include|page_file)$", "path_traversal_lfi", ["Safe path traversal enclosure test"]),
    (r"(?i)^(cmd|exec|command|run|cli|ping|host)$", "command_injection", ["Benign command syntax check with extreme caution"]),
    (r"(?i)^(sort|order|filter|by|column|direction|group_by)$", "sqli_business_logic", ["Safe order-by differential"]),
    (r"(?i)^(callback|jsonp)$", "jsonp_xss", ["JSONP wrapper context test"]),
]


@dataclass
class AuthorizedProgramScope:
    program_name: str
    in_scope: List[str]
    out_of_scope: List[str] = field(default_factory=list)
    allowed_methods: List[str] = field(default_factory=lambda: ["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS", "HEAD"])
    forbidden_tests: List[str] = field(default_factory=lambda: ["DoS", "bruteforce", "account takeover", "data deletion", "mass account creation"])
    max_requests_per_second: float = 2.0
    test_accounts: List[str] = field(default_factory=list)
    canary_callback_domain: str = "researcher-canary.collaborator.net"


@dataclass
class EndpointRecord:
    method: str
    url: str
    source: str  # "robots", "sitemap", "javascript", "openapi", "graphql", "html"
    auth_required: bool = False
    parameters: List[str] = field(default_factory=list)
    risk: str = "low"
    status: str = "discovered"


@dataclass
class ParameterRecord:
    name: str
    location: str  # "query", "body", "header", "path", "json"
    method: str
    endpoint: str
    vulnerability_category: str
    recommended_tests: List[str]
    baseline_difference: str = "body_length"
    confidence: float = 0.80


@dataclass
class SafeFinding:
    finding_id: str
    title: str
    asset: str
    vulnerability_type: str
    severity: str  # "Low", "Medium", "High", "Critical"
    summary: str
    prerequisites: str
    steps_to_reproduce: List[str]
    expected_behavior: str
    actual_behavior: str
    impact: str
    sanitized_request: str
    sanitized_response: str
    root_cause: str
    remediation: str
    safety_notes: str = "Tested exclusively with researcher test accounts without modifying third-party data."
    gate_8_passed: bool = False


class AuthorizedBugBountyPipeline:
    """
    خط سير العمل الأمني المصرح به للـ Bug Bounty (Phases 0 to 7):
    - يضمن مطابقة الـ Scope حرفياً.
    - يتحكم بمعدل الطلبات (Rate-limit: 2 req/s).
    - يمنع الاختبارات المدمّرة والـ DoS والـ Data Dumping.
    - يطبق بوابة التحقق الثمانية لمنع الـ False Positives.
    """

    def __init__(self, scope: AuthorizedProgramScope, workspace_root: Path):
        self.scope = scope
        self.workspace_root = workspace_root
        self.workspace_root.mkdir(parents=True, exist_ok=True)
        self.last_request_time = 0.0
        self.min_request_interval = 1.0 / max(0.1, scope.max_requests_per_second)

        self.discovered_endpoints: List[EndpointRecord] = []
        self.discovered_parameters: List[ParameterRecord] = []
        self.confirmed_findings: List[SafeFinding] = []

        # ── Elite Security Subsystems ────────────────────────────────
        self.oob_client = OOBInteractionClient(base_callback_domain=scope.canary_callback_domain)
        self.rbac_engine = RBACPrivilegeMatrixEngine()
        self.websocket_inspector = WebSocketSecurityInspector()
        self.waf_bridge = AdaptiveWAFPlaywrightBridge(headless=True)
        self.waf_governor = WAFAwareGovernor(requests_per_second=scope.max_requests_per_second)
        self.canary_engine = ContextCanaryEngine()

    # ── Phase 0: Scope Gate ──────────────────────────────────────────
    def is_url_in_scope(self, url: str) -> bool:
        """التحقق الصارم من أن الرابط يقع تماماً داخل الـ In-Scope وليس مستثنى"""
        if not url:
            return False
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()

        # Check out of scope first
        for oos in self.scope.out_of_scope:
            clean_oos = urlparse(oos).hostname or oos.strip().lower()
            if hostname == clean_oos or hostname.endswith("." + clean_oos):
                logger.warning(f"[ScopeGate] URL '{url}' is explicitly OUT OF SCOPE ('{oos}')")
                return False

        # Check in scope
        in_scope_match = False
        for inc in self.scope.in_scope:
            clean_inc = urlparse(inc).hostname or inc.strip().lower()
            if hostname == clean_inc or hostname.endswith("." + clean_inc):
                in_scope_match = True
                break

        if not in_scope_match:
            logger.warning(f"[ScopeGate] URL '{url}' not listed in IN-SCOPE")
            return False

        return True

    def validate_method_and_safety(self, method: str, test_type: str) -> Tuple[bool, str]:
        """التحقق من أن الطريقة ونوع الاختبار غير محظورين"""
        if method.upper() not in [m.upper() for m in self.scope.allowed_methods]:
            return False, f"HTTP method '{method}' is not permitted by program scope."

        for forbidden in self.scope.forbidden_tests:
            if forbidden.lower() in test_type.lower():
                return False, f"Test type '{test_type}' is prohibited (Forbidden: {forbidden})."

        return True, "Approved"

    def enforce_rate_limit(self):
        """تطبيق معدل الطلبات الآمن (Max 2 req/s)"""
        now = time.time()
        elapsed = now - self.last_request_time
        if elapsed < self.min_request_interval:
            sleep_time = self.min_request_interval - elapsed
            time.sleep(sleep_time)
        self.last_request_time = time.time()

    # ── Phase 1: Passive Discovery ───────────────────────────────────
    def ingest_passive_assets(self, raw_sources: Dict[str, Any]) -> List[EndpointRecord]:
        """استخراج المسارات والـ Endpoints من المصادر السلبية (Robots, Sitemap, JS, OpenAPI, GraphQL)"""
        endpoints: List[EndpointRecord] = []

        for item in raw_sources.get("robots_txt", []):
            url = item if item.startswith("http") else f"{self.scope.in_scope[0].rstrip('/')}/{item.lstrip('/')}"
            if self.is_url_in_scope(url):
                endpoints.append(EndpointRecord(method="GET", url=url, source="robots", auth_required=False, risk="low"))

        for item in raw_sources.get("javascript_endpoints", []):
            url = item if item.startswith("http") else f"{self.scope.in_scope[0].rstrip('/')}/{item.lstrip('/')}"
            if self.is_url_in_scope(url):
                endpoints.append(EndpointRecord(method="GET", url=url, source="javascript", auth_required=True, risk="medium"))

        for ep in raw_sources.get("openapi_endpoints", []):
            url = ep.get("url", "")
            if self.is_url_in_scope(url):
                endpoints.append(EndpointRecord(
                    method=ep.get("method", "GET"),
                    url=url,
                    source="openapi",
                    auth_required=ep.get("auth", True),
                    parameters=ep.get("params", []),
                    risk="medium"
                ))

        self.discovered_endpoints.extend(endpoints)
        return endpoints

    # ── Phase 2: Directory & File Discovery ──────────────────────────
    def filter_directory_results(self, ffuf_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """فلترة نتائج الـ FFUF وتجنب اعتبار الـ 200 وحدها دليلاً على ثغرة"""
        valid = []
        for r in ffuf_results:
            url = r.get("url", "")
            status = r.get("status", 404)
            length = r.get("length", 0)

            if not self.is_url_in_scope(url):
                continue

            # Accept meaningful responses, filter empty / generic 404 wrappers
            if status in (200, 204, 301, 302, 307, 401, 403) and length > 50:
                valid.append(r)

        return valid

    # ── Phase 3 & 4: Parameter Discovery & Classification ───────────
    def classify_parameter(self, param_name: str, location: str, method: str, endpoint: str) -> ParameterRecord:
        """تصنيف الـ Parameter وتحديد خطة الاختبار الآمنة المطابقة له"""
        category = "general_input"
        recommended_tests = ["context_diff"]

        for pattern, cat, tests in PARAMETER_CLASSIFICATION_RULES:
            if re.match(pattern, param_name):
                category = cat
                recommended_tests = tests
                break

        record = ParameterRecord(
            name=param_name,
            location=location,
            method=method,
            endpoint=endpoint,
            vulnerability_category=category,
            recommended_tests=recommended_tests,
            confidence=0.85
        )
        self.discovered_parameters.append(record)
        return record

    # ── Phase 5: Safe Vulnerability Validation ────────────────────────
    def perform_safe_validation(
        self,
        endpoint_url: str,
        param_record: ParameterRecord,
        probe_differential_fn: Callable[[str, str], Dict[str, Any]]
    ) -> Optional[SafeFinding]:
        """
        تنفيذ الفحص الآمن غير المدمّر:
        - استخدام Payloads غير ضارة (Canaries).
        - مقارنة الـ Baseline.
        - التوقف فور إثبات الأثر وتجنب الـ Exploitation المفرطة.
        """
        if not self.is_url_in_scope(endpoint_url):
            logger.warning(f"[SafeValidation] Blocked out-of-scope validation: {endpoint_url}")
            return None

        self.enforce_rate_limit()

        # Execute safe probe callback
        result = probe_differential_fn(endpoint_url, param_record.name)

        if not result.get("impact_proven", False):
            return None

        # Build sanitized finding
        finding_id = f"FIND-{len(self.confirmed_findings) + 1:03d}"
        sanitized_req = ReplayBundleFactory.redact_secrets(result.get("request_raw", ""))
        sanitized_resp = ReplayBundleFactory.redact_secrets(result.get("response_raw", ""))

        finding = SafeFinding(
            finding_id=finding_id,
            title=f"Confirmed {param_record.vulnerability_category.upper()} on parameter '{param_record.name}'",
            asset=endpoint_url,
            vulnerability_type=param_record.vulnerability_category,
            severity=result.get("severity", "Medium"),
            summary=result.get("summary", "Safe non-destructive probe confirmed differential behavior."),
            prerequisites=f"Two authorized test accounts ({', '.join(self.scope.test_accounts[:2])})" if self.scope.test_accounts else "Standard test session",
            steps_to_reproduce=result.get("reproduction_steps", [f"Send benign differential probe to {endpoint_url}"]),
            expected_behavior="Server rejects unauthorized access or sanitizes input parameter.",
            actual_behavior=result.get("actual_behavior", "Server executed injected benign logic or exposed object."),
            impact=result.get("impact", "Unauthorized access or execution boundary breach."),
            sanitized_request=sanitized_req,
            sanitized_response=sanitized_resp,
            root_cause=result.get("root_cause", "Missing server-side validation / authorization."),
            remediation=result.get("remediation", "Enforce strict server-side validation and authorization filter."),
            gate_8_passed=False
        )

        # ── Phase 6: 8-Question False Positive Gate ──────────────────
        gate_passed, gate_reasons = self.evaluate_8_question_gate(finding, result)
        finding.gate_8_passed = gate_passed

        if gate_passed:
            self.confirmed_findings.append(finding)
            return finding
        else:
            logger.info(f"[8-QuestionGate] Rejected finding {finding_id}: {'; '.join(gate_reasons)}")
            return None

    def evaluate_8_question_gate(self, finding: SafeFinding, test_metadata: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        بوابة الأسئلة الثمانية لمنع الـ False Positives:
        1. هل الأصل داخل النطاق؟
        2. هل السلوك قابل للتكرار؟
        3. هل يوجد فرق واضح عن baseline؟
        4. هل الفرق أمني أم مجرد اختلاف طبيعي؟
        5. هل تم استخدام حسابات اختبار؟
        6. هل تم إثبات الأثر بدون ضرر؟
        7. هل يوجد دليل HTTP أو code واضح؟
        8. هل severity متناسبة مع الأثر الحقيقي؟
        """
        reasons = []

        # Q1: In Scope
        if not self.is_url_in_scope(finding.asset):
            reasons.append("Q1 Failed: Asset is not strictly in-scope")

        # Q2: Reproducible
        if not test_metadata.get("is_reproducible", True):
            reasons.append("Q2 Failed: Behavior is intermittent / un-reproducible")

        # Q3: Baseline Difference
        if not test_metadata.get("baseline_difference_verified", True):
            reasons.append("Q3 Failed: No significant differential vs baseline")

        # Q4: Genuine Security Difference
        if test_metadata.get("is_benign_randomness", False):
            reasons.append("Q4 Failed: Difference is benign application jitter")

        # Q5: Test Accounts
        if not test_metadata.get("used_test_accounts", True):
            reasons.append("Q5 Failed: Real third-party accounts were involved")

        # Q6: Harmless Proof
        if test_metadata.get("caused_harm", False) or test_metadata.get("database_dumped", False):
            reasons.append("Q6 Failed: Destructive test performed")

        # Q7: Clear HTTP/Code Proof
        if not (finding.sanitized_request and finding.sanitized_response):
            reasons.append("Q7 Failed: Missing concrete HTTP request/response evidence")

        # Q8: Proportionate Severity
        if finding.severity.lower() == "critical" and "rce" not in finding.vulnerability_type.lower() and "auth_bypass" not in finding.vulnerability_type.lower():
            reasons.append("Q8 Warning: Severity adjusted from inflated Critical to Medium/High")

        passed = len(reasons) == 0
        return passed, reasons

    # ── Phase 7: Professional Report Generation ──────────────────────
    def generate_final_report(self) -> str:
        """توليد التقرير النهائي المطابق لمعايير منصات الـ Bug Bounty الاحترافية"""
        lines = [
            f"# [REPORT] Bug Bounty Security Assessment: {self.scope.program_name}",
            "",
            f"**Assessment Date:** {time.strftime('%Y-%m-%d %H:%M:%S')}",
            f"**In-Scope Targets:** {', '.join(self.scope.in_scope)}",
            f"**Total Confirmed Findings:** `{len(self.confirmed_findings)}`",
            "",
            "---",
            "",
            "## Findings Summary",
            "",
            "| ID | Title | Asset | Severity | 8-Question Gate |",
            "|---|---|---|---|---|",
        ]

        for f in self.confirmed_findings:
            gate_status = "[+] VERIFIED" if f.gate_8_passed else "[-] REJECTED"
            lines.append(f"| {f.finding_id} | **{f.title}** | `{f.asset}` | **{f.severity}** | {gate_status} |")

        lines.append("\n---\n")

        for f in self.confirmed_findings:
            lines.extend([
                f"### Title: {f.title} in {f.asset}",
                "",
                f"**Severity:** {f.severity}",
                f"**Asset:** `{f.asset}`",
                "",
                "#### Summary",
                f"{f.summary}",
                "",
                "#### Prerequisites",
                f"{f.prerequisites}",
                "",
                "#### Steps to Reproduce",
            ])
            for idx, step in enumerate(f.steps_to_reproduce, 1):
                lines.append(f"{idx}. {step}")

            lines.extend([
                "",
                "#### Expected Behavior",
                f"{f.expected_behavior}",
                "",
                "#### Actual Behavior",
                f"{f.actual_behavior}",
                "",
                "#### Security Impact",
                f"{f.impact}",
                "",
                "#### Evidence",
                "```http",
                "--- Request (Sanitized) ---",
                f"{f.sanitized_request}",
                "",
                "--- Response (Sanitized) ---",
                f"{f.sanitized_response}",
                "```",
                "",
                "#### Root Cause",
                f"{f.root_cause}",
                "",
                "#### Remediation",
                f"{f.remediation}",
                "",
                "#### Safety Notes",
                f"> [!NOTE]",
                f"> {f.safety_notes}",
                "",
                "---",
                ""
            ])

        report_md = "\n".join(lines)
        report_file = self.workspace_root / "authorized_bugbounty_report.md"
        report_file.write_text(report_md, encoding="utf-8")
        return report_md
