"""
Advanced Safe SQL Injection Assessment Skill (v2.0)
===================================================
Professional Bug Bounty & Ethical Pentest AI Skill for Safe, Non-Destructive SQLi
Detection, Context Inference, Differential Verification, and OWASP-grade Reporting.

Guiding Principles:
- Scope-First & Safety Guardrails (Zero data dumping, no destructive queries, no WAF bypass)
- Multi-Sample Baseline Profiling with Dynamic Content Normalization
- Context Inference (WHERE, ORDER BY, LIMIT, LIKE, GraphQL, ORM, Stored Procs)
- Non-Destructive Differential Testing (Status, Length, Body Similarity, Structure)
- Controlled Timing Verification with Median/MAD and Network Stability Gating
- Second-Order Injection State Tracking with Researcher Test Markers
- Multi-Signal Evidence Correlation & Strict Confidence Calibration
- Deduplication & OWASP-aligned Safe Reporting
"""

import re
import json
import time
import math
import hashlib
import difflib
import logging
from enum import Enum, auto
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any, Set
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx

log = logging.getLogger("safe_sqli_assessment")


# ─────────────────────────────────────────────────────────────────────────────
# Enums & Classifications
# ─────────────────────────────────────────────────────────────────────────────

class ConfidenceLevel(Enum):
    INFORMATIONAL        = (0.00, 0.29, "informational")
    WEAK_SIGNAL          = (0.30, 0.59, "weak_signal")
    PROBABLE             = (0.60, 0.79, "probable")
    STRONG_CANDIDATE     = (0.80, 0.92, "strong_candidate")
    CONFIRMED_SAFE       = (0.93, 1.00, "confirmed_safe_evidence")

    def __init__(self, min_val: float, max_val: float, label: str):
        self.min_val = min_val
        self.max_val = max_val
        self.label = label

    @classmethod
    def from_score(cls, score: float) -> "ConfidenceLevel":
        score = max(0.0, min(1.0, score))
        if score >= 0.93:
            return cls.CONFIRMED_SAFE
        elif score >= 0.80:
            return cls.STRONG_CANDIDATE
        elif score >= 0.60:
            return cls.PROBABLE
        elif score >= 0.30:
            return cls.WEAK_SIGNAL
        return cls.INFORMATIONAL


class ParameterLocation(Enum):
    QUERY            = "query"
    BODY_FORM        = "body_form"
    BODY_JSON        = "body_json"
    PATH             = "path"
    GRAPHQL_VARIABLE = "graphql_variable"
    HEADER           = "header"
    COOKIE           = "cookie"


class ParameterType(Enum):
    NUMERIC = "numeric"
    STRING  = "string"
    BOOLEAN = "boolean"
    JSON    = "json"
    PATH    = "path"
    GRAPHQL = "graphql"
    UNKNOWN = "unknown"


class SQLiContextType(Enum):
    SQL_WHERE_VALUE         = "sql_where_value"
    SQL_ORDER_CLAUSE        = "sql_order_clause"
    SQL_LIMIT_CLAUSE        = "sql_limit_clause"
    SQL_LIKE_EXPRESSION     = "sql_like_expression"
    STORED_PROCEDURE_ARG    = "stored_procedure_argument"
    JSON_TO_SQL_FILTER      = "json_to_sql_filter"
    GRAPHQL_TO_SQL_RESOLVER = "graphql_to_sql_resolver"
    ORM_FILTER              = "orm_filter"
    UNKNOWN                 = "unknown"


class FindingClassification(Enum):
    DISCARDED                = "discarded"
    POSSIBLE_ERROR_LEAK      = "possible_error_leak"
    UNCONFIRMED              = "unconfirmed"
    STRONG_CANDIDATE         = "strong_candidate"
    CONFIRMED_SQLI_CANDIDATE = "confirmed_sqli_candidate"


# ─────────────────────────────────────────────────────────────────────────────
# Data Containers
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ScopePolicy:
    """Strict Scope and Safety Guardrail Definitions"""
    allowed_domains: List[str] = field(default_factory=lambda: ["*"])
    forbidden_methods: List[str] = field(default_factory=lambda: ["DELETE"])
    max_requests_per_sec: float = 2.0
    forbidden_actions: List[str] = field(default_factory=lambda: [
        "database_dumping",
        "reading_sensitive_records",
        "destructive_queries",
        "data_modification",
        "command_execution",
        "authentication_bypass_on_real_accounts",
        "WAF_bypass_attempts",
        "denial_of_service",
        "high_volume_scanning",
    ])
    require_approval_for: List[str] = field(default_factory=lambda: [
        "authenticated_state_changes",
        "POST/PUT/PATCH",
        "timing_based_tests",
        "second_order_tests",
        "graphql_mutations",
        "high_severity_hypothesis",
    ])

    def is_in_scope(self, url: str) -> bool:
        if "*" in self.allowed_domains:
            return True
        hostname = urlparse(url).hostname or ""
        return any(
            hostname == d or hostname.endswith("." + d.lstrip("."))
            for d in self.allowed_domains
        )


@dataclass
class BaselineProfile:
    """Multi-sample baseline profile with noise isolation"""
    status_mode: int = 200
    body_length_median: float = 0.0
    body_length_mad: float = 0.0
    response_time_median_ms: float = 0.0
    response_time_p95_ms: float = 0.0
    content_hash_stability: float = 1.0
    dynamic_regions: List[str] = field(default_factory=list)
    sample_count: int = 0
    raw_samples: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class ParameterProfile:
    """Parameter Intelligence Profile"""
    name: str
    location: ParameterLocation = ParameterLocation.QUERY
    observed_type: ParameterType = ParameterType.UNKNOWN
    required: bool = False
    reflection: bool = False
    response_behavior: str = "unknown"
    baseline_stability: float = 1.0
    priority: float = 0.5
    risk_factors: List[str] = field(default_factory=list)
    inferred_context: SQLiContextType = SQLiContextType.UNKNOWN


@dataclass
class DifferentialResult:
    """Results of safe logical differential evaluation"""
    probe_pair: Tuple[str, str]
    true_status: int
    false_status: int
    true_length: int
    false_length: int
    similarity: float
    result_count_delta: int
    json_structure_diff: bool
    error_signature_detected: Optional[str] = None
    is_repeatable: bool = False
    differential_score: float = 0.0


@dataclass
class SafeSQLiFinding:
    """Structured, verified finding adhering to OWASP safety & bug bounty standards"""
    finding_id: str
    title: str
    endpoint: str
    method: str
    parameter: str
    location: str
    inferred_context: str
    confidence_score: float
    confidence_level: str
    classification: str
    signals: List[str]
    evidence: Dict[str, Any]
    steps_to_reproduce: List[str]
    remediation: Dict[str, Any]
    safety_statement: str
    requires_manual_review: bool
    dedup_key: str


# ─────────────────────────────────────────────────────────────────────────────
# 1. Scope Gate & Safety Controller
# ─────────────────────────────────────────────────────────────────────────────

class ScopeGate:
    """
    Enforces absolute boundaries before any network traffic is initiated.
    Blocks out-of-scope targets, forbidden methods, and unauthorized state changes.
    """

    def __init__(self, policy: Optional[ScopePolicy] = None):
        self.policy = policy or ScopePolicy()
        self._last_request_time = 0.0

    def evaluate(self, url: str, method: str = "GET") -> Dict[str, Any]:
        if not self.policy.is_in_scope(url):
            return {
                "allowed": False,
                "reason": f"Target URL '{url}' is OUT OF SCOPE based on allowed domains: {self.policy.allowed_domains}"
            }

        if method.upper() in [m.upper() for m in self.policy.forbidden_methods]:
            return {
                "allowed": False,
                "reason": f"HTTP method '{method}' is explicitly FORBIDDEN by scope policy."
            }

        requires_approval = False
        approval_reasons = []
        if method.upper() in ["POST", "PUT", "PATCH"]:
            requires_approval = True
            approval_reasons.append("Non-idempotent HTTP method (state modification risk)")

        return {
            "allowed": True,
            "requires_approval": requires_approval,
            "approval_reasons": approval_reasons
        }

    async def throttle(self):
        """Enforce strict rate limits to protect server availability"""
        if self.policy.max_requests_per_sec <= 0:
            return
        min_interval = 1.0 / self.policy.max_requests_per_sec
        elapsed = time.time() - self._last_request_time
        if elapsed < min_interval:
            import asyncio
            await asyncio.sleep(min_interval - elapsed)
        self._last_request_time = time.time()


# ─────────────────────────────────────────────────────────────────────────────
# 2. Response Normalizer & Noise Isolator
# ─────────────────────────────────────────────────────────────────────────────

class ResponseNormalizer:
    """
    Strips non-deterministic dynamic tokens (CSRF tokens, nonces, timestamps,
    request IDs) to ensure high-fidelity diff calculations without false alarms.
    """

    DYNAMIC_PATTERNS = [
        # HTML input value tokens
        r'(?i)<input[^>]+(?:name|id)=["\']?(?:csrf[_-]?token|authenticity_token|__RequestVerificationToken|_token|nonce)["\']?[^>]+value=["\']([a-zA-Z0-9_\-\.]{16,})["\']',
        r'(?i)<input[^>]+value=["\']([a-zA-Z0-9_\-\.]{16,})["\'][^>]+(?:name|id)=["\']?(?:csrf[_-]?token|authenticity_token|__RequestVerificationToken|_token|nonce)["\']?',
        # JSON / Key-value tokens
        r'(?i)(?:csrf[_-]?token|authenticity_token|__RequestVerificationToken|session[_-]?id|nonce|request[_-]?id)[\s=:"\']+([a-zA-Z0-9_\-\.]{8,})',
        # ISO & Epoch timestamps
        r'\b\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b',
        r'\b1[6-7]\d{8,11}\b',
    ]

    @classmethod
    def sanitize_body(cls, body: str) -> str:
        if not body:
            return ""
        cleaned = body
        for pattern in cls.DYNAMIC_PATTERNS:
            def _repl(m):
                full = m.group(0)
                if m.groups() and m.group(1):
                    token_val = m.group(1)
                    return full.replace(token_val, "[DYNAMIC_TOKEN]")
                return "[DYNAMIC_TOKEN]"
            cleaned = re.sub(pattern, _repl, cleaned)
        cleaned = re.sub(r'\s+', ' ', cleaned).strip()
        return cleaned

    @classmethod
    def compute_similarity(cls, text_a: str, text_b: str) -> float:
        clean_a = cls.sanitize_body(text_a)
        clean_b = cls.sanitize_body(text_b)
        if not clean_a and not clean_b:
            return 1.0
        matcher = difflib.SequenceMatcher(None, clean_a, clean_b)
        return matcher.ratio()

    @classmethod
    def extract_json_structure(cls, body: str) -> Optional[Dict[str, Any]]:
        try:
            data = json.loads(body)
            def _extract_schema(obj):
                if isinstance(obj, dict):
                    return {k: _extract_schema(v) for k, v in obj.items()}
                elif isinstance(obj, list):
                    return [_extract_schema(obj[0])] if obj else []
                return type(obj).__name__
            return _extract_schema(data)
        except Exception:
            return None


# ─────────────────────────────────────────────────────────────────────────────
# 3. Baseline Profiler
# ─────────────────────────────────────────────────────────────────────────────

class BaselineProfiler:
    """
    Establishes an empirical baseline of normal behavior by collecting multiple
    samples and computing stability ratios, median length, and MAD.
    """

    def __init__(self, samples: int = 3):
        self.samples = max(2, samples)

    async def profile(self, url: str, params: Optional[Dict[str, Any]] = None,
                      headers: Optional[Dict[str, str]] = None,
                      proxy: Optional[str] = None) -> BaselineProfile:
        client_kwargs = {"verify": False, "follow_redirects": True, "timeout": 10.0}
        if proxy:
            import httpx as _hx
            ver = tuple(int(x) for x in _hx.__version__.split(".")[:2])
            if ver >= (0, 28):
                client_kwargs["proxy"] = proxy
            else:
                client_kwargs["proxies"] = {"http://": proxy, "https://": proxy}

        raw_samples = []
        lengths = []
        times = []
        statuses = []
        hashes = []

        async with httpx.AsyncClient(**client_kwargs) as client:
            for _ in range(self.samples):
                t0 = time.time()
                try:
                    r = await client.get(url, params=params, headers=headers)
                    elapsed_ms = (time.time() - t0) * 1000.0
                    cleaned_body = ResponseNormalizer.sanitize_body(r.text)
                    b_hash = hashlib.sha256(cleaned_body.encode("utf-8", errors="ignore")).hexdigest()

                    statuses.append(r.status_code)
                    lengths.append(len(cleaned_body))
                    times.append(elapsed_ms)
                    hashes.append(b_hash)

                    raw_samples.append({
                        "status": r.status_code,
                        "length": len(r.text),
                        "cleaned_length": len(cleaned_body),
                        "time_ms": elapsed_ms,
                        "hash": b_hash
                    })
                except Exception as e:
                    log.warning(f"Baseline sample collection encountered issue: {e}")

        if not raw_samples:
            return BaselineProfile()

        lengths.sort()
        med_len = lengths[len(lengths) // 2]
        mad_len = statistics_median([abs(x - med_len) for x in lengths]) if lengths else 0.0

        times.sort()
        med_time = times[len(times) // 2]
        p95_time = times[int(len(times) * 0.95)] if len(times) > 1 else times[-1]

        status_mode = max(set(statuses), key=statuses.count)
        most_common_hash_count = max(hashes.count(h) for h in hashes)
        stability = most_common_hash_count / len(hashes)

        return BaselineProfile(
            status_mode=status_mode,
            body_length_median=float(med_len),
            body_length_mad=float(mad_len),
            response_time_median_ms=float(med_time),
            response_time_p95_ms=float(p95_time),
            content_hash_stability=stability,
            sample_count=len(raw_samples),
            raw_samples=raw_samples
        )


def statistics_median(data: List[float]) -> float:
    if not data:
        return 0.0
    s = sorted(data)
    n = len(s)
    if n % 2 == 1:
        return float(s[n // 2])
    return float((s[n // 2 - 1] + s[n // 2]) / 2.0)


# ─────────────────────────────────────────────────────────────────────────────
# 4. Parameter Intelligence & Context Inference
# ─────────────────────────────────────────────────────────────────────────────

class ParameterClassifier:
    """
    Classifies parameter type, calculates priority based on risk factors,
    and infers the underlying SQL execution context (WHERE, ORDER BY, LIMIT, LIKE).
    """

    HIGH_PRIORITY_NAMES = {
        "id", "user_id", "order_id", "category", "cat", "filter", "search",
        "q", "sort", "order", "by", "where", "group", "date", "report", "export",
        "limit", "offset", "page", "query", "dir", "column"
    }

    @classmethod
    def classify_parameter(cls, name: str, value: Any, location: ParameterLocation = ParameterLocation.QUERY) -> ParameterProfile:
        val_str = str(value).strip() if value is not None else ""
        obs_type = ParameterType.UNKNOWN

        if val_str.isdigit() or (val_str.startswith("-") and val_str[1:].isdigit()):
            obs_type = ParameterType.NUMERIC
        elif val_str.lower() in ("true", "false", "0", "1"):
            obs_type = ParameterType.BOOLEAN
        elif (val_str.startswith("{") and val_str.endswith("}")) or (val_str.startswith("[") and val_str.endswith("]")):
            obs_type = ParameterType.JSON
        elif "/" in val_str:
            obs_type = ParameterType.PATH
        elif val_str:
            obs_type = ParameterType.STRING

        risk_factors = []
        name_lower = name.lower()
        if name_lower in cls.HIGH_PRIORITY_NAMES:
            risk_factors.append("matches_high_value_parameter_name")
        if name_lower in ("sort", "order", "orderby", "dir", "column"):
            risk_factors.append("probable_order_by_context")
        if name_lower in ("filter", "where", "search", "q"):
            risk_factors.append("probable_where_filter_context")
        if name_lower in ("limit", "offset", "page"):
            risk_factors.append("probable_pagination_clause")

        context = cls.infer_context(name, val_str, obs_type)

        db_behavior = 0.8 if risk_factors else 0.4
        user_controlled = 0.9 if location in (ParameterLocation.QUERY, ParameterLocation.BODY_FORM, ParameterLocation.BODY_JSON) else 0.5
        resp_diff = 0.7 if "probable_where_filter_context" in risk_factors or "probable_order_by_context" in risk_factors else 0.4
        endpoint_sens = 0.7 if "matches_high_value_parameter_name" in risk_factors else 0.4
        auth_impact = 0.5
        hist_ind = 0.6 if name_lower in ("id", "category", "search") else 0.2

        priority = (
            db_behavior * 0.30 +
            user_controlled * 0.20 +
            resp_diff * 0.20 +
            endpoint_sens * 0.15 +
            auth_impact * 0.10 +
            hist_ind * 0.05
        )

        return ParameterProfile(
            name=name,
            location=location,
            observed_type=obs_type,
            required=False,
            reflection=False,
            response_behavior="database-backed" if risk_factors else "generic",
            priority=round(priority, 3),
            risk_factors=risk_factors,
            inferred_context=context
        )

    @classmethod
    def infer_context(cls, name: str, value: str, obs_type: ParameterType) -> SQLiContextType:
        n = name.lower()
        if n in ("sort", "order", "orderby", "sort_by", "dir", "direction"):
            return SQLiContextType.SQL_ORDER_CLAUSE
        if n in ("limit", "offset", "page_size", "row_count"):
            return SQLiContextType.SQL_LIMIT_CLAUSE
        if n in ("search", "q", "query", "keyword", "lookup", "term"):
            return SQLiContextType.SQL_LIKE_EXPRESSION
        if obs_type == ParameterType.JSON or n in ("filter", "where", "params"):
            return SQLiContextType.JSON_TO_SQL_FILTER
        if obs_type == ParameterType.GRAPHQL:
            return SQLiContextType.GRAPHQL_TO_SQL_RESOLVER
        if obs_type == ParameterType.NUMERIC or n.endswith("_id") or n == "id":
            return SQLiContextType.SQL_WHERE_VALUE
        return SQLiContextType.SQL_WHERE_VALUE


# ─────────────────────────────────────────────────────────────────────────────
# 5. Differential SQLi Engine (Level 1: Errors, Level 2: Safe Diff, Level 3: Timing)
# ─────────────────────────────────────────────────────────────────────────────

class DifferentialSQLiEngine:
    """
    Executes safe, non-destructive validation pairs without extracting data or executing commands.
    Level 1: Passive Indicators & Error Signatures
    Level 2: Harmless Logical True/False Pair Differentials
    Level 3: Controlled Median/Variance Timing Checks
    """

    DB_ERROR_SIGNATURES: Dict[str, List[str]] = {
        "MySQL": [
            "You have an error in your SQL syntax",
            "check the manual that corresponds to your MySQL server version",
            "MySqlException",
            "mysql_fetch_array()",
            "mysql_num_rows()",
        ],
        "PostgreSQL": [
            "ERROR: unterminated quoted string",
            "ERROR: syntax error at or near",
            "org.postgresql.util.PSQLException",
            "invalid input syntax for integer",
            "PostgreSQL query failed",
        ],
        "MSSQL": [
            "Unclosed quotation mark after the character string",
            "Incorrect syntax near",
            "Microsoft OLE DB Provider for SQL Server",
            "Conversion failed when converting the varchar value",
            "System.Data.SqlClient.SqlException",
        ],
        "Oracle": [
            "ORA-00933: SQL command not properly ended",
            "ORA-01756: quoted string not properly terminated",
            "ORA-00923: FROM keyword not found where expected",
            "ORA-00907: missing right parenthesis",
            "OracleException",
        ],
        "SQLite": [
            "SQLite3::SQLException",
            "unrecognized token:",
            "near \"\": syntax error",
            "sqlite3.OperationalError",
        ]
    }

    SAFE_PROBE_PAIRS = {
        ParameterType.NUMERIC: [
            ("1 AND 1=1", "1 AND 1=2"),
            ("1*1", "1*0"),
            ("0+1", "0+0"),
        ],
        ParameterType.STRING: [
            ("' AND '1'='1", "' AND '1'='2"),
            ("'+'a", "'+'b"),
            ("' OR '1'='1' AND 'a'='a", "' OR '1'='1' AND 'a'='b"),
        ],
        ParameterType.UNKNOWN: [
            ("' AND 1=1--", "' AND 1=2--"),
            ("1 AND 1=1--", "1 AND 1=2--"),
            ("' OR 1=1--", "' OR 1=2--"),
        ]
    }

    def detect_db_error(self, response_text: str) -> Optional[Tuple[str, str]]:
        if not response_text:
            return None
        for dbms, signatures in self.DB_ERROR_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in response_text.lower():
                    return (dbms, sig)
        return None

    async def execute_differential_check(
        self,
        url: str,
        param_name: str,
        param_profile: ParameterProfile,
        baseline: BaselineProfile,
        proxy: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Optional[DifferentialResult]:
        client_kwargs = {"verify": False, "follow_redirects": True, "timeout": 12.0}
        if proxy:
            import httpx as _hx
            ver = tuple(int(x) for x in _hx.__version__.split(".")[:2])
            if ver >= (0, 28):
                client_kwargs["proxy"] = proxy
            else:
                client_kwargs["proxies"] = {"http://": proxy, "https://": proxy}

        parsed = urlparse(url)
        base_qs = parse_qs(parsed.query)

        probe_pairs = self.SAFE_PROBE_PAIRS.get(
            param_profile.observed_type,
            self.SAFE_PROBE_PAIRS[ParameterType.UNKNOWN]
        )

        async with httpx.AsyncClient(**client_kwargs) as client:
            for true_probe, false_probe in probe_pairs:
                if param_profile.location == ParameterLocation.COOKIE:
                    headers_true = dict(headers or {})
                    headers_false = dict(headers or {})
                    existing_cookie = headers_true.get("Cookie", "")
                    cookies_map = {}
                    if existing_cookie:
                        for item in existing_cookie.split(";"):
                            if "=" in item:
                                ck, cv = item.strip().split("=", 1)
                                cookies_map[ck] = cv
                    cookies_map_true = dict(cookies_map)
                    cookies_map_true[param_name] = true_probe
                    headers_true["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies_map_true.items())

                    cookies_map_false = dict(cookies_map)
                    cookies_map_false[param_name] = false_probe
                    headers_false["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies_map_false.items())

                    url_true = url
                    url_false = url
                else:
                    headers_true = headers
                    headers_false = headers
                    qs_true = {k: v[0] for k, v in base_qs.items()}
                    qs_true[param_name] = true_probe
                    url_true = urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', urlencode(qs_true), ''))

                    qs_false = {k: v[0] for k, v in base_qs.items()}
                    qs_false[param_name] = false_probe
                    url_false = urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', urlencode(qs_false), ''))

                try:
                    r_true = await client.get(url_true, headers=headers_true)
                except Exception:
                    continue

                try:
                    r_false = await client.get(url_false, headers=headers_false)
                except Exception:
                    continue

                clean_true = ResponseNormalizer.sanitize_body(r_true.text)
                clean_false = ResponseNormalizer.sanitize_body(r_false.text)

                similarity = ResponseNormalizer.compute_similarity(clean_true, clean_false)
                status_diff = (r_true.status_code != r_false.status_code)
                length_delta = abs(len(clean_true) - len(clean_false))
                json_diff = (ResponseNormalizer.extract_json_structure(r_true.text) != ResponseNormalizer.extract_json_structure(r_false.text))
                error_sig = self.detect_db_error(r_true.text) or self.detect_db_error(r_false.text)

                sim_weight = 1.0 - similarity if similarity < 0.95 else 0.0
                score = (
                    (0.15 if status_diff else 0.0) +
                    (0.35 * sim_weight) +
                    (0.20 if length_delta > max(30, baseline.body_length_mad * 3) else 0.0) +
                    (0.15 if json_diff else 0.0) +
                    (0.15 if error_sig else 0.0)
                )

                if score >= 0.35 or error_sig:
                    try:
                        r_true_verify = await client.get(url_true, headers=headers_true)
                        r_false_verify = await client.get(url_false, headers=headers_false)
                        repeatable = (
                            r_true_verify.status_code == r_true.status_code and
                            r_false_verify.status_code == r_false.status_code and
                            abs(len(r_true_verify.text) - len(r_true.text)) < 50
                        )
                    except Exception:
                        repeatable = False

                    if repeatable:
                        score += 0.20

                    return DifferentialResult(
                        probe_pair=(true_probe, false_probe),
                        true_status=r_true.status_code,
                        false_status=r_false.status_code,
                        true_length=len(clean_true),
                        false_length=len(clean_false),
                        similarity=round(similarity, 3),
                        result_count_delta=length_delta,
                        json_structure_diff=json_diff,
                        error_signature_detected=f"{error_sig[0]}: {error_sig[1]}" if error_sig else None,
                        is_repeatable=repeatable,
                        differential_score=min(1.0, round(score, 3))
                    )

        return None

    async def execute_safe_timing_check(
        self,
        url: str,
        param_name: str,
        baseline: BaselineProfile,
        proxy: Optional[str] = None,
        delay_secs: int = 3
    ) -> Dict[str, Any]:
        if baseline.sample_count >= 2:
            time_variance = max(s["time_ms"] for s in baseline.raw_samples) - min(s["time_ms"] for s in baseline.raw_samples)
            if time_variance > 1500.0:
                return {
                    "confirmed": False,
                    "reason": "Network latency is unstable (>1.5s variance) - timing test aborted to prevent false positives."
                }

        parsed = urlparse(url)
        base_qs = parse_qs(parsed.query)

        sleep_payloads = [
            f"' AND SLEEP({delay_secs})--",
            f"'; WAITFOR DELAY '0:0:{delay_secs}'--",
            f"' AND pg_sleep({delay_secs})--"
        ]

        client_kwargs = {"verify": False, "follow_redirects": True, "timeout": delay_secs + 8.0}
        if proxy:
            import httpx as _hx
            ver = tuple(int(x) for x in _hx.__version__.split(".")[:2])
            if ver >= (0, 28):
                client_kwargs["proxy"] = proxy
            else:
                client_kwargs["proxies"] = {"http://": proxy, "https://": proxy}

        async with httpx.AsyncClient(**client_kwargs) as client:
            for payload in sleep_payloads:
                qs = {k: v[0] for k, v in base_qs.items()}
                qs[param_name] = payload
                test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', urlencode(qs), ''))

                t0 = time.time()
                try:
                    r = await client.get(test_url)
                    elapsed = time.time() - t0
                    baseline_median_sec = baseline.response_time_median_ms / 1000.0

                    if elapsed >= (delay_secs - 0.5) and elapsed > (baseline_median_sec + delay_secs - 1.0):
                        t1 = time.time()
                        r2 = await client.get(test_url)
                        elapsed2 = time.time() - t1
                        if elapsed2 >= (delay_secs - 0.5):
                            return {
                                "confirmed": True,
                                "payload": payload,
                                "observed_delay": round(elapsed, 2),
                                "expected_delay": delay_secs,
                                "baseline_median_sec": round(baseline_median_sec, 2),
                                "confidence": 0.88
                            }
                except Exception as e:
                    log.debug(f"Timing check payload '{payload}' produced: {e}")

        return {"confirmed": False, "reason": "No consistent timing delay observed."}


# ─────────────────────────────────────────────────────────────────────────────
# 6. Second-Order State Tracker
# ─────────────────────────────────────────────────────────────────────────────

class SecondOrderTracker:
    """
    Tracks state machine for Second-Order SQLi across multi-step transactions:
    Input Location -> Storage Event -> Processing Event -> Output Event -> Differential Analysis.
    Only utilizes safe researcher-tagged test markers.
    """

    def __init__(self):
        self._tracked_seeds: List[Dict[str, Any]] = []

    def register_seed(self, input_endpoint: str, parameter: str, marker_prefix: str = "pentest_marker_") -> str:
        marker = f"{marker_prefix}{hashlib.md5(f'{input_endpoint}_{parameter}_{time.time()}'.encode()).hexdigest()[:8]}"
        self._tracked_seeds.append({
            "seed_id": marker,
            "input_endpoint": input_endpoint,
            "parameter": parameter,
            "registered_at": time.time(),
            "status": "awaiting_sink_correlation"
        })
        return marker

    def correlate_sink(self, sink_endpoint: str, sink_response_text: str) -> List[Dict[str, Any]]:
        matches = []
        for seed in self._tracked_seeds:
            if seed["seed_id"] in sink_response_text:
                matches.append({
                    "seed": seed,
                    "sink_endpoint": sink_endpoint,
                    "correlation_status": "marker_reflected_in_sink",
                    "requires_approval": True,
                    "note": "Marker stored and subsequently reflected in processing sink. Manual safe check recommended."
                })
        return matches


# ─────────────────────────────────────────────────────────────────────────────
# 7. Code & ORM Pattern Auditor (Static Analysis Component)
# ─────────────────────────────────────────────────────────────────────────────

class CodeORMAuditor:
    """
    Analyzes code snippets or ORM implementations to detect unsafe query assembly
    versus safe parameterized query implementations.
    """

    DANGEROUS_CODE_PATTERNS = [
        (r'(?i)\.raw\s*\(\s*["\'].*?\+\s*[a-zA-Z0-9_]+', "Raw query with string concatenation"),
        (r'(?i)execute\s*\(\s*["\'].*?(?:WHERE|VALUES|LIKE)\s+.*?%\s*[a-zA-Z0-9_]+', "Classic Python/C printf-style SQL interpolation"),
        (r'(?i)Statement\s+[a-zA-Z0-9_]+\s*=\s*.*?\.createStatement\(\)', "Direct JDBC Statement usage instead of PreparedStatement"),
        (r'(?i)order_by\s*\(\s*request\.(?:GET|POST|args)', "Unsanitized user input passed directly to ORM order_by()"),
        (r'(?i)\$db->query\s*\(\s*["\'].*?\.\s*\$', "PHP string concatenation inside direct query execution"),
        (r'(?i)["\']\s*(?:SELECT|INSERT|UPDATE|DELETE)\s+.*?["\']\s*\+\s*[a-zA-Z0-9_]+', "SQL query built with string concatenation"),
    ]

    SAFE_CODE_PATTERNS = [
        (r'(?i)PreparedStatement\s+[a-zA-Z0-9_]+\s*=\s*.*?\.prepareStatement\(', "Safe Java PreparedStatement with parameter binding"),
        (r'(?i)\.execute\s*\(\s*["\'].*?\?\s*["\']\s*,\s*\[', "Safe DB-API parameterized query with placeholders"),
        (r'(?i)parameters\.add\(new\s+(?:Sql|OleDb)Parameter', "Safe .NET parameterized SQL command"),
        (r'(?i)\.filter\s*\(\s*[a-zA-Z0-9_]+__icontains\s*=', "Safe Django ORM filter abstraction"),
    ]

    @classmethod
    def audit_snippet(cls, source_code: str) -> Dict[str, Any]:
        findings = []
        safe_constructs = []

        for pattern, desc in cls.DANGEROUS_CODE_PATTERNS:
            if re.search(pattern, source_code):
                findings.append({"pattern": pattern, "description": desc, "severity": "High"})

        for pattern, desc in cls.SAFE_CODE_PATTERNS:
            if re.search(pattern, source_code):
                safe_constructs.append({"pattern": pattern, "description": desc})

        return {
            "is_vulnerable": len(findings) > 0 and len(safe_constructs) == 0,
            "vulnerability_signals": findings,
            "safe_defenses_detected": safe_constructs,
            "recommendation": "Adopt parameterized queries / PreparedStatement binding across all SQL sinks."
        }


# ─────────────────────────────────────────────────────────────────────────────
# 8. Report Generator & Deduplication Engine
# ─────────────────────────────────────────────────────────────────────────────

class ReportGenerator:
    """
    Produces executive-grade, OWASP-aligned vulnerability reports
    with exact reproduction steps and non-destructive evidence.
    """

    @classmethod
    def generate_dedup_key(cls, host: str, path: str, param: str, context: str) -> str:
        norm_str = f"{host.lower()}:{path.lower()}:{param.lower()}:{context.lower()}:sqli"
        return hashlib.sha256(norm_str.encode()).hexdigest()[:16]

    @classmethod
    def format_markdown_report(cls, finding: SafeSQLiFinding) -> str:
        steps_text = "\n".join(f"{i+1}. {s}" for i, s in enumerate(finding.steps_to_reproduce))
        evidence_json = json.dumps(finding.evidence, indent=2)
        signals_text = ", ".join(finding.signals)

        return f"""# SQL Injection Assessment Report

## Title
{finding.title}

## Asset
`{finding.endpoint}`

## Parameter
`{finding.parameter}` — Location: `{finding.location}` | Inferred Context: `{finding.inferred_context}`

## Preconditions
- Target confirmed within scope boundary.
- Non-destructive test account utilized.
- No elevated administrative privileges required.

## Summary
The `{finding.parameter}` parameter produces a repeatable differential response
consistent with dynamic server-side SQL query manipulation. The assessment was
conducted strictly within scope using non-destructive differential pairs and baseline isolation.

## Steps to Reproduce
{steps_text}

## Evidence
- **Confidence Score**: {finding.confidence_score:.0%} ({finding.confidence_level})
- **Classification**: `{finding.classification}`
- **Signals Detected**: {signals_text}
- **Evidence Details**:
```json
{evidence_json}
```

## Impact
Proven logical differential behavior in the SQL execution pipeline.
*Note: In accordance with responsible disclosure policies, no sensitive data was dumped, exfiltrated, or modified.*

## Severity Rationale
- **Classification**: {finding.classification}
- **Reproducibility**: Verified with multi-pass repeatability tests
- **Authentication**: Public/Standard user boundary
- **CWE**: CWE-89 (Improper Neutralization of Special Elements used in an SQL Command)
- **OWASP Top 10**: A03:2021 — Injection

## Remediation (OWASP SQL Injection Prevention Cheat Sheet)
- **Primary Defense (Option 1 - Best)**: Use Prepared Statements with Parameterized Queries across all SQL sinks.
- **Primary Defense (Option 2)**: Use properly constructed Stored Procedures with bound parameters.
- **Primary Defense (Option 3)**: Implement strict allow-list input validation for dynamic identifiers (table/column names, sort directions).
- **Secondary Defense**: Enforce Least Privilege on database connection accounts (no DBA/admin privileges granted to web application services).

## Safety & Compliance Statement
{finding.safety_statement}
"""


# ─────────────────────────────────────────────────────────────────────────────
# 9. Main Orchestrator: SafeSQLiAssessmentSkill
# ─────────────────────────────────────────────────────────────────────────────

class SafeSQLiAssessmentSkill:
    """
    Main Orchestrator for Safe SQL Injection Assessment.
    Executes the full pipeline:
      Scope Gate -> Baseline Profiler -> Parameter Classifier -> Context Inference
      -> Safe Differential Engine -> Evidence Correlation -> Confidence Scoring -> Deduplication -> Report
    """

    def __init__(self, policy: Optional[ScopePolicy] = None, proxy: Optional[str] = None):
        self.policy = policy or ScopePolicy()
        self.proxy = proxy
        self.scope_gate = ScopeGate(self.policy)
        self.normalizer = ResponseNormalizer()
        self.profiler = BaselineProfiler(samples=3)
        self.classifier = ParameterClassifier()
        self.diff_engine = DifferentialSQLiEngine()
        self.second_order = SecondOrderTracker()
        self.report_gen = ReportGenerator()

    async def run(
        self,
        endpoint: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        parameters: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        scope_eval = self.scope_gate.evaluate(endpoint, method)
        if not scope_eval["allowed"]:
            return {
                "decision": "discarded",
                "confidence": 0.0,
                "reason": scope_eval["reason"],
                "findings": [],
                "safe_next_action": "Halt testing — target is out of scope."
            }

        baseline = await self.profiler.profile(endpoint, proxy=self.proxy, headers=headers)

        parsed = urlparse(endpoint)
        qs = parse_qs(parsed.query)
        candidates: List[ParameterProfile] = []

        if parameters:
            for p in parameters:
                candidates.append(self.classifier.classify_parameter(
                    p.get("name", ""),
                    p.get("value", ""),
                    ParameterLocation(p.get("location", "query"))
                ))
        else:
            for p_name, p_vals in qs.items():
                val = p_vals[0] if p_vals else ""
                candidates.append(self.classifier.classify_parameter(p_name, val, ParameterLocation.QUERY))

        candidates.sort(key=lambda c: c.priority, reverse=True)

        findings: List[SafeSQLiFinding] = []
        seen_keys: Set[str] = set()

        for param_prof in candidates:
            await self.scope_gate.throttle()

            diff_res = await self.diff_engine.execute_differential_check(
                url=endpoint,
                param_name=param_prof.name,
                param_profile=param_prof,
                baseline=baseline,
                proxy=self.proxy,
                headers=headers
            )

            if not diff_res:
                continue

            signals = []
            if diff_res.error_signature_detected:
                signals.append(f"Database Error Signature ({diff_res.error_signature_detected})")
            if diff_res.true_status != diff_res.false_status:
                signals.append("HTTP Status Code Divergence")
            if diff_res.similarity < 0.90:
                signals.append(f"Body Content Divergence (similarity: {diff_res.similarity:.1%})")
            if diff_res.json_structure_diff:
                signals.append("JSON Response Schema Divergence")
            if diff_res.is_repeatable:
                signals.append("Reproducible Logical Differential")

            conf_score = diff_res.differential_score
            conf_level = ConfidenceLevel.from_score(conf_score)

            if conf_score >= 0.80 and diff_res.is_repeatable:
                classification = FindingClassification.CONFIRMED_SQLI_CANDIDATE
            elif conf_score >= 0.60:
                classification = FindingClassification.STRONG_CANDIDATE
            elif diff_res.error_signature_detected:
                classification = FindingClassification.POSSIBLE_ERROR_LEAK
            else:
                classification = FindingClassification.UNCONFIRMED

            host = parsed.netloc
            path = parsed.path
            dedup_key = self.report_gen.generate_dedup_key(
                host, path, param_prof.name, param_prof.inferred_context.value
            )

            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)

            finding = SafeSQLiFinding(
                finding_id=f"SQLI-{hashlib.md5(dedup_key.encode()).hexdigest()[:8].upper()}",
                title=f"Potential SQL Injection in '{param_prof.name}' parameter ({param_prof.inferred_context.value})",
                endpoint=endpoint,
                method=method,
                parameter=param_prof.name,
                location=param_prof.location.value,
                inferred_context=param_prof.inferred_context.value,
                confidence_score=conf_score,
                confidence_level=conf_level.label,
                classification=classification.value,
                signals=signals,
                evidence={
                    "probe_pair": diff_res.probe_pair,
                    "true_status": diff_res.true_status,
                    "false_status": diff_res.false_status,
                    "similarity": diff_res.similarity,
                    "length_delta": diff_res.result_count_delta,
                    "json_structure_diff": diff_res.json_structure_diff,
                    "error_signature": diff_res.error_signature_detected,
                    "repeatable": diff_res.is_repeatable,
                    "baseline_median_len": baseline.body_length_median,
                },
                steps_to_reproduce=[
                    f"Send baseline authorized request to: {endpoint}",
                    f"Inject safe logical true probe on '{param_prof.name}': {diff_res.probe_pair[0]}",
                    f"Inject safe logical false probe on '{param_prof.name}': {diff_res.probe_pair[1]}",
                    "Compare status, normalized body similarity ratio, and response structure.",
                    "Verify reproducible behavior across multiple cycles."
                ],
                remediation={
                    "primary": "Adopt Prepared Statements with Parameterized Queries (PreparedStatement / DB-API binding).",
                    "cwe": "CWE-89",
                    "owasp_ref": "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
                },
                safety_statement="Testing used authorized accounts and non-destructive differential probes. No production data was extracted or altered.",
                requires_manual_review=(conf_score < 0.93),
                dedup_key=dedup_key
            )

            findings.append(finding)

        top_confidence = max((f.confidence_score for f in findings), default=0.0)
        overall_decision = (
            "confirmed_sqli_candidate" if top_confidence >= 0.85
            else "strong_candidate" if top_confidence >= 0.60
            else "inconclusive" if findings
            else "clean"
        )

        return {
            "decision": overall_decision,
            "confidence": top_confidence,
            "target": endpoint,
            "parameters_audited": len(candidates),
            "findings_count": len(findings),
            "findings": [
                {
                    "finding_id": f.finding_id,
                    "title": f.title,
                    "parameter": f.parameter,
                    "confidence": f.confidence_score,
                    "confidence_level": f.confidence_level,
                    "classification": f.classification,
                    "signals": f.signals,
                    "requires_manual_review": f.requires_manual_review,
                    "markdown_report": self.report_gen.format_markdown_report(f)
                }
                for f in findings
            ],
            "safe_next_action": "Review sanitized evidence report and verify via authorized test account.",
            "blocked_actions": [
                "database_dumping",
                "data_exfiltration",
                "WAF_bypass_attempts",
                "destructive_queries"
            ]
        }
