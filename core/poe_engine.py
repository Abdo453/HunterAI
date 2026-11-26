"""
Proof-of-Execution (PoE) Engine & Per-Category ProofContract Registry
=====================================================================
Deterministic engine that differentiates strictly between REFLECTION and EXECUTION,
and evaluates per-vulnerability-category ProofContracts for:
  sqli, xss, cmdi, ssrf, idor, lfi, ssti, auth, jwt, deser, race, secret, misconfig.

Bare response differences (response != baseline) NEVER satisfy a ProofContract.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse


CANONICAL_PROOF_CATEGORIES: Tuple[str, ...] = (
    "sqli",
    "xss",
    "cmdi",
    "ssrf",
    "idor",
    "lfi",
    "ssti",
    "auth",
    "jwt",
    "deser",
    "race",
    "secret",
    "misconfig",
)

_PLACEHOLDER_SECRET_MARKERS = (
    "example",
    "fallback",
    "dummy",
    "placeholder",
    "your_api_key",
    "your-api-key",
    "changeme",
    "redacted",
    "***",
    "test_key",
    "sample",
    "fake",
)

_SECRET_PATTERNS: Tuple[Tuple[str, re.Pattern[str]], ...] = (
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\b(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,})\b")),
    ("openai_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("nvidia_key", re.compile(r"\bnvapi-[A-Za-z0-9_-]{20,}\b")),
    ("private_key_pem", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
)

_SSRF_INTERNAL_SIGNATURES: Tuple[Tuple[str, re.Pattern[str]], ...] = (
    ("aws_imds_ami", re.compile(r"\bami-[0-9a-f]{8,17}\b", re.I)),
    ("aws_imds_instance", re.compile(r"\bi-[0-9a-f]{8,17}\b", re.I)),
    ("aws_imds_creds", re.compile(r'"AccessKeyId"\s*:\s*"[A-Z0-9]{16,}"')),
    ("aws_imds_secret", re.compile(r'"SecretAccessKey"\s*:\s*"[^"]{16,}"')),
    ("gcp_metadata", re.compile(r"computeMetadata/v1|metadata\.google\.internal", re.I)),
    ("azure_imds", re.compile(r'"azEnvironment"\s*:\s*"AzurePublicCloud"', re.I)),
)


def _token_boundary_present(token: str, text: str) -> bool:
    """Return True iff `token` appears in `text` at non-alphanumeric boundaries."""
    if not token or not text:
        return False
    return bool(re.search(rf"(?<![A-Za-z0-9_]){re.escape(token)}(?![A-Za-z0-9_])", text))


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * ((4 - len(segment) % 4) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")


class ProofOfExecutionEngine:
    """Evaluates whether an observed HTTP response constitutes execution proof or mere reflection."""

    @classmethod
    def verify_command_injection(
        cls,
        response_text: str,
        expected_arithmetic_result: str = "72",
        probed_expression: str = "53+19",
        baseline_text: str = "",
    ) -> Tuple[bool, str]:
        """
        Inviolable Command Injection Rule:
        The computed result must appear as an isolated token, and it must be
        attributable to execution rather than reflection or pre-existing baseline content.
        """
        if not response_text:
            return False, "Empty response"

        # 1. Reflection indicators
        syntax_echo = (
            f"$(({probed_expression}))" in response_text
            or f"expr {probed_expression}" in response_text
            or "; echo " in response_text
            or "__PTST_CMD" in response_text
        )

        # Check for Next.js / JSON script reflection
        json_script_pat = r'["\']?[a-zA-Z0-9_]+["\']?\s*:\s*["\'][^"\']*' + re.escape(probed_expression)
        json_reflection = bool(re.search(json_script_pat, response_text))

        # 2. Arithmetic Result Check (strict word/token boundaries)
        result_present = _token_boundary_present(expected_arithmetic_result, response_text)

        if not result_present:
            if syntax_echo:
                return False, "Literal command syntax echo detected without the computed result (Reflection != Execution)"
            if json_reflection:
                return False, "JSON / Script parameter reflection detected"
            return False, f"Expected arithmetic result '{expected_arithmetic_result}' not found in response."

        # 3. Baseline check rules out static pre-existing content
        if baseline_text and _token_boundary_present(expected_arithmetic_result, baseline_text):
            return False, (
                f"Expected result '{expected_arithmetic_result}' is already present in the "
                "unmutated baseline; it does not prove execution."
            )

        if syntax_echo or json_reflection:
            return True, (
                f"Execution confirmed: {probed_expression} evaluated to {expected_arithmetic_result} "
                "outside the reflected command text."
            )

        return True, f"Arithmetic execution confirmed: evaluated {probed_expression} to {expected_arithmetic_result}."

    @classmethod
    def verify_sqli_extraction(
        cls,
        response_text: str,
        baseline_text: str = "",
    ) -> Tuple[bool, str, str]:
        """
        Validates database extraction proof (banner, DBMS version, table schema).
        Returns: (verified, dbms_type, proof_detail)
        """
        if not response_text:
            return False, "unknown", "Empty response"

        candidates: List[Tuple[str, Optional[re.Match[str]], Optional[str]]] = []

        # Postgres version signature
        m_pg = re.search(r"(PostgreSQL\s+\d+\.\d+[\w\.\s,-]+)", response_text, re.I)
        if m_pg:
            candidates.append(("postgresql", m_pg, m_pg.group(1).strip()))

        # MySQL / MariaDB version signature
        m_my = re.search(r"(\d+\.\d+\.\d+-(?:MariaDB|community)[\w\.\s,-]*)", response_text, re.I)
        if m_my:
            candidates.append(("mysql", m_my, m_my.group(1).strip()))

        # SQLite version signature
        m_sq = re.search(r"(3\.\d+\.\d+)", response_text)
        if m_sq and "sqlite" in response_text.lower():
            candidates.append(("sqlite", m_sq, f"SQLite version {m_sq.group(1)}"))

        # Oracle banner signature (e.g. "Oracle Database 19c Enterprise Edition")
        m_ora = re.search(r"(Oracle Database \d+[a-zA-Z]?[\w\.\s,()\-]*)", response_text, re.I)
        if m_ora:
            candidates.append(("oracle", m_ora, m_ora.group(1).strip()))

        # Microsoft SQL Server version signature
        m_mssql = re.search(r"(Microsoft SQL Server \d{4}[\w\.\s,()\-]*)", response_text, re.I)
        if m_mssql:
            candidates.append(("mssql", m_mssql, m_mssql.group(1).strip()))

        for dbms, match_obj, detail in candidates:
            if match_obj and detail:
                matched_raw = match_obj.group(1).strip()
                if baseline_text and matched_raw.lower() in baseline_text.lower():
                    return False, dbms, f"DBMS banner '{matched_raw}' already present in baseline (not causal)."
                return True, dbms, detail

        return False, "unknown", "No database version banner extracted."

    @classmethod
    def verify_lfi_extraction(
        cls,
        response_text: str,
        baseline_text: str = "",
    ) -> Tuple[bool, str]:
        """Validates LFI proof against known system files, ensuring absence from baseline."""
        if not response_text:
            return False, "Empty response"

        if re.search(r"root:x:0:0:[^:]*:/root:", response_text):
            if baseline_text and re.search(r"root:x:0:0:[^:]*:/root:", baseline_text):
                return False, "Linux /etc/passwd signature already present in baseline."
            return True, "Linux /etc/passwd user entry confirmed."

        lower = response_text.lower()
        base_lower = (baseline_text or "").lower()
        if "[boot loader]" in lower or "[extensions]" in lower:
            if base_lower and ("[boot loader]" in base_lower or "[extensions]" in base_lower):
                return False, "Windows INI signature already present in baseline."
            return True, "Windows ini system configuration confirmed."

        return False, "No recognized OS file format detected in response."


@dataclass(frozen=True)
class ProofContractResult:
    """Result returned by evaluating a typed per-category ProofContract."""
    category: str
    strength: str  # "DERIVED" | "REFUTED" | "NONE"
    detail: str


@dataclass(frozen=True)
class ProofContract:
    """Typed verification contract for a vulnerability category."""
    category: str
    aliases: Tuple[str, ...]
    requirement: str
    evaluator: Callable[[Dict[str, Any], Dict[str, Any]], ProofContractResult]

    def evaluate(
        self,
        payload_data: Dict[str, Any],
        verifier_result: Optional[Dict[str, Any]] = None,
    ) -> ProofContractResult:
        return self.evaluator(payload_data, verifier_result or {})


def _combined_meta(payload_data: Dict[str, Any], verifier_result: Dict[str, Any]) -> Dict[str, Any]:
    meta: Dict[str, Any] = {}
    if isinstance(verifier_result, dict):
        meta.update(verifier_result)
        if isinstance(verifier_result.get("metadata"), dict):
            meta.update(verifier_result["metadata"])
    if isinstance(payload_data.get("metadata"), dict):
        meta.update(payload_data["metadata"])
    return meta


def _eval_sqli(payload: Dict[str, Any], vr: Dict[str, Any]) -> ProofContractResult:
    text = str(payload.get("response_text") or "")
    baseline = str(payload.get("baseline_text") or "")
    meta = _combined_meta(payload, vr)

    ok, dbms, detail = ProofOfExecutionEngine.verify_sqli_extraction(text, baseline_text=baseline)
    if ok:
        return ProofContractResult("sqli", "DERIVED", f"{detail} (dbms={dbms})")
    if "already present in baseline" in detail:
        return ProofContractResult("sqli", "REFUTED", detail)

    # Boolean differential triad contract (requires explicit true/false/control verification)
    if (
        meta.get("boolean_true_matches_baseline") is True
        and meta.get("boolean_false_diverges") is True
        and meta.get("control_matches_baseline", True) is True
    ):
        return ProofContractResult(
            "sqli",
            "DERIVED",
            "Boolean SQLi triad verified: True probes match baseline while False probe diverges.",
        )

    # Time-based blind SQLi contract (reproduced >= 2 with clean control)
    if (
        int(meta.get("timing_reproduced_n_times", 0) or 0) >= 2
        and meta.get("control_delay_absent") is True
        and float(meta.get("observed_delay_s", 0.0) or 0.0) >= float(meta.get("expected_delay_s", 2.0) or 2.0)
    ):
        return ProofContractResult(
            "sqli",
            "DERIVED",
            "Time-based blind SQLi verified across >=2 reproductions with clean control latency.",
        )

    # Extracted data token check (must not be in baseline or reflected expression)
    token = str(payload.get("expected_token") or "")
    expr = str(payload.get("probed_expression") or "")
    if token and token in text:
        if baseline and token in baseline:
            return ProofContractResult("sqli", "REFUTED", "Expected SQLi token already present in baseline.")
        if expr and expr in text and token not in text.replace(expr, ""):
            return ProofContractResult("sqli", "REFUTED", "SQLi token only appeared inside reflected probe expression.")
        return ProofContractResult("sqli", "DERIVED", f"SQLi extracted deterministic token '{token}' absent from baseline.")

    if text:
        return ProofContractResult("sqli", "REFUTED", detail)
    return ProofContractResult("sqli", "NONE", "No checkable SQLi proof supplied.")


def _eval_xss(payload: Dict[str, Any], vr: Dict[str, Any]) -> ProofContractResult:
    text = str(payload.get("response_text") or "")
    baseline = str(payload.get("baseline_text") or "")
    token = str(payload.get("expected_token") or "")
    meta = _combined_meta(payload, vr)

    # 1. Runtime DOM execution telemetry (gold standard)
    dom_exec = bool(
        meta.get("dom_executed")
        or meta.get("dialog_triggered")
        or meta.get("console_canary_observed")
        or meta.get("js_sink_executed")
    )
    if dom_exec:
        canary = token or str(meta.get("canary") or meta.get("executed_canary") or "")
        if canary and baseline and canary in baseline:
            return ProofContractResult("xss", "REFUTED", "XSS canary already present in baseline.")
        return ProofContractResult(
            "xss",
            "DERIVED",
            f"DOM execution verified via browser runtime telemetry (canary={canary or 'observed'}).",
        )

    # 2. Unescaped executable breakout check (requires explicit executable token, never inert reflection)
    if token:
        has_exec_syntax = bool(
            re.search(r"<\s*(?:script|svg|img|iframe|body|details)\b|on[a-z]+\s*=|javascript:", token, re.I)
        )
        if not has_exec_syntax:
            return ProofContractResult(
                "xss",
                "NONE",
                "XSS token lacks executable HTML/JS breakout syntax and no DOM execution telemetry was supplied.",
            )
        if baseline and token in baseline:
            return ProofContractResult("xss", "REFUTED", "XSS token already present in baseline.")
        if token in text:
            # Ensure it is not merely echoed inside a JSON string or script literal
            json_quoted = bool(re.search(r'["\'][^"\']*' + re.escape(token) + r'[^"\']*["\']', text))
            stripped = re.sub(r"<script[^>]*>.*?</script>", "", text, flags=re.I | re.S)
            if json_quoted and token not in stripped:
                return ProofContractResult(
                    "xss",
                    "REFUTED",
                    "XSS token reflected only inside quoted script/JSON data without DOM breakout.",
                )
            return ProofContractResult(
                "xss",
                "DERIVED",
                f"Unescaped executable XSS breakout token '{token}' observed outside baseline.",
            )
        escaped_lt = token.replace("<", "&lt;").replace(">", "&gt;")
        if escaped_lt in text:
            return ProofContractResult("xss", "REFUTED", "XSS payload was HTML-encoded in response (safe).")
        return ProofContractResult("xss", "REFUTED", "Expected executable XSS token absent from response.")

    return ProofContractResult(
        "xss",
        "NONE",
        "XSS requires runtime DOM execution telemetry or verified unescaped executable breakout.",
    )


def _eval_cmdi(payload: Dict[str, Any], vr: Dict[str, Any]) -> ProofContractResult:
    text = str(payload.get("response_text") or "")
    baseline = str(payload.get("baseline_text") or "")
    expected = str(payload.get("expected_result") or payload.get("expected_token") or "72")
    expr = str(payload.get("probed_expression") or "53+19")
    ok, reason = ProofOfExecutionEngine.verify_command_injection(
        text,
        expected_arithmetic_result=expected,
        probed_expression=expr,
        baseline_text=baseline,
    )
    return ProofContractResult("cmdi", "DERIVED" if ok else "REFUTED", reason)


def _eval_ssrf(payload: Dict[str, Any], vr: Dict[str, Any]) -> ProofContractResult:
    text = str(payload.get("response_text") or "")
    baseline = str(payload.get("baseline_text") or "")
    token = str(payload.get("expected_token") or "")
    expr = str(payload.get("probed_expression") or "")
    meta = _combined_meta(payload, vr)

    # 1. OOB callback correlation with unique nonce
    callbacks = meta.get("oob_callbacks") or []
    nonce = token or str(meta.get("oob_nonce") or "")
    if nonce and callbacks and any(nonce in str(cb) for cb in callbacks):
        return ProofContractResult("ssrf", "DERIVED", f"SSRF OOB callback matched unique nonce '{nonce}'.")

    # 2. Internal/metadata response signatures absent from baseline
    for sig_name, pat in _SSRF_INTERNAL_SIGNATURES:
        m = pat.search(text)
        if m:
            if baseline and pat.search(baseline):
                return ProofContractResult("ssrf", "REFUTED", f"SSRF signature '{sig_name}' already present in baseline.")
            if expr and m.group(0) in expr and not pat.search(text.replace(expr, "")):
                return ProofContractResult("ssrf", "REFUTED", "SSRF marker appeared only as reflected input.")
            return ProofContractResult("ssrf", "DERIVED", f"SSRF internal metadata signature '{sig_name}' extracted.")

    # 3. Explicit internal service canary token
    if token and token in text:
        if baseline and token in baseline:
            return ProofContractResult("ssrf", "REFUTED", "SSRF canary already present in baseline.")
        if expr and expr in text and token not in text.replace(expr, ""):
            return ProofContractResult("ssrf", "REFUTED", "SSRF canary only appeared inside reflected probe URL.")
        return ProofContractResult("ssrf", "DERIVED", f"SSRF internal canary '{token}' observed absent from baseline.")

    return ProofContractResult("ssrf", "NONE", "No OOB callback or verified internal SSRF artifact observed.")


def _eval_idor(payload: Dict[str, Any], vr: Dict[str, Any]) -> ProofContractResult:
    text = str(payload.get("response_text") or "")
    baseline = str(payload.get("baseline_text") or "")
    meta = _combined_meta(payload, vr)
    status = meta.get("status_code") or meta.get("status")

    if isinstance(status, int) and status in (401, 403, 404):
        return ProofContractResult("idor", "REFUTED", f"Access denied with HTTP {status}; object authorization held.")

    actor_id = meta.get("actor_id")
    owner_id = meta.get("owner_id")
    if actor_id and owner_id and str(actor_id) == str(owner_id):
        return ProofContractResult("idor", "REFUTED", "Actor matches resource owner; not a cross-tenant IDOR.")

    victim_marker = str(
        payload.get("expected_token")
        or meta.get("victim_canary")
        or meta.get("owner_marker")
        or ""
    )
    if not victim_marker:
        return ProofContractResult(
            "idor",
            "NONE",
            "IDOR requires a victim-specific canary/token absent from the attacker baseline.",
        )
    if baseline and victim_marker in baseline:
        return ProofContractResult("idor", "REFUTED", "Victim marker already present in attacker baseline.")
    if victim_marker in text:
        expr = str(payload.get("probed_expression") or "")
        if expr and expr in text and victim_marker not in text.replace(expr, ""):
            return ProofContractResult("idor", "REFUTED", "Victim marker appeared only inside reflected probe input.")
        return ProofContractResult(
            "idor",
            "DERIVED",
            f"Cross-tenant victim marker '{victim_marker}' leaked to unauthorized actor absent from baseline.",
        )
    return ProofContractResult("idor", "REFUTED", f"Victim marker '{victim_marker}' absent from response.")


def _eval_lfi(payload: Dict[str, Any], vr: Dict[str, Any]) -> ProofContractResult:
    text = str(payload.get("response_text") or "")
    baseline = str(payload.get("baseline_text") or "")
    ok, reason = ProofOfExecutionEngine.verify_lfi_extraction(text, baseline_text=baseline)
    if ok:
        return ProofContractResult("lfi", "DERIVED", reason)
    if text:
        return ProofContractResult("lfi", "REFUTED", reason)
    return ProofContractResult("lfi", "NONE", "No LFI response content provided.")


def _eval_ssti(payload: Dict[str, Any], vr: Dict[str, Any]) -> ProofContractResult:
    text = str(payload.get("response_text") or "")
    baseline = str(payload.get("baseline_text") or "")
    expr = str(payload.get("probed_expression") or "")
    expected = str(payload.get("expected_result") or payload.get("expected_token") or "")

    if not expected or not text:
        return ProofContractResult("ssti", "NONE", "SSTI requires an evaluated arithmetic/template result token.")

    has_eval = _token_boundary_present(expected, text)
    if has_eval:
        if baseline and _token_boundary_present(expected, baseline):
            return ProofContractResult("ssti", "REFUTED", f"SSTI result '{expected}' already present in baseline.")
        return ProofContractResult(
            "ssti",
            "DERIVED",
            f"SSTI template expression '{expr or 'probe'}' evaluated to '{expected}' absent from baseline.",
        )

    if expr and (f"{{{{{expr}}}}}" in text or f"${{{expr}}}" in text or f"<%={expr}%>" in text or expr in text):
        return ProofContractResult(
            "ssti",
            "REFUTED",
            f"Template expression '{expr}' reflected literally without server-side evaluation.",
        )
    return ProofContractResult("ssti", "REFUTED", f"Expected SSTI evaluation token '{expected}' absent from response.")


def _eval_auth(payload: Dict[str, Any], vr: Dict[str, Any]) -> ProofContractResult:
    text = str(payload.get("response_text") or "")
    baseline = str(payload.get("baseline_text") or "")
    meta = _combined_meta(payload, vr)
    probe_status = meta.get("probe_status") or meta.get("status_code") or meta.get("status")
    baseline_status = meta.get("baseline_status")

    if isinstance(probe_status, int) and probe_status in (401, 403):
        return ProofContractResult("auth", "REFUTED", f"Authentication/authorization enforced with HTTP {probe_status}.")

    protected_marker = str(payload.get("expected_token") or meta.get("protected_marker") or "")
    if protected_marker:
        if baseline and protected_marker in baseline:
            return ProofContractResult("auth", "REFUTED", "Protected marker already visible in unauthenticated baseline.")
        if protected_marker in text:
            return ProofContractResult(
                "auth",
                "DERIVED",
                f"Protected resource marker '{protected_marker}' accessed without authorization.",
            )
        return ProofContractResult("auth", "REFUTED", "Protected marker absent from unauthenticated response.")

    if (
        baseline_status in (401, 403)
        and probe_status == 200
        and meta.get("sensitive_data_leaked") is True
        and text
        and text != baseline
    ):
        return ProofContractResult(
            "auth",
            "DERIVED",
            f"Auth bypass verified: baseline HTTP {baseline_status} bypassed to HTTP 200 with protected data.",
        )

    return ProofContractResult("auth", "NONE", "Auth bypass requires protected marker or verified 401/403->200 protected data proof.")


def _eval_jwt(payload: Dict[str, Any], vr: Dict[str, Any]) -> ProofContractResult:
    text = str(payload.get("response_text") or "")
    baseline = str(payload.get("baseline_text") or "")
    meta = _combined_meta(payload, vr)

    # 1. Cryptographic weak-secret re-verification (deterministic HMAC recomputation)
    raw_jwt = str(meta.get("raw_jwt") or "")
    if raw_jwt and "cracked_secret" in meta and raw_jwt.count(".") == 2:
        secret_candidate = str(meta.get("cracked_secret") or "")
        parts = raw_jwt.split(".")
        try:
            header = json.loads(_b64url_decode(parts[0]).decode("utf-8"))
            alg = str(header.get("alg", "")).upper()
            digest_map = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
            digest_fn = digest_map.get(alg)
            if digest_fn is not None:
                expected_sig = _b64url_encode(
                    hmac.new(secret_candidate.encode("utf-8"), f"{parts[0]}.{parts[1]}".encode("utf-8"), digest_fn).digest()
                )
                if hmac.compare_digest(expected_sig, parts[2]):
                    return ProofContractResult("jwt", "DERIVED", f"JWT {alg} signature cryptographically verified with weak secret.")
                return ProofContractResult("jwt", "REFUTED", "Supplied JWT secret does not reproduce the token signature.")
        except Exception:
            return ProofContractResult("jwt", "REFUTED", "Malformed JWT supplied for cryptographic verification.")

    # 2. Forged/unsigned JWT accepted against protected endpoint
    baseline_status = meta.get("baseline_status")
    probe_status = meta.get("probe_status") or meta.get("status_code") or meta.get("status")
    protected_marker = str(payload.get("expected_token") or meta.get("protected_marker") or "")

    if isinstance(probe_status, int) and probe_status in (401, 403):
        return ProofContractResult("jwt", "REFUTED", f"Forged JWT rejected with HTTP {probe_status}.")

    if baseline_status in (401, 403) and probe_status == 200 and protected_marker:
        if baseline and protected_marker in baseline:
            return ProofContractResult("jwt", "REFUTED", "Protected marker already present in rejected baseline.")
        if protected_marker in text:
            return ProofContractResult(
                "jwt",
                "DERIVED",
                f"Forged JWT bypassed HTTP {baseline_status} to HTTP 200 and exposed '{protected_marker}'.",
            )
        return ProofContractResult("jwt", "REFUTED", "Protected marker absent from forged-JWT response.")

    return ProofContractResult(
        "jwt",
        "NONE",
        "JWT proof requires cryptographic weak-secret verification or 401/403->200 forged-token protected marker proof.",
    )


def _eval_deser(payload: Dict[str, Any], vr: Dict[str, Any]) -> ProofContractResult:
    text = str(payload.get("response_text") or "")
    baseline = str(payload.get("baseline_text") or "")
    token = str(payload.get("expected_token") or "")
    meta = _combined_meta(payload, vr)

    # 1. OOB gadget callback
    callbacks = meta.get("oob_callbacks") or []
    nonce = token or str(meta.get("oob_nonce") or "")
    if nonce and callbacks and any(nonce in str(cb) for cb in callbacks):
        return ProofContractResult("deser", "DERIVED", f"Deserialization gadget OOB callback matched nonce '{nonce}'.")

    # 2. Arithmetic/code execution output
    if payload.get("expected_result") and payload.get("probed_expression"):
        ok, reason = ProofOfExecutionEngine.verify_command_injection(
            text,
            expected_arithmetic_result=str(payload.get("expected_result")),
            probed_expression=str(payload.get("probed_expression")),
            baseline_text=baseline,
        )
        if ok:
            return ProofContractResult("deser", "DERIVED", f"Deserialization execution confirmed: {reason}")
        return ProofContractResult("deser", "REFUTED", reason)

    # 3. Deterministic execution marker absent from baseline
    if token and token in text:
        if baseline and token in baseline:
            return ProofContractResult("deser", "REFUTED", "Deserialization marker already present in baseline.")
        return ProofContractResult("deser", "DERIVED", f"Deserialization side-effect marker '{token}' confirmed.")

    return ProofContractResult(
        "deser",
        "NONE",
        "Deserialization requires verified execution output or OOB gadget callback (stack trace alone is insufficient).",
    )


def _eval_race(payload: Dict[str, Any], vr: Dict[str, Any]) -> ProofContractResult:
    meta = _combined_meta(payload, vr)
    if "concurrent_success_count" not in meta:
        return ProofContractResult(
            "race",
            "NONE",
            "Race condition requires concurrent_success_count exceeding expected_max_success with verified state delta.",
        )
    success_count = int(meta.get("concurrent_success_count", 0) or 0)
    expected_max = int(meta.get("expected_max_success", 1) or 1)
    state_delta = bool(meta.get("state_delta_verified", False))

    if success_count > expected_max and state_delta:
        return ProofContractResult(
            "race",
            "DERIVED",
            f"Race condition invariant breached: {success_count} concurrent successes exceeded limit {expected_max} with verified state delta.",
        )
    if success_count <= expected_max:
        return ProofContractResult(
            "race",
            "REFUTED",
            f"Concurrency invariant held: {success_count} <= {expected_max} successes.",
        )
    return ProofContractResult(
        "race",
        "NONE",
        "Concurrent HTTP 200 responses observed without verified duplicate state mutation.",
    )


def _eval_secret(payload: Dict[str, Any], vr: Dict[str, Any]) -> ProofContractResult:
    text = str(payload.get("response_text") or "")
    meta = _combined_meta(payload, vr)

    if meta.get("secret_live_verified") is True and text:
        return ProofContractResult("secret", "DERIVED", "Exposed credential verified active against issuer endpoint.")

    if not text:
        return ProofContractResult("secret", "NONE", "No secret material supplied for verification.")

    lower_text = text.lower()
    for secret_kind, pat in _SECRET_PATTERNS:
        m = pat.search(text)
        if m:
            matched_val = m.group(0)
            if any(ph in matched_val.lower() for ph in _PLACEHOLDER_SECRET_MARKERS):
                return ProofContractResult(
                    "secret",
                    "REFUTED",
                    f"Matched '{secret_kind}' pattern is a placeholder/synthetic dummy value.",
                )
            return ProofContractResult(
                "secret",
                "DERIVED",
                f"High-confidence secret pattern '{secret_kind}' verified in response artifact.",
            )

    if any(ph in lower_text for ph in ("redacted", "fallback", "***")):
        return ProofContractResult("secret", "REFUTED", "Secret artifact is redacted or synthetic placeholder.")

    return ProofContractResult(
        "secret",
        "NONE",
        "No recognized high-confidence secret pattern or live credential verification proof supplied.",
    )


def _eval_misconfig(payload: Dict[str, Any], vr: Dict[str, Any]) -> ProofContractResult:
    text = str(payload.get("response_text") or "")
    baseline = str(payload.get("baseline_text") or "")
    meta = _combined_meta(payload, vr)

    # 1. Permissive CORS arbitrary origin reflection with credentials
    probe_origin = str(meta.get("probe_origin") or "")
    acao = str(meta.get("acao") or "")
    acac = bool(meta.get("acac", False))
    if probe_origin and acao:
        if acao == probe_origin and (acac or meta.get("sensitive_body") is True):
            return ProofContractResult(
                "misconfig",
                "DERIVED",
                f"CORS misconfiguration verified: ACAO reflected '{probe_origin}' (ACAC={acac}).",
            )
        if acao != probe_origin:
            return ProofContractResult("misconfig", "REFUTED", f"CORS origin '{probe_origin}' was not reflected (ACAO='{acao}').")

    # 2. Open redirect to external attacker host
    probe_redirect_host = str(meta.get("probe_redirect_host") or "")
    location = str(meta.get("location") or "")
    status_code = meta.get("status_code") or meta.get("status")
    if probe_redirect_host and location:
        parsed_loc = urlparse(location)
        loc_host = (parsed_loc.hostname or "").lower()
        if status_code in (301, 302, 303, 307, 308) and (
            loc_host == probe_redirect_host.lower() or loc_host.endswith("." + probe_redirect_host.lower())
        ):
            if baseline and probe_redirect_host.lower() in baseline.lower():
                return ProofContractResult("misconfig", "REFUTED", "Redirect target already present in baseline.")
            return ProofContractResult(
                "misconfig",
                "DERIVED",
                f"Open redirect verified: HTTP {status_code} Location redirected to external host '{loc_host}'.",
            )
        return ProofContractResult("misconfig", "REFUTED", f"Location '{location}' did not redirect to '{probe_redirect_host}'.")

    # 3. Exposed .git/HEAD
    if "ref: refs/" in text:
        if baseline and "ref: refs/" in baseline:
            return ProofContractResult("misconfig", "REFUTED", "Git HEAD signature already present in soft-404 baseline.")
        return ProofContractResult("misconfig", "DERIVED", "Exposed .git/HEAD repository metadata verified absent from baseline.")

    # 4. Exposed .env with non-HTML content-type and key-value assignments
    content_type = str(meta.get("content_type") or "").lower()
    env_pat = re.compile(r"^(?:APP_KEY|DB_PASSWORD|SECRET_KEY|DATABASE_URL|AWS_SECRET_ACCESS_KEY)\s*=\s*\S+", re.M)
    if "text/html" not in content_type and env_pat.search(text):
        if baseline and env_pat.search(baseline):
            return ProofContractResult("misconfig", "REFUTED", "Environment file signature already present in baseline.")
        return ProofContractResult("misconfig", "DERIVED", "Exposed .env secret configuration verified absent from baseline.")

    # 5. Cache poisoning clean refetch canary
    token = str(payload.get("expected_token") or "")
    if token and meta.get("clean_refetch_verified") is True:
        if baseline and token in baseline:
            return ProofContractResult("misconfig", "REFUTED", "Cache poisoning canary already present in baseline.")
        if token in text:
            return ProofContractResult(
                "misconfig",
                "DERIVED",
                f"Cache poisoning verified: canary '{token}' persisted in subsequent clean unheadered request.",
            )
        return ProofContractResult("misconfig", "REFUTED", "Cache poisoning canary absent on clean refetch.")

    return ProofContractResult(
        "misconfig",
        "NONE",
        "Misconfiguration requires verifiable CORS/open-redirect/.git/.env/cache-poisoning proof artifact.",
    )


class ProofContractRegistry:
    """Registry of typed per-vulnerability-category ProofContracts."""

    def __init__(self) -> None:
        self._contracts: Dict[str, ProofContract] = {}
        self._alias_map: Dict[str, str] = {}

    def register(self, contract: ProofContract) -> None:
        cat = contract.category.lower().strip()
        self._contracts[cat] = contract
        self._alias_map[cat] = cat
        for alias in contract.aliases:
            self._alias_map[alias.lower().strip()] = cat

    def normalize_category(self, vuln_class: str) -> Optional[str]:
        if not vuln_class:
            return None
        key = vuln_class.lower().strip().replace("-", "_").replace(" ", "_")
        if key in self._alias_map:
            return self._alias_map[key]
        # Substring fallback against registered aliases (longest first for precision)
        for alias in sorted(self._alias_map.keys(), key=len, reverse=True):
            if alias and alias in key:
                return self._alias_map[alias]
        return None

    def get(self, vuln_class: str) -> Optional[ProofContract]:
        cat = self.normalize_category(vuln_class)
        return self._contracts.get(cat) if cat else None

    def list_categories(self) -> List[str]:
        return list(self._contracts.keys())

    def evaluate(
        self,
        vuln_class: str,
        payload_data: Dict[str, Any],
        verifier_result: Optional[Dict[str, Any]] = None,
    ) -> Optional[ProofContractResult]:
        contract = self.get(vuln_class)
        if contract is None:
            return None
        return contract.evaluate(payload_data, verifier_result or {})


def _build_default_registry() -> ProofContractRegistry:
    reg = ProofContractRegistry()
    reg.register(ProofContract(
        category="sqli",
        aliases=("sql_injection", "sql_injection_error", "sqli_boolean", "sqli_error", "sqli_time", "blind_sqli"),
        requirement="Extracted DBMS version banner, verified boolean/time triad, or extracted DB token absent from baseline.",
        evaluator=_eval_sqli,
    ))
    reg.register(ProofContract(
        category="xss",
        aliases=("dom_xss", "reflected_xss", "stored_xss", "xss_reflected", "cross_site_scripting"),
        requirement="Runtime browser DOM execution telemetry or unescaped executable HTML breakout absent from baseline.",
        evaluator=_eval_xss,
    ))
    reg.register(ProofContract(
        category="cmdi",
        aliases=("command_injection", "cmd_injection", "rce", "remote_code_execution", "os_command_injection"),
        requirement="Deterministic arithmetic/command output at token boundary, absent from baseline and not mere syntax reflection.",
        evaluator=_eval_cmdi,
    ))
    reg.register(ProofContract(
        category="ssrf",
        aliases=("server_side_request_forgery", "blind_ssrf"),
        requirement="Unique OOB callback nonce match or internal cloud/service metadata signature absent from baseline.",
        evaluator=_eval_ssrf,
    ))
    reg.register(ProofContract(
        category="idor",
        aliases=("bola", "bfla_idor", "idor_bola", "cross_tenant_isolation_breach", "broken_object_level_authorization"),
        requirement="Cross-tenant victim canary leaked to distinct unauthorized actor and absent from attacker baseline.",
        evaluator=_eval_idor,
    ))
    reg.register(ProofContract(
        category="lfi",
        aliases=("path_traversal", "directory_traversal", "arbitrary_file_read", "local_file_inclusion", "traversal"),
        requirement="Verified OS file content signature (/etc/passwd, win.ini/boot.ini) absent from baseline.",
        evaluator=_eval_lfi,
    ))
    reg.register(ProofContract(
        category="ssti",
        aliases=("template_injection", "server_side_template_injection"),
        requirement="Evaluated template arithmetic output at token boundary absent from baseline (literal template echo refuted).",
        evaluator=_eval_ssti,
    ))
    reg.register(ProofContract(
        category="auth",
        aliases=("auth_bypass", "authentication_bypass", "bfla", "broken_auth", "privilege_escalation"),
        requirement="Unauthenticated/unprivileged access to protected resource marker or verified 401/403->200 protected data leak.",
        evaluator=_eval_auth,
    ))
    reg.register(ProofContract(
        category="jwt",
        aliases=("jwt_advanced", "jwt_bypass", "jwt_none", "jwt_weak_secret"),
        requirement="Cryptographically re-verified HMAC secret or forged JWT bypassing 401/403 to expose protected marker.",
        evaluator=_eval_jwt,
    ))
    reg.register(ProofContract(
        category="deser",
        aliases=("deserialization", "insecure_deserialization"),
        requirement="Verified execution output or OOB gadget callback nonce (stack traces alone are insufficient).",
        evaluator=_eval_deser,
    ))
    reg.register(ProofContract(
        category="race",
        aliases=("race_condition", "toctou", "double_execution"),
        requirement="Concurrent success count strictly exceeding limit with verified duplicate state mutation.",
        evaluator=_eval_race,
    ))
    reg.register(ProofContract(
        category="secret",
        aliases=("exposed_secret", "secret_leak", "credential_exposure", "leaked_secret"),
        requirement="High-confidence non-placeholder credential pattern or live active credential validation.",
        evaluator=_eval_secret,
    ))
    reg.register(ProofContract(
        category="misconfig",
        aliases=(
            "misconfiguration",
            "cors",
            "cors_arbitrary_origin_reflection",
            "open_redirect",
            "exposed_dotenv_file",
            "exposed_git_head",
            "cache_poisoning",
            "web_cache_poisoning",
        ),
        requirement="Verifiable CORS ACAC reflection, external Location redirect, .git/HEAD, .env secret, or clean-refetch cache canary.",
        evaluator=_eval_misconfig,
    ))
    return reg


PROOF_CONTRACT_REGISTRY: ProofContractRegistry = _build_default_registry()


def normalize_vuln_category(vuln_class: str) -> Optional[str]:
    """Map an arbitrary vulnerability class string to one of the 13 canonical ProofContract categories."""
    return PROOF_CONTRACT_REGISTRY.normalize_category(vuln_class)
