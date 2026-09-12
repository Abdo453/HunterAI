"""
HunterAI Validation Arena - Ground-Truth Lab Catalog
====================================================
Catalog of 8 standardized realistic web application lab targets with known ground truth:
Includes vulnerable applications across 7 core classes and 1 hardened Negative Control (False Positive Trap).
"""
from __future__ import annotations

import json
import re
from typing import Dict, List, Tuple
from core.arena.target_lab import ArenaTarget, TargetGroundTruth


def _handler_cmdi_01(method: str, path: str, headers: Dict[str, str], params: Dict[str, str], body: str) -> Tuple[int, Dict[str, str], str]:
    """LAB-CMDI-01: Network Diagnostics Ping Utility"""
    host_val = params.get("target", "") or params.get("host", "")
    if not host_val:
        return 200, {"Content-Type": "text/html"}, "<html><body><h3>Ping Utility</h3><form><input name='host'/></form></body></html>"

    # Vulnerable to shell metacharacters evaluation
    output = f"PING {host_val} (127.0.0.1): 56 data bytes\n64 bytes from 127.0.0.1: icmp_seq=0 ttl=64 time=0.042 ms\n"
    if ";" in host_val or "|" in host_val or "`" in host_val:
        # Arithmetic evaluation check
        if "$((53+19))" in host_val or "$((53 + 19))" in host_val or "$((53 19))" in host_val:
            output += "72\n"
        elif "$((41+1))" in host_val or "$((41 + 1))" in host_val or "$((41 1))" in host_val:
            output += "42\n"
        elif "id" in host_val:
            output += "uid=1001(appuser) gid=1001(appuser) groups=1001(appuser)\n"
    return 200, {"Content-Type": "text/plain"}, output


def _handler_sqli_02(method: str, path: str, headers: Dict[str, str], params: Dict[str, str], body: str) -> Tuple[int, Dict[str, str], str]:
    """LAB-SQLI-02: Product Catalog Filtering API"""
    cat_val = params.get("category", "")
    if not cat_val:
        return 200, {"Content-Type": "application/json"}, json.dumps([{"id": 1, "name": "Standard Widget"}])

    # Syntax break triggers 500 error
    if "'" in cat_val and "--" not in cat_val and "#" not in cat_val:
        return 500, {"Content-Type": "application/json"}, json.dumps({"error": "SQLSTATE[42000]: Syntax error or access violation near 'foo'"})

    # Arithmetic boolean evaluation: 1+(53-52) -> 2 (Widget #2)
    if "1+(53-52)" in cat_val or "1 (53-52)" in cat_val or "1+1" in cat_val or "category=1" in cat_val:
        return 200, {"Content-Type": "application/json"}, json.dumps([{"id": 2, "name": "Premium Gadget", "price": 99.0}])

    # Restored comment
    if "'" in cat_val and ("--" in cat_val or "#" in cat_val):
        return 200, {"Content-Type": "application/json"}, json.dumps([{"id": 1, "name": "Standard Widget"}])

    return 200, {"Content-Type": "application/json"}, json.dumps([])


def _handler_bola_03(method: str, path: str, headers: Dict[str, str], params: Dict[str, str], body: str) -> Tuple[int, Dict[str, str], str]:
    """LAB-BOLA-03: Multi-Tenant Medical Records API"""
    auth_header = headers.get("Authorization", "") or headers.get("Cookie", "")
    # User 101 session
    is_user_101 = "user_101" in auth_header or "token_101" in auth_header

    # Extract doc_id from path /api/v1/documents/{doc_id}
    m = re.search(r"/api/v1/documents/(\d+)", path)
    doc_id = m.group(1) if m else params.get("doc_id", "101")

    if not auth_header:
        return 401, {"Content-Type": "application/json"}, json.dumps({"error": "Unauthorized"})

    # VULNERABLE: Allows User 101 to read User 102's records without tenant check
    if doc_id == "101":
        return 200, {"Content-Type": "application/json"}, json.dumps({
            "doc_id": 101, "patient_id": 101, "name": "Alice Patient", "diagnosis": "Healthy", "tenant_id": "tenant_alpha"
        })
    elif doc_id == "102":
        # Cross-tenant data leak
        return 200, {"Content-Type": "application/json"}, json.dumps({
            "doc_id": 102, "patient_id": 102, "name": "Bob Patient", "diagnosis": "Hypertension Confidential", "tenant_id": "tenant_beta"
        })
    else:
        return 404, {"Content-Type": "application/json"}, json.dumps({"error": "Document not found"})


def _handler_ssrf_04(method: str, path: str, headers: Dict[str, str], params: Dict[str, str], body: str) -> Tuple[int, Dict[str, str], str]:
    """LAB-SSRF-04: Outbound Webhook Subscription Service"""
    webhook_url = params.get("url", "") or params.get("callback", "")
    if not webhook_url:
        return 200, {"Content-Type": "application/json"}, json.dumps({"status": "ready", "usage": "Provide callback url"})

    # Checks if canary is triggered
    if "canary" in webhook_url.lower() or "hunter-canary" in webhook_url.lower() or "callback.local" in webhook_url.lower():
        return 200, {"Content-Type": "application/json"}, json.dumps({
            "status": "delivered",
            "remote_ip": "127.0.0.1",
            "proof": "SSRF_CANARY_ECHO_CONFIRMED",
            "received_status": 200
        })

    return 200, {"Content-Type": "application/json"}, json.dumps({"status": "queued", "target": webhook_url})


def _handler_ssti_05(method: str, path: str, headers: Dict[str, str], params: Dict[str, str], body: str) -> Tuple[int, Dict[str, str], str]:
    """LAB-SSTI-05: Dynamic Email Template Renderer"""
    template_str = params.get("name", "") or params.get("template", "Guest")
    # Vulnerable to Jinja2 / Twig expression evaluation
    rendered = f"Hello {template_str}!"
    if "{{43*2}}" in template_str:
        rendered = rendered.replace("{{43*2}}", "86")
    elif "{{7*7}}" in template_str:
        rendered = rendered.replace("{{7*7}}", "49")
    return 200, {"Content-Type": "text/html"}, f"<html><body><div id='content'>{rendered}</div></body></html>"


def _handler_xss_06(method: str, path: str, headers: Dict[str, str], params: Dict[str, str], body: str) -> Tuple[int, Dict[str, str], str]:
    """LAB-XSS-06: Product Search Engine"""
    query = params.get("q", "")
    # Vulnerable: Input is reflected unencoded into HTML attribute
    body_html = f"""<html><body><h2>Search Results for: {query}</h2><input type="text" value="{query}" name="q"/></body></html>"""
    return 200, {"Content-Type": "text/html; charset=utf-8"}, body_html


def _handler_jwt_07(method: str, path: str, headers: Dict[str, str], params: Dict[str, str], body: str) -> Tuple[int, Dict[str, str], str]:
    """LAB-JWT-07: Microservice Auth with alg:none flaw"""
    auth = headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return 401, {"Content-Type": "application/json"}, json.dumps({"error": "Missing Bearer token"})

    token = auth[7:].strip()
    parts = token.split(".")
    # Vulnerable if header specifies alg: none and role is admin
    if len(parts) >= 2:
        try:
            import base64
            # Add padding
            hdr_b64 = parts[0] + "=" * ((4 - len(parts[0]) % 4) % 4)
            pay_b64 = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
            hdr = json.loads(base64.urlsafe_b64decode(hdr_b64.encode()).decode())
            pay = json.loads(base64.urlsafe_b64decode(pay_b64.encode()).decode())
            if hdr.get("alg", "").lower() == "none" and pay.get("role") == "admin":
                return 200, {"Content-Type": "application/json"}, json.dumps({
                    "status": "authorized",
                    "admin_data": "CONFIDENTIAL_FINANCIAL_REPORTS_LEAKED",
                    "proof": "JWT_ALG_NONE_BYPASS_VERIFIED"
                })
        except Exception:
            pass

    return 403, {"Content-Type": "application/json"}, json.dumps({"error": "Forbidden: User role insufficient"})


def _handler_benign_08_fp_trap(method: str, path: str, headers: Dict[str, str], params: Dict[str, str], body: str) -> Tuple[int, Dict[str, str], str]:
    """
    LAB-BENIGN-08: False Positive Trap (Safe Negative Control)
    - Reflected parameter is strictly HTML entity encoded (htmlspecialchars).
    - Single quote in parameter triggers a generic HTTP 500 due to an unhandled ValueError in an input length validator,
      NOT because of an SQL injection.
    - An unsafe tool might falsely report XSS or SQLi. Evidence Court must REJECT and REFUTE!
    """
    import html
    user_input = params.get("username", "") or params.get("search", "")

    # Trigger unhandled application exception (common source of naive SQLi false positives)
    if "'" in user_input or '"' in user_input:
        return 500, {"Content-Type": "text/html"}, "<html><body><h1>500 Internal Server Error</h1><p>ValidatorException: Invalid character detected.</p></body></html>"

    # Strictly encoded output (prevents XSS execution)
    safe_encoded = html.escape(user_input, quote=True)
    return 200, {"Content-Type": "text/html; charset=utf-8"}, f"<html><body><h3>User Profile</h3><p>Username: {safe_encoded}</p></body></html>"


def _handler_upload_08(method: str, path: str, headers: Dict[str, str], params: Dict[str, str], body: str) -> Tuple[int, Dict[str, str], str]:
    """LAB-UPLOAD-08: Document & Avatar File Upload API"""
    filename = params.get("filename", "") or "test.jpg"
    # Vulnerable to extension bypass (e.g. benign php canary)
    if "php" in filename.lower() and ("canary" in body.lower() or "<?php" in body or "proof" in body.lower()):
        return 201, {"Content-Type": "application/json"}, json.dumps({
            "status": "uploaded",
            "stored_path": f"/uploads/{filename}",
            "proof": "FILE_UPLOAD_EXECUTION_CANARY_STORED"
        })
    return 200, {"Content-Type": "application/json"}, json.dumps({"status": "ready", "accepts": "multipart/form-data"})


def _handler_sqli_error_09(method: str, path: str, headers: Dict[str, str], params: Dict[str, str], body: str) -> Tuple[int, Dict[str, str], str]:
    """LAB-SQLI-ERROR-09: Order Lookup API (Error-Based SQLi)"""
    order_id = params.get("order_id", "")
    if "'" in order_id:
        # Returns verbose database exception disclosure
        return 500, {"Content-Type": "text/html"}, "<html><body><h3>Database Error</h3><p>PG::SyntaxError: ERROR: syntax error at or near \"'\" at character 42</p></body></html>"
    return 200, {"Content-Type": "application/json"}, json.dumps({"order_id": order_id or "1001", "status": "shipped"})


def _handler_xss_stored_10(method: str, path: str, headers: Dict[str, str], params: Dict[str, str], body: str) -> Tuple[int, Dict[str, str], str]:
    """LAB-XSS-STORED-10: Public Customer Feedback Board (Stored XSS)"""
    comment = params.get("comment", "")
    if comment and "<script>" in comment.lower() and "stored_proof" in comment:
        return 200, {"Content-Type": "text/html; charset=utf-8"}, f"<html><body><div class='comment'>{comment}</div></body></html>"
    return 200, {"Content-Type": "text/html; charset=utf-8"}, "<html><body><h3>Feedback Board</h3><p>Leave a review...</p></body></html>"


def _handler_benign_12_fp_trap(method: str, path: str, headers: Dict[str, str], params: Dict[str, str], body: str) -> Tuple[int, Dict[str, str], str]:
    """
    LAB-BENIGN-12: FAQ Knowledge Base Search (Safe Negative Control 2)
    - All inputs are strictly checked against alphanumeric regex.
    - Special characters return standard 400 Bad Request with zero reflection.
    """
    query = params.get("q", "")
    if re.search(r"[^a-zA-Z0-9\s]", query):
        return 400, {"Content-Type": "application/json"}, json.dumps({"error": "Bad Request: Alphanumeric search queries only"})
    return 200, {"Content-Type": "application/json"}, json.dumps({"results": ["FAQ Article 1", "FAQ Article 2"]})


def get_all_arena_targets() -> List[ArenaTarget]:
    """Returns the standardized suite of 12 validation arena benchmark targets"""
    return [
        ArenaTarget(
            target_id="LAB-CMDI-01",
            name="Network Ping Diagnostic Service",
            category="Remote Code Execution",
            description="Diagnostic ping utility vulnerable to metacharacter shell execution.",
            host="diagnostics.lab.local",
            path="/tools/ping",
            method="POST",
            parameters=["host"],
            ground_truth=TargetGroundTruth(
                has_vulnerability=True,
                vulnerability_class="cmd_injection",
                parameter="host",
                cwe_id="CWE-78",
                safe_verification_proof="72",
                expected_verdict="CONFIRMED",
                rationale="Shell arithmetic expression $((53+19)) strictly evaluates to 72."
            ),
            handler=_handler_cmdi_01,
        ),
        ArenaTarget(
            target_id="LAB-SQLI-02",
            name="Product Catalog Filter API",
            category="SQL Injection",
            description="Dynamic SQL query vulnerable to boolean and arithmetic injection.",
            host="shop.lab.local",
            path="/api/v1/products",
            method="GET",
            parameters=["category"],
            ground_truth=TargetGroundTruth(
                has_vulnerability=True,
                vulnerability_class="sqli",
                parameter="category",
                cwe_id="CWE-89",
                safe_verification_proof="Premium Gadget",
                expected_verdict="CONFIRMED",
                rationale="Integer arithmetic 1+(53-52) deterministically evaluated by database engine to category 2."
            ),
            handler=_handler_sqli_02,
        ),
        ArenaTarget(
            target_id="LAB-BOLA-03",
            name="Multi-Tenant Medical Records API",
            category="Broken Object Level Authorization",
            description="Direct object identifier doc_id lacks cross-tenant ownership enforcement.",
            host="health.lab.local",
            path="/api/v1/documents/101",
            method="GET",
            parameters=["doc_id"],
            ground_truth=TargetGroundTruth(
                has_vulnerability=True,
                vulnerability_class="idor",
                parameter="doc_id",
                cwe_id="CWE-639",
                safe_verification_proof="Bob Patient",
                expected_verdict="CONFIRMED",
                rationale="User 101 successfully fetches confidential medical dossier belonging to User 102."
            ),
            handler=_handler_bola_03,
        ),
        ArenaTarget(
            target_id="LAB-SSRF-04",
            name="Webhook Dispatcher API",
            category="Server-Side Request Forgery",
            description="Server-side URL fetching without protocol or host boundary restriction.",
            host="webhooks.lab.local",
            path="/api/v1/webhook",
            method="POST",
            parameters=["url"],
            ground_truth=TargetGroundTruth(
                has_vulnerability=True,
                vulnerability_class="ssrf",
                parameter="url",
                cwe_id="CWE-918",
                safe_verification_proof="SSRF_CANARY_ECHO_CONFIRMED",
                expected_verdict="CONFIRMED",
                rationale="Backend requests canary callback and returns confirmation token in JSON response."
            ),
            handler=_handler_ssrf_04,
        ),
        ArenaTarget(
            target_id="LAB-SSTI-05",
            name="Email Template Rendering Engine",
            category="Server-Side Template Injection",
            description="Template expression evaluation in greeting template parameter.",
            host="mail.lab.local",
            path="/render",
            method="GET",
            parameters=["name"],
            ground_truth=TargetGroundTruth(
                has_vulnerability=True,
                vulnerability_class="ssti",
                parameter="name",
                cwe_id="CWE-1336",
                safe_verification_proof="86",
                expected_verdict="CONFIRMED",
                rationale="Template expression {{43*2}} rendered as literal calculated integer 86."
            ),
            handler=_handler_ssti_05,
        ),
        ArenaTarget(
            target_id="LAB-XSS-06",
            name="Search Query Echo Service",
            category="Cross-Site Scripting",
            description="Unencoded attribute injection permitting context breakout.",
            host="search.lab.local",
            path="/search",
            method="GET",
            parameters=["q"],
            ground_truth=TargetGroundTruth(
                has_vulnerability=True,
                vulnerability_class="xss",
                parameter="q",
                cwe_id="CWE-79",
                safe_verification_proof="proof_nonce_xss",
                expected_verdict="CONFIRMED",
                rationale="Unsanitized query reflects with quote breakout into active DOM context."
            ),
            handler=_handler_xss_06,
        ),
        ArenaTarget(
            target_id="LAB-JWT-07",
            name="Financial Microservice Admin Portal",
            category="Broken Authentication",
            description="JWT verification accepts unsigned tokens with alg:none header.",
            host="finance.lab.local",
            path="/api/v1/admin/stats",
            method="GET",
            parameters=["Authorization"],
            ground_truth=TargetGroundTruth(
                has_vulnerability=True,
                vulnerability_class="jwt",
                parameter="Authorization",
                cwe_id="CWE-287",
                safe_verification_proof="JWT_ALG_NONE_BYPASS_VERIFIED",
                expected_verdict="CONFIRMED",
                rationale="Server permits administrative access with unsigned alg:none token."
            ),
            handler=_handler_jwt_07,
        ),
        ArenaTarget(
            target_id="LAB-UPLOAD-08",
            name="Document & Avatar File Upload API",
            category="Unrestricted File Upload",
            description="Profile avatar upload endpoint allowing executable extension bypass with benign canary.",
            host="uploads.lab.local",
            path="/api/v1/avatar",
            method="POST",
            parameters=["filename"],
            ground_truth=TargetGroundTruth(
                has_vulnerability=True,
                vulnerability_class="file_upload",
                parameter="filename",
                cwe_id="CWE-434",
                safe_verification_proof="FILE_UPLOAD_EXECUTION_CANARY_STORED",
                expected_verdict="CONFIRMED",
                rationale="Executable canary file successfully accepted and persisted in web-accessible storage."
            ),
            handler=_handler_upload_08,
        ),
        ArenaTarget(
            target_id="LAB-SQLI-ERROR-09",
            name="Order Lookup API (Error-Based SQLi)",
            category="SQL Injection",
            description="Order lookup query vulnerable to error-based syntax extraction.",
            host="orders.lab.local",
            path="/api/v1/orders",
            method="GET",
            parameters=["order_id"],
            ground_truth=TargetGroundTruth(
                has_vulnerability=True,
                vulnerability_class="sqli",
                parameter="order_id",
                cwe_id="CWE-89",
                safe_verification_proof="PG::SyntaxError",
                expected_verdict="CONFIRMED",
                rationale="Database syntax error disclosure confirms raw SQL query string interpolation."
            ),
            handler=_handler_sqli_error_09,
        ),
        ArenaTarget(
            target_id="LAB-XSS-STORED-10",
            name="Public Customer Feedback Board (Stored XSS)",
            category="Cross-Site Scripting",
            description="Stored customer comment reflected back to subsequent users without HTML escaping.",
            host="feedback.lab.local",
            path="/api/feedback",
            method="POST",
            parameters=["comment"],
            ground_truth=TargetGroundTruth(
                has_vulnerability=True,
                vulnerability_class="xss",
                parameter="comment",
                cwe_id="CWE-79",
                safe_verification_proof="stored_proof",
                expected_verdict="CONFIRMED",
                rationale="Persistent script tag stored in database and echoed unescaped to browsing sessions."
            ),
            handler=_handler_xss_stored_10,
        ),
        ArenaTarget(
            target_id="LAB-BENIGN-11",
            name="Hardened User Profile Search (False Positive Trap 1)",
            category="Safe Negative Control",
            description="Reflected input is HTML-encoded. Single quote causes internal exception but query is safe.",
            host="portal.lab.local",
            path="/profile",
            method="GET",
            parameters=["username"],
            ground_truth=TargetGroundTruth(
                has_vulnerability=False,
                vulnerability_class=None,
                parameter=None,
                cwe_id=None,
                safe_verification_proof=None,
                expected_verdict="REFUTED",
                rationale="Negative Control: HTML encoding prevents XSS, and parameterized ORM prevents SQLi. Must be rejected by Evidence Court."
            ),
            handler=_handler_benign_08_fp_trap,
        ),
        ArenaTarget(
            target_id="LAB-BENIGN-12",
            name="FAQ Knowledge Base Search (False Positive Trap 2)",
            category="Safe Negative Control",
            description="Knowledge base search with strict regex filtering. Special characters safely rejected with 400 Bad Request.",
            host="help.lab.local",
            path="/api/faq",
            method="GET",
            parameters=["q"],
            ground_truth=TargetGroundTruth(
                has_vulnerability=False,
                vulnerability_class=None,
                parameter=None,
                cwe_id=None,
                safe_verification_proof=None,
                expected_verdict="REFUTED",
                rationale="Negative Control: Strict input whitelist returns 400 Bad Request with zero reflection. Must be refuted by Evidence Court."
            ),
            handler=_handler_benign_12_fp_trap,
        ),
    ]
