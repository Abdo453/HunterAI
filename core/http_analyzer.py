"""
Deep HTTP & Burp Suite Traffic Analyzer
محلل حركة المرور وطلبات Burp Suite / HTTP العميقة
يقوم بفحص: JWT, CORS, IDOR, Security Headers, Cookies, وتوليد تقرير أمني ذكي
"""
import re
import json
import base64
import time
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse, parse_qs


class HTTPTrafficAnalyzer:
    """
    محلل حركة الـ HTTP لطلبات Burp Suite و ZAP و Raw Requests
    """

    def __init__(self):
        pass

    def parse_raw_http_request(self, raw_request: str) -> Dict[str, Any]:
        """تحليل نص طلب HTTP الخام"""
        lines = raw_request.strip().splitlines()
        if not lines:
            return {"error": "Empty request"}

        req_line = lines[0].strip().split()
        method = req_line[0] if len(req_line) > 0 else "GET"
        path = req_line[1] if len(req_line) > 1 else "/"
        http_version = req_line[2] if len(req_line) > 2 else "HTTP/1.1"

        headers = {}
        body_lines = []
        is_body = False

        for line in lines[1:]:
            if not is_body:
                if line.strip() == "":
                    is_body = True
                    continue
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()
            else:
                body_lines.append(line)

        body = "\n".join(body_lines)
        host = headers.get("host", "unknown")

        return {
            "method": method,
            "path": path,
            "http_version": http_version,
            "host": host,
            "headers": headers,
            "body": body,
            "full_url": f"https://{host}{path}" if host != "unknown" else path
        }

    def parse_raw_http_response(self, raw_response: str) -> Dict[str, Any]:
        """تحليل نص استجابة HTTP الخام"""
        lines = raw_response.strip().splitlines()
        if not lines:
            return {"error": "Empty response"}

        status_line = lines[0].strip().split(" ", 2)
        http_version = status_line[0] if len(status_line) > 0 else "HTTP/1.1"
        status_code = int(status_line[1]) if len(status_line) > 1 and status_line[1].isdigit() else 200
        status_msg = status_line[2] if len(status_line) > 2 else "OK"

        headers = {}
        body_lines = []
        is_body = False

        for line in lines[1:]:
            if not is_body:
                if line.strip() == "":
                    is_body = True
                    continue
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()
            else:
                body_lines.append(line)

        body = "\n".join(body_lines)

        return {
            "http_version": http_version,
            "status_code": status_code,
            "status_message": status_msg,
            "headers": headers,
            "body": body
        }

    def analyze(self, raw_request: str, raw_response: Optional[str] = None) -> Dict[str, Any]:
        """فحص شامل لطلب واستجابة HTTP واستخراج الثغرات والـ Weaknesses"""
        req = self.parse_raw_http_request(raw_request)
        resp = self.parse_raw_http_response(raw_response) if raw_response else None

        findings = []
        jwt_findings = self._check_jwt(req, resp)
        findings.extend(jwt_findings)

        cors_findings = self._check_cors(req, resp)
        findings.extend(cors_findings)

        header_findings = self._check_security_headers(resp)
        findings.extend(header_findings)

        cookie_findings = self._check_cookies(req, resp)
        findings.extend(cookie_findings)

        idor_findings = self._check_idor_candidates(req)
        findings.extend(idor_findings)

        info_findings = self._check_info_disclosure(resp)
        findings.extend(info_findings)

        # حساب تقييم الخطورة العام
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for f in findings:
            sev = f.get("severity", "Info")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        risk_score = (
            severity_counts["Critical"] * 10 +
            severity_counts["High"] * 7 +
            severity_counts["Medium"] * 4 +
            severity_counts["Low"] * 2
        )

        return {
            "parsed_request": req,
            "parsed_response": resp,
            "findings": findings,
            "findings_count": len(findings),
            "severity_summary": severity_counts,
            "risk_score": min(100, risk_score),
            "timestamp": time.time()
        }

    def _check_jwt(self, req: Dict, resp: Optional[Dict]) -> List[Dict[str, Any]]:
        findings = []
        tokens = []

        # البحث عن JWT في الـ Headers
        auth_h = req.get("headers", {}).get("authorization", "")
        if auth_h.startswith("Bearer "):
            tokens.append(auth_h.split(" ", 1)[1])

        # البحث في الـ Cookies أو الـ Body
        cookie_h = req.get("headers", {}).get("cookie", "")
        jwt_matches = re.findall(r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+", cookie_h + " " + req.get("body", ""))
        tokens.extend(jwt_matches)

        for token in set(tokens):
            parts = token.split(".")
            if len(parts) == 3:
                try:
                    # decode header
                    h_padded = parts[0] + "=" * ((4 - len(parts[0]) % 4) % 4)
                    header_json = json.loads(base64.urlsafe_b64decode(h_padded).decode("utf-8", errors="ignore"))

                    # decode payload
                    p_padded = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
                    payload_json = json.loads(base64.urlsafe_b64decode(p_padded).decode("utf-8", errors="ignore"))

                    alg = header_json.get("alg", "").upper()
                    if alg == "NONE":
                        findings.append({
                            "title": "JWT 'none' Algorithm Vulnerability",
                            "severity": "Critical",
                            "category": "JWT Authentication",
                            "description": "JWT uses 'none' algorithm allowing arbitrary signature bypass and privilege escalation.",
                            "evidence": f"Header: {header_json}",
                            "recommendation": "Reject tokens with 'none' algorithm and enforce RS256/ES256."
                        })
                    elif alg == "HS256":
                        findings.append({
                            "title": "Symmetric JWT Algorithm (HS256) Detected",
                            "severity": "Low",
                            "category": "JWT Authentication",
                            "description": "JWT uses symmetric HMAC-SHA256. If secret key is weak, it can be brute-forced with hashcat/jwt_tool.",
                            "evidence": f"Algorithm: {alg}, Claims: {list(payload_json.keys())}",
                            "recommendation": "Use strong random 256-bit secret or switch to asymmetric RS256."
                        })

                    # Check expiration
                    exp = payload_json.get("exp")
                    if not exp:
                        findings.append({
                            "title": "JWT Missing Expiration ('exp') Claim",
                            "severity": "Medium",
                            "category": "JWT Authentication",
                            "description": "The token does not have an expiration time, allowing replay attacks indefinitely.",
                            "evidence": f"Payload: {payload_json}",
                            "recommendation": "Include an 'exp' claim with short lifespan (e.g. 15-60 mins)."
                        })

                except Exception:
                    pass
        return findings

    def _check_cors(self, req: Dict, resp: Optional[Dict]) -> List[Dict[str, Any]]:
        findings = []
        if not resp:
            return findings

        r_headers = resp.get("headers", {})
        acao = r_headers.get("access-control-allow-origin", "")
        acac = r_headers.get("access-control-allow-credentials", "").lower()

        if acao == "*" and acac == "true":
            findings.append({
                "title": "Insecure CORS: Wildcard Origin with Credentials",
                "severity": "High",
                "category": "CORS",
                "description": "Server allows any origin with credentials, allowing malicious sites to read sensitive user data.",
                "evidence": f"Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
                "recommendation": "Do not reflect arbitrary origins or combine '*' with credentials."
            })
        elif "null" in acao:
            findings.append({
                "title": "Insecure CORS: 'null' Origin Allowed",
                "severity": "Medium",
                "category": "CORS",
                "description": "Server trusts the 'null' origin, enabling attacks via sandboxed iframes or local files.",
                "evidence": f"Access-Control-Allow-Origin: {acao}",
                "recommendation": "Remove 'null' from trusted CORS origins whitelist."
            })
        return findings

    def _check_security_headers(self, resp: Optional[Dict]) -> List[Dict[str, Any]]:
        findings = []
        if not resp:
            return findings

        headers = resp.get("headers", {})
        missing = []

        if "content-security-policy" not in headers:
            missing.append("Content-Security-Policy (CSP)")
        if "strict-transport-security" not in headers:
            missing.append("Strict-Transport-Security (HSTS)")
        if "x-frame-options" not in headers:
            missing.append("X-Frame-Options (Clickjacking Protection)")
        if "x-content-type-options" not in headers:
            missing.append("X-Content-Type-Options (MIME Sniffing)")

        if missing:
            findings.append({
                "title": f"Missing Security Headers ({len(missing)})",
                "severity": "Low",
                "category": "Hardening",
                "description": f"Target server is missing protective HTTP security headers: {', '.join(missing)}.",
                "evidence": f"Missing: {', '.join(missing)}",
                "recommendation": "Configure web server/reverse proxy to enforce modern security headers."
            })
        return findings

    def _check_cookies(self, req: Dict, resp: Optional[Dict]) -> List[Dict[str, Any]]:
        findings = []
        if not resp:
            return findings

        set_cookie = resp.get("headers", {}).get("set-cookie", "")
        if set_cookie:
            sc_lower = set_cookie.lower()
            issues = []
            if "httponly" not in sc_lower:
                issues.append("Missing HttpOnly (Accessible to XSS)")
            if "secure" not in sc_lower:
                issues.append("Missing Secure flag (Transmitted in plaintext)")
            if "samesite" not in sc_lower:
                issues.append("Missing SameSite attribute (CSRF Risk)")

            if issues:
                findings.append({
                    "title": "Insecure Cookie Configuration",
                    "severity": "Medium",
                    "category": "Session Security",
                    "description": f"Session cookies lack essential security attributes: {', '.join(issues)}.",
                    "evidence": f"Set-Cookie: {set_cookie}",
                    "recommendation": "Set 'Secure; HttpOnly; SameSite=Lax' (or Strict) on all sensitive cookies."
                })
        return findings

    def _check_idor_candidates(self, req: Dict) -> List[Dict[str, Any]]:
        findings = []
        path = req.get("path", "")
        body = req.get("body", "")

        # البحث عن معرفات رقمية أو UUID في المسار
        id_in_path = re.findall(r"/(?:users?|accounts?|orders?|invoices?|items?|profiles?)/([0-9]{1,10}|[0-9a-fA-F-]{36})", path)
        if id_in_path:
            findings.append({
                "title": "Potential IDOR / BOLA Endpoint Detected",
                "severity": "Medium",
                "category": "Access Control (IDOR)",
                "description": f"Endpoint directly references object identifier ({id_in_path[0]}) in URL path. Test by modifying ID to another user's object.",
                "evidence": f"Path: {path}",
                "recommendation": "Enforce server-side object-level authorization (BOLA check) before returning data."
            })

        # البحث في الباراميترات
        if "?" in path:
            params = parse_qs(path.split("?", 1)[1])
            idor_keys = ["id", "user_id", "userid", "account_id", "profile_id", "doc_id", "file_id"]
            matched_keys = [k for k in params.keys() if k.lower() in idor_keys]
            if matched_keys:
                findings.append({
                    "title": f"Candidate IDOR Parameters in Query: {', '.join(matched_keys)}",
                    "severity": "Medium",
                    "category": "Access Control (IDOR)",
                    "description": f"Sensitive ID parameters found in GET query: {matched_keys}. Verify if changing parameter values accesses unauthorized records.",
                    "evidence": f"Query parameters: {params}",
                    "recommendation": "Validate user ownership of the requested resource ID."
                })
        return findings

    def _check_info_disclosure(self, resp: Optional[Dict]) -> List[Dict[str, Any]]:
        findings = []
        if not resp:
            return findings

        headers = resp.get("headers", {})
        server = headers.get("server", "")
        x_powered = headers.get("x-powered-by", "")

        if server or x_powered:
            findings.append({
                "title": "Server / Tech Stack Version Disclosure",
                "severity": "Info",
                "category": "Information Disclosure",
                "description": "Server reveals underlying technology and version numbers via response headers.",
                "evidence": f"Server: {server} | X-Powered-By: {x_powered}",
                "recommendation": "Suppress Server and X-Powered-By banners in web server configuration."
            })
        return findings
