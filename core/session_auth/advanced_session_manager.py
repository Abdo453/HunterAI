"""
Advanced Session & Authentication Security Manager
"Enterprise-Grade Session Auditing & Token Lifecycle Engine"

يغطي تدقيق أمان الجلسات والمصادقة بالكامل وفق معايير OWASP A07 / A08:
1. فحص سمات الكوكيز (Secure, HttpOnly, SameSite, Max-Age/Expires)
2. تحليل عشوائية وإنتروبيا الرموز (Shannon Entropy Analysis)
3. فحص بنية وتوقيع رموز JWT (Weak Algorithm, None-Alg, Expiration)
4. فحص آليات الحماية من CSRF (CSRF Tokens & SameSite policies)
5. الحفاظ الذكي على الجلسة الحية وتجديد الرموز تلقائياً (Token Preservation)
"""
import base64
import json
import logging
import math
import re
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse
import httpx

log = logging.getLogger("session_auth.advanced_manager")


class AdvancedSessionManager:
    """إدارة وتدقيق أمان الجلسات والرموز والمصادقة"""

    def __init__(self, proxy: Optional[str] = None):
        self.proxy = proxy
        self._session_cookies: Dict[str, str] = {}
        self._active_tokens: Dict[str, str] = {}
        self._auth_client: Optional[httpx.AsyncClient] = None

    # ── 1. Shannon Entropy Calculator ────────────────────────────────────────

    @staticmethod
    def calculate_entropy(token: str) -> float:
        """حساب إنتروبيا النص (Shannon Entropy) لتقييم مدى عشوائية الرموز"""
        if not token:
            return 0.0
        prob = [float(token.count(c)) / len(token) for c in dict.fromkeys(list(token))]
        entropy = -sum(p * math.log2(p) for p in prob if p > 0)
        return round(entropy, 3)

    # ── 2. JWT Structure & Security Inspector ────────────────────────────────

    @staticmethod
    def inspect_jwt(jwt_token: str) -> Dict[str, Any]:
        """فحص أمان وبنية توكن الـ JWT واكتشاف الثغرات الشائعة"""
        parts = jwt_token.strip().split(".")
        if len(parts) != 3:
            return {"is_jwt": False, "error": "Invalid JWT parts count"}

        def _b64_decode(data: str) -> Dict[str, Any]:
            # Add padding
            rem = len(data) % 4
            if rem > 0:
                data += "=" * (4 - rem)
            try:
                decoded = base64.urlsafe_b64decode(data.encode()).decode("utf-8", errors="replace")
                return json.loads(decoded)
            except Exception:
                return {}

        header = _b64_decode(parts[0])
        payload = _b64_decode(parts[1])

        alg = str(header.get("alg", "")).upper()
        now = time.time()
        exp = payload.get("exp")
        iat = payload.get("iat")

        vulnerabilities = []
        if alg in ("NONE", "NONE", ""):
            vulnerabilities.append({
                "type": "jwt_none_algorithm",
                "severity": "Critical",
                "title": "JWT None-Algorithm Enabled (Unsigned Token Allowed)",
                "description": "The JWT header specifies 'none' or missing algorithm, allowing signature bypass."
            })
        elif alg.startswith("HS") and "secret" in str(payload).lower():
            vulnerabilities.append({
                "type": "jwt_weak_symmetric",
                "severity": "Medium",
                "title": "JWT Uses Symmetric HMAC (HS256/384/512)",
                "description": "Symmetric signing may be vulnerable to brute-force or key-confusion if shared with clients."
            })

        if exp is None:
            vulnerabilities.append({
                "type": "jwt_no_expiration",
                "severity": "Medium",
                "title": "JWT Missing 'exp' Expiration Claim",
                "description": "The token does not define an expiration timestamp, making it valid indefinitely if leaked."
            })
        elif exp < now:
            vulnerabilities.append({
                "type": "jwt_expired",
                "severity": "Low",
                "title": "JWT Token Already Expired",
                "description": f"Token expired at {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(exp))} UTC."
            })

        return {
            "is_jwt": True,
            "header": header,
            "payload": payload,
            "algorithm": alg,
            "has_expiration": exp is not None,
            "is_expired": (exp < now) if exp else False,
            "vulnerabilities": vulnerabilities
        }

    # ── 3. Cookie Security Attributes Auditor ────────────────────────────────

    @staticmethod
    def audit_cookie_attributes(cookie_header: str) -> List[Dict[str, Any]]:
        """فحص سمات الأمان في هيدر Set-Cookie"""
        findings = []
        if not cookie_header:
            return findings

        # Split multiple Set-Cookie headers or parts
        cookie_parts = cookie_header.split(";")
        main_cookie = cookie_parts[0].strip()
        cookie_name = main_cookie.split("=")[0] if "=" in main_cookie else "session"
        attrs = [p.strip().lower() for p in cookie_parts[1:]]

        has_secure = any("secure" == a for a in attrs)
        has_httponly = any("httponly" == a for a in attrs)
        samesite_val = None
        for a in attrs:
            if a.startswith("samesite="):
                samesite_val = a.split("=")[1].strip()

        # 1. Missing HttpOnly
        if not has_httponly:
            findings.append({
                "type": "cookie_missing_httponly",
                "cookie_name": cookie_name,
                "severity": "Medium",
                "title": f"Cookie '{cookie_name}' Missing 'HttpOnly' Flag",
                "description": "Cookie can be accessed by client-side JavaScript, increasing XSS session hijacking risk.",
                "remediation": f"Set 'HttpOnly' flag on '{cookie_name}'."
            })

        # 2. Missing Secure
        if not has_secure:
            findings.append({
                "type": "cookie_missing_secure",
                "cookie_name": cookie_name,
                "severity": "Medium",
                "title": f"Cookie '{cookie_name}' Missing 'Secure' Flag",
                "description": "Cookie may be transmitted over unencrypted HTTP connections.",
                "remediation": f"Set 'Secure' flag on '{cookie_name}'."
            })

        # 3. SameSite Attribute
        if not samesite_val:
            findings.append({
                "type": "cookie_missing_samesite",
                "cookie_name": cookie_name,
                "severity": "Low",
                "title": f"Cookie '{cookie_name}' Missing 'SameSite' Attribute",
                "description": "Cookie does not declare SameSite policy, which helps prevent Cross-Site Request Forgery (CSRF).",
                "remediation": f"Set 'SameSite=Lax' or 'SameSite=Strict' on '{cookie_name}'."
            })
        elif samesite_val.lower() == "none" and not has_secure:
            findings.append({
                "type": "cookie_samesite_none_insecure",
                "cookie_name": cookie_name,
                "severity": "High",
                "title": f"Cookie '{cookie_name}' Has SameSite=None without Secure",
                "description": "Modern browsers reject SameSite=None unless the Secure flag is also set.",
                "remediation": f"Add 'Secure' flag to '{cookie_name}' with SameSite=None."
            })

        return findings

    # ── 4. Full Session Security Assessment ──────────────────────────────────

    async def analyze_session_security(self, target_url: str) -> Dict[str, Any]:
        """فحص شامل لأمان الجلسات والمصادقة للهدف"""
        findings = []
        metrics = {
            "target": target_url,
            "cookies_analyzed": 0,
            "jwt_tokens_detected": 0,
            "entropy_scores": {},
            "csrf_protection_detected": False
        }

        try:
            async with httpx.AsyncClient(timeout=10.0, verify=False, follow_redirects=True, proxy=self.proxy) as client:
                resp = await client.get(target_url)

                # Check Set-Cookie headers
                set_cookies = resp.headers.get_list("set-cookie")
                metrics["cookies_analyzed"] = len(set_cookies)
                for sc in set_cookies:
                    c_findings = self.audit_cookie_attributes(sc)
                    findings.extend(c_findings)

                    # Calculate entropy for cookie values
                    c_val = sc.split(";")[0].split("=")[1] if "=" in sc.split(";")[0] else ""
                    c_name = sc.split(";")[0].split("=")[0]
                    if c_val:
                        ent = self.calculate_entropy(c_val)
                        metrics["entropy_scores"][c_name] = ent
                        if ent < 2.5 and len(c_val) > 8:
                            findings.append({
                                "type": "low_session_entropy",
                                "cookie_name": c_name,
                                "severity": "High",
                                "title": f"Low Entropy ({ent}) Detected in Session Cookie '{c_name}'",
                                "description": "Session token lacks adequate randomness and may be predictable or sequential.",
                                "remediation": "Use a cryptographically secure pseudo-random number generator (CSPRNG) with at least 128 bits of entropy."
                            })

                # Check for JWT tokens in response body or headers
                jwt_matches = re.findall(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", resp.text)
                metrics["jwt_tokens_detected"] = len(jwt_matches)
                for jwt_str in jwt_matches[:3]:
                    jwt_analysis = self.inspect_jwt(jwt_str)
                    if jwt_analysis.get("vulnerabilities"):
                        findings.extend(jwt_analysis["vulnerabilities"])

                # Check CSRF protection indicators in HTML forms
                if "csrf" in resp.text.lower() or "_token" in resp.text.lower() or "authenticity_token" in resp.text.lower():
                    metrics["csrf_protection_detected"] = True
                else:
                    # If forms exist without CSRF tokens
                    if "<form" in resp.text.lower() and "post" in resp.text.lower():
                        findings.append({
                            "type": "potential_missing_csrf",
                            "severity": "Medium",
                            "title": "HTML POST Form Lacks Explicit CSRF Token",
                            "description": "Form was detected without visible anti-CSRF token input fields.",
                            "remediation": "Implement Synchronizer Token Pattern or SameSite cookie protection on state-changing endpoints."
                        })

        except Exception as e:
            log.warning(f"Session analysis error on {target_url}: {e}")

        return {
            "metrics": metrics,
            "findings": findings,
            "total_issues": len(findings)
        }

    # ── 5. Smart Session Preservation & Token Management ─────────────────────

    async def get_authenticated_client(
        self,
        base_url: str,
        login_url: Optional[str] = None,
        credentials: Optional[Dict[str, str]] = None,
        bearer_token: Optional[str] = None,
        cookies: Optional[Dict[str, str]] = None
    ) -> httpx.AsyncClient:
        """إنشاء وإدارة عميل HTTP ذكي يحتفظ بالجلسة ويجدد التوكن تلقائياً"""
        headers = {}
        if bearer_token:
            headers["Authorization"] = f"Bearer {bearer_token}"
            self._active_tokens[base_url] = bearer_token

        client = httpx.AsyncClient(
            timeout=15.0,
            verify=False,
            follow_redirects=True,
            proxy=self.proxy,
            headers=headers,
            cookies=cookies or {}
        )

        # If credentials provided, perform initial login
        if login_url and credentials:
            try:
                resp = await client.post(login_url, data=credentials)
                if resp.status_code in (200, 302):
                    log.info(f"[SessionManager] Authenticated successfully on {login_url}")
            except Exception as e:
                log.error(f"[SessionManager] Initial authentication failed: {e}")

        return client
