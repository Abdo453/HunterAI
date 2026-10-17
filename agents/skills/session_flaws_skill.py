"""
Session Flaws Skill (CWE-613 — Insufficient Session Expiration / Session Management)
==================================================================================
"""
from __future__ import annotations

import logging
import re
import time
from typing import Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import httpx

from agents.skills.base_skill import BaseSkill, SkillResult

log = logging.getLogger("hunter_ai.skills.session_flaws")


class SessionFlawsSkill(BaseSkill):
    name = "session_flaws_skill"
    vuln_type = "session_flaws"
    cwe = "CWE-613"
    owasp_top10 = "A07:2021 — Identification and Authentication Failures"
    default_severity = "Medium"

    # أسماء الكوكيات المرشحة لكونها رموز جلسات
    SESSION_COOKIE_HINTS = (
        "session", "sess", "sessionid", "jsessionid", "phpsessid",
        "asp.net_sessionid", "cfid", "cftoken", "auth", "token", "jwt",
        "connect.sid", "session_token", "access_token",
    )

    def __init__(self, proxy: Optional[str] = None, timeout: float = 12.0):
        super().__init__(proxy=proxy, timeout=timeout)

    async def run(self, target_url: str, param_name: str = "", **kwargs) -> SkillResult:
        logs: list[str] = [f"[SessionFlaws] Auditing session management on {target_url}"]
        findings_evidence: list[str] = []
        severity = self.default_severity

        parsed = urlparse(target_url)
        if not parsed.hostname:
            return SkillResult(verified=False, vuln_type=self.vuln_type,
                               endpoint=target_url, param_name=param_name,
                               evidence="Invalid target URL", tool=self.name)

        transport = None
        if self.proxy:
            try:
                transport = httpx.AsyncHTTPTransport(proxy=self.proxy, verify=False)
            except Exception:
                pass

        async with httpx.AsyncClient(transport=transport, timeout=self.timeout,
                                     follow_redirects=False, verify=False) as client:

            # ── فحص 1: الرمز في عنوان URL (Session Exposure in URL) ───────
            qs = parse_qs(parsed.query)
            session_params = [k for k in qs if any(h in k.lower() for h in self.SESSION_COOKIE_HINTS)]
            if session_params:
                url_without_token = urlunparse(parsed._replace(query=urlencode(
                    {k: v for k, v in qs.items() if k not in session_params}, doseq=True)))
                try:
                    r_token = await client.get(target_url)
                    r_clean = await client.get(url_without_token)
                    # إثبات: نفس المحتوى يُعاد مع وبدون الرمز → الرمز غير ضروري / مُسرب في العنوان
                    if r_token.status_code == r_clean.status_code and abs(len(r_token.content) - len(r_clean.content)) < 64:
                        findings_evidence.append(
                            f"Session token passed in URL ({', '.join(session_params)}) — "
                            f"same response (status {r_token.status_code}) with and without token."
                        )
                        severity = "High"
                        logs.append(f"[SessionFlaws] session token in URL: {session_params}")
                except Exception as exc:
                    logs.append(f"[SessionFlaws] URL-token check error: {exc}")

            # ── فحص 2: حماية 쿠كيات الجلسة من رؤوس Set-Cookie الفعلية ───
            try:
                resp = await client.get(target_url)
                set_cookie_headers = resp.headers.get_list("set-cookie")
            except Exception:
                set_cookie_headers = []

            session_cookies = []
            for header in set_cookie_headers:
                name = header.split("=", 1)[0].strip().lower() if "=" in header else ""
                if any(h in name for h in self.SESSION_COOKIE_HINTS) or "session" in header.lower():
                    session_cookies.append(header)

            insecure_flags = []
            for cookie in session_cookies:
                cl = cookie.lower()
                if "secure" not in cl:
                    insecure_flags.append("missing Secure")
                if "httponly" not in cl:
                    insecure_flags.append("missing HttpOnly")
                samesite = re.search(r"samesite=(\w+)", cl)
                if not samesite or samesite.group(1).lower() in ("none", ""):
                    insecure_flags.append("missing/weak SameSite")

            if session_cookies and insecure_flags:
                findings_evidence.append(
                    f"{len(session_cookies)} session cookie(s) with weak flags: "
                    f"{', '.join(dict.fromkeys(insecure_flags))}."
                )
                logs.append(f"[SessionFlaws] {len(session_cookies)} session cookies; weak flags: {insecure_flags}")

            # ── فحص 3: انتهاء الجلسة (Max-Age / Expires) ────────────────
            no_expiry = 0
            for cookie in session_cookies:
                cl = cookie.lower()
                if "max-age" not in cl and "expires" not in cl:
                    no_expiry += 1
            if session_cookies and no_expiry == len(session_cookies) and len(session_cookies) > 0:
                findings_evidence.append(
                    f"All {len(session_cookies)} session cookie(s) lack Max-Age/Expires "
                    f"(session expires only on browser close — extended exposure window)."
                )
                logs.append(f"[SessionFlaws] {no_expiry}/{len(session_cookies)} cookies without expiration")

        verified = bool(findings_evidence)
        evidence = " | ".join(findings_evidence) or "No session management flaws detected (cookie flags and expiry present, no token-in-URL)."

        return SkillResult(
            verified=verified,
            vuln_type=self.vuln_type,
            title=f"Session Management Flaws on {urlparse(target_url).netloc or target_url}",
            severity=severity if verified else self.default_severity,
            endpoint=target_url,
            param_name=param_name,
            evidence=evidence,
            payload_used="",
            remediation=(
                "إيقاف تمرير رموز الجلسات في عناوين URL؛ فرض Secure+HttpOnly+SameSite=Strict/Lax على "
                "كوكيات الجلسات؛ تحديد مهلة انتهاء صلاحية الجلسة (Max-Age/Expires) وإلغاء الرمز عند تسجيل الخروج."
            ),
            confidence=0.78 if verified else 0.0,
            tool=self.name,
            evidence_sources=["SessionFlawsSkill/HTTPHeaders"],
            cwe=self.cwe,
            owasp_top10=self.owasp_top10,
            logs=logs,
        )

    def can_handle(self, param_name: str, url: str = "", sample_value: str = "") -> float:
        p = (param_name or "").lower()
        if any(h in p for h in self.SESSION_COOKIE_HINTS):
            return 0.85
        return 0.3
