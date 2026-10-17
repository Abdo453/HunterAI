"""عميل CTFd — أشهر منصة CTF مفتوحة المصدر.

يعتمد على REST API:
- المصادقة: رمز API (Authorization: Token <token>)
- التحديات: GET /api/v1/challenges
- الإرسال:  POST /api/v1/challenges/<id>/attempt
"""
from __future__ import annotations

import time
from typing import Dict, List, Optional

import httpx

from ctf.base import CTFChallenge, CTFPlatform, SubmitResult, SubmitStatus


class CTFdPlatform(CTFPlatform):
    name = "ctfd"

    def __init__(self, base_url: str, token: str, *, timeout_s: float = 30.0):
        super().__init__(base_url, token, timeout_s=timeout_s)
        self._client: Optional[httpx.Client] = None

    def _headers(self) -> Dict[str, str]:
        h = {"User-Agent": "HunterAI-CTF/1.0"}
        if self.token:
            h["Authorization"] = f"Token {self.token}"
        return h

    def _http(self) -> httpx.Client:
        if self._client is None or self._client.is_closed:
            self._client = httpx.Client(
                base_url=self.base_url, headers=self._headers(),
                timeout=self.timeout_s, follow_redirects=True)
        return self._client

    def close(self) -> None:
        if self._client and not self._client.is_closed:
            self._client.close()

    def auth_ok(self) -> bool:
        try:
            r = self._http().get("/api/v1/users/me")
            return r.status_code == 200 and r.json().get("success") is True
        except httpx.HTTPError:
            return False

    def list_challenges(self) -> List[CTFChallenge]:
        out: List[CTFChallenge] = []
        try:
            r = self._http().get(
                "/api/v1/challenges",
                params={"page": 1, "per_page": 100})
            if r.status_code != 200:
                return out
            data = r.json()
            if not data.get("success"):
                return out
            for item in data.get("data") or []:
                out.append(CTFChallenge(
                    id=str(item.get("id")),
                    title=str(item.get("title") or ""),
                    category=str(item.get("category") or ""),
                    value=int(item.get("value") or 0),
                    solved_by_me=bool(item.get("solved")),
                    url=f"{self.base_url}/challenges#{item.get('id')}",
                    raw=item,
                ))
        except (httpx.HTTPError, ValueError):
            pass
        return out

    def submit(self, challenge_id: str, flag: str) -> SubmitResult:
        started = time.time()
        try:
            r = self._http().post(
                f"/api/v1/challenges/{challenge_id}/attempt",
                json={"submission": flag})
            elapsed = time.time() - started
            if r.status_code == 429:
                retry_after = float(r.headers.get("Retry-After") or 30)
                return SubmitResult(
                    status=SubmitStatus.THROTTLED,
                    message=f"429 Too Many Requests — أعد بعد {retry_after:.0f}s",
                    challenge_id=challenge_id, flag=flag,
                    elapsed_s=elapsed, raw={"retry_after": retry_after})
            body = r.json() if r.headers.get(
                "content-type", "").startswith("application/json") else {}
            if r.status_code == 200 and body.get("success"):
                data = body.get("data") or {}
                correct = bool(data.get("correct") or data.get("status") == "correct")
                msg = str(data.get("message") or "")
                if correct:
                    return SubmitResult(
                        status=SubmitStatus.ACCEPTED, message=msg or "صحيح",
                        challenge_id=challenge_id, flag=flag,
                        elapsed_s=elapsed, raw=body)
                return SubmitResult(
                    status=SubmitStatus.WRONG, message=msg or "خطأ",
                    challenge_id=challenge_id, flag=flag,
                    elapsed_s=elapsed, raw=body)
            return SubmitResult(
                status=SubmitStatus.ERROR,
                message=f"HTTP {r.status_code}: {r.text[:200]}",
                challenge_id=challenge_id, flag=flag, elapsed_s=elapsed)
        except httpx.HTTPError as exc:
            return SubmitResult(
                status=SubmitStatus.ERROR, message=str(exc)[:200],
                challenge_id=challenge_id, flag=flag,
                elapsed_s=time.time() - started)
