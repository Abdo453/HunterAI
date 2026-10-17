"""عميل rCTF — منصة CTF مفتوحة المصدر (GraphQL-ish REST).

rCTF يستخدم:
- المصادقة: رمز دعوة/جلسة في Authorization
- التحديات: GET /api/v1/challs
- الإرسال:  POST /api/v1/challs/<id>/submit
"""
from __future__ import annotations

import time
from typing import Dict, List, Optional

import httpx

from ctf.base import CTFChallenge, CTFPlatform, SubmitResult, SubmitStatus


class RCTFPlatform(CTFPlatform):
    name = "rctf"

    def __init__(self, base_url: str, token: str, *, timeout_s: float = 30.0):
        super().__init__(base_url, token, timeout_s=timeout_s)
        self._client: Optional[httpx.Client] = None

    def _headers(self) -> Dict[str, str]:
        h = {"User-Agent": "HunterAI-CTF/1.0"}
        if self.token:
            h["Authorization"] = f"Bearer {self.token}"
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
            r = self._http().get("/api/v1/auth/me")
            return r.status_code == 200
        except httpx.HTTPError:
            return False

    def list_challenges(self) -> List[CTFChallenge]:
        out: List[CTFChallenge] = []
        try:
            r = self._http().get("/api/v1/challs")
            if r.status_code != 200:
                return out
            body = r.json()
            for item in body.get("data") or []:
                out.append(CTFChallenge(
                    id=str(item.get("id")),
                    title=str(item.get("name") or item.get("title") or ""),
                    category=str(item.get("category") or ""),
                    description=str(item.get("description") or ""),
                    value=int(item.get("points") or 0),
                    solved_by_me=bool(item.get("solves", 0) and item.get("solved")),
                    url=f"{self.base_url}/challs#{item.get('id')}",
                    raw=item,
                ))
        except (httpx.HTTPError, ValueError):
            pass
        return out

    def submit(self, challenge_id: str, flag: str) -> SubmitResult:
        started = time.time()
        try:
            r = self._http().post(
                f"/api/v1/challs/{challenge_id}/submit", json={"flag": flag})
            elapsed = time.time() - started
            if r.status_code == 429:
                retry_after = float(r.headers.get("Retry-After") or 30)
                return SubmitResult(
                    status=SubmitStatus.THROTTLED,
                    message=f"429 — أعد بعد {retry_after:.0f}s",
                    challenge_id=challenge_id, flag=flag,
                    elapsed_s=elapsed, raw={"retry_after": retry_after})
            body = r.json() if r.headers.get(
                "content-type", "").startswith("application/json") else {}
            if r.status_code == 200:
                kind = str(body.get("kind") or "")
                if kind in ("correct", "duplicate"):
                    return SubmitResult(
                        status=(SubmitStatus.ACCEPTED if kind == "correct"
                                else SubmitStatus.DUPLICATE),
                        message=kind, challenge_id=challenge_id, flag=flag,
                        elapsed_s=elapsed, raw=body)
                if kind in ("incorrect", "wrong"):
                    return SubmitResult(
                        status=SubmitStatus.WRONG,
                        message=str(body.get("message") or "خطأ"),
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
