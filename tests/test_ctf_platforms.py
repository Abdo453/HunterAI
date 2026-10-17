"""
Unit Tests for CTF Platform Integrations — Phase 4
Tests: throttler math, platform factory, submit normalization (mocked HTTP).
"""
import time

import pytest

from ctf.base import CTFChallenge, SubmitResult, SubmitStatus
from ctf.ctfd import CTFdPlatform
from ctf.gzctf import GZCTFPlatform
from ctf.rctf import RCTFPlatform
from ctf.throttler import SubmitThrottler


# ── Throttler ─────────────────────────────────────────────────────────────

class TestThrottler:
    def test_first_permit_immediate(self):
        t = SubmitThrottler(min_interval_s=5.0)
        assert t.seconds_until_permit() == 0.0
        assert t.permit() is True

    def test_min_interval_enforced(self):
        t = SubmitThrottler(min_interval_s=0.3)
        t.record()
        wait = t.seconds_until_permit()
        assert 0 < wait <= 0.3

    def test_window_limit(self):
        t = SubmitThrottler(min_interval_s=0.0, max_per_window=3, window_s=60.0)
        for _ in range(3):
            t.record()
        assert t.seconds_until_permit() > 0

    def test_penalize_retry_after(self):
        t = SubmitThrottler(min_interval_s=0.0)
        t.penalize(0.2)
        assert t.seconds_until_permit() > 0

    def test_permit_timeout(self):
        t = SubmitThrottler(min_interval_s=5.0)
        t.record()
        assert t.permit(timeout_s=0.1) is False


# ── Platform factory (كل المنصات تشترك النموذج) ─────────────────────────

class TestPlatforms:
    def test_all_platforms_share_interface(self):
        for cls in (CTFdPlatform, RCTFPlatform, GZCTFPlatform):
            p = cls("https://ctf.example", "token-abc")
            assert hasattr(p, "auth_ok")
            assert hasattr(p, "list_challenges")
            assert hasattr(p, "submit")
            p.close()

    def test_base_url_normalized(self):
        p = CTFdPlatform("https://ctf.example/", "tok")
        assert p.base_url == "https://ctf.example"

    def test_submit_result_accepted_property(self):
        r = SubmitResult(status=SubmitStatus.ACCEPTED)
        assert r.accepted
        r2 = SubmitResult(status=SubmitStatus.WRONG)
        assert not r2.accepted
        r3 = SubmitResult(status=SubmitStatus.DUPLICATE)
        assert r3.accepted  # duplicate = مقبول سابقًا ⇒ إيجابي

    def test_challenge_dataclass_defaults(self):
        c = CTFChallenge(id="1", title="Web 100")
        assert c.solved_by_me is False
        assert c.category == ""


# ── CTFd submit مع HTTP مُزيَّف ───────────────────────────────────────────

class _FakeResponse:
    def __init__(self, status_code=200, json_body=None, headers=None, text=""):
        self.status_code = status_code
        self._json = json_body or {}
        self.headers = headers or {"content-type": "application/json"}
        self.text = text or ""

    def json(self):
        return self._json


class _FakeClient:
    def __init__(self, response):
        self._response = response
        self.is_closed = False
        self.last_url = ""
        self.last_json = None

    def get(self, url, **kw):
        self.last_url = url
        return self._response

    def post(self, url, json=None, **kw):
        self.last_url = url
        self.last_json = json
        return self._response

    def close(self):
        self.is_closed = True


class TestCTFdSubmitMocked:
    def _patch(self, platform, response):
        platform._client = _FakeClient(response)

    def test_submit_accepted(self):
        p = CTFdPlatform("https://x.example", "tok")
        self._patch(p, _FakeResponse(200, {
            "success": True, "data": {"correct": True, "message": "ok"}}))
        r = p.submit("5", "flag{test}")
        assert r.accepted
        assert r.challenge_id == "5"

    def test_submit_wrong(self):
        p = CTFdPlatform("https://x.example", "tok")
        self._patch(p, _FakeResponse(200, {
            "success": True, "data": {"correct": False, "message": "nope"}}))
        r = p.submit("5", "flag{wrong}")
        assert r.status == SubmitStatus.WRONG

    def test_submit_throttled_429(self):
        p = CTFdPlatform("https://x.example", "tok")
        self._patch(p, _FakeResponse(429, headers={
            "Retry-After": "45", "content-type": "application/json"}))
        r = p.submit("5", "flag{x}")
        assert r.status == SubmitStatus.THROTTLED
        assert r.raw["retry_after"] == 45.0

    def test_list_challenges_normalizes(self):
        p = CTFdPlatform("https://x.example", "tok")
        self._patch(p, _FakeResponse(200, {
            "success": True,
            "data": [{"id": 1, "title": "SQLi 100", "category": "web",
                      "value": 100, "solved": False}]}))
        chs = p.list_challenges()
        assert len(chs) == 1
        assert chs[0].title == "SQLi 100"
        assert chs[0].value == 100

    def test_auth_ok_false_on_error(self):
        p = CTFdPlatform("https://x.example", "bad-token")

        class _ErrClient:
            is_closed = False
            def get(self, *a, **k):
                import httpx
                raise httpx.ConnectError("nope")
        p._client = _ErrClient()
        assert p.auth_ok() is False
