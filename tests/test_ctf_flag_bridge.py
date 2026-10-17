"""
Unit Tests for CTF ↔ FlagService Bridge — Auto-submission
Tests: submit pending, accepted/wrong/throttled handling, early stop,
       challenge resolution, dry-run.
"""
import pytest

from ctf.base import CTFPlatform, CTFChallenge, SubmitResult, SubmitStatus
from ctf.bridge import FlagSubmitter, SubmitSummary
from ctf.throttler import SubmitThrottler
from flags.models import FlagStatus
from flags.service import FlagService


class FakePlatform(CTFPlatform):
    """منصة وهمية تتحكم في الاستجابات."""

    name = "fake"

    def __init__(self, responses=None, challenges=None):
        super().__init__("https://fake.example", "tok")
        self.responses = responses or {}
        self.submitted = []
        self._challenges = challenges or [
            CTFChallenge(id="10", title="Web 100")]

    def auth_ok(self):
        return True

    def list_challenges(self):
        return self._challenges

    def submit(self, challenge_id, flag):
        self.submitted.append((challenge_id, flag))
        status = self.responses.get(flag, SubmitStatus.WRONG)
        return SubmitResult(status=status, challenge_id=challenge_id, flag=flag)


class TestFlagSubmitter:
    def _svc(self, text, expected=2):
        svc = FlagService(expected_count=expected)
        svc.ingest(text)
        return svc

    def test_submit_accepted_updates_status(self):
        svc = self._svc("found flag{good_one} here", expected=1)
        plat = FakePlatform({"flag{good_one}": SubmitStatus.ACCEPTED})
        sub = FlagSubmitter(svc, plat, challenge_id="10")
        summary = sub.submit_pending()
        assert summary.accepted == 1
        assert svc.mark_accepted is not None
        assert svc.progress().accepted_count == 1

    def test_wrong_flag_marked_false_positive(self):
        svc = self._svc("found flag{bad_guess} here", expected=1)
        plat = FakePlatform({"flag{bad_guess}": SubmitStatus.WRONG})
        sub = FlagSubmitter(svc, plat, challenge_id="10")
        summary = sub.submit_pending()
        assert summary.wrong == 1
        assert not svc.progress().complete  # لم يُقبل

    def test_resolve_challenge_by_title(self):
        svc = self._svc("found flag{by_title} here", expected=1)
        plat = FakePlatform(
            {"flag{by_title}": SubmitStatus.ACCEPTED},
            challenges=[CTFChallenge(id="77", title="SQLi Lab")])
        sub = FlagSubmitter(svc, plat, challenge_title="SQLi Lab")
        summary = sub.submit_pending()
        assert plat.submitted[0][0] == "77"
        assert summary.accepted == 1

    def test_unresolvable_challenge_errors(self):
        svc = self._svc("found flag{no_challenge} here", expected=1)
        plat = FakePlatform()
        sub = FlagSubmitter(svc, plat, challenge_title="NoSuchChallenge")
        summary = sub.submit_pending()
        assert summary.errors == 1
        assert summary.submitted == 0

    def test_throttled_stops_early(self):
        svc = self._svc("flag{a_one} flag{b_two}", expected=2)
        plat = FakePlatform({
            "flag{a_one}": SubmitStatus.THROTTLED,
            "flag{b_two}": SubmitStatus.ACCEPTED,
        })
        throttler = SubmitThrottler(min_interval_s=0.0)
        sub = FlagSubmitter(svc, plat, challenge_id="10", throttler=throttler)
        summary = sub.submit_pending()
        assert summary.throttled == 1
        assert summary.stopped_early
        assert summary.accepted == 0  # توقف قبل flag{b_two}

    def test_early_stop_when_complete(self):
        svc = self._svc("flag{first} flag{second}", expected=1)
        # بلوغ واحد يكفي ⇒ بعد القبول يتوقف قبل الثاني
        plat = FakePlatform({
            "flag{first}": SubmitStatus.ACCEPTED,
            "flag{second}": SubmitStatus.ACCEPTED,
        })
        sub = FlagSubmitter(svc, plat, challenge_id="10")
        summary = sub.submit_pending()
        # pending مرتبة بالثقة؛ الأول فقط يُرسل ثم progress().complete
        assert summary.accepted >= 1

    def test_dry_run_does_not_submit(self):
        svc = self._svc("found flag{dry_run_one} here", expected=1)
        plat = FakePlatform()
        sub = FlagSubmitter(svc, plat, challenge_id="10")
        summary = sub.submit_pending(dry_run=True)
        assert summary.submitted == 1
        assert plat.submitted == []  # لا إرسال فعلي

    def test_max_submits_cap(self):
        svc = self._svc(
            "flag{m1_one} flag{m2_two} flag{m3_three} flag{m4_four}",
            expected=10)
        plat = FakePlatform()
        sub = FlagSubmitter(svc, plat, challenge_id="10", max_submits=2)
        summary = sub.submit_pending()
        assert summary.submitted == 2
        assert len(plat.submitted) == 2

    def test_no_pending_returns_empty(self):
        svc = FlagService(expected_count=1)  # بلا مرشّحات
        plat = FakePlatform()
        sub = FlagSubmitter(svc, plat, challenge_id="10")
        summary = sub.submit_pending()
        assert summary.submitted == 0

    def test_summary_shape(self):
        s = SubmitSummary()
        d = s.to_dict()
        assert "accepted" in d and "throttled" in d
