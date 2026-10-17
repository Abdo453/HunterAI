"""
Unit Tests for CTF Flag Pipeline (flags package) — Phase 2
Tests: extraction patterns, custom format, dedupe, confidence,
       false-positive marking, multi-flag progress, persistence.
"""
import json

import pytest

from flags.extractor import extract_flag_candidates
from flags.models import FlagCandidate, FlagStatus
from flags.service import FlagService
from flags.store import FlagStore


# ── Extraction ────────────────────────────────────────────────────────────

class TestExtraction:
    def test_extracts_generic_flag_patterns(self):
        text = "after bypassing auth I found flag{abc123_secret} in the response"
        cands = extract_flag_candidates(text)
        assert len(cands) == 1
        assert cands[0].value == "flag{abc123_secret}"

    def test_extracts_htb_and_ctf_prefixes(self):
        text = "htb{hash_here} and ctf{another_one} found"
        cands = extract_flag_candidates(text)
        values = {c.value for c in cands}
        assert "htb{hash_here}" in values
        assert "ctf{another_one}" in values

    def test_custom_format_boosts_format_ok(self):
        text = "the flag is flag{deadbeefcafe}"
        cands = extract_flag_candidates(
            text, flag_format=r"flag\{[a-f0-9]{12}\}")
        assert cands
        assert cands[0].format_ok

    def test_context_confidence_boost(self):
        low = extract_flag_candidates("x flag{plain_value} y")[0]
        high = extract_flag_candidates(
            "congratulations! correct flag: flag{plain_value}")[0]
        assert high.confidence > low.confidence

    def test_suspicious_context_penalized(self):
        c = extract_flag_candidates(
            "example format: flag{placeholder_xxx}")[0]
        assert c.confidence < 0.5

    def test_empty_text_no_candidates(self):
        assert extract_flag_candidates("") == []

    def test_dedupe_same_value_in_one_text(self):
        text = "flag{dup} flag{dup} flag{dup}"
        cands = extract_flag_candidates(text)
        assert len(cands) == 1


# ── Store ─────────────────────────────────────────────────────────────────

class TestFlagStore:
    def test_add_duplicate_returns_false(self):
        store = FlagStore()
        c1 = FlagCandidate(value="flag{a}", confidence=0.6)
        c2 = FlagCandidate(value="flag{a}", confidence=0.9)
        assert store.add(c1) is True
        assert store.add(c2) is False
        assert len(store) == 1
        # الثقة تتحد لأعلى قيمة
        assert store.best().confidence == 0.9

    def test_mark_false_positive_zeroes_confidence(self):
        store = FlagStore()
        c = FlagCandidate(value="flag{bad}", confidence=0.9)
        store.add(c)
        assert store.mark_false_positive(c.fingerprint)
        assert store.best(exclude_rejected=True) is None
        assert store.counts()[FlagStatus.REJECTED] == 1

    def test_mark_unknown_status_raises(self):
        store = FlagStore()
        with pytest.raises(ValueError):
            store.mark("nonexistent", "bogus-status")

    def test_persistence_roundtrip(self, tmp_path):
        path = tmp_path / "flags.json"
        store1 = FlagStore(str(path))
        store1.add(FlagCandidate(value="flag{persist}", confidence=0.7))
        store2 = FlagStore(str(path))  # يعيد تحميل من الملف
        assert len(store2) == 1
        assert store2.best().value == "flag{persist}"

    def test_pending_excludes_rejected(self):
        store = FlagStore()
        ok = FlagCandidate(value="flag{ok}", confidence=0.5)
        bad = FlagCandidate(value="flag{bad}", confidence=0.5)
        store.add(ok)
        store.add(bad)
        store.mark_false_positive(bad.fingerprint)
        pending = store.pending()
        assert len(pending) == 1
        assert pending[0].value == "flag{ok}"


# ── Service (multi-flag) ──────────────────────────────────────────────────

class TestFlagService:
    def test_multi_flag_progress_complete(self):
        svc = FlagService(expected_count=2)
        svc.ingest("found flag{one} and flag{two} here")
        # بعد القبول الكامل يتغير complete
        svc.mark_accepted("flag{one}")
        prog1 = svc.progress()
        assert prog1.accepted_count == 1
        assert not prog1.complete
        svc.mark_accepted("flag{two}")
        assert svc.progress().complete

    def test_single_flag_complete_on_high_confidence(self):
        svc = FlagService(expected_count=1)
        # سياق قوي ⇒ ثقة ≥ 0.8 ⇒ complete
        svc.ingest("congratulations correct flag: flag{high_conf_value}")
        assert svc.progress().complete

    def test_false_positive_reopens_solving(self):
        svc = FlagService(expected_count=1)
        svc.ingest("congratulations correct flag: flag{wrong_guess}")
        assert svc.progress().complete
        svc.mark_false_positive("flag{wrong_guess}")
        assert not svc.progress().complete  # الحل يُعاد فتحه

    def test_on_candidate_callback_fires_only_for_new(self):
        seen = []
        svc = FlagService(
            expected_count=1, on_candidate=lambda c: seen.append(c.value))
        svc.ingest("flag{first} here")
        svc.ingest("flag{first} again")  # مكرر — لا callback جديد
        assert seen == ["flag{first}"]

    def test_ingest_returns_only_fresh(self):
        svc = FlagService(expected_count=1)
        fresh1 = svc.ingest("flag{exp_one} appears")
        fresh2 = svc.ingest("flag{exp_one} appears again")
        assert len(fresh1) == 1
        assert len(fresh2) == 0

    def test_summary_shape(self):
        svc = FlagService(expected_count=2)
        svc.ingest("flag{sol_one} flag{sol_two}")
        s = svc.summary()
        assert s["progress"]["expected"] == 2
        assert len(s["candidates"]) == 2
