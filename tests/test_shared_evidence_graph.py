"""
Unit Tests for Shared Evidence Graph — Phase 7
Tests: facts (confidence merge), intents (dedupe work), resource locks,
       insight bus publish/subscribe, snapshot.
"""
import threading

import pytest

from core.shared_evidence import Fact, Intent, SharedEvidenceGraph


# ── Facts ─────────────────────────────────────────────────────────────────

class TestFacts:
    def test_add_and_get(self):
        g = SharedEvidenceGraph()
        assert g.add_fact(Fact(key="port:443", value="https", source="nmap"))
        f = g.get_fact("port:443")
        assert f.value == "https"

    def test_higher_confidence_replaces(self):
        g = SharedEvidenceGraph()
        g.add_fact(Fact(key="k", value="low", confidence=0.4))
        assert g.add_fact(Fact(key="k", value="high", confidence=0.9))
        assert g.get_fact("k").value == "high"

    def test_weaker_confidence_rejected(self):
        g = SharedEvidenceGraph()
        g.add_fact(Fact(key="k", value="strong", confidence=0.9))
        assert not g.add_fact(Fact(key="k", value="weak", confidence=0.3))
        assert g.get_fact("k").value == "strong"

    def test_facts_filter_prefix_and_confidence(self):
        g = SharedEvidenceGraph(min_confidence=0.5)
        g.add_fact(Fact(key="port:80", value="http", confidence=0.9))
        g.add_fact(Fact(key="port:22", value="ssh", confidence=0.3))
        g.add_fact(Fact(key="vuln:sqli", value="login", confidence=0.8))
        ports = g.facts(prefix="port:")
        assert len(ports) == 1  # 0.3 أقل من الحد
        assert ports[0].key == "port:80"
        assert len(g.facts(min_confidence=0.0)) == 3

    def test_has_fact_respects_confidence(self):
        g = SharedEvidenceGraph(min_confidence=0.7)
        g.add_fact(Fact(key="k", value="v", confidence=0.4))
        assert not g.has_fact("k")
        assert g.has_fact("k", min_confidence=0.3)

    def test_on_fact_callback(self):
        seen = []
        g = SharedEvidenceGraph(on_fact=lambda f: seen.append(f.key))
        g.add_fact(Fact(key="a", value="first", confidence=0.5))
        g.add_fact(Fact(key="a", value="stronger", confidence=0.9))
        g.add_fact(Fact(key="a", value="weaker", confidence=0.3))  # مرفوضة
        assert seen == ["a", "a"]  # الكتابة الثالثة أدنى ثقة ⇒ لا استدعاء


# ── Intents ───────────────────────────────────────────────────────────────

class TestIntents:
    def test_begin_and_finish(self):
        g = SharedEvidenceGraph()
        g.begin_intent("i1", "scan web", owner="worker-a")
        assert g.is_intent_active("i1")
        assert g.finish_intent("i1")
        assert not g.is_intent_active("i1")

    def test_active_intents_list(self):
        g = SharedEvidenceGraph()
        g.begin_intent("i1", "a")
        g.begin_intent("i2", "b")
        g.finish_intent("i1")
        active = g.active_intents()
        assert [i.intent_id for i in active] == ["i2"]

    def test_finish_unknown_returns_false(self):
        g = SharedEvidenceGraph()
        assert not g.finish_intent("ghost")


# ── Locks ─────────────────────────────────────────────────────────────────

class TestLocks:
    def test_acquire_and_release(self):
        g = SharedEvidenceGraph()
        assert g.acquire_lock("target:web1", "w1")
        assert g.lock_holder("target:web1") == "w1"
        assert g.release_lock("target:web1", "w1")
        assert g.lock_holder("target:web1") is None

    def test_conflict_blocks_second_owner(self):
        g = SharedEvidenceGraph()
        assert g.acquire_lock("t", "w1")
        assert not g.acquire_lock("t", "w2")
        assert g.acquire_lock("t", "w1")   # نفس المالك يعيد القفل

    def test_release_wrong_owner_fails(self):
        g = SharedEvidenceGraph()
        g.acquire_lock("t", "w1")
        assert not g.release_lock("t", "w2")


# ── Insight Bus ───────────────────────────────────────────────────────────

class TestInsightBus:
    def test_subscribe_receives_publish(self):
        g = SharedEvidenceGraph()
        received = []
        g.subscribe(lambda ev, pl: received.append((ev, pl)))
        g.publish("flag_found", {"value": "flag{x}"})
        assert received == [("flag_found", {"value": "flag{x}"})]

    def test_add_fact_publishes_insight(self):
        g = SharedEvidenceGraph()
        events = []
        g.subscribe(lambda ev, pl: events.append(ev))
        g.add_fact(Fact(key="k", value="v"))
        assert "fact_added" in events

    def test_faulty_subscriber_does_not_break_others(self):
        g = SharedEvidenceGraph()
        good = []
        g.subscribe(lambda ev, pl: 1 / 0)   # مشترك معطّل
        g.subscribe(lambda ev, pl: good.append(ev))
        g.publish("e", {})
        assert good == ["e"]


# ── Snapshot & concurrency ────────────────────────────────────────────────

class TestSnapshotConcurrency:
    def test_snapshot_shape(self):
        g = SharedEvidenceGraph()
        g.add_fact(Fact(key="port:80", value="http"))
        g.add_fact(Fact(key="vuln:sqli", value="x"))
        g.acquire_lock("t", "w1")
        snap = g.snapshot()
        assert snap["facts_count"] == 2
        assert snap["locks"] == {"t": "w1"}
        assert snap["facts_by_prefix"]["port"] == 1

    def test_concurrent_fact_adds_no_crash(self):
        g = SharedEvidenceGraph()
        def _add(n):
            for i in range(50):
                g.add_fact(Fact(key=f"k{n}-{i}", value="v"))
        threads = [threading.Thread(target=_add, args=(n,)) for n in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(g.facts(min_confidence=0.0)) == 8 * 50

    def test_concurrent_lock_single_winner(self):
        g = SharedEvidenceGraph()
        results = []
        def _try(owner):
            results.append(g.acquire_lock("hot", owner))
        threads = [threading.Thread(target=_try, args=(f"w{i}",))
                   for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert results.count(True) == 1   # واحد فقط يفوز بالقفل
