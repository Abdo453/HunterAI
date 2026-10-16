"""Tests لـ OSINT Identity Subsystem — Phase 1"""
import sys
import os
import asyncio
from unittest.mock import MagicMock, AsyncMock

# إضافة الجذر للمسار
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.osint.schemas import IdentityEvidenceRecord, IdentityCluster, ConfidenceLabel
from core.osint.platform_registry import is_generic_username, canonicalize_platform
from core.osint.evidence_normalizer import EvidenceNormalizer
from core.osint.fp_guards import FPGuards
from core.osint.confidence_model import ConfidenceModel
from core.osint.identity_correlation import IdentityCorrelationEngine


def make_record(platform, url, tool, query="testuser", vector="username", level="E0"):
    return IdentityEvidenceRecord(
        record_id="",
        vector=vector,
        platform=platform,
        query_value=query,
        match_url=url,
        detection_method="web_status",
        raw_response_digest="abc123",
        tool_name=tool,
        evidence_level=level,
    )


def test_platform_registry():
    assert is_generic_username("admin") is True
    assert is_generic_username("abdo123") is False
    assert canonicalize_platform("GITHUB") == "github"
    assert canonicalize_platform("com.github") == "github"
    assert canonicalize_platform("unknownsite") == "unknownsite"
    print("[PASS] platform_registry tests passed")


def test_normalizer_dedupe_and_corroboration():
    norm = EvidenceNormalizer()

    # أداة واحدة تُسجل GitHub مرتين (نفس URL) → dedupe
    r1 = norm.normalize("sherlock", "username", "abdo123",
                        "[+] GitHub: https://github.com/abdo123")
    r2 = norm.normalize("sherlock", "username", "abdo123",
                        "[+] GitHub: https://github.com/abdo123")
    assert len(r1) == 1
    assert len(r2) == 0  # مكرر تمامًا

    # أداة ثانية تُسجل نفس GitHub → corroboration → E1
    r3 = norm.normalize("maigret", "username", "abdo123",
                        "[+] GitHub (100%): https://github.com/abdo123")
    all_recs = norm.flush()
    github_recs = [r for r in all_recs if r.platform == "github"]
    assert len(github_recs) == 1
    assert github_recs[0].evidence_level == "E1", f"Expected E1, got {github_recs[0].evidence_level}"
    assert "maigret" in github_recs[0].corroborating_tools
    assert "sherlock" in github_recs[0].corroborating_tools
    print("[PASS] normalizer dedupe + corroboration tests passed")


def test_fp_guards():
    guards = FPGuards()

    # G1: generic username يُرفض
    res = guards.check_generic_username("admin")
    assert res.passed is False
    assert res.penalty == 0.30

    # G1: اسم عادي يُقبل
    res = guards.check_generic_username("abdo453")
    assert res.passed is True

    # G2: soft404 يُرفض
    res = guards.check_soft404("Page not found", "https://github.com/x")
    assert res.passed is False
    assert res.penalty == 0.50

    # G2: صفحة عادية تُقبل
    res = guards.check_soft404("<html>Welcome</html>", "https://github.com/x")
    assert res.passed is True

    # G4: redirect collapse يُرفض
    res = guards.check_redirect_to_homepage("https://github.com", "https://github.com/abdo123")
    assert res.passed is False

    # G6: non-identity domain يُرفض
    res = guards.check_non_identity_domain("https://google.com/search?q=x")
    assert res.passed is False

    print("[PASS] fp_guards tests passed")


def test_confidence_model():
    model = ConfidenceModel()

    # weak: إشارات قليلة
    cluster = IdentityCluster(
        cluster_id="c1",
        anchor="abdo123",
        members=[
            make_record("github", "https://github.com/abdo123", "sherlock"),
        ],
        correlation_signals={"username_exact_match": 0.15},
    )
    calc = model.calculate(cluster)
    assert calc.label == "weak"

    # probable: إشارات قوية
    cluster2 = IdentityCluster(
        cluster_id="c2",
        anchor="abdo123",
        members=[
            make_record("github", "https://github.com/abdo123", "sherlock"),
            make_record("twitter", "https://twitter.com/abdo123", "maigret"),
        ],
        correlation_signals={
            "username_exact_match": 0.15,
            "bio_cross_links": 0.25,
            "avatar_similarity": 0.20,
            "linked_website": 0.20,
        },
    )
    calc2 = model.calculate(cluster2)
    assert calc2.label in ("probable", "strong"), f"Expected probable/strong, got {calc2.label}"

    # FP penalty يخفض الدرجة
    calc3 = model.calculate(cluster2, fp_penalties={"generic_username": -0.30, "soft404": -0.50})
    assert calc3.label == "weak", f"Expected weak after penalties, got {calc3.label}"

    print("[PASS] confidence_model tests passed")


def test_correlation_engine():
    engine = IdentityCorrelationEngine()

    records = [
        make_record("github", "https://github.com/abdo123", "sherlock"),
        make_record("twitter", "https://twitter.com/abdo123", "maigret"),
        make_record("reddit", "https://reddit.com/user/abdo123", "blackbird"),
    ]

    clusters = engine.correlate(records, anchor="abdo123")
    assert len(clusters) == 1
    cl = clusters[0]
    assert len(cl.members) == 3
    assert cl.confidence_label != "weak"  # 3 منصات + exact match

    # multi-anchor
    records2 = [
        make_record("github", "https://github.com/abdo123", "sherlock", query="abdo123", vector="username"),
        make_record("google", "https://accounts.google.com", "ghunt", query="abdo@example.com", vector="email"),
    ]
    clusters2 = engine.correlate_multi_anchor(records2)
    assert len(clusters2) == 2  # كل anchor يُعطى كلاستر منفصل
    print("[PASS] correlation_engine tests passed")


def test_agent_imports():
    # التأكد من أن الوكيل يُستورد بدون أخطاء (حتى لو الأدوات غير مثبتة)
    from agents.osint_identity_agent import OSINTIdentityAgent
    print("[PASS] agent import test passed")


if __name__ == "__main__":
    test_platform_registry()
    test_normalizer_dedupe_and_corroboration()
    test_fp_guards()
    test_confidence_model()
    test_correlation_engine()
    test_agent_imports()
    print("\n[INFO] جميع اختبارات Phase 1 نجحت!")
