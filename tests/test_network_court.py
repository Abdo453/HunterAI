"""Tests لـ Network Court Adjudicator و Network Report Generator (Phase 5)."""
import json
import os

from core.network_model import NetworkFinding
from core.reporting.network_court_adjudicator import (
    CourtAdjudicationResult,
    NegativeSpaceEntry,
    NetworkCourtAdjudicator,
    NetworkCourtReport,
)
from core.reporting.network_report_generator import NetworkReportGenerator


def _finding(
    title: str = "Test Redis Exposure",
    host: str = "10.0.0.5",
    port: int = 6379,
    vuln_class: str = "UNAUTHENTICATED_SERVICE",
    severity: str = "HIGH",
    status: str = "candidate",
) -> NetworkFinding:
    return NetworkFinding(
        title=title,
        host=host,
        port=port,
        protocol="tcp",
        service_name="redis",
        vuln_class=vuln_class,
        severity=severity,
        confidence=0.5,
        evidence_level="E0",
        status=status,
        description="test description",
        reproduction_command="redis-cli -h 10.0.0.5 -p 6379 INFO",
        remediation="bind to loopback",
        cwe="CWE-306",
        evidence_ids=["svc_abc123"],
    )


def test_court_adjudicator_keeps_candidates_unconfirmed():
    """الاكتشاف الشبكي الخام لا يُؤكد تلقائيًا — يبقى UNVERIFIED/INCONCLUSIVE وغير قابل للإبلاغ."""
    court = NetworkCourtAdjudicator(is_in_scope=True)
    report = court.adjudicate([_finding()], target="10.0.0.5")
    assert report.total_findings == 1
    assert report.confirmed_findings == 0
    assert report.unconfirmed_findings == 1
    assert report.false_positives == 0
    u = report.unconfirmed[0]
    assert u.verdict in ("UNVERIFIED", "INCONCLUSIVE")
    assert u.reportable is False
    assert u.proof_strength == "NONE"


def test_out_of_scope_target_rejected():
    """الهدف خارج النطاق يُحجب ولا يُدرج في الاكتشافات المؤكدة."""
    court = NetworkCourtAdjudicator(is_in_scope=False)
    report = court.adjudicate([_finding()], target="evil.example.net")
    assert report.confirmed_findings == 0
    assert report.unconfirmed_findings == 1


def test_negative_space_entry_model():
    entry = NegativeSpaceEntry(
        host="169.254.169.254",
        port=80,
        protocol="tcp",
        reason="SKIPPED_SCOPE",
        detail="Metadata cloud endpoint blocked by inviolable invariant.",
    )
    d = entry.to_dict()
    assert d["host"] == "169.254.169.254"
    assert d["port"] == 80
    assert d["reason"] == "SKIPPED_SCOPE"


def test_network_court_report_serialization():
    report = NetworkCourtReport(target="10.0.0.5", total_findings=2)
    assert report.confirmation_rate == 0.0
    d = report.to_dict()
    assert d["target"] == "10.0.0.5"
    assert d["total_findings"] == 2
    assert d["confirmation_rate"] == 0.0


def test_report_generator_produces_files():
    court = NetworkCourtAdjudicator(is_in_scope=True)
    report = court.adjudicate([_finding()], target="10.0.0.5")
    ns = NegativeSpaceEntry(
        host="evil.example.net", port=None, protocol="tcp",
        reason="OUT_OF_SCOPE", detail="هدف خارج نطاق التفويض",
    )
    court.add_negative_space(report, [ns])

    gen = NetworkReportGenerator(output_dir="data/reports")
    result = gen.generate(report, "10.0.0.5", formats=["json", "markdown"])

    assert "json" in result["formats"]
    assert "markdown" in result["formats"]
    assert "signature" in result["formats"]
    sig = result["formats"]["signature"]
    assert sig["algorithm"] == "HMAC-SHA256"
    assert len(sig["digest"]) == 64  # SHA-256 hex

    # التحقق من وجود الملفات
    for fmt in ("json", "markdown"):
        assert os.path.exists(result["formats"][fmt]), f"{fmt} file missing"

    # فحص محتوى JSON
    with open(result["formats"]["json"], encoding="utf-8") as fh:
        payload = json.load(fh)
    assert payload["target"] == "10.0.0.5"
    assert payload["total_findings"] == 1
    assert payload["confirmed_findings"] == 0
    assert payload["negative_space_entries"] == 1

    # فحص محتوى Markdown
    with open(result["formats"]["markdown"], encoding="utf-8") as fh:
        md = fh.read()
    assert "10.0.0.5" in md
    assert "مساحة سلبية" in md or "Negative Space" in md

    print("[PASS] Network Report Generator produces JSON + Markdown + signature")


def test_court_adjudication_result_dict():
    r = CourtAdjudicationResult(
        finding_id="f1",
        title="Test",
        host="10.0.0.5",
        port=6379,
        protocol="tcp",
        vuln_class="UNAUTHENTICATED_SERVICE",
        severity="HIGH",
        verdict="INCONCLUSIVE",
        reportable=False,
        proof_strength="NONE",
        epistemic_state="TESTED",
        confidence=0.5,
        rationale="No independent verifier",
        court_judgment_id="judg_abc",
        evidence_ids=["svc_1"],
    )
    d = r.to_dict()
    assert d["verdict"] == "INCONCLUSIVE"
    assert d["reportable"] is False
    assert d["evidence_ids"] == ["svc_1"]
