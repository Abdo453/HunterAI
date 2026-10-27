"""Deterministic vulnerability-class extraction (evidence for selection)."""
from __future__ import annotations

from core.vuln_intel.vuln_classes import classify_vuln_classes


def test_cwe_is_the_primary_evidence(make_record):
    record = make_record(cwes=["CWE-89"])
    analysis = classify_vuln_classes(record)
    assert analysis.classes == ["sqli"]
    assert analysis.cwe_classes == ["sqli"]
    assert analysis.text_classes == []
    assert analysis.evidence == ["CWE-89 -> sqli"]


def test_multiple_cwes_produce_multiple_classes(make_record):
    record = make_record(cwes=["CWE-89", "CWE-79", "CWE-918"])
    analysis = classify_vuln_classes(record)
    assert analysis.classes == ["sqli", "ssrf", "xss"]
    assert len(analysis.evidence) == 3


def test_unknown_cwe_is_ignored_without_guessing(make_record):
    record = make_record(cwes=["CWE-999999"])
    analysis = classify_vuln_classes(record)
    assert analysis.classes == []
    assert analysis.evidence == []


def test_explicit_advisory_phrase_is_supporting_evidence(make_record):
    record = make_record(cwes=[], description="A SQL injection flaw in the parser.")
    analysis = classify_vuln_classes(record)
    assert analysis.classes == ["sqli"]
    assert analysis.cwe_classes == []
    assert analysis.text_classes == ["sqli"]
    assert "advisory phrase 'sql injection' -> sqli" in analysis.evidence


def test_a_bare_generic_word_never_creates_a_class(make_record):
    record = make_record(cwes=[], description="The sql table and the php runtime are fine.")
    analysis = classify_vuln_classes(record)
    assert analysis.classes == []


def test_xss_acronym_is_recognized(make_record):
    record = make_record(cwes=[], summary="Stored XSS in the dashboard")
    analysis = classify_vuln_classes(record)
    assert analysis.classes == ["xss"]


def test_text_evidence_can_be_disabled(make_record):
    record = make_record(cwes=[], description="A SQL injection flaw in the parser.")
    analysis = classify_vuln_classes(record, use_text=False)
    assert analysis.classes == []


def test_cwe_evidence_wins_and_text_is_not_duplicated(make_record):
    record = make_record(cwes=["CWE-89"], description="SQL injection in the query builder")
    analysis = classify_vuln_classes(record)
    assert analysis.classes == ["sqli"]
    assert analysis.cwe_classes == ["sqli"]
    assert analysis.text_classes == []


def test_record_without_any_text_has_no_classes(make_record):
    record = make_record(cwes=[], description=None, summary=None, title=None)
    analysis = classify_vuln_classes(record)
    assert analysis.classes == []


def test_authorization_cwes_map_to_authorization_flaw(make_record):
    record = make_record(cwes=["CWE-285"])
    analysis = classify_vuln_classes(record)
    assert analysis.classes == ["authorization_flaw"]
    assert analysis.evidence == ["CWE-285 -> authorization_flaw"]

    record = make_record(cwes=["CWE-862"])
    assert classify_vuln_classes(record).classes == ["missing_authorization"]
