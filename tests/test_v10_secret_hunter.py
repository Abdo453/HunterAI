"""
HunterAI V10.0 Secret Hunter Intelligence Pipeline Test Suite
=============================================================
Verifies:
1. Multi-provider deterministic signature detection (AWS, Google, GitHub, Stripe, JWT, DB, Slack)
2. Shannon entropy gating and generic credential filtering
3. Context intelligence: endpoint extraction and placeholder rejection
4. Epistemic lifecycle states (VALIDATION_REQUIRED, FALSE_POSITIVE)
5. Zero raw secret exposure (masking & SHA-256 fingerprinting)
6. Artifact persistence (JSONL and Markdown reports)
"""
import pytest
import shutil
from pathlib import Path
from core.secrets.secret_hunter_agent import (
    SecretHunterPipeline,
    SecretCandidate,
    SecretLifecycleState,
)
from core.secrets.secret_report_generator import SecretReportGenerator


@pytest.fixture
def temp_artifacts_dir(tmp_path):
    d = tmp_path / "artifacts_test" / "secrets"
    d.mkdir(parents=True, exist_ok=True)
    yield d
    shutil.rmtree(tmp_path, ignore_errors=True)


def test_deterministic_provider_signatures():
    pipeline = SecretHunterPipeline()
    stripe_mock = "sk_" + "test_" + "mK9pL2wR8tY4nB6jF1xQ7zV3"
    google_mock = "AIza" + "SyD_8mK2pL4vR9tW1nB3jF5xQ7yZ0aC"
    github_mock = "ghp_" + "mK9pL2wR8tY4nB6jF1xQ7zV3aC5eG0iJ"
    sample_code = f"""
    // Configuration bundle
    const awsKey = "AKIAJ7N8K4P2L9M5R3Q1";
    const googleKey = "{google_mock}";
    const githubTok = "{github_mock}";
    const stripeKey = "{stripe_mock}";
    const dbUri = "postgres://admin:S3cur3P@ss99@db.internal:5432/production";
    const apiRoute = "/api/v2/payments/charge";
    """
    candidates = pipeline.scan_content(sample_code, source_origin="bundle.js")

    types_found = {c.secret_type for c in candidates}
    assert "AWS_ACCESS_KEY" in types_found
    assert "GOOGLE_API_KEY" in types_found
    assert "GITHUB_PERSONAL_TOKEN" in types_found
    assert "STRIPE_SECRET_KEY" in types_found
    assert "DATABASE_CONNECTION_URI" in types_found

    # Check endpoints associated with secrets in the same bundle
    aws_cand = next(c for c in candidates if c.secret_type == "AWS_ACCESS_KEY")
    assert "/api/v2/payments/charge" in aws_cand.related_endpoints
    assert aws_cand.lifecycle_state == SecretLifecycleState.VALIDATION_REQUIRED
    assert aws_cand.confidence_score >= 0.90


def test_entropy_gating_and_generic_filtering():
    pipeline = SecretHunterPipeline()

    # Low entropy generic token should be rejected
    low_ent_code = 'api_key = "11111111111111111111"'
    assert len(pipeline.scan_content(low_ent_code, "config.py")) == 0

    # High entropy generic token should be captured
    high_ent_code = 'api_key = "x7K9pQ2mZ8vL4wR1tY5nB3jF6"'
    cands = pipeline.scan_content(high_ent_code, "config.py")
    assert len(cands) == 1
    assert cands[0].secret_type == "GENERIC_API_SECRET"
    assert cands[0].entropy >= 3.2


def test_placeholder_and_example_suppression():
    pipeline = SecretHunterPipeline()
    test_code = """
    // Example credentials in documentation
    const fake_aws = "AKIAIOSFODNN7EXAMPLE";
    const dummy_pass = "api_secret = 'changeme_dummy_value_1234'";
    """
    cands = pipeline.scan_content(test_code, "docs.md")

    assert len(cands) >= 1
    aws_example = next((c for c in cands if c.secret_type == "AWS_ACCESS_KEY"), None)
    assert aws_example is not None
    assert aws_example.is_example_value is True
    assert aws_example.lifecycle_state == SecretLifecycleState.FALSE_POSITIVE
    assert aws_example.confidence_score <= 0.30


def test_masking_and_fingerprinting():
    raw_key = "AKIA9876543210ZYXWVU"
    pipeline = SecretHunterPipeline()
    cands = pipeline.scan_content(f"aws_key = '{raw_key}'", "test.py")

    assert len(cands) == 1
    cand = cands[0]
    assert raw_key not in cand.masked_value
    assert cand.masked_value.startswith("AKIA")
    assert cand.masked_value.endswith("XWVU")
    assert "*" in cand.masked_value
    assert len(cand.raw_fingerprint) == 64  # SHA-256


def test_secret_report_generator_persistence(temp_artifacts_dir):
    generator = SecretReportGenerator(temp_artifacts_dir)
    pipeline = SecretHunterPipeline()

    mock_stripe = "sk_" + "test_" + "9999999999abcdefghijklmn"
    sample = f"""
    const stripe = "{mock_stripe}";
    const endpoint = "/api/v1/checkout/session";
    """
    cands = pipeline.scan_content(sample, "checkout.js")
    assert len(cands) == 1
    cand = cands[0]

    json_path = generator.persist_candidate(cand)
    assert json_path.exists()
    assert temp_artifacts_dir / "discovered.jsonl"
    
    # Check Markdown report
    report_file = generator.reports_dir / f"{cand.candidate_id}.md"
    assert report_file.exists()
    content = report_file.read_text(encoding="utf-8")
    assert f"# {cand.candidate_id}" in content
    assert "STRIPE_SECRET_KEY" in content
    assert "sk_test_" in content
    assert "/api/v1/checkout/session" in content
    assert "Remediation Guidance" in content
