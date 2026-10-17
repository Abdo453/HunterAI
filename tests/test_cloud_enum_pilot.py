"""Tests لـ Cloud-Enum Cloud Storage Pilot — L1→L5"""
import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.cloud_enum.schemas import (
    CloudBucketRecord, CloudBucketProfile,
    CloudEnumEvidenceLevel,
)
from core.cloud_enum.analyzer import (
    CloudEnumNormalizer, DuplicateDetector, EvidenceReviewer,
)
from core.cloud_enum.context import ContextEnricher, AdaptiveTestAdvisor


CLOUD_ENUM_SAMPLE = json.dumps({
    "bucket_name": "my-backup-bucket",
    "provider": "aws_s3",
    "access_level": "public",
    "region": "us-east-1",
    "url": "https://my-backup-bucket.s3.amazonaws.com",
}, ensure_ascii=False)


def test_normalizer():
    norm = CloudEnumNormalizer()
    rec = norm.normalize_cloud_enum_line(CLOUD_ENUM_SAMPLE)
    assert rec is not None
    assert rec.bucket_name == "my-backup-bucket"
    assert rec.provider == "aws_s3"
    assert rec.access_level == "public"
    assert rec.region == "us-east-1"
    assert rec.url == "https://my-backup-bucket.s3.amazonaws.com"
    assert rec.evidence_level == CloudEnumEvidenceLevel.E0
    print("[PASS] cloud-enum normalizer")


def test_duplicate_detector():
    norm = CloudEnumNormalizer()
    dedup = DuplicateDetector()

    r1 = norm.normalize_cloud_enum_line(CLOUD_ENUM_SAMPLE)
    r2 = norm.normalize_cloud_enum_line(CLOUD_ENUM_SAMPLE)  # نفس الدلو → تكرار

    g1 = dedup.add(r1)
    assert g1 is None  # أصل جديد

    g2 = dedup.add(r2)
    assert g2 is not None  # تكرار

    groups = dedup.flush()
    assert len(groups) == 1
    assert len(groups["my-backup-bucket"]) == 2
    print("[PASS] cloud-enum duplicate detector")


def test_evidence_reviewer():
    norm = CloudEnumNormalizer()
    reviewer = EvidenceReviewer()

    rec = norm.normalize_cloud_enum_line(CLOUD_ENUM_SAMPLE)
    report = reviewer.review(rec)

    # فيه bucket_name + provider → sufficient → E1
    assert report["evidence_status"] == "sufficient"
    assert report["needs_verification"] is False
    assert rec.evidence_level == CloudEnumEvidenceLevel.E1  # تمت ترقيتها
    assert report["is_public"] is True

    print("[PASS] cloud-enum evidence reviewer")


def test_context_enricher():
    enricher = ContextEnricher(
        httpx_results={"my-backup-bucket": ["https://my-backup-bucket.s3.amazonaws.com/"]},
    )
    rec = CloudBucketRecord(
        record_id="cb1",
        bucket_name="my-backup-bucket",
        provider="aws_s3",
        access_level="public",
        region="us-east-1",
        url="https://my-backup-bucket.s3.amazonaws.com",
        evidence_level=CloudEnumEvidenceLevel.E0,
    )
    ctx = enricher.enrich(rec)
    assert ctx["is_public"] is True
    assert len(ctx["related_urls"]) == 1
    print("[PASS] cloud-enum context enricher")


def test_adaptive_advisor():
    advisor = AdaptiveTestAdvisor()
    rec = CloudBucketRecord(
        record_id="cb2",
        bucket_name="my-backup-bucket",
        provider="aws_s3",
        access_level="public",
        region="us-east-1",
        url="https://my-backup-bucket.s3.amazonaws.com",
        evidence_level=CloudEnumEvidenceLevel.E0,
    )
    advice = advisor.advise(rec, {"is_public": True})
    assert "nuclei -t http/exposed-panels" in advice
    assert "aws s3 ls s3://<bucket_name> --no-sign-request" in advice
    assert len(advice) <= 8
    print("[PASS] cloud-enum adaptive advisor")


def test_cloud_bucket_profile():
    profile = CloudBucketProfile(
        bucket_name="my-backup-bucket",
        provider="aws_s3",
        access_level="public",
        region="us-east-1",
        url="https://my-backup-bucket.s3.amazonaws.com",
        confidence_score=0.85,
        confidence_label="strong",
        evidence_level=CloudEnumEvidenceLevel.E1,
        is_public=True,
    )
    d = profile.to_dict()
    assert d["confidence_label"] == "strong"
    assert d["evidence_level"] == "E1"
    assert d["is_public"] is True
    print("[PASS] cloud-enum cloud bucket profile")


if __name__ == "__main__":
    test_normalizer()
    test_duplicate_detector()
    test_evidence_reviewer()
    test_context_enricher()
    test_adaptive_advisor()
    test_cloud_bucket_profile()
    print("\n[INFO] جميع اختبارات Cloud-Enum Pilot نجحت!")
