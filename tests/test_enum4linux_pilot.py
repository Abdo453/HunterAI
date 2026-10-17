"""Tests لـ enum4linux-ng Pilot — L1→L5"""
import json

from core.enum4linux.schemas import (
    Enum4LinuxAssetRecord,
    Enum4LinuxEvidenceLevel,
    SMBShareRecord,
    SMBUserRecord,
)
from core.enum4linux.analyzer import (
    DuplicateDetector,
    Enum4LinuxNormalizer,
    EvidenceReviewer,
)
from core.enum4linux.context import AdaptiveTestAdvisor, ContextEnricher

E4L_SAMPLE = json.dumps({
    "target": {"host": "10.0.0.10", "port": 445, "username": "", "password": ""},
    "hostname": "DC01",
    "domain": "corp.local",
    "os_info": {"OS": "Windows Server 2019", "OS version": "10.0"},
    "users": {
        "Administrator": {"username": "Administrator", "rid": "500", "description": "Built-in admin"},
        "svc_sql": {"username": "svc_sql", "rid": "1105", "description": "SQL service"},
    },
    "shares": {
        "IPC$": {"share": "IPC$", "access": "READ", "comment": "Remote IPC"},
        "Public": {"share": "Public", "access": "READ,WRITE", "comment": "Shared docs"},
    },
    "groups": {"Domain Admins": {"members": ["Administrator"]}},
    "policy": {"min_password_length": 7, "lockout_threshold": 0},
}, ensure_ascii=False)


def test_normalizer_parses_sample():
    records = Enum4LinuxNormalizer().normalize(E4L_SAMPLE)
    assert len(records) == 1
    rec = records[0]
    assert rec.host == "10.0.0.10"
    assert rec.domain == "corp.local"
    assert rec.netbios == "DC01"
    assert rec.is_dc is True
    assert rec.anonymous_access is True            # no creds supplied + users enumerated
    assert {u.username for u in rec.users} == {"Administrator", "svc_sql"}
    assert {s.name for s in rec.shares} == {"IPC$", "Public"}
    admin = [u for u in rec.users if u.username == "Administrator"][0]
    assert admin.rid == 500


def test_normalizer_handles_garbage_and_empty():
    n = Enum4LinuxNormalizer()
    assert n.normalize("") == []
    assert n.normalize("not json") == []
    assert n.normalize(json.dumps({"no": "host"})) == []


def test_writable_share_flag():
    rec = Enum4LinuxNormalizer().normalize(E4L_SAMPLE)[0]
    pub = [s for s in rec.shares if s.name == "Public"][0]
    assert pub.writable is True
    ipc = [s for s in rec.shares if s.name == "IPC$"][0]
    assert ipc.writable is False


def test_duplicate_detector_merges_hosts():
    rec1 = Enum4LinuxAssetRecord(host="10.0.0.10", domain="corp.local",
                                 users=[SMBUserRecord(host="10.0.0.10", username="a")])
    rec2 = Enum4LinuxAssetRecord(host="10.0.0.10", domain="corp.local",
                                 users=[SMBUserRecord(host="10.0.0.10", username="b")],
                                 shares=[SMBShareRecord(host="10.0.0.10", name="Public")])
    d = DuplicateDetector()
    d.add(rec1)
    d.add(rec2)
    merged = d.flush()
    assert len(merged) == 1
    assert {u.username for u in merged[0].users} == {"a", "b"}
    assert len(merged[0].shares) == 1


def test_reviewer_promotes_on_evidence():
    rec = Enum4LinuxNormalizer().normalize(E4L_SAMPLE)[0]
    report = EvidenceReviewer().review(rec)
    assert report["evidence_status"] == "sufficient"
    assert rec.evidence_level == Enum4LinuxEvidenceLevel.E1
    assert report["confidence"] >= 0.5
    assert any("null session" in n for n in report["notes"])


def test_reviewer_stays_raw_without_data():
    rec = Enum4LinuxAssetRecord(host="10.0.0.1")
    report = EvidenceReviewer().review(rec)
    assert report["evidence_status"] == "raw"
    assert rec.evidence_level == Enum4LinuxEvidenceLevel.E0


def test_context_and_advisor():
    rec = Enum4LinuxNormalizer().normalize(E4L_SAMPLE)[0]
    ctx = ContextEnricher().enrich(rec)
    assert ctx["role"] == "domain_controller"
    assert "writable_share" in ctx["attack_surface"]
    advice = AdaptiveTestAdvisor().advise(rec, ctx)
    assert any("GetNPUsers" in s for s in advice)      # anonymous → AS-REP roast
    assert any("bloodhound" in s for s in advice)
