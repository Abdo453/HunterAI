"""Tests لـ NetExec (nxc) Pilot — L1→L5"""
from core.netexec.schemas import (
    NetExecEvidenceLevel,
    NetExecHostRecord,
)
from core.netexec.analyzer import (
    DuplicateDetector,
    EvidenceReviewer,
    NetExecNormalizer,
)
from core.netexec.context import AdaptiveTestAdvisor, ContextEnricher

NXC_SAMPLE = (
    "SMB  10.0.0.10  445  DC01  [*] Windows Server 2019 Build 17763 x64 "
    "(name:DC01) (domain:corp.local) (signing:False) (SMBv1:True)\n"
    "SMB  10.0.0.10  445  DC01  [+] corp.local\\svc_sql:Password123 (Pwn3d!)\n"
    "LDAP 10.0.0.10  389  DC01  [*] Windows Server 2019 Build 17763 "
    "(name:DC01) (domain:corp.local)\n"
)


def test_normalizer_parses_lines():
    records = NetExecNormalizer().normalize_text(NXC_SAMPLE)
    assert len(records) == 3
    smb = [r for r in records if r.protocol == "smb"][0]
    assert smb.host == "10.0.0.10"
    assert smb.port == 445
    assert smb.hostname == "DC01"
    assert smb.domain == "corp.local"
    assert smb.signing is False
    assert smb.smbv1 is True
    assert "Windows Server 2019" in (smb.os_family or "")


def test_normalizer_detects_valid_credentials_and_pwned():
    records = NetExecNormalizer().normalize_text(NXC_SAMPLE)
    cred = [r for r in records if r.username == "svc_sql"][0]
    assert cred.pwned is True
    assert cred.credentials_valid is True
    assert cred.evidence_level == NetExecEvidenceLevel.E1


def test_normalizer_ignores_noise_and_empty():
    n = NetExecNormalizer()
    assert n.normalize_text("") == []
    assert n.normalize_text("random banner line without structure") == []


def test_duplicate_detector_merges_by_endpoint():
    records = NetExecNormalizer().normalize_text(NXC_SAMPLE)
    d = DuplicateDetector()
    for r in records:
        d.add(r)
    merged = d.flush()
    keys = {r.canonical_key for r in merged}
    assert keys == {"smb://10.0.0.10:445", "ldap://10.0.0.10:389"}
    smb = [r for r in merged if r.protocol == "smb"][0]
    # merged record keeps the richest facts (signing + pwned)
    assert smb.signing is False and smb.pwned is True


def test_reviewer_flags_relay_and_smbv1():
    rec = NetExecNormalizer().normalize_text(NXC_SAMPLE)[0]
    report = EvidenceReviewer().review(rec)
    assert any("signing" in n for n in report["notes"])
    assert any("SMBv1" in n for n in report["notes"])
    assert report["confidence"] >= 0.5


def test_reviewer_promotes_pwned():
    rec = NetExecHostRecord(host="10.0.0.10", protocol="smb", port=445,
                            domain="corp.local", pwned=True, credentials_valid=True,
                            evidence_level=NetExecEvidenceLevel.E1)
    report = EvidenceReviewer().review(rec)
    assert report["pwned"] is True
    assert report["needs_verification"] is False


def test_context_role_and_surface():
    records = NetExecNormalizer().normalize_text(NXC_SAMPLE)
    smb = [r for r in records if r.protocol == "smb"][0]
    ctx = ContextEnricher().enrich(smb)
    assert ctx["role"] == "domain_controller"
    assert "ntlm_relay" in ctx["attack_surface"]
    assert "smbv1" in ctx["attack_surface"]


def test_advisor_suggests_post_exploitation_when_pwned():
    rec = NetExecHostRecord(host="10.0.0.10", protocol="smb", port=445,
                            domain="corp.local", pwned=True, username="svc_sql")
    advice = AdaptiveTestAdvisor().advise(rec, {"role": "domain_controller"})
    assert any("--sam" in s for s in advice)
    assert any("lsassy" in s for s in advice)
    assert any("--ntds" in s for s in advice)
