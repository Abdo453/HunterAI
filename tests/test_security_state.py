"""
Unit Tests for SecurityState (Attack State Memory — Cairn Inspired)
Tests: Assets, Endpoints, Identities, Vulnerability Tracking, Unknowns, Attack Paths, Versioning & Snapshots
"""
import pytest
from core.state.security_state import SecurityState
from agents.security_intelligence.schemas import (
    FindingStatus,
    IntelligenceFinding,
    EvidenceItem,
    EvidenceType,
    ConfidenceLevel,
    SeverityLevel
)
from agents.security_intelligence.finding_validator import FindingValidator


def _make_sample_finding():
    return IntelligenceFinding(
        target="api.target.local",
        title="IDOR on /api/v1/orders/77",
        vulnerability_type="BOLA",
        severity=SeverityLevel.HIGH,
        confidence_score=0.65,
        confidence_level=ConfidenceLevel.POSSIBLE,
        status=FindingStatus.OBSERVED,
        hypotheses_validated=["HYP-01"],
        evidence=[
            EvidenceItem(
                type=EvidenceType.REQUEST,
                source="burp",
                description="Observed order request",
                data={"id": 77}
            )
        ]
    )


class TestSecurityStateCore:
    """Test state mutation, versioning, and node storage"""

    def test_state_initialization(self):
        state = SecurityState(target="target.local")
        assert state.target == "target.local"
        assert state.version == 1
        assert len(state.assets) == 0
        assert len(state.endpoints) == 0

    def test_add_asset_and_technologies(self):
        state = SecurityState(target="target.local")
        asset = state.add_asset("api.target.local", ip="10.0.0.5", ports=[443, 8443], technologies=["FastAPI", "Uvicorn"])
        assert asset.host == "api.target.local"
        assert asset.ip == "10.0.0.5"
        assert 443 in asset.ports
        assert "FastAPI" in state.technologies
        assert state.version == 2

        # Idempotent re-add with merge
        asset2 = state.add_asset("API.TARGET.LOCAL", ports=[80], technologies=["Python"])
        assert asset2.ports == [80, 443, 8443]
        assert "Python" in state.technologies

    def test_add_endpoint(self):
        state = SecurityState(target="target.local")
        ep = state.add_endpoint(
            path="/api/v1/users",
            method="GET",
            parameters=["page", "limit"],
            auth_required=True,
            status_code=200
        )
        assert ep.method == "GET"
        assert ep.path == "/api/v1/users"
        assert ep.auth_required is True
        assert 200 in ep.status_codes_seen

        # Update endpoint with new parameter and status code
        state.add_endpoint(path="/api/v1/users", method="GET", parameters=["role"], status_code=403)
        assert "role" in ep.parameters
        assert 403 in ep.status_codes_seen

    def test_add_identity(self):
        state = SecurityState(target="target.local")
        ident = state.add_identity("alice_admin", role="admin", token="jwt_alice_token")
        assert ident.username == "alice_admin"
        assert ident.role == "admin"
        assert ident.token == "jwt_alice_token"
        assert "alice_admin" in state.identities

    def test_record_finding_and_evidence(self):
        state = SecurityState(target="target.local")
        f = _make_sample_finding()
        v_node = state.record_finding(f)
        assert v_node.finding_id == f.id
        assert v_node.status == FindingStatus.OBSERVED
        assert len(state.evidence_store) == 1

    def test_transition_finding_with_validator(self):
        state = SecurityState(target="target.local")
        validator = FindingValidator()
        f = _make_sample_finding()
        state.record_finding(f)

        # Transition to SUSPECTED
        success, reason = state.transition_finding_status(
            finding_id=f.id,
            target_status=FindingStatus.SUSPECTED,
            validator=validator,
            rationale="Context enriched with user parameter"
        )
        assert success is True
        assert state.vulnerabilities[f.id].status == FindingStatus.SUSPECTED

        # Attempt CONFIRMED without differential evidence -> should fail
        fail_success, fail_reason = state.transition_finding_status(
            finding_id=f.id,
            target_status=FindingStatus.CONFIRMED,
            validator=validator
        )
        assert fail_success is False
        assert state.vulnerabilities[f.id].status == FindingStatus.SUSPECTED

        # Add differential evidence -> should succeed
        diff_ev = EvidenceItem(
            type=EvidenceType.BEHAVIOR_DIFF,
            source="test_prober",
            description="Horizontal data leak confirmed",
            data={}
        )
        conf_success, conf_reason = state.transition_finding_status(
            finding_id=f.id,
            target_status=FindingStatus.CONFIRMED,
            validator=validator,
            new_evidence=[diff_ev],
            rationale="Cross-user test verified 200 OK"
        )
        assert conf_success is True
        assert state.vulnerabilities[f.id].status == FindingStatus.CONFIRMED
        assert diff_ev.id in state.evidence_store

    def test_unknowns_and_facts_lifecycle(self):
        state = SecurityState(target="target.local")
        q = "Can regular users access /admin/metrics?"
        state.add_unknown(q)
        assert q in state.unknowns

        # Resolving unknown
        fact = "/admin/metrics returned 403 Forbidden for low-privileged role (RBAC enforced)"
        state.resolve_unknown(q, fact)
        assert q not in state.unknowns
        assert fact in state.known_facts

    def test_add_attack_path(self):
        state = SecurityState(target="target.local")
        path = state.add_attack_path(
            title="Public Registration to Admin Escalation",
            steps=[
                "POST /api/register creates user",
                "PUT /api/profile with role=admin (Mass Assignment)",
                "Access GET /api/admin/secrets"
            ],
            source_node="PUBLIC_REGISTRATION",
            target_node="ADMIN_SECRETS"
        )
        assert path.title == "Public Registration to Admin Escalation"
        assert len(state.attack_paths) == 1

    def test_snapshot_generation(self):
        state = SecurityState(target="target.local")
        state.add_asset("api.target.local", ports=[443])
        state.add_endpoint("/api/data", method="POST")
        f = _make_sample_finding()
        state.record_finding(f)

        snap = state.get_snapshot()
        assert snap["target"] == "target.local"
        assert "summary" in snap
        assert snap["summary"]["assets_count"] == 1
        assert snap["summary"]["endpoints_count"] == 1
        assert snap["summary"]["vulnerabilities_count"] == 1
        assert "OBSERVED" in snap["summary"]["status_breakdown"]
        assert len(snap["recent_transitions"]) > 0
