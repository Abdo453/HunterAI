"""
Tests for the InvestigationController -> Evidence Court promotion gate.

Closes the audit finding that ``_promote_to_evidence_court`` created CONFIRMED
findings without ever consulting the Evidence Court.
"""
import pytest

from hunter_ai.pipeline.investigation_controller import InvestigationController, Hypothesis


class _MockOrchestrator:
    def __init__(self):
        self.domain = "target.com"
        self.findings = []
        self.profile = "full"
        self.timeout_multiplier = 1.0
        self.proxy = None
        self.parameters = []
        self.endpoints = []
        self.live_assets = []

    def _emit(self, *a, **k):
        pass


def _hyp(vuln_type="XSS"):
    return Hypothesis(
        id="H-001",
        vuln_type=vuln_type,
        target_url="https://target.com/search",
        param="q",
        rationale="unit-test",
        priority=0.9,
        source="Seed",
    )


# ── Promotion gate (direct) ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_promotion_declared_proof_confirms_and_labels():
    orc = _MockOrchestrator()
    ctrl = InvestigationController(orchestrator=orc)
    raw = {"state": "COMPLETE", "objective_met": True, "evidence_snippet": "reflected <b>marker</b>"}

    finding = await ctrl._promote_to_evidence_court(_hyp("XSS"), raw)

    assert finding is not None
    assert finding in orc.findings
    checks = finding.false_positive_checks
    assert checks["court_verdict"] == "CONFIRMED"
    # No re-evaluable payload => honestly labelled declared-proof confirmation.
    assert checks["court_epistemic_state"] == "CONFIRMED_ON_DECLARED_PROOF"
    assert finding.severity == "Medium"  # court calibrates XSS as Medium


@pytest.mark.asyncio
async def test_promotion_derived_proof_confirms():
    orc = _MockOrchestrator()
    ctrl = InvestigationController(orchestrator=orc)
    raw = {"state": "COMPLETE", "extracted_data": "Oracle Database 19c Enterprise Edition"}

    finding = await ctrl._promote_to_evidence_court(_hyp("SQLi"), raw)

    assert finding is not None
    checks = finding.false_positive_checks
    assert checks["court_verdict"] == "CONFIRMED"
    assert checks["court_proof_strength"] == "DERIVED"
    assert checks["court_epistemic_state"] == "CONFIRMED"


@pytest.mark.asyncio
async def test_promotion_refutation_drops_finding():
    orc = _MockOrchestrator()
    ctrl = InvestigationController(orchestrator=orc)
    raw = {
        "state": "COMPLETE",
        "objective_met": True,
        "evidence_snippet": "no marker present",
        # A payload the engine can evaluate and that FAILS => refutation.
        "proof_payload": {"artifact_type": "token", "expected_token": "ABSENT_TOKEN"},
    }

    finding = await ctrl._promote_to_evidence_court(_hyp("XSS"), raw)

    assert finding is None
    assert orc.findings == []


# ── Promotion gate (full OODA loop) ──────────────────────────────────────────

@pytest.mark.asyncio
async def test_run_records_only_court_confirmed_findings(monkeypatch):
    orc = _MockOrchestrator()
    ctrl = InvestigationController(orchestrator=orc)
    hyp = _hyp("XSS")

    async def _no_ai(h):
        return None

    async def _noop():
        return None

    def _seed():
        ctrl.queue.push(hyp)
        return 1

    async def _exec(h, ai_context=None):
        h.test_count += 1
        return True, {"state": "COMPLETE", "objective_met": True, "evidence_snippet": "reflected marker"}

    monkeypatch.setattr(ctrl, "_seed_from_parameters", _seed)
    monkeypatch.setattr(ctrl, "_seed_from_decision_core", lambda: 0)
    monkeypatch.setattr(ctrl, "_execute_skill", _exec)
    monkeypatch.setattr(ctrl, "_ai_strategize", _no_ai)
    monkeypatch.setattr(ctrl, "_browser_recovery", _noop)

    summary = await ctrl.run(budget_seconds=3.0)

    assert summary.confirmed == 1
    assert len(orc.findings) == 1
    assert orc.findings[0].false_positive_checks["court_verdict"] == "CONFIRMED"


@pytest.mark.asyncio
async def test_run_drops_skill_claim_when_court_refutes(monkeypatch):
    orc = _MockOrchestrator()
    ctrl = InvestigationController(orchestrator=orc)
    hyp = _hyp("XSS")

    async def _no_ai(h):
        return None

    async def _noop():
        return None

    def _seed():
        ctrl.queue.push(hyp)
        return 1

    async def _exec(h, ai_context=None):
        h.test_count += 1
        # Skill claims success, but its evidence cannot be re-evaluated by the Court.
        return True, {
            "state": "COMPLETE",
            "objective_met": True,
            "evidence_snippet": "no marker present",
            "proof_payload": {"artifact_type": "token", "expected_token": "ABSENT_TOKEN"},
        }

    monkeypatch.setattr(ctrl, "_seed_from_parameters", _seed)
    monkeypatch.setattr(ctrl, "_seed_from_decision_core", lambda: 0)
    monkeypatch.setattr(ctrl, "_execute_skill", _exec)
    monkeypatch.setattr(ctrl, "_ai_strategize", _no_ai)
    monkeypatch.setattr(ctrl, "_browser_recovery", _noop)

    summary = await ctrl.run(budget_seconds=3.0)

    assert summary.confirmed == 0
    assert orc.findings == []
