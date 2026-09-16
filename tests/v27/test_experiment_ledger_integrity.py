"""
Tests for Tamper-Evident Experiment Ledger
"""
import pytest
from core.reasoning.experiment_ledger import (
    ExperimentRecord,
    TamperEvidentExperimentLedger,
)


def test_tamper_evident_ledger_chaining_and_tamper_detection():
    ledger = TamperEvidentExperimentLedger()

    r1 = ledger.append(ExperimentRecord(experiment_id="exp_01", hypothesis_id="hyp_01"))
    r2 = ledger.append(ExperimentRecord(experiment_id="exp_02", hypothesis_id="hyp_02"))
    r3 = ledger.append(ExperimentRecord(experiment_id="exp_03", hypothesis_id="hyp_03"))

    assert len(ledger) == 3
    assert r2.parent_hash == r1.block_hash
    assert r3.parent_hash == r2.block_hash

    valid, err = ledger.verify_chain_integrity()
    assert valid is True
    assert err is None

    r2.hypothesis_id = "hyp_tampered_maliciously"
    tampered_valid, tamper_err = ledger.verify_chain_integrity()
    assert tampered_valid is False
    assert "Hash mismatch" in tamper_err
