"""
Unit Test Wrapper for Burp E2E Validation v2 (15 Checkpoints)
=============================================================
Certifies the complete bidirectional contract between Burp Suite, the Jython Extender,
Gateway Bridge (:8085), EventBus, CaptureStore, Reasoning Memory, Experiment Engine,
Evidence Court, Target Tab Issue Export, Failure Resiliency, and Strict Scope Enforcement:
"""
import pytest
from validate_burp_e2e_v2 import BurpE2EValidatorV2


def test_burp_e2e_validation_v2():
    validator = BurpE2EValidatorV2()
    ok = validator.run_all()
    assert ok is True
