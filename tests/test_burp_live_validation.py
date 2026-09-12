"""
Unit Test wrapper for Burp Integration Validation v1
====================================================
Runs the 10 real validation checkpoints as part of pytest suite.
"""
import pytest
from validate_burp_integration import BurpIntegrationValidatorV1


def test_burp_integration_validation_v1():
    validator = BurpIntegrationValidatorV1()
    ok = validator.run_all()
    assert ok is True
