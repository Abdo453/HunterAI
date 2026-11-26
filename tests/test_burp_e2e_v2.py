"""
Unit Test Wrapper for Burp E2E Validation v2 (15 Checkpoints)
=============================================================
Certifies the complete bidirectional contract between Burp Suite, the Jython Extender,
Gateway Bridge (:8085), EventBus, CaptureStore, Reasoning Memory, Experiment Engine,
Evidence Court, Target Tab Issue Export, Failure Resiliency, and Strict Scope Enforcement:
"""
import sys
import pytest
from validate_burp_e2e_v2 import BurpE2EValidatorV2

_SHIM_MODULE_NAMES = (
    "burp",
    "javax",
    "javax.swing",
    "java",
    "java.awt",
    "java.util",
    "java.io",
    "urllib2",
)


def test_burp_e2e_validation_v2():
    saved_modules = {name: sys.modules.get(name) for name in _SHIM_MODULE_NAMES}
    validator = None
    try:
        validator = BurpE2EValidatorV2()
        ok = validator.run_all()
        assert ok is True
    finally:
        if validator is not None:
            extender = getattr(getattr(validator, "harness", None), "extender", None)
            if extender is not None:
                if hasattr(extender, "stop"):
                    extender.stop()
                elif hasattr(extender, "extensionUnloaded"):
                    extender.extensionUnloaded()
        for name, prev in saved_modules.items():
            if prev is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = prev
