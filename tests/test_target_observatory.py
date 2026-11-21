"""
Tests for TargetSandboxObserver — صندوق مرصد الأهداف
"""
import pytest
import asyncio
from core.observatory.target_sandbox_observer import TargetSandboxObserver

@pytest.mark.asyncio
async def test_target_sandbox_observer_local_mock():
    observer = TargetSandboxObserver(timeout_s=3.0)
    # Observe localhost or simulated endpoint (even when offline, produces safe fallback report)
    report = await observer.observe_target("http://127.0.0.1:8000")
    assert report is not None
    assert report.canonical_host in ("127.0.0.1:8000", "127.0.0.1")
    assert isinstance(report.technologies, list)
    assert isinstance(report.exposure_score, float)
    assert report.risk_level in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
    assert isinstance(report.to_dict(), dict)
