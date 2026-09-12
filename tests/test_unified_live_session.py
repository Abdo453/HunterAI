"""
Unit Test wrapper for Unified Live Session
==========================================
Runs the unified Browser -> Burp -> HunterAI -> Evidence session under pytest.
"""
import asyncio
import pytest
from run_unified_live_session import UnifiedLiveSession


@pytest.mark.asyncio
async def test_unified_live_session_execution():
    session = UnifiedLiveSession()
    res = await session.run()
    assert res["status"] == "COMPLETED_CONFIRMED"
    assert res["court_verdict"] == "CONFIRMED"
    assert res["severity"] == "Critical"
    assert len(res["provenance_chain"]) == 7
    assert "[HunterAI]" in res["burp_target_issue"]["issue_name"]
