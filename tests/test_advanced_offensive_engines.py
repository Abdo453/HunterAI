"""
Comprehensive Unit Test Suite for Advanced Offensive Engines:
1. Embedded OOB Engine (Blind SSRF verification via asynchronous HTTP callbacks)
2. Race Condition & High-Concurrency State Engine (Synchronized burst testing)
3. Privilege Escalation & Authorization Engine (BOLA, BFLA, Mass Assignment)
"""
from __future__ import annotations

import asyncio
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import pytest
import httpx

from core.business_logic.privilege_escalation_engine import (
    AuthContext,
    PrivilegeEscalationEngine,
)
from core.business_logic.race_condition_engine import RaceConditionEngine
from core.oob.oob_engine import OOBEngine


def test_embedded_oob_engine_blind_ssrf_verification():
    """
    Verifies that the Embedded OOB Engine successfully catches local SSRF callbacks,
    associates the token with the probe, and generates a binding confirmation verdict.
    """
    oob = OOBEngine(callback_domain="test.hunterai.internal")
    host, port = oob.start_local_listener(host="127.0.0.1", port=0)
    try:
        ctx, payloads = oob.create_probe(
            endpoint="http://victim.lab/api/webhook",
            param_name="callback_url",
            vuln_type="blind_ssrf",
        )
        token = ctx.token

        # Before interaction
        initial_verdict = oob.verify_interaction(token)
        assert initial_verdict.is_confirmed is False

        # Simulate victim server fetching our canary URL (Simulated Blind SSRF trigger)
        callback_url = f"http://127.0.0.1:{port}/canary_{token}"
        with httpx.Client() as client:
            resp = client.get(callback_url)
            assert resp.status_code == 200
            assert resp.headers.get("X-HunterAI-OOB") == "Received"

        # Verify interaction now confirmed
        confirmed_verdict = oob.verify_interaction(token)
        assert confirmed_verdict.is_confirmed is True
        assert confirmed_verdict.vulnerability_type == "blind_ssrf"
        assert confirmed_verdict.canary_token == token
        assert confirmed_verdict.interaction_protocol == "HTTP"
        assert confirmed_verdict.evidence_artifact is not None
    finally:
        oob.stop_local_listener()


@pytest.mark.asyncio
async def test_race_condition_engine_double_spend():
    """
    Tests synchronized race conditions against a vulnerable server that lacks database locking.
    """
    # Vulnerable in-memory balance: starts at 1, should only permit 1 redemption
    # But because of no mutex lock, multiple concurrent requests succeed
    claimed_count = 0
    lock = asyncio.Lock()

    class VulnerableHandler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def do_POST(self):
            nonlocal claimed_count
            # Simulated sleep to expand race window
            import time
            time.sleep(0.02)
            claimed_count += 1
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status": "redeemed", "balance": 100}')

    server = HTTPServer(("127.0.0.1", 0), VulnerableHandler)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        race_engine = RaceConditionEngine()
        target_url = f"http://127.0.0.1:{port}/api/redeem"
        analysis = await race_engine.run_synchronized_race(
            url=target_url,
            method="POST",
            concurrency=10,
            max_permitted_success=1,
        )

        assert analysis.total_dispatched == 10
        # More than 1 succeeded due to lack of locking
        assert analysis.successful_count > 1
        assert analysis.is_vulnerable is True
        assert analysis.violation_report is not None
        assert analysis.violation_report.invariant_id == "INV-06-CONCURRENCY-LIMIT"
    finally:
        server.shutdown()
        server.server_close()


def test_privilege_escalation_engine_bola_and_mass_assignment():
    """
    Verifies detection of BOLA (IDOR) and Mass Assignment against a test server.
    """
    class AuthTestHandler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def do_GET(self):
            # Endpoint: /api/users/999/profile (User 999 is victim)
            if "/api/users/999/profile" in self.path:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"id": "999", "name": "Victim User", "ssn": "123-45-6789"}')
            else:
                self.send_response(404)
                self.end_headers()

        def do_POST(self):
            # Mass assignment test endpoint: /api/profile
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8")
            data = json.loads(body)

            # Reflects whatever was submitted
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(data).encode("utf-8"))

    server = HTTPServer(("127.0.0.1", 0), AuthTestHandler)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        pe_engine = PrivilegeEscalationEngine()
        attacker_context = AuthContext(
            user_id="101",
            role="user",
            headers={"Authorization": "Bearer attacker_token_101"},
        )

        # 1. Test BOLA
        template = f"http://127.0.0.1:{port}/api/users/{{id}}/profile"
        verdict = pe_engine.test_bola_idor(
            endpoint_template=template,
            user_a=attacker_context,
            victim_b_id="999",
        )
        assert verdict.is_vulnerable is True
        assert verdict.vulnerability_type == "BOLA"
        assert verdict.status_code == 200
        assert verdict.violation_report is not None

        # 2. Test Mass Assignment
        profile_url = f"http://127.0.0.1:{port}/api/profile"
        ma_verdicts = pe_engine.test_mass_assignment(
            endpoint=profile_url,
            user=attacker_context,
            base_payload={"username": "hacker", "bio": "cyber researcher"},
        )
        assert len(ma_verdicts) > 0
        assert any(v.is_vulnerable for v in ma_verdicts)
        assert any(v.vulnerability_type == "MASS_ASSIGNMENT" for v in ma_verdicts)
    finally:
        server.shutdown()
        server.server_close()
