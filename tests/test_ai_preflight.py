"""
Unit Tests for HunterAI AI Preflight Gate & Cognitive Model Verification
========================================================================
Tests:
  - Connectivity probe and latency tracking
  - Model tag matching & alias normalization
  - Active inference probe
  - Fail-closed execution vs Degraded Mode
  - Status banner generation
  - State machine lifecycle & transition invariants
"""
import io
import json
import pytest
from unittest.mock import patch, MagicMock
from urllib.error import URLError

from hunter_ai.brain.ai_preflight import (
    AIPreflightGate,
    AIPreflightResult,
    ModelProbeResult,
    REQUIRED_MODELS,
)
from hunter_ai.pipeline.state_machine import (
    HunterState,
    HunterStateMachine,
    IllegalStateTransitionError,
)


class TestAIPreflightGate:

    def test_normalize_host(self):
        assert AIPreflightGate.normalize_host("127.0.0.1:11434") == "http://127.0.0.1:11434"
        assert AIPreflightGate.normalize_host("http://0.0.0.0:11434/") == "http://127.0.0.1:11434"
        assert AIPreflightGate.normalize_host("https://ollama.internal:11434") == "https://ollama.internal:11434"

    @patch("urllib.request.urlopen")
    def test_check_connectivity_success(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = json.dumps({
            "models": [
                {"name": "qwen2.5-coder:14b"},
                {"name": "xploiter/pentester:latest"},
                {"name": "WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B:latest"}
            ]
        }).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_response

        online, latency, tags, err = AIPreflightGate.check_connectivity("http://127.0.0.1:11434")
        assert online is True
        assert latency >= 0.0
        assert len(tags) == 3
        assert "qwen2.5-coder:14b" in tags
        assert err is None

    @patch("urllib.request.urlopen")
    def test_check_connectivity_connection_refused(self, mock_urlopen):
        mock_urlopen.side_effect = URLError("Connection refused")
        online, latency, tags, err = AIPreflightGate.check_connectivity("http://127.0.0.1:11434")
        assert online is False
        assert len(tags) == 0
        assert "Connection refused" in str(err)

    def test_match_models(self):
        tags = [
            "qwen2.5-coder:14b",
            "xploiter/pentester:latest",
            "WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B:latest",
            "nmap-eval:v1"
        ]
        results = AIPreflightGate.match_models(tags)
        assert results["reasoning"].available is True
        assert results["reasoning"].matched_tag == "WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B:latest"
        assert results["recon"].available is True
        assert results["recon"].matched_tag == "xploiter/pentester:latest"
        assert results["code"].available is True
        assert results["code"].matched_tag == "qwen2.5-coder:14b"

    def test_match_models_partial_or_missing(self):
        tags = ["qwen2.5-coder:7b"]
        results = AIPreflightGate.match_models(tags)
        assert results["code"].available is True
        assert results["code"].matched_tag == "qwen2.5-coder:7b"
        assert results["reasoning"].available is False
        assert results["recon"].available is False

    @patch("urllib.request.urlopen")
    def test_test_inference_success(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = json.dumps({
            "message": {"content": "HUNTERAI_AI_READY"}
        }).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_response

        ok, latency, output, err = AIPreflightGate.test_inference(
            "http://127.0.0.1:11434", "qwen2.5-coder:14b"
        )
        assert ok is True
        assert output == "HUNTERAI_AI_READY"
        assert err is None

    @patch("urllib.request.urlopen")
    def test_test_inference_failure(self, mock_urlopen):
        mock_urlopen.side_effect = TimeoutError("Request timed out")
        ok, latency, output, err = AIPreflightGate.test_inference(
            "http://127.0.0.1:11434", "qwen2.5-coder:14b"
        )
        assert ok is False
        assert output == ""
        assert "timed out" in str(err).lower()

    @patch.object(AIPreflightGate, "check_connectivity")
    def test_run_preflight_fail_closed_when_offline(self, mock_conn):
        mock_conn.return_value = (False, 15.0, [], "Connection refused")
        res = AIPreflightGate.run_preflight(allow_degraded=False)
        assert res.online is False
        assert res.allowed is False
        assert res.status == "FAILED"
        assert res.degraded is False
        assert len(res.remediation_steps) > 0

    @patch.object(AIPreflightGate, "check_connectivity")
    def test_run_preflight_degraded_when_allowed(self, mock_conn):
        mock_conn.return_value = (False, 15.0, [], "Connection refused")
        res = AIPreflightGate.run_preflight(allow_degraded=True)
        assert res.online is False
        assert res.allowed is True
        assert res.status == "DEGRADED"
        assert res.degraded is True

    @patch.object(AIPreflightGate, "check_connectivity")
    @patch.object(AIPreflightGate, "test_inference")
    def test_run_preflight_full_ai_ready(self, mock_inf, mock_conn):
        mock_conn.return_value = (
            True,
            12.0,
            ["qwen2.5-coder:14b", "xploiter/pentester:latest", "WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B:latest"],
            None
        )
        mock_inf.return_value = (True, 350.0, "HUNTERAI_AI_READY", None)

        res = AIPreflightGate.run_preflight(allow_degraded=False)
        assert res.online is True
        assert res.allowed is True
        assert res.status == "AI_READY"
        assert res.degraded is False
        assert res.inference_ok is True

    def test_format_status_banner(self):
        res = AIPreflightGate.run_preflight(allow_degraded=True, timeout_sec=0.1)
        banner = AIPreflightGate.format_status_banner(res)
        assert "AI COGNITIVE PREFLIGHT GATE" in banner
        assert "Operating Mode" in banner
        assert ("DEGRADED" in banner or "AI_READY" in banner or "BLOCKED" in banner or "AI_POWERED" in banner)


class TestPreflightStateMachine:

    def test_happy_path_preflight_to_ready(self):
        fsm = HunterStateMachine("target.local", "session_test")
        assert fsm.current_state == HunterState.INIT

        fsm.transition_to(HunterState.PREFLIGHT, "Start preflight")
        assert fsm.current_state == HunterState.PREFLIGHT

        fsm.transition_to(HunterState.AI_CONNECTING, "Connecting to host")
        assert fsm.current_state == HunterState.AI_CONNECTING

        fsm.transition_to(HunterState.MODEL_VERIFYING, "Verifying models")
        assert fsm.current_state == HunterState.MODEL_VERIFYING

        fsm.transition_to(HunterState.INFERENCE_VERIFYING, "Verifying inference")
        assert fsm.current_state == HunterState.INFERENCE_VERIFYING

        fsm.transition_to(HunterState.AI_READY, "All checks pass")
        assert fsm.current_state == HunterState.AI_READY

        fsm.transition_to(HunterState.SCOPE_CHECK, "Proceed to scope check")
        assert fsm.current_state == HunterState.SCOPE_CHECK

    def test_offline_to_degraded_mode(self):
        fsm = HunterStateMachine("target.local", "session_test")
        fsm.transition_to(HunterState.PREFLIGHT, "Start preflight")
        fsm.transition_to(HunterState.AI_CONNECTING, "Connecting to host")
        fsm.transition_to(HunterState.AI_UNAVAILABLE, "Host offline")
        fsm.transition_to(HunterState.DEGRADED_MODE, "Degraded mode active")
        assert fsm.current_state == HunterState.DEGRADED_MODE

        fsm.transition_to(HunterState.SCOPE_CHECK, "Proceed with heuristic scan")
        assert fsm.current_state == HunterState.SCOPE_CHECK

    def test_offline_to_aborted_fail_closed(self):
        fsm = HunterStateMachine("target.local", "session_test")
        fsm.transition_to(HunterState.PREFLIGHT, "Start preflight")
        fsm.transition_to(HunterState.AI_CONNECTING, "Connecting to host")
        fsm.transition_to(HunterState.AI_UNAVAILABLE, "Host offline")
        fsm.transition_to(HunterState.ABORTED, "Fail-closed abort")
        assert fsm.current_state == HunterState.ABORTED

    def test_illegal_jump_from_preflight_to_report(self):
        fsm = HunterStateMachine("target.local", "session_test")
        fsm.transition_to(HunterState.PREFLIGHT, "Start preflight")
        with pytest.raises(IllegalStateTransitionError):
            fsm.transition_to(HunterState.REPORT, "Illegal jump")
