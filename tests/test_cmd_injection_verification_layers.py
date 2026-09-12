"""
Unit Tests for CmdInjectionSkill Multi-Layer Verification
Verifies:
- Core Principle: REFLECTION != COMMAND EXECUTION != CONFIRMED RCE
- Literal reflection filtering (false positive rejection)
- Controlled execution verification & evidence chain assembly
- Dynamic CVSS v3.1 calculation (never hard-coded 9.5)
- Delimiter analysis and reproducibility checks
"""
import pytest
from unittest.mock import AsyncMock, patch
import httpx

from agents.skills.cmd_injection_skill import CmdInjectionSkill, calculate_cvss31


def _make_mock_resp(text: str, status_code: int = 200) -> httpx.Response:
    req = httpx.Request("GET", "http://test")
    return httpx.Response(status_code=status_code, text=text, request=req)


class TestCmdInjectionVerificationLayers:

    def test_dynamic_cvss31_calculation(self):
        # 1. Unauthenticated Network RCE (Full CIA compromise)
        score_rce, vec_rce = calculate_cvss31(av="N", ac="L", pr="N", ui="N", scope="U", c="H", i="H", a="H")
        assert score_rce == 9.8
        assert "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" in vec_rce

        # 2. Authenticated RCE (Low privileges)
        score_auth, vec_auth = calculate_cvss31(av="N", ac="L", pr="L", ui="N", scope="U", c="H", i="H", a="H")
        assert score_auth == 8.8
        assert "PR:L" in vec_auth

        # 3. Blind Time-Delay (High Availability impact, Low/Partial Conf/Integ)
        score_blind, vec_blind = calculate_cvss31(av="N", ac="L", pr="N", ui="N", scope="U", c="L", i="L", a="H")
        assert score_blind == 8.6
        assert "C:L/I:L/A:H" in vec_blind

        # Prove 9.5 is NOT hard-coded
        assert score_rce != 9.5
        assert score_blind != 9.5

    @pytest.mark.asyncio
    async def test_pure_html_reflection_is_not_confirmed_rce(self):
        """
        Tests the core tenet: REFLECTION != COMMAND EXECUTION.
        When a web page merely echoes back the parameter in an input tag or search header,
        it must NOT be flagged as Confirmed Command Injection or Critical RCE!
        """
        cmd = CmdInjectionSkill()
        mock_client = AsyncMock()

        # Baseline: normal search page
        baseline_html = '<html><body><h1>Search</h1><input name="modal" value="default"></body></html>'
        
        # When injected with '; echo __PTST_CMD_7331__', the page literally reflects the whole command!
        reflected_html = f'<html><body><h1>Search Results</h1><input name="modal" value="; echo {CmdInjectionSkill.CANARY}"></body></html>'

        mock_client.get.side_effect = [
            _make_mock_resp(baseline_html),
            _make_mock_resp(reflected_html),
            _make_mock_resp(reflected_html),
            _make_mock_resp(reflected_html),
            _make_mock_resp(reflected_html),
            _make_mock_resp(reflected_html),
            _make_mock_resp(reflected_html),
            _make_mock_resp(reflected_html),
            _make_mock_resp(reflected_html),
        ]

        with patch("httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__.return_value = mock_client
            res = await cmd.run("http://example.com/search?modal=default", "modal")

            # Must NOT confirm vulnerability
            assert res.verified is False
            assert res.severity == "Info"
            assert "CONFIRMED" not in res.title
            # Logs must document reflection rejection
            assert any("REFLECTION" in log_entry for log_entry in res.logs)

    @pytest.mark.asyncio
    async def test_genuine_command_execution_generates_evidence_chain(self):
        """
        Tests that when real command execution occurs (output contains isolated canary,
        without command syntax or literal reflection), the skill:
        - Confirms OS Command Injection
        - Calculates dynamic CVSS (9.8 for Network unauth)
        - Assembles structured Evidence Chain with 6 validation points
        """
        cmd = CmdInjectionSkill()
        mock_client = AsyncMock()

        # Baseline response
        baseline_resp = "Host status: Alive"
        
        # Probe response from command execution: only the stdout of echo is returned!
        probe_resp = f"Ping output:\n{CmdInjectionSkill.CANARY}\n1 packets transmitted"

        # Reproducibility probe response
        repro_resp = "Ping output:\n72\n1 packets transmitted"

        mock_client.get.side_effect = [
            _make_mock_resp(baseline_resp),
            _make_mock_resp(probe_resp),
            _make_mock_resp(repro_resp),
        ]

        with patch("httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__.return_value = mock_client
            res = await cmd.run("http://example.com/admin/diagnostics?modal=127.0.0.1", "modal")

            assert res.verified is True
            assert res.severity == "Critical"
            assert "Confirmed" in res.title
            assert res.extra["status"] == "CONFIRMED"
            assert res.extra["cvss_score"] == 9.8
            assert res.extra["delimiter"] == ";"

            # Evidence Chain verification
            chain = res.extra["evidence_chain"]
            assert len(chain) >= 5
            assert "1. Canary supplied" in chain[0]
            assert "2. Literal reflection check: Passed" in chain[1]
            assert "3. Delimiter altered command processing" in chain[2]
            assert "4. Controlled execution evidence" in chain[3]
            assert "Dynamic CVSS: 9.8" in chain[-1]

    @pytest.mark.asyncio
    async def test_blind_time_delay_dynamic_cvss(self):
        """
        Tests that blind time-based command injection is confirmed with
        appropriate High severity and calculated CVSS 8.6 (not hard-coded 9.5).
        """
        cmd = CmdInjectionSkill()
        mock_client = AsyncMock()

        # Baseline: fast 0.05s response
        baseline_resp = "Status: OK"
        delay_resp = "Status: Delayed OK"

        mock_client.get.side_effect = [
            _make_mock_resp(baseline_resp),
            _make_mock_resp("No canary here"),  # echo probe fails
            _make_mock_resp("No canary here"),
            _make_mock_resp("No canary here"),
            _make_mock_resp("No canary here"),
            _make_mock_resp("No canary here"),
            _make_mock_resp("No canary here"),
            _make_mock_resp("No canary here"),
            _make_mock_resp("No canary here"),
            _make_mock_resp(delay_resp),        # time probe 1
            _make_mock_resp(delay_resp),        # time probe 2
        ]

        with patch("httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__.return_value = mock_client
            # Mock time.time() to simulate baseline fast (0.05s), then 3.2s elapsed, then 5.2s elapsed
            time_points = [
                100.0, 100.05,  # baseline
                101.0, 104.2,   # time probe 1 (elapsed = 3.2s)
                105.0, 110.2,   # time probe 2 (elapsed = 5.2s)
            ]
            with patch("time.time", side_effect=time_points):
                res = await cmd.run("http://example.com/ping?target=127.0.0.1", "target")

                assert res.verified is True
                assert res.severity == "High"
                assert "Blind Time-Based" in res.title
                assert res.extra["cvss_score"] == 8.6
                assert res.extra["cvss_score"] != 9.5
