"""
Unit tests for VulnerabilityEngine, BaseSkill, LFISkill, and CmdInjectionSkill
"""
import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from agents.skills.base_skill import BaseSkill, SkillResult, SkillState
from agents.skills.lfi_skill import LFISkill
from agents.skills.cmd_injection_skill import CmdInjectionSkill
from agents.skills.sqli_skill import SQLiSkill
from core.vuln_engine import VulnerabilityEngine


def _make_mock_resp(text: str, status_code: int = 200):
    m = MagicMock()
    m.text = text
    m.status_code = status_code
    return m


class TestBaseSkillAndResult:
    def test_skill_result_to_dict(self):
        res = SkillResult(
            verified=True,
            vuln_type="sqli",
            title="SQLi Test",
            severity="Critical",
            endpoint="http://example.com/filter",
            param_name="category",
            fallback_used=True,
            fallback_engine="sqlmap",
        )
        d = res.to_dict()
        assert d["verified"] is True
        assert d["type"] == "sqli"
        assert d["fallback_used"] is True
        assert d["fallback_engine"] == "sqlmap"


class TestLFISkill:
    @pytest.mark.asyncio
    async def test_can_handle(self):
        lfi = LFISkill()
        assert lfi.can_handle("file") > 0.9
        assert lfi.can_handle("page") > 0.9
        assert lfi.can_handle("id") < 0.8

    @pytest.mark.asyncio
    async def test_lfi_detects_unix_passwd(self):
        lfi = LFISkill()
        mock_client = AsyncMock()
        # Baseline response
        mock_client.get.side_effect = [
            _make_mock_resp("Welcome to the website"),
            _make_mock_resp("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"),
        ]

        with patch("httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__.return_value = mock_client
            res = await lfi.run("http://example.com/view?file=main.php", "file")
            assert res.verified is True
            assert res.severity == "Critical"
            assert "etc/passwd" in res.payload_used
            assert "root:x:0:0:" in res.evidence

    @pytest.mark.asyncio
    async def test_lfi_clean_target(self):
        lfi = LFISkill()
        mock_client = AsyncMock()
        mock_client.get.return_value = _make_mock_resp("Safe response without file content")

        with patch("httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__.return_value = mock_client
            res = await lfi.run("http://example.com/view?file=main.php", "file")
            assert res.verified is False


class TestCmdInjectionSkill:
    @pytest.mark.asyncio
    async def test_can_handle(self):
        cmd = CmdInjectionSkill()
        assert cmd.can_handle("ip") > 0.9
        assert cmd.can_handle("exec") > 0.9
        assert cmd.can_handle("cat") < 0.8

    @pytest.mark.asyncio
    async def test_echo_canary_detected(self):
        cmd = CmdInjectionSkill()
        mock_client = AsyncMock()
        # Baseline response (no canary), then probe response containing canary
        mock_client.get.side_effect = [
            _make_mock_resp("Ping output: 1 packets transmitted"),
            _make_mock_resp(f"output:\n{CmdInjectionSkill.CANARY}\n"),
            _make_mock_resp("output:\n72\n"),
        ]

        with patch("httpx.AsyncClient") as mock_cls:
            mock_cls.return_value.__aenter__.return_value = mock_client
            res = await cmd.run("http://example.com/ping?ip=127.0.0.1", "ip")
            assert res.verified is True
            assert res.severity == "Critical"
            assert CmdInjectionSkill.CANARY in res.evidence


class TestSQLiFallback:
    @pytest.mark.asyncio
    async def test_fallback_triggers_when_sqlmap_finds_vuln(self):
        skill = SQLiSkill()
        with patch("shutil.which", return_value="/usr/bin/sqlmap"):
            fake_stdout = b"""
[INFO] testing connection to the target URL
sqlmap identified the following injection point(s) with a total of 56 HTTP(s) requests:
---
Parameter: category (GET)
    Type: UNION query
    Title: Generic UNION query (NULL) - 2 columns
---
[INFO] the back-end DBMS is Oracle
web application technology: Apache
back-end DBMS: Oracle
banner: Oracle Database 19c Enterprise Edition Release 19.0.0.0.0 - Production
current database: ACADEMY
            """
            mock_proc = AsyncMock()
            mock_proc.communicate.return_value = (fake_stdout, b"")
            with patch("asyncio.create_subprocess_exec", return_value=mock_proc):
                fb_res = await skill.fallback("http://example.com/filter?category=Gifts", "category")
                assert fb_res is not None
                assert fb_res["verified"] is True
                assert "Oracle" in fb_res["evidence"]


class TestVulnerabilityEngine:
    def test_prioritize_skills(self):
        engine = VulnerabilityEngine()
        sqli_p = engine.prioritize_skills_for_param("category", "http://test.com/filter?category=Gifts")
        top_skill = sqli_p[0][0]
        assert top_skill in ("sqli", "xss")

        lfi_p = engine.prioritize_skills_for_param("filename", "http://test.com/download?filename=a.pdf")
        assert lfi_p[0][0] == "lfi"

        cmd_p = engine.prioritize_skills_for_param("ip", "http://test.com/ping?ip=127.0.0.1")
        assert cmd_p[0][0] == "cmd_injection"

    @pytest.mark.asyncio
    async def test_assess_target_collects_findings(self):
        engine = VulnerabilityEngine()
        with patch("core.vuln_engine.run_sqli_skill", new_callable=AsyncMock) as mock_sqli:
            mock_sqli.return_value = {
                "state": "COMPLETE",
                "objective_met": True,
                "dbms": "oracle",
                "extracted_data": "Oracle Database 19c Enterprise Edition",
                "union_payload": "'+UNION+SELECT+BANNER,NULL+FROM+v$version--",
                "fallback_used": False,
            }
            findings = await engine.assess_target(
                target_url="https://target-lab.net/filter?category=Gifts",
                primary_focus="sqli",
            )
            assert len(findings) >= 1
            f0 = findings[0]
            assert f0["type"] == "sqli"
            assert "ORACLE" in f0["title"].upper()
            assert f0["severity"] == "Critical"
