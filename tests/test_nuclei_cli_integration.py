"""اختبار تكامل 명령 hunter nuclei عبر CLI"""
import sys
import os
import json
import unittest
from unittest.mock import patch, MagicMock, AsyncMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cli.hunter_cli import main


class TestNucleiCLIIntegration(unittest.TestCase):
    """اختبار تكامل 명령 hunter nuclei"""

    def _run_cli(self, args):
        """يشغل 명령 nuclei عبر main() ويُرجع المخرجات"""
        try:
            main(args)
        except SystemExit as e:
            return e.code
        return 0

    @patch("agents.nuclei_agent.NucleiAgent.run")
    @patch("agents.nuclei_agent.NucleiAgent.__init__", return_value=None)
    @patch("agents.nuclei_agent.NucleiTools.is_available", return_value=True)
    @patch("agents.nuclei_agent.NucleiTools.scan")
    def test_nuclei_success_flow(self, mock_scan, mock_is_available, mock_init, mock_run):
        """تدفق ناجح: نطاق مسموح + nuclei متاح → Findings تُعرض"""
        # محاكاة نتيجة الوكيل
        mock_run.return_value = MagicMock(
            agent_name="nuclei_agent",
            target="https://authorized.target.local",
            success=True,
            findings=[
                {
                    "record_id": "nf_abc123",
                    "template_id": "http-exposure-env",
                    "template_name": "Environment File Exposure",
                    "severity": "high",
                    "matched_at": "https://authorized.target.local/.env",
                    "matcher_name": "env_file",
                    "evidence_level": "E1",
                    "status": "needs_verification",
                    "confidence": 0.75,
                    "needs_verification": True,
                    "scope_check": "passed",
                    "context": {"auth_sensitive": False, "admin_sensitive": False, "is_on_known_endpoint": True},
                    "adaptive_templates": ["http/nginx"],
                    "recommendation": "راجع الاستجابة الأصلية وتحقق يدويًا.",
                    "raw_match": {},
                }
            ],
            raw_output={"raw_matches": [{"template-id": "http-exposure-env"}], "duplicates": []},
            errors=[],
        )

        code = self._run_cli(["nuclei", "--target", "https://authorized.target.local", "--json"])
        self.assertEqual(code, 0)

    @patch("agents.nuclei_agent.NucleiTools.is_available", return_value=False)
    def test_nuclei_binary_missing(self, mock_is_available):
        """غياب nuclei → خطأ لطيف + exit code 1"""
        code = self._run_cli(["nuclei", "--target", "https://authorized.target.local"])
        self.assertEqual(code, 1)

    def test_nuclei_out_of_scope(self):
        """نطاق خاص (RFC1918) → رفض من Scope Gate + exit code 1"""
        code = self._run_cli(["nuclei", "--target", "https://192.168.1.1"])
        self.assertEqual(code, 1)

    def test_nuclei_localhost_blocked(self):
        """localhost → رفض من Scope Gate"""
        code = self._run_cli(["nuclei", "--target", "http://localhost"])
        self.assertEqual(code, 1)

    def test_nuclei_metadata_ip_blocked(self):
        """Cloud metadata IP → رفض من Scope Gate"""
        code = self._run_cli(["nuclei", "--target", "http://169.254.169.254"])
        self.assertEqual(code, 1)

    def test_nuclei_missing_target(self):
        """غياب --target → خطأ من الـ parser"""
        code = self._run_cli(["nuclei"])
        self.assertNotEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
