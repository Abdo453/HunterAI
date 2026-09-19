"""
Unit Tests for Desktop Workspace & Artifact Exporter
===================================================
"""
import os
import json
import shutil
import tempfile
from pathlib import Path
import pytest

from hunter_ai.pipeline.desktop_exporter import DesktopExportManager


class TestDesktopExportManager:

    def test_get_desktop_dir(self):
        d = DesktopExportManager.get_desktop_dir()
        assert d is not None
        assert isinstance(d, Path)

    def test_get_target_desktop_folder(self, tmp_path):
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(DesktopExportManager, "get_desktop_dir", lambda: tmp_path)
            target_folder = DesktopExportManager.get_target_desktop_folder("sub.target-domain.com")
            assert target_folder.exists()
            assert "HunterAI_sub.target-domain.com" in str(target_folder)

    def test_export_engagement(self, tmp_path):
        desktop_dir = tmp_path / "Desktop"
        desktop_dir.mkdir(parents=True, exist_ok=True)
        artifact_dir = tmp_path / "engagement_run"
        artifact_dir.mkdir(parents=True, exist_ok=True)

        # Create dummy stage dirs and files
        (artifact_dir / "00_scope").mkdir()
        with open(artifact_dir / "00_scope" / "scope.json", "w") as f:
            f.write("{}")

        (artifact_dir / "01_osint").mkdir()
        with open(artifact_dir / "01_osint" / "google_dorks.txt", "w") as f:
            f.write("site:example.com\n")

        reports_dir = artifact_dir / "14_reports"
        reports_dir.mkdir()
        md_file = reports_dir / "report.md"
        html_file = reports_dir / "report.html"
        json_file = reports_dir / "report.json"
        with open(md_file, "w") as f: f.write("# Report")
        with open(html_file, "w") as f: f.write("<html><body>Report</body></html>")
        with open(json_file, "w") as f: f.write("[]")

        reports_dict = {
            "markdown": str(md_file),
            "html": str(html_file),
            "json": str(json_file),
        }

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(DesktopExportManager, "get_desktop_dir", lambda: desktop_dir)

            res = DesktopExportManager.export_engagement(
                domain="target.com",
                artifact_root=str(artifact_dir),
                reports_dict=reports_dict,
                subdomains=[{"subdomain": "api.target.com"}],
                live_assets=[{"url": "https://api.target.com"}],
                endpoints=[{"url": "https://api.target.com/v1/users"}],
                parameters=[{"name": "user_id"}],
                findings=[{"finding": "Test Finding", "severity": "Medium"}],
                tool_logs=[],
                workflow="full",
                profile="hunter",
            )

            assert res != ""
            target_path = Path(res)
            assert target_path.exists()
            assert (target_path / "📌_OVERVIEW.md").exists()
            assert (target_path / "📊_EXECUTIVE_REPORT.html").exists()
            assert (target_path / "📑_TECHNICAL_REPORT.md").exists()
            assert (target_path / "📋_FINDINGS.json").exists()
            assert (target_path / "02_Subdomains" / "subdomains.txt").exists()
            assert (target_path / "03_Live_Hosts_and_Services" / "live_hosts.txt").exists()
            assert (target_path / "04_Attack_Surface_and_URLs" / "all_urls.txt").exists()
            assert (target_path / "06_Vulnerabilities_and_Findings" / "confirmed_findings.json").exists()
