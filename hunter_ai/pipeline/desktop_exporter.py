"""
HunterAI Desktop Workspace & Artifact Exporter
==============================================
Automatically generates a cleanly structured, beautifully organized workspace
directly on the user's Desktop for every target scan.

Folder Structure:
  ~/Desktop/HunterAI_{target}/
    ├── 📊_EXECUTIVE_REPORT.html
    ├── 📑_TECHNICAL_REPORT.md
    ├── 📌_OVERVIEW.md
    ├── 00_Preflight_and_Scope/
    ├── 01_OSINT_and_Dorks/
    ├── 02_Subdomains/
    ├── 03_Live_Hosts_and_Services/
    ├── 04_Attack_Surface_and_URLs/
    ├── 05_Browser_and_Screenshots/
    ├── 06_Vulnerabilities_and_Findings/
    ├── 07_Reports/
    └── 08_Raw_Tool_Logs/
"""
from __future__ import annotations

import json
import logging
import os
import re
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("hunter_ai.desktop_exporter")


class DesktopExportManager:
    """
    Manages exporting structured engagement artifacts directly to a clean Desktop folder.
    """

    @staticmethod
    def get_desktop_dir() -> Path:
        """Locates or creates the user's Desktop directory across Windows / Linux / macOS."""
        # Check standard user home Desktop
        desktop = Path.home() / "Desktop"
        if desktop.is_dir():
            return desktop

        # Check XDG user dir on Linux
        xdg_desktop = os.getenv("XDG_DESKTOP_DIR")
        if xdg_desktop and os.path.isdir(xdg_desktop):
            return Path(xdg_desktop)

        # In Linux container / root / headless environment: try creating ~/Desktop
        try:
            desktop.mkdir(parents=True, exist_ok=True)
            return desktop
        except Exception:
            pass

        # Fallback to local workspace Desktop_Exports
        fallback = Path("data") / "Desktop_Exports"
        fallback.mkdir(parents=True, exist_ok=True)
        return fallback

    @classmethod
    def get_target_desktop_folder(cls, domain: str) -> Path:
        """Returns the target-specific folder on Desktop."""
        desktop = cls.get_desktop_dir()
        clean_name = re.sub(r'[^a-zA-Z0-9_.-]', '_', domain).strip('._')
        target_folder = desktop / f"HunterAI_{clean_name}"
        target_folder.mkdir(parents=True, exist_ok=True)
        return target_folder

    @classmethod
    def export_engagement(
        cls,
        domain: str,
        artifact_root: str,
        reports_dict: Dict[str, Any],
        subdomains: List[Any],
        live_assets: List[Any],
        endpoints: List[Any],
        parameters: List[Any],
        findings: List[Any],
        tool_logs: List[str],
        workflow: str = "full",
        profile: str = "hunter",
        ai_status: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Populates the formatted Desktop target folder with categorized artifacts.
        """
        try:
            target_dir = cls.get_target_desktop_folder(domain)
            artifact_path = Path(artifact_root)

            # Subfolders layout
            folders = {
                "00_Preflight_and_Scope": target_dir / "00_Preflight_and_Scope",
                "01_OSINT_and_Dorks": target_dir / "01_OSINT_and_Dorks",
                "02_Subdomains": target_dir / "02_Subdomains",
                "03_Live_Hosts_and_Services": target_dir / "03_Live_Hosts_and_Services",
                "04_Attack_Surface_and_URLs": target_dir / "04_Attack_Surface_and_URLs",
                "05_Browser_and_Screenshots": target_dir / "05_Browser_and_Screenshots",
                "06_Vulnerabilities_and_Findings": target_dir / "06_Vulnerabilities_and_Findings",
                "07_Reports": target_dir / "07_Reports",
                "08_Burp_Suite": target_dir / "08_Burp_Suite",
                "09_Raw_Tool_Logs": target_dir / "09_Raw_Tool_Logs",
            }
            for f in folders.values():
                f.mkdir(parents=True, exist_ok=True)

            # ── 1. Copy Preflight & Scope ─────────────────────────────────────
            for src_folder in ["00_preflight", "00_scope"]:
                src = artifact_path / src_folder
                if src.is_dir():
                    for item in src.glob("*"):
                        if item.is_file():
                            shutil.copy2(item, folders["00_Preflight_and_Scope"] / item.name)

            # ── 2. Copy OSINT & Dorks ─────────────────────────────────────────
            src_osint = artifact_path / "01_osint"
            if src_osint.is_dir():
                for item in src_osint.glob("*"):
                    if item.is_file():
                        shutil.copy2(item, folders["01_OSINT_and_Dorks"] / item.name)

            # ── 3. Subdomains list & JSON ─────────────────────────────────────
            sub_names = sorted(list({
                s.subdomain if hasattr(s, "subdomain") else (s.get("subdomain") if isinstance(s, dict) else str(s))
                for s in subdomains if s
            }))
            with open(folders["02_Subdomains"] / "subdomains.txt", "w", encoding="utf-8") as f:
                f.write("\n".join(sub_names) + ("\n" if sub_names else ""))

            sub_records = [
                s.model_dump() if hasattr(s, "model_dump") else s
                for s in subdomains
            ]
            with open(folders["02_Subdomains"] / "subdomains.json", "w", encoding="utf-8") as f:
                json.dump(sub_records, f, indent=2, default=str)

            src_sub = artifact_path / "02_subdomains"
            if src_sub.is_dir():
                for item in src_sub.glob("*"):
                    if item.is_file():
                        shutil.copy2(item, folders["02_Subdomains"] / item.name)

            # ── 4. Live Hosts & Services ──────────────────────────────────────
            live_urls = sorted(list({
                a.url if hasattr(a, "url") else (a.get("url") if isinstance(a, dict) else str(a))
                for a in live_assets if a
            }))
            with open(folders["03_Live_Hosts_and_Services"] / "live_hosts.txt", "w", encoding="utf-8") as f:
                f.write("\n".join(live_urls) + ("\n" if live_urls else ""))

            live_records = [
                a.model_dump() if hasattr(a, "model_dump") else a
                for a in live_assets
            ]
            with open(folders["03_Live_Hosts_and_Services"] / "live_assets.json", "w", encoding="utf-8") as f:
                json.dump(live_records, f, indent=2, default=str)

            for src_f in ["04_alive", "05_ports", "11_technology"]:
                src = artifact_path / src_f
                if src.is_dir():
                    for item in src.glob("*"):
                        if item.is_file():
                            shutil.copy2(item, folders["03_Live_Hosts_and_Services"] / item.name)

            # ── 5. Attack Surface & URLs ──────────────────────────────────────
            ep_urls = sorted(list({
                e.url if hasattr(e, "url") else (e.get("url") if isinstance(e, dict) else str(e))
                for e in endpoints if e
            }))
            with open(folders["04_Attack_Surface_and_URLs"] / "all_urls.txt", "w", encoding="utf-8") as f:
                f.write("\n".join(ep_urls) + ("\n" if ep_urls else ""))

            ep_records = [
                e.model_dump() if hasattr(e, "model_dump") else e
                for e in endpoints
            ]
            with open(folders["04_Attack_Surface_and_URLs"] / "endpoints.json", "w", encoding="utf-8") as f:
                json.dump(ep_records, f, indent=2, default=str)

            param_records = [
                p.model_dump() if hasattr(p, "model_dump") else p
                for p in parameters
            ]
            with open(folders["04_Attack_Surface_and_URLs"] / "parameters.json", "w", encoding="utf-8") as f:
                json.dump(param_records, f, indent=2, default=str)

            for src_f in ["06_content", "07_urls", "08_parameters", "09_javascript", "10_api"]:
                src = artifact_path / src_f
                if src.is_dir():
                    for item in src.glob("*"):
                        if item.is_file():
                            shutil.copy2(item, folders["04_Attack_Surface_and_URLs"] / item.name)

            # ── 6. Browser & Screenshots ──────────────────────────────────────
            for src_f in ["15_browser", "data/screenshots"]:
                src = artifact_path / src_f if "data" not in src_f else Path(src_f)
                if src.is_dir():
                    for item in src.glob("*"):
                        if item.is_file():
                            shutil.copy2(item, folders["05_Browser_and_Screenshots"] / item.name)

            # ── 7. Vulnerabilities & Findings ─────────────────────────────────
            findings_records = [
                fn.model_dump() if hasattr(fn, "model_dump") else fn
                for fn in findings
            ]
            with open(folders["06_Vulnerabilities_and_Findings"] / "confirmed_findings.json", "w", encoding="utf-8") as f:
                json.dump(findings_records, f, indent=2, default=str)

            for src_f in ["12_vulnerabilities", "13_evidence"]:
                src = artifact_path / src_f
                if src.is_dir():
                    for item in src.glob("*"):
                        if item.is_file():
                            shutil.copy2(item, folders["06_Vulnerabilities_and_Findings"] / item.name)

            # ── 8. Reports ────────────────────────────────────────────────────
            for src_f in ["09_reports", "14_reports"]:
                src = artifact_path / src_f
                if src.is_dir():
                    for item in src.glob("*"):
                        if item.is_file():
                            shutil.copy2(item, folders["07_Reports"] / item.name)

            # ── 9. Burp Suite Traffic & Experiments ───────────────────────────
            for src_f in ["08_burp_suite"]:
                src = artifact_path / src_f
                if src.is_dir():
                    for item in src.glob("*"):
                        if item.is_file():
                            shutil.copy2(item, folders["08_Burp_Suite"] / item.name)

            # Copy burp specific files from 04_attack_surface and 12_vulnerabilities
            for extra_src in [
                artifact_path / "04_attack_surface" / "burp_traffic.json",
                artifact_path / "12_vulnerabilities" / "burp_repeater_experiments.json",
                artifact_path / "burp_traffic.db"
            ]:
                if extra_src.is_file():
                    try:
                        shutil.copy2(extra_src, folders["08_Burp_Suite"] / extra_src.name)
                    except Exception:
                        pass

            # Copy top-level Master Reports directly to root of target folder
            md_src = reports_dict.get("markdown")
            html_src = reports_dict.get("html")
            json_src = reports_dict.get("json")
            diff_src = reports_dict.get("diff_md")

            if md_src and os.path.isfile(md_src):
                shutil.copy2(md_src, target_dir / "📑_TECHNICAL_REPORT.md")
            if html_src and os.path.isfile(html_src):
                shutil.copy2(html_src, target_dir / "📊_EXECUTIVE_REPORT.html")
            if json_src and os.path.isfile(json_src):
                shutil.copy2(json_src, target_dir / "📋_FINDINGS.json")
            if diff_src and os.path.isfile(diff_src):
                shutil.copy2(diff_src, target_dir / "📈_TEMPORAL_DIFF.md")

            # ── 10. Tool Logs ─────────────────────────────────────────────────
            for tl in tool_logs:
                if tl and os.path.isfile(tl):
                    try:
                        shutil.copy2(tl, folders["09_Raw_Tool_Logs"] / os.path.basename(tl))
                    except Exception:
                        pass

            # ── 11. Generate Top-Level OVERVIEW.md ────────────────────────────
            now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            ai_mode_str = "AI_POWERED (Local Cognitive Triad)" if (ai_status and ai_status.get("allowed") and not ai_status.get("degraded")) else "DEGRADED_MODE (Deterministic Heuristics)"

            overview_content = f"""# 🎯 HunterAI Security Engagement Workspace

## Target: `{domain}`
- **Scan Date & Time:** `{now_str}`
- **Workflow:** `{workflow.upper()}` | **Profile:** `{profile}`
- **Cognitive Engine:** `{ai_mode_str}`

---

## 📊 Summary of Discoveries

| Metric | Count | Primary File Location |
| :--- | :--- | :--- |
| **Discovered Subdomains** | `{len(sub_names)}` | `02_Subdomains/subdomains.txt` |
| **Live Web Hosts** | `{len(live_urls)}` | `03_Live_Hosts_and_Services/live_hosts.txt` |
| **Attack Surface URLs** | `{len(ep_urls)}` | `04_Attack_Surface_and_URLs/all_urls.txt` |
| **Parameters Cataloged** | `{len(parameters)}` | `04_Attack_Surface_and_URLs/parameters.json` |
| **Confirmed Vulnerabilities** | `{len(findings)}` | `06_Vulnerabilities_and_Findings/` |

---

## 📁 Workspace Directory Map

```text
HunterAI_{domain}/
├── 📊_EXECUTIVE_REPORT.html       -> Interactive Visual Dashboard (Open in Browser)
├── 📑_TECHNICAL_REPORT.md         -> Detailed Vulnerability & CVSS Report
├── 📋_FINDINGS.json               -> Structured JSON Machine-Readable Findings
├── 📌_OVERVIEW.md                 -> This Master Workspace Summary
│
├── 📁 00_Preflight_and_Scope/     -> AI Status, Scope Policy & Program Metadata
├── 📁 01_OSINT_and_Dorks/         -> Google Dorks, GitHub Dorks & OSINT Intel
├── 📁 02_Subdomains/              -> Subdomains (TXT & JSON)
├── 📁 03_Live_Hosts_and_Services/ -> Live Endpoints, Open Ports & Tech Stack
├── 📁 04_Attack_Surface_and_URLs/ -> Crawled Endpoints, Parameters & API Routes
├── 📁 05_Browser_and_Screenshots/ -> Headless Browser Screenshots & Session Data
├── 📁 06_Vulnerabilities_and_Findings/ -> Verified Flaws, PoCs & Evidences
├── 📁 07_Reports/                 -> Intermediate and Final Markdown/HTML Reports
└── 📁 08_Raw_Tool_Logs/           -> Complete Unmodified Tool Output Transcripts
```

---
*Generated autonomously by HunterAI Master Pipeline.*
"""
            with open(target_dir / "📌_OVERVIEW.md", "w", encoding="utf-8") as f:
                f.write(overview_content)

            target_dir_str = str(target_dir)
            cls.print_export_banner(target_dir_str, domain, len(sub_names), len(live_urls), len(ep_urls), len(findings))
            return target_dir_str

        except Exception as e:
            logger.error(f"Failed to generate Desktop workspace export: {e}", exc_info=True)
            return ""

    @classmethod
    def print_export_banner(cls, target_path: str, domain: str, subs: int, hosts: int, urls: int, findings: int):
        """Prints a structured banner confirming Desktop export creation."""
        sep = "═" * 72
        print(f"\n╔{sep}╗")
        print(f"║ 📁 HUNTERAI :: DESKTOP WORKSPACE CREATED                             ║")
        print(f"╠{sep}╣")
        print(f"║  Target Domain : {domain:<51} ║")
        print(f"║  Desktop Folder: {target_path:<51} ║")
        print(f"║  Stats Summary : {subs} Subdomains | {hosts} Live Hosts | {urls} URLs | {findings} Findings ║")
        print(f"╠{sep}╣")
        print(f"║  Top-Level Reports:                                                    ║")
        print(f"║    • 📊_EXECUTIVE_REPORT.html   (Open in your browser for dashboard)   ║")
        print(f"║    • 📑_TECHNICAL_REPORT.md     (Comprehensive bug bounty markdown)    ║")
        print(f"║    • 📌_OVERVIEW.md             (Target stats & organized directory)   ║")
        print(f"║  Organized Subfolders:                                                 ║")
        print(f"║    • 00_Preflight/  01_OSINT/  02_Subdomains/  03_Live_Hosts/          ║")
        print(f"║    • 04_Attack_Surface/  05_Screenshots/  06_Findings/  08_Logs/       ║")
        print(f"╚{sep}╝\n")
