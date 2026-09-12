"""
HunterAI Temporal Diff Engine
Compares current engagement run (Run T) against previous runs (Run T-1)
to track attack surface drift, newly exposed assets, closed/opened ports,
route changes, and resolved or newly introduced vulnerabilities.
"""
from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("hunter_ai.diff_engine")


class EngagementDiffEngine:
    """
    Computes temporal delta between two engagement runs for a target.
    Enables Continuous Attack Surface Management (CASM) tracking.
    """

    def __init__(self, current_run_dir: str, previous_run_dir: Optional[str] = None):
        self.current_run_dir = os.path.abspath(current_run_dir)
        self.previous_run_dir = os.path.abspath(previous_run_dir) if previous_run_dir else None

    @classmethod
    def find_previous_run(cls, target_dir: str, current_run_dir: str) -> Optional[str]:
        """
        Locates the most recent engagement run directory strictly prior to current_run_dir.
        """
        if not os.path.exists(target_dir) or not os.path.isdir(target_dir):
            return None

        current_name = os.path.basename(os.path.normpath(current_run_dir))
        all_runs = []
        for entry in os.listdir(target_dir):
            entry_path = os.path.join(target_dir, entry)
            if os.path.isdir(entry_path) and entry != current_name:
                # Expecting format YYYY-MM-DD_HHMMSS
                all_runs.append(entry)

        if not all_runs:
            return None

        # Sort chronologically
        all_runs.sort()
        
        # Find runs strictly older than current_name
        older_runs = [r for r in all_runs if r < current_name]
        if older_runs:
            return os.path.join(target_dir, older_runs[-1])

        # If current name didn't sort after (e.g. custom name), return the most recent other run
        return os.path.join(target_dir, all_runs[-1])

    def _read_json(self, file_path: str) -> Optional[Any]:
        """Safely read JSON file"""
        if not os.path.exists(file_path):
            return None
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                return json.load(f)
        except Exception as e:
            logger.debug(f"Failed to read JSON at {file_path}: {e}")
            return None

    def _read_lines(self, file_path: str) -> Set[str]:
        """Safely read lines from a text file as a set of non-empty stripped strings"""
        if not os.path.exists(file_path):
            return set()
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                return {line.strip() for line in f if line.strip() and not line.startswith("#")}
        except Exception as e:
            logger.debug(f"Failed to read lines at {file_path}: {e}")
            return set()

    def _extract_subdomains(self, run_dir: str) -> Set[str]:
        """Extract all discovered subdomains from a run directory"""
        subdomains: Set[str] = set()
        sub_dir = os.path.join(run_dir, "02_subdomains")
        if not os.path.exists(sub_dir):
            return subdomains

        for fname in os.listdir(sub_dir):
            fpath = os.path.join(sub_dir, fname)
            if fname.endswith(".json"):
                data = self._read_json(fpath)
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict):
                            val = item.get("asset") or item.get("subdomain") or item.get("host")
                            if val:
                                subdomains.add(str(val).lower())
                        elif isinstance(item, str):
                            subdomains.add(item.lower())
                elif isinstance(data, dict):
                    for sub in data.get("subdomains", []):
                        subdomains.add(str(sub).lower())
            elif fname.endswith(".txt"):
                subdomains.update(s.lower() for s in self._read_lines(fpath))
        return subdomains

    def _extract_live_hosts(self, run_dir: str) -> Dict[str, Dict[str, Any]]:
        """Extract alive HTTP/HTTPS services {url: metadata}"""
        live: Dict[str, Dict[str, Any]] = {}
        alive_dir = os.path.join(run_dir, "04_alive")
        if not os.path.exists(alive_dir):
            return live

        for fname in os.listdir(alive_dir):
            fpath = os.path.join(alive_dir, fname)
            if fname.endswith(".json"):
                data = self._read_json(fpath)
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict) and "url" in item:
                            live[item["url"]] = item
            elif fname.endswith(".txt"):
                for line in self._read_lines(fpath):
                    if line.startswith("http://") or line.startswith("https://"):
                        if line not in live:
                            live[line] = {"url": line}
        return live

    def _extract_ports(self, run_dir: str) -> Set[str]:
        """Extract open host:port combinations"""
        ports: Set[str] = set()
        ports_dir = os.path.join(run_dir, "05_ports")
        if not os.path.exists(ports_dir):
            return ports

        for fname in os.listdir(ports_dir):
            fpath = os.path.join(ports_dir, fname)
            if fname.endswith(".json"):
                data = self._read_json(fpath)
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict):
                            host = item.get("host", "")
                            port = item.get("port", "")
                            if host and port:
                                ports.add(f"{host}:{port}")
            elif fname.endswith(".txt"):
                for line in self._read_lines(fpath):
                    if ":" in line:
                        ports.add(line)
        return ports

    def _extract_endpoints(self, run_dir: str) -> Set[str]:
        """Extract crawled / discovered endpoints"""
        endpoints: Set[str] = set()
        urls_dir = os.path.join(run_dir, "07_urls")
        if not os.path.exists(urls_dir):
            return endpoints

        for fname in os.listdir(urls_dir):
            fpath = os.path.join(urls_dir, fname)
            if fname.endswith(".json"):
                data = self._read_json(fpath)
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict):
                            val = item.get("url") or item.get("path")
                            if val:
                                endpoints.add(str(val))
                        elif isinstance(item, str):
                            endpoints.add(item)
            elif fname.endswith(".txt"):
                endpoints.update(self._read_lines(fpath))
        return endpoints

    def _extract_parameters(self, run_dir: str) -> Set[str]:
        """Extract parameters {param_name or endpoint?param}"""
        parameters: Set[str] = set()
        param_dir = os.path.join(run_dir, "08_parameters")
        if not os.path.exists(param_dir):
            return parameters

        for fname in os.listdir(param_dir):
            fpath = os.path.join(param_dir, fname)
            if fname.endswith(".json"):
                data = self._read_json(fpath)
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict):
                            param = item.get("parameter")
                            endpoint = item.get("endpoint", "")
                            if param:
                                parameters.add(f"{endpoint}?{param}" if endpoint else str(param))
            elif fname.endswith(".txt"):
                parameters.update(self._read_lines(fpath))
        return parameters

    def _extract_findings(self, run_dir: str) -> Dict[str, Dict[str, Any]]:
        """Extract findings keyed by signature (vuln_type + endpoint + param)"""
        findings: Dict[str, Dict[str, Any]] = {}
        reports_dir = os.path.join(run_dir, "14_reports")
        final_file = os.path.join(reports_dir, "final_findings.json")

        data = self._read_json(final_file)
        if not data:
            # Fallback to 12_vulnerabilities
            vuln_file = os.path.join(run_dir, "12_vulnerabilities", "vulnerabilities_all.parsed.json")
            data = self._read_json(vuln_file)

        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    vuln_type = item.get("vuln_type") or item.get("finding", "Unknown")
                    endpoint = item.get("endpoint", "")
                    param = item.get("parameter", "")
                    sig = f"{vuln_type}::{endpoint}::{param}"
                    findings[sig] = item
        return findings

    def compute_diff(self) -> Dict[str, Any]:
        """Computes complete delta between current and previous engagement runs"""
        cur_ts = os.path.basename(self.current_run_dir)
        prev_ts = os.path.basename(self.previous_run_dir) if self.previous_run_dir else None

        if not self.previous_run_dir or not os.path.exists(self.previous_run_dir):
            # Baseline run
            cur_subs = sorted(list(self._extract_subdomains(self.current_run_dir)))
            cur_live = self._extract_live_hosts(self.current_run_dir)
            cur_ports = sorted(list(self._extract_ports(self.current_run_dir)))
            cur_urls = sorted(list(self._extract_endpoints(self.current_run_dir)))
            cur_params = sorted(list(self._extract_parameters(self.current_run_dir)))
            cur_findings = self._extract_findings(self.current_run_dir)

            diff_result = {
                "is_baseline": True,
                "current_run": cur_ts,
                "previous_run": None,
                "timestamp_utc": datetime.utcnow().isoformat() + "Z",
                "summary": {
                    "subdomains_count": len(cur_subs),
                    "live_hosts_count": len(cur_live),
                    "ports_count": len(cur_ports),
                    "endpoints_count": len(cur_urls),
                    "parameters_count": len(cur_params),
                    "findings_count": len(cur_findings),
                    "new_assets_detected": len(cur_subs),
                    "new_vulnerabilities_detected": len(cur_findings),
                },
                "subdomains": {
                    "added": cur_subs,
                    "removed": [],
                    "current_total": len(cur_subs),
                    "previous_total": 0,
                },
                "live_hosts": {
                    "added": list(cur_live.keys()),
                    "removed": [],
                    "status_changes": [],
                    "current_total": len(cur_live),
                    "previous_total": 0,
                },
                "ports": {
                    "added": cur_ports,
                    "closed": [],
                    "current_total": len(cur_ports),
                    "previous_total": 0,
                },
                "endpoints": {
                    "added": cur_urls,
                    "current_total": len(cur_urls),
                    "previous_total": 0,
                },
                "parameters": {
                    "added": cur_params,
                    "current_total": len(cur_params),
                    "previous_total": 0,
                },
                "findings": {
                    "new": list(cur_findings.values()),
                    "resolved": [],
                    "persistent": [],
                    "current_total": len(cur_findings),
                    "previous_total": 0,
                }
            }
            return diff_result

        # Both runs exist -> compute deltas
        cur_subs = self._extract_subdomains(self.current_run_dir)
        prev_subs = self._extract_subdomains(self.previous_run_dir)
        added_subs = sorted(list(cur_subs - prev_subs))
        removed_subs = sorted(list(prev_subs - cur_subs))

        cur_live = self._extract_live_hosts(self.current_run_dir)
        prev_live = self._extract_live_hosts(self.previous_run_dir)
        cur_urls_set = set(cur_live.keys())
        prev_urls_set = set(prev_live.keys())
        added_live = sorted(list(cur_urls_set - prev_urls_set))
        removed_live = sorted(list(prev_urls_set - cur_urls_set))

        # Check status code changes on common live hosts
        status_changes = []
        for common_url in cur_urls_set.intersection(prev_urls_set):
            c_code = cur_live[common_url].get("status_code")
            p_code = prev_live[common_url].get("status_code")
            if c_code and p_code and c_code != p_code:
                status_changes.append({
                    "url": common_url,
                    "previous_status": p_code,
                    "current_status": c_code,
                })

        cur_ports = self._extract_ports(self.current_run_dir)
        prev_ports = self._extract_ports(self.previous_run_dir)
        added_ports = sorted(list(cur_ports - prev_ports))
        closed_ports = sorted(list(prev_ports - cur_ports))

        cur_endpoints = self._extract_endpoints(self.current_run_dir)
        prev_endpoints = self._extract_endpoints(self.previous_run_dir)
        added_endpoints = sorted(list(cur_endpoints - prev_endpoints))

        cur_params = self._extract_parameters(self.current_run_dir)
        prev_params = self._extract_parameters(self.previous_run_dir)
        added_params = sorted(list(cur_params - prev_params))

        cur_findings = self._extract_findings(self.current_run_dir)
        prev_findings = self._extract_findings(self.previous_run_dir)
        cur_sigs = set(cur_findings.keys())
        prev_sigs = set(prev_findings.keys())

        new_finding_sigs = cur_sigs - prev_sigs
        resolved_finding_sigs = prev_sigs - cur_sigs
        persistent_sigs = cur_sigs.intersection(prev_sigs)

        diff_result = {
            "is_baseline": False,
            "current_run": cur_ts,
            "previous_run": prev_ts,
            "timestamp_utc": datetime.utcnow().isoformat() + "Z",
            "summary": {
                "subdomains_drift": f"+{len(added_subs)} / -{len(removed_subs)}",
                "live_hosts_drift": f"+{len(added_live)} / -{len(removed_live)}",
                "ports_drift": f"+{len(added_ports)} / -{len(closed_ports)}",
                "new_endpoints_count": len(added_endpoints),
                "new_parameters_count": len(added_params),
                "new_vulnerabilities_count": len(new_finding_sigs),
                "resolved_vulnerabilities_count": len(resolved_finding_sigs),
                "persistent_vulnerabilities_count": len(persistent_sigs),
            },
            "subdomains": {
                "added": added_subs,
                "removed": removed_subs,
                "current_total": len(cur_subs),
                "previous_total": len(prev_subs),
            },
            "live_hosts": {
                "added": added_live,
                "removed": removed_live,
                "status_changes": status_changes,
                "current_total": len(cur_live),
                "previous_total": len(prev_live),
            },
            "ports": {
                "added": added_ports,
                "closed": closed_ports,
                "current_total": len(cur_ports),
                "previous_total": len(prev_ports),
            },
            "endpoints": {
                "added": added_endpoints,
                "current_total": len(cur_endpoints),
                "previous_total": len(prev_endpoints),
            },
            "parameters": {
                "added": added_params,
                "current_total": len(cur_params),
                "previous_total": len(prev_params),
            },
            "findings": {
                "new": [cur_findings[s] for s in sorted(list(new_finding_sigs))],
                "resolved": [prev_findings[s] for s in sorted(list(resolved_finding_sigs))],
                "persistent": [cur_findings[s] for s in sorted(list(persistent_sigs))],
                "current_total": len(cur_findings),
                "previous_total": len(prev_findings),
            }
        }
        return diff_result

    def generate_markdown_report(self, diff_data: Dict[str, Any], target: str) -> str:
        """Renders temporal diff into a clean GitHub-style Markdown report"""
        lines = [
            f"# 🔄 HunterAI Temporal Diff & Attack Surface Drift: {target}",
            f"- **Current Run (T)**: `{diff_data.get('current_run')}`",
            f"- **Previous Run (T-1)**: `{diff_data.get('previous_run') or 'None (Baseline Run)'}`",
            f"- **Generated At**: `{diff_data.get('timestamp_utc')}`\n",
        ]

        if diff_data.get("is_baseline"):
            lines.append("> [!NOTE]")
            lines.append("> **Baseline Engagement Established**: This is the initial scan for this target. All discovered assets and findings constitute the attack surface baseline.\n")
            lines.append("## Baseline Summary")
            lines.append("| Metric | Discovered Count |")
            lines.append("| :--- | :--- |")
            sum_data = diff_data.get("summary", {})
            for k, v in sum_data.items():
                lines.append(f"| `{k}` | **{v}** |")
            return "\n".join(lines)

        sum_data = diff_data.get("summary", {})
        lines.append("## 📊 Attack Surface Drift Summary\n")
        lines.append("| Asset Dimension | Drift (Delta) | Previous Total | Current Total |")
        lines.append("| :--- | :--- | :--- | :--- |")
        lines.append(f"| **Subdomains** | `{sum_data.get('subdomains_drift')}` | {diff_data['subdomains']['previous_total']} | **{diff_data['subdomains']['current_total']}** |")
        lines.append(f"| **Live Hosts** | `{sum_data.get('live_hosts_drift')}` | {diff_data['live_hosts']['previous_total']} | **{diff_data['live_hosts']['current_total']}** |")
        lines.append(f"| **Open Ports** | `{sum_data.get('ports_drift')}` | {diff_data['ports']['previous_total']} | **{diff_data['ports']['current_total']}** |")
        lines.append(f"| **Endpoints** | `+{sum_data.get('new_endpoints_count')}` | {diff_data['endpoints']['previous_total']} | **{diff_data['endpoints']['current_total']}** |")
        lines.append(f"| **Parameters** | `+{sum_data.get('new_parameters_count')}` | {diff_data['parameters']['previous_total']} | **{diff_data['parameters']['current_total']}** |")
        lines.append(f"| **New Vulns** | `+{sum_data.get('new_vulnerabilities_count')}` | {diff_data['findings']['previous_total']} | **{diff_data['findings']['current_total']}** |")
        lines.append(f"| **Resolved Vulns** | `-{sum_data.get('resolved_vulnerabilities_count')}` | - | - |\n")

        # Newly Discovered Subdomains
        new_subs = diff_data["subdomains"]["added"]
        if new_subs:
            lines.append("### 🌐 Newly Discovered Subdomains")
            for sub in new_subs[:50]:
                lines.append(f"- `{sub}`")
            if len(new_subs) > 50:
                lines.append(f"- *...and {len(new_subs) - 50} more*")
            lines.append("")

        # Removed Subdomains
        rem_subs = diff_data["subdomains"]["removed"]
        if rem_subs:
            lines.append("### ❌ Decommissioned / Unreachable Subdomains")
            for sub in rem_subs[:50]:
                lines.append(f"- `~{sub}~`")
            lines.append("")

        # Newly Opened Ports
        new_ports = diff_data["ports"]["added"]
        if new_ports:
            lines.append("> [!WARNING]")
            lines.append("> **Newly Opened Ports Detected**:")
            for p in new_ports:
                lines.append(f"> - `{p}`")
            lines.append("")

        # Closed Ports
        closed_ports = diff_data["ports"]["closed"]
        if closed_ports:
            lines.append("### 🔒 Closed Ports")
            for p in closed_ports:
                lines.append(f"- `{p}`")
            lines.append("")

        # Security Findings Drift
        new_findings = diff_data["findings"]["new"]
        if new_findings:
            lines.append("> [!CAUTION]")
            lines.append(f"> **{len(new_findings)} New Vulnerabilit{'ies' if len(new_findings) > 1 else 'y'} Detected!**")
            for f in new_findings:
                lines.append(f"> - **{f.get('finding', 'Unknown')}** on `{f.get('endpoint', '')}` ({f.get('severity', 'Medium')})")
            lines.append("")

        resolved_findings = diff_data["findings"]["resolved"]
        if resolved_findings:
            lines.append("> [!TIP]")
            lines.append(f"> **{len(resolved_findings)} Vulnerabilit{'ies' if len(resolved_findings) > 1 else 'y'} Resolved / Remediated:**")
            for f in resolved_findings:
                lines.append(f"> - `{f.get('finding', 'Unknown')}` on `{f.get('endpoint', '')}`")
            lines.append("")

        return "\n".join(lines)

    def write_diff_reports(self, target: str) -> Tuple[str, str]:
        """
        Computes diff and writes both diff_report.json and diff_report.md to 14_reports/
        """
        diff_data = self.compute_diff()
        reports_dir = os.path.join(self.current_run_dir, "14_reports")
        os.makedirs(reports_dir, exist_ok=True)

        json_path = os.path.join(reports_dir, "diff_report.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(diff_data, f, indent=2, default=str)

        md_content = self.generate_markdown_report(diff_data, target)
        md_path = os.path.join(reports_dir, "diff_report.md")
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(md_content)

        return json_path, md_path
