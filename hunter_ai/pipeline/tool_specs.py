"""
HunterAI Master Tool Registry & Specifications
Defines every tool in the Master Bug Bounty Pipeline with:
purpose / input / output / prerequisites / timeout / fallback / parser / confidence / next_stage / risk_level
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from tools.tool_manager import ToolManager, ToolResult

logger = logging.getLogger("hunter_ai.tool_specs")


@dataclass
class ToolSpec:
    name: str
    stage: str
    purpose: str
    input_desc: str
    output_desc: str
    command_template: str
    prerequisites: List[str]
    timeout: int
    fallback_tool: Optional[str] = None
    fallback_handler: Optional[Callable[..., Any]] = None
    parser: Optional[Callable[[str], Any]] = None
    confidence: float = 0.85
    next_stage: str = "NEXT"
    risk_level: str = "AUDIT"  # SAFE, AUDIT, ACTIVE


class MasterToolRegistry:
    """
    Central Master Tool Registry with automatic fallbacks and structured parsers.
    Knows when an external tool is missing and routes seamlessly to python fallbacks.
    """

    def __init__(self, tool_manager: Optional[ToolManager] = None):
        self.tm = tool_manager or ToolManager()
        self.specs: Dict[str, ToolSpec] = {}
        self._init_master_specs()

    def _init_master_specs(self):
        # 1. Subfinder
        self.specs["subfinder"] = ToolSpec(
            name="subfinder",
            stage="01_PASSIVE_RECON",
            purpose="Fast passive subdomain enumeration from public APIs",
            input_desc="Root domain",
            output_desc="List of unique subdomains",
            command_template="subfinder -d {domain} -silent",
            prerequisites=["subfinder"],
            timeout=90,
            fallback_tool="crtsh",
            parser=lambda out: [l.strip().lower() for l in out.splitlines() if l.strip() and "." in l],
            confidence=0.90,
            next_stage="05_NORMALIZE",
            risk_level="SAFE"
        )

        # 1b. Subfinder Deep (All OSINT Sources)
        self.specs["subfinder_deep"] = ToolSpec(
            name="subfinder_deep",
            stage="01_PASSIVE_RECON",
            purpose="Comprehensive passive subdomain enumeration querying all sources (-all)",
            input_desc="Root domain",
            output_desc="Comprehensive list of unique subdomains",
            command_template="subfinder -d {domain} -all -silent",
            prerequisites=["subfinder"],
            timeout=300,
            fallback_tool="crtsh",
            parser=lambda out: [l.strip().lower() for l in out.splitlines() if l.strip() and "." in l],
            confidence=0.95,
            next_stage="05_NORMALIZE",
            risk_level="SAFE"
        )

        # 2. Assetfinder
        self.specs["assetfinder"] = ToolSpec(
            name="assetfinder",
            stage="01_PASSIVE_RECON",
            purpose="Subdomain enumeration via certificate transparency & archive scraping",
            input_desc="Root domain",
            output_desc="List of unique subdomains",
            command_template="assetfinder --subs-only {domain}",
            prerequisites=["assetfinder"],
            timeout=60,
            fallback_tool="crtsh",
            parser=lambda out: [l.strip().lower() for l in out.splitlines() if l.strip() and "." in l],
            confidence=0.85,
            next_stage="05_NORMALIZE",
            risk_level="SAFE"
        )

        # 3. Crt.sh (Built-in HTTP CT Logs)
        self.specs["crtsh"] = ToolSpec(
            name="crtsh",
            stage="02_CERTIFICATE_OSINT",
            purpose="Certificate Transparency logs extraction for subdomains",
            input_desc="Root domain",
            output_desc="Set of validated domain names from certificates",
            command_template="",
            prerequisites=[],
            timeout=30,
            fallback_tool=None,
            confidence=0.95,
            next_stage="05_NORMALIZE",
            risk_level="SAFE"
        )

        # 3b. Gobuster DNS Brute-force (SecLists Wordlist)
        self.specs["gobuster_dns"] = ToolSpec(
            name="gobuster_dns",
            stage="02_DNS_BRUTEFORCE",
            purpose="Active DNS subdomain brute-forcing with SecLists wordlists",
            input_desc="Target domain and wordlist",
            output_desc="Resolved subdomains",
            command_template="gobuster dns -d {domain} -w {wordlist} -q --no-error",
            prerequisites=["gobuster"],
            timeout=180,
            fallback_tool="crtsh",
            parser=lambda out: [l.split()[1].strip().lower() for l in out.splitlines() if "Found:" in l],
            confidence=0.92,
            next_stage="05_NORMALIZE",
            risk_level="AUDIT"
        )

        # 4. HTTPX Live Host Discovery
        self.specs["httpx"] = ToolSpec(
            name="httpx",
            stage="06_HTTPX_LIVE_HOSTS",
            purpose="Probing HTTP/HTTPS alive hosts, status codes, titles, servers, and technologies",
            input_desc="Subdomain or list of subdomains",
            output_desc="Structured alive hosts with metadata",
            command_template="httpx -u {target} -status-code -title -tech-detect -content-length -silent",
            prerequisites=["httpx", "httpx-toolkit"],
            timeout=60,
            fallback_tool="python_http_probe",
            confidence=0.95,
            next_stage="08_DIRECTORY_DISCOVERY",
            risk_level="SAFE"
        )

        # 5. Nmap Port & Service Discovery
        self.specs["nmap"] = ToolSpec(
            name="nmap",
            stage="07_PORT_DISCOVERY",
            purpose="Port scanning, open service detection, and service banner grabbing",
            input_desc="Clean Hostname or IP",
            output_desc="Open ports, protocol names, and service versions",
            command_template="nmap -sV -T4 --open -p 80,443,8080,8443,8000,8888,3000,5000,21,22,25,3306,5432 {host}",
            prerequisites=["nmap"],
            timeout=120,
            fallback_tool="python_socket_scan",
            parser=lambda out: [l.strip() for l in out.splitlines() if "/tcp" in l and "open" in l],
            confidence=0.98,
            next_stage="08_DIRECTORY_DISCOVERY",
            risk_level="AUDIT"
        )

        # 5b. Nmap Deep (Top 1000 Ports)
        self.specs["nmap_deep"] = ToolSpec(
            name="nmap_deep",
            stage="07_PORT_DISCOVERY",
            purpose="Deep port scanning across top 1000 ports with service version detection",
            input_desc="Clean Hostname or IP",
            output_desc="Open ports, protocol names, and service versions",
            command_template="nmap -sV -T4 --open --top-ports 1000 {host}",
            prerequisites=["nmap"],
            timeout=600,
            fallback_tool="python_socket_scan",
            parser=lambda out: [l.strip() for l in out.splitlines() if "/tcp" in l and "open" in l],
            confidence=0.98,
            next_stage="08_DIRECTORY_DISCOVERY",
            risk_level="AUDIT"
        )

        # 6. Gobuster Directory Enumeration
        self.specs["gobuster"] = ToolSpec(
            name="gobuster",
            stage="08_DIRECTORY_DISCOVERY",
            purpose="Directory and sensitive file enumeration",
            input_desc="Target base URL and wordlist",
            output_desc="Discovered paths with HTTP status codes and content lengths",
            command_template="gobuster dir -u {url} -w {wordlist} -q --no-error",
            prerequisites=["gobuster"],
            timeout=180,
            fallback_tool="python_dir_fuzz",
            parser=lambda out: [l.strip() for l in out.splitlines() if "(Status:" in l],
            confidence=0.88,
            next_stage="09_URL_DISCOVERY",
            risk_level="AUDIT"
        )

        # 7. Katana / Crawler URL Discovery
        self.specs["katana"] = ToolSpec(
            name="katana",
            stage="09_URL_DISCOVERY",
            purpose="Spidering and crawling URLs, endpoints, and form actions",
            input_desc="Live web URL",
            output_desc="List of unique internal URLs",
            command_template="katana -u {url} -silent -depth 3",
            prerequisites=["katana"],
            timeout=120,
            fallback_tool="python_crawler",
            parser=lambda out: [l.strip() for l in out.splitlines() if l.strip().startswith("http")],
            confidence=0.90,
            next_stage="10_PARAMETER_DISCOVERY",
            risk_level="SAFE"
        )

        # 8. Nuclei Triage
        self.specs["nuclei"] = ToolSpec(
            name="nuclei",
            stage="16_NUCLEI_TRIAGE",
            purpose="Template-based vulnerability, exposure, and misconfiguration scanning",
            input_desc="Live target URL",
            output_desc="Identified CVEs, exposed panels, and information disclosures",
            command_template="nuclei -u {url} -severity critical,high,medium -silent",
            prerequisites=["nuclei"],
            timeout=240,
            fallback_tool="python_exposure_check",
            parser=lambda out: [l.strip() for l in out.splitlines() if "[" in l and l.strip()],
            confidence=0.80,
            next_stage="17_VULNERABILITY_ROUTER",
            risk_level="AUDIT"
        )

        # 9. TheHarvester OSINT
        self.specs["theharvester"] = ToolSpec(
            name="theharvester",
            stage="01_PASSIVE_RECON",
            purpose="Search engine OSINT for emails, employee names, and subdomains",
            input_desc="Root domain",
            output_desc="Discovered emails, hosts, and virtual hosts",
            command_template="theHarvester -d {domain} -l 100 -b google,bing,duckduckgo,crtsh,hackertarget,otx,urlscan",
            prerequisites=["theHarvester", "theharvester"],
            timeout=120,
            fallback_tool="crtsh",
            confidence=0.85,
            next_stage="05_NORMALIZE",
            risk_level="SAFE"
        )

        # 10. Subzy Subdomain Takeover
        self.specs["subzy"] = ToolSpec(
            name="subzy",
            stage="04_SUBDOMAIN_TAKEOVER",
            purpose="Probing dangling CNAME records for vulnerable third-party services",
            input_desc="List of unique subdomains",
            output_desc="Vulnerable takeover candidates",
            command_template="subzy run --targets {targets_file} --vuln --hide_fails",
            prerequisites=["subzy"],
            timeout=120,
            fallback_tool="python_takeover_check",
            confidence=0.92,
            next_stage="06_HTTPX_LIVE_HOSTS",
            risk_level="AUDIT"
        )

        # 11. Waybackurls
        self.specs["waybackurls"] = ToolSpec(
            name="waybackurls",
            stage="09_URL_DISCOVERY",
            purpose="Fetching historical URLs from the Wayback Machine archive",
            input_desc="Target domain or host",
            output_desc="List of archived URLs",
            command_template="waybackurls {domain}",
            prerequisites=["waybackurls"],
            timeout=90,
            fallback_tool="python_wayback_fetch",
            confidence=0.90,
            next_stage="10_PARAMETER_DISCOVERY",
            risk_level="SAFE"
        )

        # 12. GAU (GetAllUrls)
        self.specs["gau"] = ToolSpec(
            name="gau",
            stage="09_URL_DISCOVERY",
            purpose="Fetching URLs from AlienVault, Wayback, and CommonCrawl",
            input_desc="Target domain",
            output_desc="List of URLs",
            command_template="gau --threads 50 {domain}",
            prerequisites=["gau"],
            timeout=90,
            fallback_tool="python_wayback_fetch",
            confidence=0.90,
            next_stage="10_PARAMETER_DISCOVERY",
            risk_level="SAFE"
        )

        # 13. Arjun Parameter Discovery
        self.specs["arjun"] = ToolSpec(
            name="arjun",
            stage="10_PARAMETER_DISCOVERY",
            purpose="Automated discovery of hidden GET and POST parameters",
            input_desc="Target URL",
            output_desc="Discovered parameter names",
            command_template="arjun -u {url} --passive -t 10",
            prerequisites=["arjun"],
            timeout=120,
            fallback_tool="python_param_extract",
            confidence=0.88,
            next_stage="17_VULNERABILITY_ROUTER",
            risk_level="AUDIT"
        )

        # 14. Dirsearch
        self.specs["dirsearch"] = ToolSpec(
            name="dirsearch",
            stage="08_DIRECTORY_DISCOVERY",
            purpose="Advanced directory search with multi-extension brute-forcing",
            input_desc="Target URL",
            output_desc="Discovered status 200/401/403 paths",
            command_template="dirsearch -u {url} -i 200,401,403 -e php,asp,aspx,jsp,json,xml,txt,log,ini,cfg,config,conf,bak,old,backup,sql,db -q",
            prerequisites=["dirsearch"],
            timeout=180,
            fallback_tool="python_dir_fuzz",
            confidence=0.90,
            next_stage="09_URL_DISCOVERY",
            risk_level="AUDIT"
        )

        # 15. WPScan
        self.specs["wpscan"] = ToolSpec(
            name="wpscan",
            stage="16_NUCLEI_TRIAGE",
            purpose="WordPress plugin, theme, and user enumeration",
            input_desc="Target WordPress URL",
            output_desc="Vulnerable plugins, users, and versions",
            command_template="wpscan --url {url} --disable-tls-checks -e at,ap,u --plugins-detection aggressive",
            prerequisites=["wpscan"],
            timeout=180,
            fallback_tool="python_wp_check",
            confidence=0.92,
            next_stage="17_VULNERABILITY_ROUTER",
            risk_level="AUDIT"
        )

        # 16. SQLMap
        self.specs["sqlmap"] = ToolSpec(
            name="sqlmap",
            stage="18_ACTIVE_TESTING",
            purpose="Automated SQL injection testing and database extraction",
            input_desc="Target URL with injection marker (*)",
            output_desc="Database type, version, and confirmation proof",
            command_template="sqlmap -u {url} --batch --random-agent --banner --dbs --ignore-code 403",
            prerequisites=["sqlmap"],
            timeout=180,
            fallback_tool="python_sqli_verify",
            confidence=0.98,
            next_stage="19_VERIFICATION",
            risk_level="ACTIVE"
        )

        # ─────────────────────────────────────────────────────────────────────────
        # 17. FFUF — Fast Web Fuzzer (Directories, Parameters, Vhosts)
        # ─────────────────────────────────────────────────────────────────────────
        self.specs["ffuf"] = ToolSpec(
            name="ffuf",
            stage="08_DIRECTORY_DISCOVERY",
            purpose="Ultra-fast multi-mode HTTP fuzzer: directories, parameters, vhosts, and content discovery",
            input_desc="Target URL with FUZZ keyword and wordlist",
            output_desc="Discovered paths, parameters, and vhosts with status codes and sizes",
            command_template="ffuf -u {url}/FUZZ -w {wordlist} -mc 200,201,204,301,302,307,401,403,405 -t 40 -of json -o /tmp/ffuf_out.json -s",
            prerequisites=["ffuf"],
            timeout=300,
            fallback_tool="python_dir_fuzz",
            parser=lambda out: [l.strip() for l in out.splitlines() if l.strip() and "Status:" in l],
            confidence=0.93,
            next_stage="09_URL_DISCOVERY",
            risk_level="AUDIT"
        )

        # 17b. FFUF Parameter Discovery mode
        self.specs["ffuf_params"] = ToolSpec(
            name="ffuf_params",
            stage="10_PARAMETER_DISCOVERY",
            purpose="Discover hidden GET/POST parameters using FFUF",
            input_desc="Target URL with FUZZ keyword substituted into parameter position",
            output_desc="Valid parameter names that produce different HTTP responses",
            command_template="ffuf -u {url}?FUZZ=testvalue -w {wordlist} -mc 200,302 -fs {content_size} -t 30 -s",
            prerequisites=["ffuf"],
            timeout=240,
            fallback_tool="python_param_extract",
            parser=lambda out: [l.strip().split(" ")[0] for l in out.splitlines() if l.strip() and "200" in l],
            confidence=0.88,
            next_stage="17_VULNERABILITY_ROUTER",
            risk_level="AUDIT"
        )

        # 17c. FFUF Vhost Discovery mode
        self.specs["ffuf_vhost"] = ToolSpec(
            name="ffuf_vhost",
            stage="02_CERTIFICATE_OSINT",
            purpose="Virtual host discovery by fuzzing Host header for hidden vhosts",
            input_desc="Base URL and wordlist of hostnames",
            output_desc="Discovered virtual hosts with different response sizes",
            command_template="ffuf -u {url} -H 'Host: FUZZ.{domain}' -w {wordlist} -mc 200,302,400 -fs {content_size} -t 30 -s",
            prerequisites=["ffuf"],
            timeout=240,
            fallback_tool="crtsh",
            parser=lambda out: [l.strip() for l in out.splitlines() if "FUZZ" in l or ".{" not in l],
            confidence=0.85,
            next_stage="05_NORMALIZE",
            risk_level="AUDIT"
        )

        # ─────────────────────────────────────────────────────────────────────────
        # 18. Feroxbuster — Recursive Directory Bruteforcer
        # ─────────────────────────────────────────────────────────────────────────
        self.specs["feroxbuster"] = ToolSpec(
            name="feroxbuster",
            stage="08_DIRECTORY_DISCOVERY",
            purpose="Fast recursive directory discovery with automatic recursion into found paths",
            input_desc="Target base URL and wordlist",
            output_desc="Recursively discovered directories and files with status codes",
            command_template="feroxbuster -u {url} -w {wordlist} --silent --status-codes 200,201,204,301,302,401,403 --depth 3 --threads 50",
            prerequisites=["feroxbuster"],
            timeout=300,
            fallback_tool="python_dir_fuzz",
            parser=lambda out: [l.strip() for l in out.splitlines() if l.strip() and any(c in l for c in ["200", "301", "401", "403"])],
            confidence=0.90,
            next_stage="09_URL_DISCOVERY",
            risk_level="AUDIT"
        )

        # ─────────────────────────────────────────────────────────────────────────
        # 19. Amass — Deep Subdomain Intelligence
        # ─────────────────────────────────────────────────────────────────────────
        self.specs["amass"] = ToolSpec(
            name="amass",
            stage="01_PASSIVE_RECON",
            purpose="Comprehensive subdomain enumeration using DNS brute-forcing, certificate transparency, and OSINT APIs",
            input_desc="Root domain",
            output_desc="Comprehensive list of subdomains from multi-source intelligence gathering",
            command_template="amass enum -passive -d {domain} -silent",
            prerequisites=["amass"],
            timeout=300,
            fallback_tool="crtsh",
            parser=lambda out: [l.strip().lower() for l in out.splitlines() if l.strip() and "." in l],
            confidence=0.95,
            next_stage="05_NORMALIZE",
            risk_level="SAFE"
        )

        # ─────────────────────────────────────────────────────────────────────────
        # 20. DNSRecon — DNS Enumeration and Zone Transfer Checks
        # ─────────────────────────────────────────────────────────────────────────
        self.specs["dnsrecon"] = ToolSpec(
            name="dnsrecon",
            stage="03_DNS_ENUM",
            purpose="DNS zone transfer attempts, record enumeration (A, MX, NS, TXT, SRV, SOA), and DNSSEC checks",
            input_desc="Target domain",
            output_desc="DNS records, zone transfer results, and subdomain enumeration",
            command_template="dnsrecon -d {domain} -t std,axfr,brt -D {wordlist} --csv /tmp/dnsrecon_out.csv -q",
            prerequisites=["dnsrecon"],
            timeout=180,
            fallback_tool="crtsh",
            parser=lambda out: [l.strip() for l in out.splitlines() if l.strip() and any(t in l for t in ["A ", "MX ", "NS ", "TXT ", "CNAME", "SOA "])],
            confidence=0.90,
            next_stage="05_NORMALIZE",
            risk_level="AUDIT"
        )

        # ─────────────────────────────────────────────────────────────────────────
        # 21. Nikto — Web Server Vulnerability Scanner
        # ─────────────────────────────────────────────────────────────────────────
        self.specs["nikto"] = ToolSpec(
            name="nikto",
            stage="16_NUCLEI_TRIAGE",
            purpose="Comprehensive web server scanner for misconfigurations, default files, dangerous headers, and CVEs",
            input_desc="Target URL",
            output_desc="Identified vulnerabilities, misconfigurations, and information disclosures",
            command_template="nikto -h {url} -nointeractive -Cgidirs all -Format txt",
            prerequisites=["nikto"],
            timeout=300,
            fallback_tool="python_exposure_check",
            parser=lambda out: [l.strip() for l in out.splitlines() if l.strip().startswith("+") and "OK" not in l],
            confidence=0.78,
            next_stage="17_VULNERABILITY_ROUTER",
            risk_level="AUDIT"
        )

        # ─────────────────────────────────────────────────────────────────────────
        # 22. Dalfox — XSS Vulnerability Scanner
        # ─────────────────────────────────────────────────────────────────────────
        self.specs["dalfox"] = ToolSpec(
            name="dalfox",
            stage="18_ACTIVE_TESTING",
            purpose="Parameter-aware XSS vulnerability scanning with DOM analysis and reflection detection",
            input_desc="Target URL with parameter",
            output_desc="Verified XSS injection points with working payloads",
            command_template="dalfox url {url} --skip-bav --no-spinner --silence",
            prerequisites=["dalfox"],
            timeout=180,
            fallback_tool="python_xss_probe",
            parser=lambda out: [l.strip() for l in out.splitlines() if "[POC]" in l or "[VERIFIED]" in l or "Triggered!" in l],
            confidence=0.95,
            next_stage="19_VERIFICATION",
            risk_level="ACTIVE"
        )

        # ─────────────────────────────────────────────────────────────────────────
        # 23. kxss — Reflected Parameter XSS Scanner
        # ─────────────────────────────────────────────────────────────────────────
        self.specs["kxss"] = ToolSpec(
            name="kxss",
            stage="18_ACTIVE_TESTING",
            purpose="Fast reflected XSS detection by testing special character reflection in HTTP responses",
            input_desc="Target URLs piped via stdin",
            output_desc="URLs reflecting dangerous characters unencoded",
            command_template="echo {url} | kxss",
            prerequisites=["kxss"],
            timeout=60,
            fallback_tool="python_xss_probe",
            parser=lambda out: [l.strip() for l in out.splitlines() if "Param:" in l or "URL:" in l],
            confidence=0.85,
            next_stage="19_VERIFICATION",
            risk_level="ACTIVE"
        )

        # ─────────────────────────────────────────────────────────────────────────
        # 24. Hakrawler — Fast Web Crawler
        # ─────────────────────────────────────────────────────────────────────────
        self.specs["hakrawler"] = ToolSpec(
            name="hakrawler",
            stage="09_URL_DISCOVERY",
            purpose="Fast, focused web crawler for links, forms, JS sources, and API endpoints",
            input_desc="Target URL",
            output_desc="Discovered URLs, forms, and API endpoints",
            command_template="echo {url} | hakrawler -depth 3 -plain",
            prerequisites=["hakrawler"],
            timeout=120,
            fallback_tool="python_crawler",
            parser=lambda out: [l.strip() for l in out.splitlines() if l.strip().startswith("http")],
            confidence=0.88,
            next_stage="10_PARAMETER_DISCOVERY",
            risk_level="SAFE"
        )

        # ─────────────────────────────────────────────────────────────────────────
        # 25. TruffleHog — Secrets & Credentials Scanner
        # ─────────────────────────────────────────────────────────────────────────
        self.specs["trufflehog"] = ToolSpec(
            name="trufflehog",
            stage="09_JAVASCRIPT",
            purpose="Deep secrets detection in git repos, S3, and web content using Shannon entropy and regex patterns",
            input_desc="GitHub repo URL or target domain URL",
            output_desc="Exposed API keys, tokens, passwords, and credentials with source location",
            command_template="trufflehog git {url} --only-verified --json",
            prerequisites=["trufflehog"],
            timeout=180,
            fallback_tool="python_secret_scan",
            parser=lambda out: [l.strip() for l in out.splitlines() if "DetectorName" in l or "Raw:" in l],
            confidence=0.92,
            next_stage="19_VERIFICATION",
            risk_level="SAFE"
        )

        # ─────────────────────────────────────────────────────────────────────────
        # 26. SSRFmap — SSRF Vulnerability Scanner
        # ─────────────────────────────────────────────────────────────────────────
        self.specs["ssrfmap"] = ToolSpec(
            name="ssrfmap",
            stage="18_ACTIVE_TESTING",
            purpose="SSRF vulnerability detection and exploitation via automatic payload injection",
            input_desc="Target URL with SSRF parameter",
            output_desc="SSRF confirmation with out-of-band interaction proof",
            command_template="python3 ssrfmap.py -r {request_file} -p {param} -m all",
            prerequisites=["ssrfmap"],
            timeout=120,
            fallback_tool="python_ssrf_probe",
            parser=lambda out: [l.strip() for l in out.splitlines() if "[+]" in l or "VULNERABLE" in l.upper()],
            confidence=0.90,
            next_stage="19_VERIFICATION",
            risk_level="ACTIVE"
        )

        # ─────────────────────────────────────────────────────────────────────────
        # 27. Httprobe — Live Host Prober
        # ─────────────────────────────────────────────────────────────────────────
        self.specs["httprobe"] = ToolSpec(
            name="httprobe",
            stage="06_HTTPX_LIVE_HOSTS",
            purpose="Fast HTTP/HTTPS alive host prober — pipes subdomain list and returns live URLs only",
            input_desc="List of subdomains from file or stdin",
            output_desc="Live HTTP/HTTPS URLs confirmed with 200/301 responses",
            command_template="cat {targets_file} | httprobe -c 50",
            prerequisites=["httprobe"],
            timeout=120,
            fallback_tool="python_http_probe",
            parser=lambda out: [l.strip() for l in out.splitlines() if l.strip().startswith("http")],
            confidence=0.95,
            next_stage="08_DIRECTORY_DISCOVERY",
            risk_level="SAFE"
        )

        # ─────────────────────────────────────────────────────────────────────────
        # 28. Shodan CLI — Public IP Intelligence
        # ─────────────────────────────────────────────────────────────────────────
        self.specs["shodan"] = ToolSpec(
            name="shodan",
            stage="01_PASSIVE_RECON",
            purpose="Shodan internet-wide scan intelligence: open ports, CVEs, banners, and exposed services",
            input_desc="Target domain or IP",
            output_desc="Open ports, banners, and known CVEs from Shodan database",
            command_template="shodan domain {domain}",
            prerequisites=["shodan"],
            timeout=30,
            fallback_tool="crtsh",
            parser=lambda out: [l.strip() for l in out.splitlines() if l.strip()],
            confidence=0.90,
            next_stage="05_NORMALIZE",
            risk_level="SAFE"
        )

    def is_available(self, tool_name: str) -> bool:
        spec = self.specs.get(tool_name)
        if not spec:
            return self.tm.is_available(tool_name)
        if not spec.prerequisites:
            return True  # Built-in python fallback available
        return any(self.tm.is_available(p) for p in spec.prerequisites)

    def print_tools_status(self, profile: str = "hunter") -> None:
        """
        Print a clear real-time tool availability diagnostic.
        Shows which tools will run natively vs fall back to python.
        """
        # Tools relevant to each profile
        PROFILE_TOOLS = {
            "hunter": [
                "crtsh", "subfinder_deep", "subfinder", "assetfinder", "amass",
                "gobuster_dns", "theharvester", "nmap_deep", "nmap",
                "ffuf", "feroxbuster", "gobuster", "dirsearch",
                "katana", "hakrawler", "waybackurls", "gau",
                "nuclei", "nikto", "dalfox", "kxss", "sqlmap",
                "subzy", "trufflehog", "httprobe", "shodan",
            ],
            "deep": [
                "subfinder_deep", "assetfinder", "amass", "gobuster_dns",
                "nmap_deep", "ffuf", "feroxbuster", "katana", "waybackurls", "gau",
                "nuclei", "nikto", "dalfox",
            ],
            "safe": ["subfinder", "gobuster", "nmap", "katana", "nuclei"],
        }
        tools_to_check = PROFILE_TOOLS.get(profile, PROFILE_TOOLS["hunter"])

        live, fallback, missing = [], [], []
        for t in tools_to_check:
            spec = self.specs.get(t)
            if spec and spec.prerequisites:
                if self.is_available(t):
                    live.append(t)
                elif spec.fallback_tool:
                    fallback.append(f"{t} → {spec.fallback_tool}")
                else:
                    missing.append(t)
            elif spec and not spec.prerequisites:
                live.append(f"{t} [built-in]")

        print("\n" + "─" * 60)
        print(f"  🛠  TOOL STATUS CHECK  (profile={profile})")
        print("─" * 60)
        if live:
            print(f"  ✅  LIVE ({len(live)}): {', '.join(live)}")
        if fallback:
            print(f"  🔄  FALLBACK ({len(fallback)}): {', '.join(fallback)}")
        if missing:
            print(f"  ❌  MISSING / NO FALLBACK ({len(missing)}): {', '.join(missing)}")
        print("─" * 60 + "\n")


    async def execute(self, tool_name: str, context: Dict[str, Any]) -> Tuple[List[Any], Optional[str]]:
        """
        Execute tool with automatic fallback handling.
        Returns: (parsed_results: List[Any], log_file: Optional[str])
        """
        spec = self.specs.get(tool_name)
        if not spec:
            # Fallback to direct tool manager execution
            cmd = context.get("command") or tool_name
            res = await self.tm.execute(cmd)
            return ([res.stdout] if res.stdout else [], res.output_file)

        mult = getattr(self, "timeout_multiplier", float(os.getenv("TOOL_TIMEOUT_MULTIPLIER", "1.0")))
        effective_timeout = int(spec.timeout * mult) if spec else 300

        # Check if primary tool is available
        if self.is_available(tool_name) and spec.command_template:
            cmd = spec.command_template.format(**context)
            res = await self.tm.execute(cmd, timeout=effective_timeout)
            parsed = spec.parser(res.stdout) if spec.parser else res.stdout.splitlines()
            return (parsed, res.output_file)

        # Otherwise, trigger fallback
        logger.info(f"Tool '{tool_name}' not available in PATH; routing to fallback: '{spec.fallback_tool}'")
        if spec.fallback_tool:
            return await self._execute_fallback(spec.fallback_tool, context)

        return ([], None)

    async def execute_artifact(
        self,
        tool_name: str,
        context: Dict[str, Any],
        engagement_mgr: Any,
        stage: str,
        input_source: Optional[str] = None
    ) -> Tuple[List[Any], Any]:
        """
        Executes tool and automatically saves the Triple Artifact Pattern via EngagementManager:
        1. {tool}.raw.txt
        2. {tool}.parsed.json
        3. {tool}.meta.json
        """
        import time
        spec = self.specs.get(tool_name)
        mult = getattr(self, "timeout_multiplier", float(os.getenv("TOOL_TIMEOUT_MULTIPLIER", "1.0")))
        effective_timeout = int(spec.timeout * mult) if spec else 300
        cmd_str = spec.command_template.format(**context) if (spec and spec.command_template) else (context.get("command") or tool_name)
        t0 = time.time()

        status = "success"
        error_msg = None
        raw_str = ""
        parsed = []

        try:
            if self.is_available(tool_name) and spec and spec.command_template:
                print(f"[*] [{stage.upper()}] ⚡ Dispatching {tool_name} (Max Timeout: {effective_timeout}s)...")
                res = await self.tm.execute(cmd_str, timeout=effective_timeout)
                raw_str = res.output
                parsed = spec.parser(res.stdout) if spec.parser else res.stdout.splitlines()
                if not res.success:
                    status = "failed"
                    error_msg = res.error or res.stderr
                duration = time.time() - t0
                print(f"[+] [{stage.upper()}] ✅ {tool_name} finished in {duration:.1f}s ({len(parsed)} items extracted)")
            elif spec and spec.fallback_tool:
                status = "fallback"
                print(f"[*] [{stage.upper()}] 🔄 {tool_name} missing from PATH; routing to fallback: '{spec.fallback_tool}'")
                logger.info(f"Tool '{tool_name}' missing; executing fallback: '{spec.fallback_tool}'")
                parsed, log_f = await self._execute_fallback(spec.fallback_tool, context)
                if log_f and os.path.isfile(log_f):
                    try:
                        with open(log_f, "r", encoding="utf-8", errors="replace") as f:
                            raw_str = f.read()
                    except Exception:
                        raw_str = f"[Fallback: {spec.fallback_tool}]\n" + "\n".join(str(p) for p in parsed)
                else:
                    raw_str = f"[Fallback: {spec.fallback_tool}]\n" + "\n".join(str(p) for p in parsed)
                duration = time.time() - t0
                print(f"[+] [{stage.upper()}] ✅ Fallback {spec.fallback_tool} finished in {duration:.1f}s ({len(parsed)} items extracted)")
            else:
                print(f"[*] [{stage.upper()}] ⚡ Running {tool_name}...")
                res = await self.tm.execute(cmd_str)
                raw_str = res.output
                parsed = [res.stdout] if res.stdout else []
                duration = time.time() - t0
                print(f"[+] [{stage.upper()}] ✅ {tool_name} finished in {duration:.1f}s")
        except Exception as e:
            status = "error"
            error_msg = str(e)
            raw_str = f"Error executing {tool_name}: {e}"
            print(f"[!] [{stage.upper()}] ❌ Error running {tool_name}: {e}")

        duration = time.time() - t0
        meta = engagement_mgr.save_tool_artifact(
            stage=stage,
            tool_name=tool_name,
            command=cmd_str,
            raw_output=raw_str,
            parsed_data=parsed,
            input_source=input_source,
            next_stage=spec.next_stage if spec else None,
            duration=duration,
            status=status,
            error=error_msg,
        )
        return (parsed, meta)


    async def _execute_fallback(self, fallback_name: str, context: Dict[str, Any]) -> Tuple[List[Any], Optional[str]]:
        """Executes designated fallback tool or built-in python routine"""
        if fallback_name == "crtsh":
            from core.playbooks.bug_bounty_methodology import BugBountyMethodology
            bb = BugBountyMethodology(self.tm)
            domain = context.get("domain") or context.get("host") or ""
            subs = await bb.fetch_crtsh_subdomains(domain)
            log_f = self.tm._save_tool_output("crtsh", f"crt.sh query for {domain}", "\n".join(subs), "", 0, 1.0)
            return (subs, log_f)

        elif fallback_name == "python_dir_fuzz":
            from tools.web_tools import WebTools
            wt = WebTools(self.tm)
            url = context.get("url") or context.get("target") or ""
            res = await wt.python_dir_fuzz(url)
            parsed = [l.strip() for l in res.stdout.splitlines() if "(Status:" in l]
            return (parsed, res.output_file)

        elif fallback_name == "python_http_probe":
            import httpx
            url = context.get("target") or context.get("url") or ""
            try:
                async with httpx.AsyncClient(verify=False, timeout=6.0, follow_redirects=True) as client:
                    resp = await client.get(url)
                    line = f"{resp.url} [{resp.status_code}] [Size: {len(resp.content)}]"
                    log_f = self.tm._save_tool_output("python_http_probe", f"probe {url}", line, "", 0, 0.5)
                    return ([line], log_f)
            except Exception:
                return ([], None)

        elif fallback_name == "python_socket_scan":
            import socket
            host = context.get("host") or context.get("domain") or "127.0.0.1"
            ports = [80, 443, 8080, 8443, 3000, 5000, 22, 21, 3306, 5432]
            open_ports = []
            for p in ports:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(1.0)
                    if s.connect_ex((host, p)) == 0:
                        open_ports.append(f"{p}/tcp   open   service")
                    s.close()
                except Exception:
                    pass
            log_f = self.tm._save_tool_output("python_socket_scan", f"socket scan {host}", "\n".join(open_ports), "", 0, 1.0)
            return (open_ports, log_f)

        elif fallback_name == "python_wayback_fetch":
            import httpx
            domain = context.get("domain") or context.get("host") or ""
            cdx_url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&collapse=urlkey&output=text&fl=original"
            try:
                async with httpx.AsyncClient(verify=False, timeout=12.0) as client:
                    resp = await client.get(cdx_url)
                    urls = [l.strip() for l in resp.text.splitlines() if l.strip().startswith("http")][:100]
                    log_f = self.tm._save_tool_output("python_wayback_fetch", f"wayback cdx {domain}", "\n".join(urls), "", 0, 1.5)
                    return (urls, log_f)
            except Exception:
                return ([], None)

        elif fallback_name == "python_wp_check":
            from core.playbooks.bug_bounty_methodology import BugBountyMethodology
            bb = BugBountyMethodology(self.tm)
            url = context.get("url") or context.get("target") or ""
            exposures = await bb.check_wordpress_exposures(url)
            lines = [f"{e.get('type')}: {e.get('url')} [{e.get('severity')}]" for e in exposures]
            log_f = self.tm._save_tool_output("python_wp_check", f"wp check {url}", "\n".join(lines), "", 0, 1.0)
            return (lines, log_f)

        elif fallback_name == "python_takeover_check":
            import socket
            targets = context.get("targets") or [context.get("domain", "")]
            vulns = []
            for t in targets:
                try:
                    cname = socket.gethostbyname_ex(t)[0]
                    if any(d in cname for d in ["s3.amazonaws.com", "github.io", "herokuapp.com", "azurewebsites.net"]):
                        vulns.append(f"[POTENTIAL TAKEOVER] {t} -> {cname}")
                except Exception:
                    pass
            log_f = self.tm._save_tool_output("python_takeover_check", "takeover check", "\n".join(vulns), "", 0, 0.5)
            return (vulns, log_f)

        elif fallback_name == "python_param_extract":
            url = context.get("url") or ""
            parsed = urlparse(url)
            params = [p.split("=")[0] for p in parsed.query.split("&") if "=" in p]
            log_f = self.tm._save_tool_output("python_param_extract", f"extract params from {url}", "\n".join(params), "", 0, 0.1)
            return (params, log_f)

        elif fallback_name == "python_sqli_verify":
            from agents.skills.sqli_skill import run_sqli_skill
            url = context.get("url") or ""
            param = context.get("param", "id")
            res = await run_sqli_skill(url, param)
            lines = [f"SQLi Test on {param}: {res.get('state')} | Extracted: {res.get('extracted_data')}"]
            log_f = self.tm._save_tool_output("python_sqli_verify", f"sqli verify {url}", "\n".join(lines), "", 0, 2.0)
            return (lines, log_f)

        return ([], None)
