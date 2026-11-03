"""
HunterAI Universal Kali Linux Tool Catalog
==========================================
Comprehensive registry of security tools spanning the 14 Kali Linux & MITRE ATT&CK categories.
Provides tool metadata, Debian/Kali package names, execution parameters, risk levels, and output formats.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class ToolCategory(str, Enum):
    RECON           = "recon"             # Information Gathering & OSINT
    PORT_SCAN       = "port_scan"         # Network & Service Discovery
    WEB_CRAWL       = "web_crawl"         # Spidering, Endpoints & Tech Stack
    FUZZING         = "fuzzing"           # Content Discovery & Directory Bruteforce
    PARAMETERS      = "parameters"        # Hidden Parameter Discovery
    VULN_SCAN       = "vuln_scan"         # Automated Vulnerability Scanning
    EXPLOITATION    = "exploitation"      # Safe Exploit Proof & Verification
    AUTH_TESTING    = "auth_testing"      # Credential & Password Assessment
    SECRETS         = "secrets"           # Code Intelligence & Leaked Keys
    SSL_TLS         = "ssl_tls"           # Cryptography & Certificate Audit
    CLOUD           = "cloud"             # Cloud Infrastructure & S3 Buckets
    WAF_BYPASS      = "waf_bypass"        # WAF Fingerprinting & Evasion
    REVERSE_ENG     = "reverse_eng"       # Binary & Bytecode Analysis
    REPORTING       = "reporting"         # Documentation & Evidence Packaging


@dataclass(frozen=True)
class ToolDefinition:
    name: str
    binary_name: str
    kali_package: str
    category: ToolCategory
    description: str
    default_args: List[str]
    risk_level: str                       # "low", "medium", "high", "critical"
    requires_authorization: bool = True
    timeout_secs: float = 60.0
    output_format: str = "json"          # "json", "text", "xml", "har"
    tags: List[str] = field(default_factory=list)


# Authoritative Universal Kali Catalog (50+ core tools across all 14 categories)
KALI_TOOL_CATALOG: Dict[str, ToolDefinition] = {
    # ── 1. Information Gathering / OSINT ───────────────────────────────────────
    "subfinder": ToolDefinition(
        name="subfinder", binary_name="subfinder", kali_package="subfinder",
        category=ToolCategory.RECON, description="Fast passive subdomain enumeration tool",
        default_args=["-d", "{target}", "-silent", "-all"], risk_level="low",
        requires_authorization=False, timeout_secs=60.0, output_format="text",
        tags=["dns", "recon", "subdomains"],
    ),
    "assetfinder": ToolDefinition(
        name="assetfinder", binary_name="assetfinder", kali_package="assetfinder",
        category=ToolCategory.RECON, description="Find domains and subdomains related to a given domain",
        default_args=["--subs-only", "{target}"], risk_level="low",
        requires_authorization=False, timeout_secs=45.0, output_format="text",
        tags=["dns", "recon", "subdomains"],
    ),
    "amass": ToolDefinition(
        name="amass", binary_name="amass", kali_package="amass",
        category=ToolCategory.RECON, description="In-depth Attack Surface Mapping and Asset Discovery",
        default_args=["enum", "-passive", "-d", "{target}"], risk_level="low",
        requires_authorization=False, timeout_secs=120.0, output_format="text",
        tags=["dns", "graph", "osint"],
    ),
    "dnsx": ToolDefinition(
        name="dnsx", binary_name="dnsx", kali_package="dnsx",
        category=ToolCategory.RECON, description="Fast and multi-purpose DNS toolkit for resolution and probing",
        default_args=["-silent", "-a", "-resp"], risk_level="low",
        requires_authorization=False, timeout_secs=45.0, output_format="json",
        tags=["dns", "resolver"],
    ),
    "theHarvester": ToolDefinition(
        name="theHarvester", binary_name="theHarvester", kali_package="theharvester",
        category=ToolCategory.RECON, description="E-mails, subdomains and names harvester",
        default_args=["-d", "{target}", "-b", "all"], risk_level="low",
        requires_authorization=False, timeout_secs=90.0, output_format="json",
        tags=["osint", "emails", "employees"],
    ),
    "whois": ToolDefinition(
        name="whois", binary_name="whois", kali_package="whois",
        category=ToolCategory.RECON, description="Domain WHOIS registrar record query client",
        default_args=["{target}"], risk_level="low",
        requires_authorization=False, timeout_secs=30.0, output_format="text",
        tags=["whois", "asn"],
    ),

    # ── 2. Port & Service Scanning ─────────────────────────────────────────────
    "nmap": ToolDefinition(
        name="nmap", binary_name="nmap", kali_package="nmap",
        category=ToolCategory.PORT_SCAN, description="Network exploration tool and security / port scanner",
        default_args=["-sT", "-T4", "-Pn", "-p", "80,443,8080,8443,3000,5000", "{target}"],
        risk_level="medium", requires_authorization=True, timeout_secs=120.0, output_format="text",
        tags=["portscan", "services", "fingerprint"],
    ),
    "masscan": ToolDefinition(
        name="masscan", binary_name="masscan", kali_package="masscan",
        category=ToolCategory.PORT_SCAN, description="Mass IP port scanner, TCP port scanner",
        default_args=["-p80,443,8080", "{target}", "--rate=1000"],
        risk_level="high", requires_authorization=True, timeout_secs=60.0, output_format="json",
        tags=["portscan", "highspeed"],
    ),
    "naabu": ToolDefinition(
        name="naabu", binary_name="naabu", kali_package="naabu",
        category=ToolCategory.PORT_SCAN, description="Fast port scanner written in Go focused on reliability",
        default_args=["-host", "{target}", "-silent", "-p", "top-100"],
        risk_level="medium", requires_authorization=True, timeout_secs=60.0, output_format="json",
        tags=["portscan", "recon"],
    ),
    "enum4linux-ng": ToolDefinition(
        name="enum4linux-ng", binary_name="enum4linux-ng", kali_package="enum4linux-ng",
        category=ToolCategory.PORT_SCAN, description="Next generation SMB enumeration tool",
        default_args=["-A", "-oJ", "-", "{target}"],
        risk_level="medium", requires_authorization=True, timeout_secs=90.0, output_format="json",
        tags=["smb", "windows", "active_directory"],
    ),
    "netexec": ToolDefinition(
        name="netexec", binary_name="nxc", kali_package="netexec",
        category=ToolCategory.PORT_SCAN, description="Network service auditing and exploitation tool (formerly CrackMapExec)",
        default_args=["smb", "{target}"],
        risk_level="high", requires_authorization=True, timeout_secs=60.0, output_format="text",
        tags=["smb", "winrm", "lateral_movement"],
    ),

    # ── 3. Web Crawling & Asset Discovery ──────────────────────────────────────
    "katana": ToolDefinition(
        name="katana", binary_name="katana", kali_package="katana",
        category=ToolCategory.WEB_CRAWL, description="Next-generation crawling and spidering framework",
        default_args=["-u", "{target}", "-silent", "-jc", "-d", "3"],
        risk_level="low", requires_authorization=True, timeout_secs=90.0, output_format="text",
        tags=["crawler", "spider", "endpoints"],
    ),
    "httpx": ToolDefinition(
        name="httpx", binary_name="httpx", kali_package="httpx",
        category=ToolCategory.WEB_CRAWL, description="Fast and multi-purpose HTTP toolkit for probing live services",
        default_args=["-silent", "-status-code", "-title", "-tech-detect", "-json"],
        risk_level="low", requires_authorization=True, timeout_secs=45.0, output_format="json",
        tags=["http", "probe", "tech_stack"],
    ),
    "gau": ToolDefinition(
        name="gau", binary_name="gau", kali_package="gau",
        category=ToolCategory.WEB_CRAWL, description="Fetch known URLs from AlienVault OTX, Wayback Machine, and Common Crawl",
        default_args=["--subs", "{target}"],
        risk_level="low", requires_authorization=False, timeout_secs=60.0, output_format="text",
        tags=["archive", "wayback", "endpoints"],
    ),
    "waybackurls": ToolDefinition(
        name="waybackurls", binary_name="waybackurls", kali_package="waybackurls",
        category=ToolCategory.WEB_CRAWL, description="Fetch known URLs from the Wayback Machine",
        default_args=["{target}"],
        risk_level="low", requires_authorization=False, timeout_secs=45.0, output_format="text",
        tags=["archive", "wayback"],
    ),
    "whatweb": ToolDefinition(
        name="whatweb", binary_name="whatweb", kali_package="whatweb",
        category=ToolCategory.WEB_CRAWL, description="Next generation web scanner identifying content management systems",
        default_args=["-a", "3", "--log-json", "-", "{target}"],
        risk_level="low", requires_authorization=False, timeout_secs=30.0, output_format="json",
        tags=["fingerprint", "tech_stack", "cms"],
    ),
    "wafw00f": ToolDefinition(
        name="wafw00f", binary_name="wafw00f", kali_package="wafw00f",
        category=ToolCategory.WAF_BYPASS, description="Identify and fingerprint Web Application Firewall (WAF) products",
        default_args=["-a", "{target}", "-o", "-"],
        risk_level="low", requires_authorization=False, timeout_secs=30.0, output_format="text",
        tags=["waf", "fingerprint", "defense"],
    ),

    # ── 4. Active Fuzzing & Parameter Discovery ────────────────────────────────
    "ffuf": ToolDefinition(
        name="ffuf", binary_name="ffuf", kali_package="ffuf",
        category=ToolCategory.FUZZING, description="Fast web fuzzer written in Go",
        default_args=["-u", "{target}/FUZZ", "-mc", "200,301,302,403", "-silent", "-o", "-"],
        risk_level="medium", requires_authorization=True, timeout_secs=90.0, output_format="json",
        tags=["fuzzer", "directory", "bruteforce"],
    ),
    "dirsearch": ToolDefinition(
        name="dirsearch", binary_name="dirsearch", kali_package="dirsearch",
        category=ToolCategory.FUZZING, description="Web path scanner",
        default_args=["-u", "{target}", "--format=json", "-q"],
        risk_level="medium", requires_authorization=True, timeout_secs=90.0, output_format="json",
        tags=["directory", "fuzzer"],
    ),
    "feroxbuster": ToolDefinition(
        name="feroxbuster", binary_name="feroxbuster", kali_package="feroxbuster",
        category=ToolCategory.FUZZING, description="Fast, simple, recursive content discovery tool written in Rust",
        default_args=["-u", "{target}", "--silent", "--json"],
        risk_level="medium", requires_authorization=True, timeout_secs=90.0, output_format="json",
        tags=["directory", "recursive", "fast"],
    ),
    "arjun": ToolDefinition(
        name="arjun", binary_name="arjun", kali_package="arjun",
        category=ToolCategory.PARAMETERS, description="HTTP parameter discovery suite",
        default_args=["-u", "{target}", "--passive", "-oJ", "-"],
        risk_level="medium", requires_authorization=True, timeout_secs=60.0, output_format="json",
        tags=["params", "hidden_parameters", "api"],
    ),
    "x8": ToolDefinition(
        name="x8", binary_name="x8", kali_package="x8",
        category=ToolCategory.PARAMETERS, description="Hidden parameter discovery tool written in Rust",
        default_args=["-u", "{target}", "-W", "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt"],
        risk_level="medium", requires_authorization=True, timeout_secs=60.0, output_format="text",
        tags=["params", "rust", "fast"],
    ),

    # ── 5. Vulnerability & Template Scanning ───────────────────────────────────
    "nuclei": ToolDefinition(
        name="nuclei", binary_name="nuclei", kali_package="nuclei",
        category=ToolCategory.VULN_SCAN, description="Fast and customizable vulnerability scanner based on simple YAML DSL",
        default_args=["-target", "{target}", "-silent", "-jsonl", "-severity", "low,medium,high,critical"],
        risk_level="high", requires_authorization=True, timeout_secs=180.0, output_format="json",
        tags=["cve", "templates", "scanner"],
    ),
    "dalfox": ToolDefinition(
        name="dalfox", binary_name="dalfox", kali_package="dalfox",
        category=ToolCategory.VULN_SCAN, description="Powerful open-source XSS scanner and utility focused on automation",
        default_args=["url", "{target}", "--format", "json", "--silence"],
        risk_level="high", requires_authorization=True, timeout_secs=90.0, output_format="json",
        tags=["xss", "domxss", "stored_xss"],
    ),
    "nikto": ToolDefinition(
        name="nikto", binary_name="nikto", kali_package="nikto",
        category=ToolCategory.VULN_SCAN, description="Web server scanner checking for dangerous files and CGIs",
        default_args=["-h", "{target}", "-Format", "json"],
        risk_level="medium", requires_authorization=True, timeout_secs=120.0, output_format="json",
        tags=["web_server", "outdated_components"],
    ),
    "wpscan": ToolDefinition(
        name="wpscan", binary_name="wpscan", kali_package="wpscan",
        category=ToolCategory.VULN_SCAN, description="WordPress security scanner",
        default_args=["--url", "{target}", "--format", "json", "--stealthy"],
        risk_level="medium", requires_authorization=True, timeout_secs=90.0, output_format="json",
        tags=["wordpress", "plugins", "cms"],
    ),

    # ── 6. Exploitation & PoC Verification ─────────────────────────────────────
    "sqlmap": ToolDefinition(
        name="sqlmap", binary_name="sqlmap", kali_package="sqlmap",
        category=ToolCategory.EXPLOITATION, description="Automatic SQL injection and database takeover tool",
        default_args=["-u", "{target}", "--batch", "--banner", "--is-dba"],
        risk_level="critical", requires_authorization=True, timeout_secs=180.0, output_format="text",
        tags=["sqli", "database", "rce"],
    ),
    "commix": ToolDefinition(
        name="commix", binary_name="commix", kali_package="commix",
        category=ToolCategory.EXPLOITATION, description="Automated all-in-one OS command injection and exploitation tool",
        default_args=["--url", "{target}", "--batch", "--current-user"],
        risk_level="critical", requires_authorization=True, timeout_secs=120.0, output_format="text",
        tags=["cmdi", "command_injection", "rce"],
    ),

    # ── 7. Credential & Auth Testing ───────────────────────────────────────────
    "hydra": ToolDefinition(
        name="hydra", binary_name="hydra", kali_package="hydra",
        category=ToolCategory.AUTH_TESTING, description="Very fast network logon cracker which supports many different services",
        default_args=["-t", "4", "{target}"],
        risk_level="high", requires_authorization=True, timeout_secs=120.0, output_format="text",
        tags=["bruteforce", "credentials", "passwords"],
    ),
    "ssh-audit": ToolDefinition(
        name="ssh-audit", binary_name="ssh-audit", kali_package="ssh-audit",
        category=ToolCategory.AUTH_TESTING, description="SSH server security auditing tool",
        default_args=["-j", "{target}"],
        risk_level="low", requires_authorization=True, timeout_secs=30.0, output_format="json",
        tags=["ssh", "ciphers", "hardening"],
    ),

    # ── 8. Secrets & Code Intelligence ─────────────────────────────────────────
    "gitleaks": ToolDefinition(
        name="gitleaks", binary_name="gitleaks", kali_package="gitleaks",
        category=ToolCategory.SECRETS, description="Audit git repositories for secrets and leaked API tokens",
        default_args=["detect", "--source", "{target}", "--report-format", "json"],
        risk_level="low", requires_authorization=False, timeout_secs=60.0, output_format="json",
        tags=["secrets", "api_keys", "tokens"],
    ),
    "trivy": ToolDefinition(
        name="trivy", binary_name="trivy", kali_package="trivy",
        category=ToolCategory.SECRETS, description="Scanner for vulnerabilities in container images, file systems, and Git repositories",
        default_args=["repo", "{target}", "--format", "json"],
        risk_level="low", requires_authorization=False, timeout_secs=90.0, output_format="json",
        tags=["cve", "sast", "dependencies"],
    ),
    "semgrep": ToolDefinition(
        name="semgrep", binary_name="semgrep", kali_package="semgrep",
        category=ToolCategory.SECRETS, description="Lightweight static analysis for many languages",
        default_args=["scan", "--json", "{target}"],
        risk_level="low", requires_authorization=False, timeout_secs=90.0, output_format="json",
        tags=["sast", "code_review"],
    ),

    # ── 9. SSL/TLS & Cryptography ──────────────────────────────────────────────
    "testssl": ToolDefinition(
        name="testssl", binary_name="testssl.sh", kali_package="testssl.sh",
        category=ToolCategory.SSL_TLS, description="Testing TLS/SSL encryption anywhere on any port",
        default_args=["--jsonfile", "-", "{target}"],
        risk_level="low", requires_authorization=True, timeout_secs=120.0, output_format="json",
        tags=["ssl", "tls", "heartbleed", "poodle"],
    ),
    "sslscan": ToolDefinition(
        name="sslscan", binary_name="sslscan", kali_package="sslscan",
        category=ToolCategory.SSL_TLS, description="Fast SSL/TLS cipher suite and vulnerability scanner",
        default_args=["--xml=-", "{target}"],
        risk_level="low", requires_authorization=True, timeout_secs=45.0, output_format="xml",
        tags=["ssl", "ciphers"],
    ),

    # ── 10. Cloud Infrastructure & Buckets ─────────────────────────────────────
    "cloud_enum": ToolDefinition(
        name="cloud_enum", binary_name="cloud_enum", kali_package="cloud-enum",
        category=ToolCategory.CLOUD, description="Multi-cloud OSINT tool for AWS, Azure, and Google Cloud",
        default_args=["-k", "{target}", "-l", "-"],
        risk_level="low", requires_authorization=False, timeout_secs=90.0, output_format="text",
        tags=["cloud", "aws", "s3", "azure", "gcp"],
    ),
    # ── Additional Recon & OSINT ──────────────────────────────────────────────
    "sublist3r": ToolDefinition(
        name="sublist3r", binary_name="sublist3r", kali_package="sublist3r",
        category=ToolCategory.RECON, description="Fast subdomains discovery tool using OSINT",
        default_args=["-d", "{target}", "-t", "10"], risk_level="low",
        requires_authorization=False, timeout_secs=60.0, output_format="text",
        tags=["osint", "subdomains", "dns"],
    ),
    "recon_ng": ToolDefinition(
        name="recon_ng", binary_name="recon-ng", kali_package="recon-ng",
        category=ToolCategory.RECON, description="Full-featured Web Reconnaissance framework written in Python",
        default_args=["-r", "{target}"], risk_level="low",
        requires_authorization=False, timeout_secs=120.0, output_format="text",
        tags=["recon", "framework", "osint"],
    ),
    "dnsenum": ToolDefinition(
        name="dnsenum", binary_name="dnsenum", kali_package="dnsenum",
        category=ToolCategory.RECON, description="Multithreaded script to enumerate DNS information and discover non-contiguous ip blocks",
        default_args=["--noreverse", "{target}"], risk_level="low",
        requires_authorization=False, timeout_secs=90.0, output_format="text",
        tags=["dns", "zone-transfer", "recon"],
    ),
    "fierce": ToolDefinition(
        name="fierce", binary_name="fierce", kali_package="fierce",
        category=ToolCategory.RECON, description="DNS reconnaissance tool for locating non-contiguous IP space",
        default_args=["--domain", "{target}"], risk_level="low",
        requires_authorization=False, timeout_secs=60.0, output_format="text",
        tags=["dns", "recon"],
    ),

    # ── Additional Web Crawl & Fingerprinting ──────────────────────────────────
    "gobuster": ToolDefinition(
        name="gobuster", binary_name="gobuster", kali_package="gobuster",
        category=ToolCategory.FUZZING, description="Directory/file, DNS and VHost busting tool written in Go",
        default_args=["dir", "-u", "{target}", "-q"], risk_level="medium",
        requires_authorization=True, timeout_secs=90.0, output_format="text",
        tags=["fuzzing", "dirbuster", "vhosts"],
    ),
    "wfuzz": ToolDefinition(
        name="wfuzz", binary_name="wfuzz", kali_package="wfuzz",
        category=ToolCategory.FUZZING, description="Web application fuzzer and bruteforcer",
        default_args=["-z", "list,test", "--hc", "404", "{target}/FUZZ"], risk_level="medium",
        requires_authorization=True, timeout_secs=60.0, output_format="text",
        tags=["fuzzing", "web"],
    ),
    "aquatone": ToolDefinition(
        name="aquatone", binary_name="aquatone", kali_package="aquatone",
        category=ToolCategory.WEB_CRAWL, description="Visual inspection tool for web applications across a large number of hosts",
        default_args=["-out", "aquatone_out"], risk_level="low",
        requires_authorization=False, timeout_secs=90.0, output_format="text",
        tags=["screenshot", "visual-recon", "web"],
    ),
    "eyewitness": ToolDefinition(
        name="eyewitness", binary_name="eyewitness", kali_package="eyewitness",
        category=ToolCategory.WEB_CRAWL, description="Rapid screenshots and server header identification for web services",
        default_args=["--web", "--single", "{target}"], risk_level="low",
        requires_authorization=False, timeout_secs=60.0, output_format="text",
        tags=["screenshots", "headers", "web"],
    ),
    "mitmproxy": ToolDefinition(
        name="mitmproxy", binary_name="mitmproxy", kali_package="mitmproxy",
        category=ToolCategory.WEB_CRAWL, description="Interactive, SSL/TLS-capable intercepting HTTP proxy",
        default_args=["--version"], risk_level="low",
        requires_authorization=True, timeout_secs=30.0, output_format="text",
        tags=["proxy", "interception", "http"],
    ),

    # ── Additional Exploitation & Frameworks ───────────────────────────────────
    "searchsploit": ToolDefinition(
        name="searchsploit", binary_name="searchsploit", kali_package="exploitdb",
        category=ToolCategory.EXPLOITATION, description="Command line search tool for Exploit-DB archives",
        default_args=["--json", "{target}"], risk_level="low",
        requires_authorization=False, timeout_secs=30.0, output_format="json",
        tags=["exploitdb", "cve", "poc"],
    ),
    "msfconsole": ToolDefinition(
        name="msfconsole", binary_name="msfconsole", kali_package="metasploit-framework",
        category=ToolCategory.EXPLOITATION, description="World's most used penetration testing framework",
        default_args=["-q", "-x", "version; exit"], risk_level="critical",
        requires_authorization=True, timeout_secs=120.0, output_format="text",
        tags=["metasploit", "framework", "exploit"],
    ),
    "routersploit": ToolDefinition(
        name="routersploit", binary_name="rsf.py", kali_package="routersploit",
        category=ToolCategory.EXPLOITATION, description="Exploitation framework dedicated to embedded devices and routers",
        default_args=["--version"], risk_level="high",
        requires_authorization=True, timeout_secs=60.0, output_format="text",
        tags=["iot", "routers", "exploitation"],
    ),
    "responder": ToolDefinition(
        name="responder", binary_name="responder", kali_package="responder",
        category=ToolCategory.EXPLOITATION, description="LLMNR, NBT-NS and MDNS poisoner and credential gatherer",
        default_args=["-I", "eth0", "-A"], risk_level="high",
        requires_authorization=True, timeout_secs=60.0, output_format="text",
        tags=["poisoning", "llmnr", "ntlm"],
    ),
    "bloodhound": ToolDefinition(
        name="bloodhound", binary_name="bloodhound-python", kali_package="bloodhound.py",
        category=ToolCategory.RECON, description="Active Directory domain trust and relationship attack path mapper",
        default_args=["-d", "{target}", "-c", "All"], risk_level="medium",
        requires_authorization=True, timeout_secs=120.0, output_format="json",
        tags=["active-directory", "graph", "privilege-escalation"],
    ),

    # ── Additional Password & Auth Testing ─────────────────────────────────────
    "john": ToolDefinition(
        name="john", binary_name="john", kali_package="john",
        category=ToolCategory.AUTH_TESTING, description="John the Ripper advanced offline password cracker",
        default_args=["--test"], risk_level="medium",
        requires_authorization=True, timeout_secs=60.0, output_format="text",
        tags=["cracking", "hashes", "offline"],
    ),
    "hashcat": ToolDefinition(
        name="hashcat", binary_name="hashcat", kali_package="hashcat",
        category=ToolCategory.AUTH_TESTING, description="World's fastest and most advanced password recovery utility",
        default_args=["-b"], risk_level="medium",
        requires_authorization=True, timeout_secs=60.0, output_format="text",
        tags=["hashcat", "gpu", "cracking"],
    ),
    "medusa": ToolDefinition(
        name="medusa", binary_name="medusa", kali_package="medusa",
        category=ToolCategory.AUTH_TESTING, description="Speedy, parallel, and modular login brute-forcer",
        default_args=["-h", "{target}", "-M", "http"], risk_level="high",
        requires_authorization=True, timeout_secs=90.0, output_format="text",
        tags=["bruteforce", "credentials", "auth"],
    ),
    "cewl": ToolDefinition(
        name="cewl", binary_name="cewl", kali_package="cewl",
        category=ToolCategory.AUTH_TESTING, description="Custom wordlist generator spidering a target URL",
        default_args=["-d", "2", "-m", "5", "{target}"], risk_level="low",
        requires_authorization=False, timeout_secs=60.0, output_format="text",
        tags=["wordlists", "spider", "custom-words"],
    ),
    "crunch": ToolDefinition(
        name="crunch", binary_name="crunch", kali_package="crunch",
        category=ToolCategory.AUTH_TESTING, description="Wordlist generator that can generate all possible combinations",
        default_args=["4", "6"], risk_level="low",
        requires_authorization=False, timeout_secs=30.0, output_format="text",
        tags=["wordlist", "generator"],
    ),

    # ── Reverse Engineering & Firmware ────────────────────────────────────────
    "binwalk": ToolDefinition(
        name="binwalk", binary_name="binwalk", kali_package="binwalk",
        category=ToolCategory.REVERSE_ENG, description="Firmware analysis tool to search for embedded files and code",
        default_args=["-B", "{target}"], risk_level="low",
        requires_authorization=False, timeout_secs=60.0, output_format="text",
        tags=["firmware", "decompression", "embedded"],
    ),
    "radare2": ToolDefinition(
        name="radare2", binary_name="r2", kali_package="radare2",
        category=ToolCategory.REVERSE_ENG, description="UNIX-like reverse engineering framework and command-line tool",
        default_args=["-q", "-c", "aaa; afl", "{target}"], risk_level="low",
        requires_authorization=False, timeout_secs=60.0, output_format="text",
        tags=["reversing", "disassembly", "binary"],
    ),
    "jadx": ToolDefinition(
        name="jadx", binary_name="jadx", kali_package="jadx",
        category=ToolCategory.REVERSE_ENG, description="Dex to Java decompiler for Android APK files",
        default_args=["--version"], risk_level="low",
        requires_authorization=False, timeout_secs=30.0, output_format="text",
        tags=["android", "apk", "decompiler"],
    ),
    "apktool": ToolDefinition(
        name="apktool", binary_name="apktool", kali_package="apktool",
        category=ToolCategory.REVERSE_ENG, description="Tool for reverse engineering 3rd party, closed, binary Android apps",
        default_args=["-version"], risk_level="low",
        requires_authorization=False, timeout_secs=30.0, output_format="text",
        tags=["android", "smali", "manifest"],
    ),

    # ── Additional Cloud & Container Security ─────────────────────────────────
    "prowler": ToolDefinition(
        name="prowler", binary_name="prowler", kali_package="prowler",
        category=ToolCategory.CLOUD, description="Security assessment tool for AWS, Azure, GCP and Kubernetes",
        default_args=["aws", "--compliance", "cis_1.4_aws"], risk_level="low",
        requires_authorization=True, timeout_secs=180.0, output_format="json",
        tags=["cloud", "aws", "compliance", "cis"],
    ),
    "scoutsuite": ToolDefinition(
        name="scoutsuite", binary_name="scout", kali_package="scoutsuite",
        category=ToolCategory.CLOUD, description="Multi-cloud security auditing tool for AWS, Azure, and Google Cloud",
        default_args=["aws", "--report-dir", "scout_out"], risk_level="low",
        requires_authorization=True, timeout_secs=180.0, output_format="json",
        tags=["cloud", "audit", "security-posture"],
    ),
    "checkov": ToolDefinition(
        name="checkov", binary_name="checkov", kali_package="checkov",
        category=ToolCategory.SECRETS, description="Static code analysis tool for Infrastructure as Code (Terraform, CloudFormation, K8s)",
        default_args=["-d", "{target}", "-o", "json"], risk_level="low",
        requires_authorization=False, timeout_secs=60.0, output_format="json",
        tags=["iac", "terraform", "k8s", "static-analysis"],
    ),
}


def get_tools_by_category(category: ToolCategory) -> List[ToolDefinition]:
    """Returns all tools belonging to a specific category."""
    return [t for t in KALI_TOOL_CATALOG.values() if t.category == category]


def get_tool_definition(tool_name: str) -> Optional[ToolDefinition]:
    """Retrieves definition for tool by name."""
    return KALI_TOOL_CATALOG.get(tool_name.lower())


def search_tools_for_objective(objective: str) -> List[ToolDefinition]:
    """Finds matching tools based on objective keyword or tags."""
    obj = objective.lower()
    matches = []
    for t in KALI_TOOL_CATALOG.values():
        if (
            obj in t.name.lower()
            or obj in t.category.value.lower()
            or any(obj in tag.lower() for tag in t.tags)
            or obj in t.description.lower()
        ):
            matches.append(t)
    return matches
