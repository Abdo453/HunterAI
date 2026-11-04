"""
Methodology Knowledge Base & Dorking Engine (MethodologyKB)
===========================================================
Codified knowledge engine integrating:
1. Google Hacking Database (GHDB) Dorking Engine across 6 categories.
2. GitHub Dorking & Leaked Credential Discovery Patterns.
3. 403 / 401 Bypass Header & Path Traversal Injection Matrix.
4. Content Discovery Master Profiles (60+ file extensions & sensitive CMS endpoints).
5. HexStrike v6.0 Tool Arsenal Directory (150+ security tools mapped across 7 domains).
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import quote_plus, urljoin, urlparse


# ---------------------------------------------------------------------------
# 1. Google Hacking Database (GHDB) & Search Dork Templates
# ---------------------------------------------------------------------------

GHDB_CATEGORIES: Dict[str, Dict[str, Any]] = {
    "bug_bounty_discovery": {
        "title": "Bug Bounty & Vulnerability Disclosure Targets",
        "description": "Discover programs offering responsible disclosure and monetary bounties.",
        "dorks": [
            'intext:"security report monetary" inurl:security',
            'intext:"responsible disclosure" inurl:security',
            '"submit vulnerability report" | "bug bounty program"',
            'site:hackerone.com "{domain}"',
            'site:bugcrowd.com "{domain}"',
            'site:yeswehack.com "{domain}"',
            'site:standoff365.com "{domain}"',
            'site:intigriti.com "{domain}"',
            'site:{domain} "security.txt" | inurl:".well-known/security.txt"',
        ],
    },
    "sensitive_files": {
        "title": "Sensitive Files & Leaked Documents",
        "description": "Exposed environment files, database dumps, archives, and spreadsheets.",
        "dorks": [
            "site:{domain} filetype:env | filetype:sql | filetype:bak | filetype:backup | filetype:old | filetype:conf | filetype:config",
            "site:{domain} filetype:xls | filetype:xlsx | filetype:csv | filetype:json | filetype:xml",
            "site:{domain} filetype:log | filetype:ini | filetype:yaml | filetype:yml | filetype:pem | filetype:key | filetype:crt",
            "site:{domain} filetype:tar.gz | filetype:tgz | filetype:zip | filetype:7z | filetype:rar | filetype:dump | filetype:dmp",
            "site:{domain} inurl:wp-content/uploads/ | inurl:wp-config.php.bak",
            'site:{domain} inurl:"/.git" | inurl:"/.env" | inurl:"/id_rsa" | inurl:"/.htaccess"',
            'site:docs.google.com/spreadsheets "{domain}"',
            'site:docs.google.com/spreadsheets "password" "{domain}"',
            'site:docs.google.com/spreadsheets "@{domain}"',
            'site:*.{domain} intext:"docs.google.com/spreadsheets"',
        ],
    },
    "admin_and_portals": {
        "title": "Admin & Authentication Portals",
        "description": "Administrative dashboards, single-sign-on portals, and management interfaces.",
        "dorks": [
            "site:{domain} inurl:admin | inurl:login | inurl:signin | inurl:auth | inurl:dashboard | inurl:portal",
            "site:{domain} inurl:phpmyadmin | inurl:cpanel | inurl:webmail",
            'site:{domain} intitle:"index of /" "admin"',
            "site:{domain} inurl:oauth | inurl:sso | inurl:register | inurl:signup | inurl:reset | inurl:password",
            'site:{domain} inurl:"/granite" | inurl:"/crx/de" | inurl:"/system/console"',
        ],
    },
    "api_and_endpoints": {
        "title": "API & Developer Endpoints",
        "description": "REST APIs, GraphQL schemas, Swagger definitions, and debug routes.",
        "dorks": [
            "site:{domain} inurl:api | inurl:v1 | inurl:v2 | inurl:v3 | inurl:graphql | inurl:gql",
            "site:{domain} inurl:swagger | inurl:openapi | inurl:actuator | inurl:debug | inurl:test | inurl:beta | inurl:staging",
            "site:{domain} inurl:webhook | inurl:callback | inurl:redirect_uri | inurl:dest= | inurl:return=",
            "site:{domain} filetype:json inurl:swagger.json | inurl:openapi.json",
        ],
    },
    "leaked_secrets_and_creds": {
        "title": "Secret & Credential Disclosures",
        "description": "Exposed tokens, passwords, API keys, and authorization headers.",
        "dorks": [
            'site:{domain} intext:"password" | intext:"api_key" | intext:"apikey" | intext:"secret" | intext:"token"',
            'site:{domain} intext:"authorization: bearer" | intext:"AWS_SECRET_ACCESS_KEY" | intext:"BEGIN PRIVATE KEY"',
            'site:github.com "{domain}" "API_KEY"',
            'site:github.com "{domain}" "Credentials"',
            'site:github.com "{domain}" "password"',
            'site:github.com "{domain}" "secret"',
        ],
    },
    "error_and_database_exposure": {
        "title": "Database Errors & Stack Traces",
        "description": "Detailed SQL syntax errors, database dumps, and application exceptions.",
        "dorks": [
            'site:{domain} intext:"sql syntax" | intext:"mysql_fetch" | intext:"ORA-[0-9]{5}" | intext:"PostgreSQL query failed"',
            'site:{domain} intext:"warning: mysql" | intext:"valid MySQL result" | intext:"MySqlClient"',
            'site:{domain} intext:"Exception Details:" | intext:"Stack Trace:" | intext:"Whoops! There was an error."',
        ],
    },
}

# ---------------------------------------------------------------------------
# 2. GitHub Dorking Patterns & Search Queries
# ---------------------------------------------------------------------------

GITHUB_DORK_PATTERNS: List[Dict[str, str]] = [
    {"name": "API_KEY", "query": '"{domain}" "API_KEY"'},
    {"name": "Credentials", "query": '"{domain}" "Credentials"'},
    {"name": "Password", "query": '"{domain}" "password"'},
    {"name": "AWS_Keys", "query": '"{domain}" "AWS_SECRET_ACCESS_KEY"'},
    {"name": "Private_Key", "query": '"{domain}" "BEGIN PRIVATE KEY"'},
    {"name": "Database_URL", "query": '"{domain}" "postgres://" OR "mysql://" OR "mongodb://"'},
    {"name": "Stripe_Secret", "query": '"{domain}" "sk_live_"'},
    {"name": "Slack_Webhook", "query": '"{domain}" "hooks.slack.com/services"'},
    {"name": "Auth_Bearer", "query": '"{domain}" "Bearer eyJ"'},
    {"name": "Internal_Domain", "query": '"{domain}" "internal" OR "corp" OR "staging"'},
]

# ---------------------------------------------------------------------------
# 3. 403 / 401 Bypass Header & Path Traversal Injection Matrix
# ---------------------------------------------------------------------------

BYPASS_403_HEADERS: List[Dict[str, str]] = [
    {"header": "X-Forwarded-For", "value": "127.0.0.1"},
    {"header": "X-Forwarded-Host", "value": "127.0.0.1"},
    {"header": "X-Forwarded-Server", "value": "127.0.0.1"},
    {"header": "X-Originating-IP", "value": "127.0.0.1"},
    {"header": "X-Remote-IP", "value": "127.0.0.1"},
    {"header": "X-Remote-Addr", "value": "127.0.0.1"},
    {"header": "X-Client-IP", "value": "127.0.0.1"},
    {"header": "Client-IP", "value": "127.0.0.1"},
    {"header": "True-Client-IP", "value": "127.0.0.1"},
    {"header": "Cluster-Client-IP", "value": "127.0.0.1"},
    {"header": "X-Custom-IP-Authorization", "value": "127.0.0.1"},
    {"header": "X-Real-IP", "value": "127.0.0.1"},
    {"header": "X-Original-URL", "value": "{path}"},
    {"header": "X-Rewrite-URL", "value": "{path}"},
    {"header": "X-Override-URL", "value": "{path}"},
    {"header": "Host", "value": "localhost"},
]

BYPASS_403_PATH_TRICKS: List[str] = [
    "{path}/",
    "{path}/.",
    "//{path}//",
    "{path}/..;/",
    "{path}/%20",
    "{path}%09",
    "{path}..;/",
    "/%2e/{path}",
    "{path}.json",
    "{path}/*",
    "{path}.php",
    "{path}#",
    "{path}?",
]

# ---------------------------------------------------------------------------
# 4. Master Wordlists & Extensions Directory
# ---------------------------------------------------------------------------

MASTER_EXTENSIONS: List[str] = [
    "conf", "config", "bak", "backup", "swp", "old", "db", "sql", "asp",
    "aspx", "aspx~", "asp~", "py", "py~", "rb", "rb~", "php", "php~",
    "bkp", "cache", "cgi", "csv", "html", "inc", "jar", "js", "json",
    "jsp", "jsp~", "lock", "log", "rar", "sql.gz", "sql.zip", "sql.tar.gz",
    "sql~", "swp~", "tar", "tar.bz2", "tar.gz", "txt", "wadl", "zip",
    "xml", "env", "ini", "yml", "yaml", "sqlite", "sqlite3", "dmp", "dump",
    "orig", "original", "save", "save~", "tmp", "temp", "pub", "key",
]

SENSITIVE_CMS_PATHS: List[Dict[str, str]] = [
    {"path": "/wp-json/wp/v2/users", "category": "wordpress_users", "description": "WordPress REST API User Enumeration"},
    {"path": "/wp-json/?rest_route=/wp/v2/users/", "category": "wordpress_users", "description": "Alternative WordPress User REST Route"},
    {"path": "/index.php?rest_route=/wp/v2/users", "category": "wordpress_users", "description": "Query-string WordPress User Enumeration"},
    {"path": "/author-sitemap.xml", "category": "wordpress_users", "description": "Yoast / SEO Author Sitemap exposing usernames"},
    {"path": "/wp-content/debug.log", "category": "sensitive_log", "description": "WordPress Debug Log containing stack traces and credentials"},
    {"path": "/wp-login.php?action=register", "category": "auth", "description": "Open WordPress Registration Form"},
    {"path": "/wp-content/uploads/", "category": "sensitive_files", "description": "Open Directory Listing of WordPress Uploads"},
    {"path": "/.git/HEAD", "category": "source_leak", "description": "Exposed Git Repository Root"},
    {"path": "/.env", "category": "sensitive_files", "description": "Environment Configuration File"},
    {"path": "/actuator/env", "category": "spring_actuator", "description": "Spring Boot Actuator Environment Disclosure"},
    {"path": "/actuator/heapdump", "category": "spring_actuator", "description": "Spring Boot Heapdump Leak"},
    {"path": "/swagger-ui.html", "category": "api_docs", "description": "Exposed Swagger UI API Explorer"},
    {"path": "/graphql", "category": "api_docs", "description": "GraphQL Endpoint with Introspection potential"},
]

# ---------------------------------------------------------------------------
# 5. HexStrike v6.0 Tool Arsenal Directory (150+ Tools across 7 Domains)
# ---------------------------------------------------------------------------

HEXSTRIKE_ARSENAL_CATEGORIES: Dict[str, Dict[str, Any]] = {
    "network_recon": {
        "name": "Network & Reconnaissance",
        "count": "25+",
        "tools": [
            "nmap", "masscan", "rustscan", "autorecon", "amass", "subfinder",
            "assetfinder", "theharvester", "fierce", "dnsenum", "dnsx", "puredns",
            "responder", "netexec", "enum4linux-ng", "subenum", "findomain",
            "chaos", "hakrevdns", "smbclient", "subzy", "dnscan", "naabu",
            "c99", "shrewdeye"
        ],
    },
    "web_security": {
        "name": "Web Application Security",
        "count": "40+",
        "tools": [
            "gobuster", "feroxbuster", "ffuf", "dirb", "dirsearch", "nuclei",
            "nikto", "sqlmap", "wpscan", "arjun", "paramspider", "x8",
            "katana", "httpx", "dalfox", "jaeles", "hakrawler", "gau",
            "gauplus", "waybackurls", "waymore", "wafw00f", "smuggler",
            "subjs", "mantra", "jsleak", "jsluice", "trufflehog", "secretfinder",
            "qsreplace", "dontgo403", "commix", "crlfuzz", "interactsh-client"
        ],
    },
    "auth_and_passwords": {
        "name": "Authentication & Password",
        "count": "12+",
        "tools": [
            "hydra", "john", "hashcat", "medusa", "patator", "netexec",
            "evil-winrm", "hash-identifier", "ophcrack", "crowbar", "cewl", "cupp"
        ],
    },
    "binary_and_reversing": {
        "name": "Binary Analysis & Reverse Engineering",
        "count": "25+",
        "tools": [
            "ghidra", "radare2", "gdb", "binwalk", "ropgadget", "checksec",
            "strings", "volatility3", "foremost", "steghide", "exiftool",
            "angr", "pwntools", "cutter", "floss", "upx", "objdump"
        ],
    },
    "cloud_and_containers": {
        "name": "Cloud & Container Security",
        "count": "20+",
        "tools": [
            "prowler", "scout-suite", "trivy", "kube-hunter", "kube-bench",
            "docker-bench-security", "checkov", "terrascan", "falco", "cloud-enum",
            "cloudmapper", "pacu", "s3scanner"
        ],
    },
    "ctf_and_forensics": {
        "name": "CTF & Forensics",
        "count": "20+",
        "tools": [
            "volatility3", "autopsy", "sleuthkit", "stegsolve", "zsteg",
            "outguess", "photorec", "testdisk", "scalpel", "bulk-extractor"
        ],
    },
    "osint_and_intel": {
        "name": "OSINT & Intelligence",
        "count": "20+",
        "tools": [
            "sherlock", "social-analyzer", "recon-ng", "maltego", "spiderfoot",
            "shodan", "censys", "have-i-been-pwned", "securitytrails", "bgp-he-net",
            "favihash", "urlscan", "viewdns", "netlas"
        ],
    },
}


# ---------------------------------------------------------------------------
# Methodology Knowledge Base Engine
# ---------------------------------------------------------------------------

class MethodologyKB:
    """Central codified methodology and intelligence knowledge base."""

    @classmethod
    def clean_domain(cls, target: str) -> str:
        """Extracts clean hostname/domain from arbitrary target input."""
        t = (target or "").strip().lower()
        if "://" in t:
            t = urlparse(t).netloc
        t = t.split("/")[0].split("@")[-1].split(":")[0]
        return t.strip(".")

    @classmethod
    def get_google_dorks(cls, target: str) -> Dict[str, List[Dict[str, str]]]:
        """Generates populated Google Dorks with clickable Google search URLs."""
        domain = cls.clean_domain(target)
        output: Dict[str, List[Dict[str, str]]] = {}
        for cat_id, cat_meta in GHDB_CATEGORIES.items():
            entries: List[Dict[str, str]] = []
            for dork in cat_meta["dorks"]:
                populated = dork.replace("{domain}", domain)
                search_url = f"https://www.google.com/search?q={quote_plus(populated)}"
                entries.append({
                    "dork": populated,
                    "search_url": search_url,
                })
            output[cat_id] = entries
        return output

    @classmethod
    def get_github_dorks(cls, target: str) -> List[Dict[str, str]]:
        """Generates populated GitHub dorks with direct GitHub Search URLs."""
        domain = cls.clean_domain(target)
        results: List[Dict[str, str]] = []
        for pat in GITHUB_DORK_PATTERNS:
            query = pat["query"].replace("{domain}", domain)
            search_url = f"https://github.com/search?q={quote_plus(query)}&type=code"
            results.append({
                "name": pat["name"],
                "query": query,
                "search_url": search_url,
            })
        return results

    @classmethod
    def get_403_bypass_variations(cls, base_url: str) -> List[Dict[str, Any]]:
        """Generates 403 bypass attempts using header injection and path mutations."""
        parsed = urlparse(base_url)
        path = parsed.path or "/"
        host = parsed.netloc

        variations: List[Dict[str, Any]] = []

        # 1. Header Bypasses
        for h in BYPASS_403_HEADERS:
            header_name = h["header"]
            header_val = h["value"].replace("{path}", path).replace("{host}", host)
            variations.append({
                "type": "header_injection",
                "url": base_url,
                "headers": {header_name: header_val},
                "description": f"Inject {header_name}: {header_val}",
            })

        # 2. Path Traversal & Normalization Bypasses
        for trick in BYPASS_403_PATH_TRICKS:
            mutated_path = trick.replace("{path}", path.rstrip("/"))
            mutated_url = urljoin(base_url, mutated_path)
            variations.append({
                "type": "path_mutation",
                "url": mutated_url,
                "headers": {},
                "description": f"Mutated path: {mutated_path}",
            })

        return variations

    @classmethod
    def get_master_extensions(cls) -> List[str]:
        """Returns the full 60+ extensions list for dirsearch and ffuf."""
        return list(MASTER_EXTENSIONS)

    @classmethod
    def get_sensitive_cms_paths(cls) -> List[Dict[str, str]]:
        """Returns high-value CMS paths (WordPress REST endpoints, .git, .env)."""
        return list(SENSITIVE_CMS_PATHS)

    @classmethod
    def get_hexstrike_catalog(cls) -> Dict[str, Dict[str, Any]]:
        """Returns the complete 150+ HexStrike tools inventory across 7 domains."""
        return HEXSTRIKE_ARSENAL_CATEGORIES
