"""
Google Hacking Database (GHDB), OSINT Hub & Bug Bounty 13-Step Methodology Engine
Enriches the Agent's knowledge base with:
1. Google Hacking Database (GHDB) Dorking Engine (sensitive files, admin portals, API endpoints, leaked sheets, GitHub dorks).
2. OSINT Reconnaissance Hub (Subdomain & Infrastructure discovery: C99, Shrewdeye, SecurityTrails, Censys, Shodan, BGP, ViewDNS, Netlas, Urlscan).
3. Comprehensive Bug Bounty 13-Step Playbook (Subdomains -> Deduplication -> Nmap -> Subzy -> Httpx -> Smuggler -> Dirsearch -> Nuclei -> URLs -> JS Mining -> Arjun -> WordPress -> SQLMap).
4. Master Wordlists Catalog (SecLists DNS, Web Content, Kiterunner assetnote routes).
5. 403 Bypass Headers, Extensions, and Sensitive Regex Patterns.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)

# ── 1. Google Hacking Database (GHDB) Categories & Dork Templates ─────────────
GHDB_DORK_TEMPLATES: Dict[str, List[str]] = {
    "sensitive_files": [
        "site:{domain} filetype:env | filetype:sql | filetype:bak | filetype:backup | filetype:old | filetype:conf | filetype:config",
        "site:{domain} filetype:xls | filetype:xlsx | filetype:csv | filetype:json | filetype:xml",
        "site:{domain} filetype:log | filetype:ini | filetype:yaml | filetype:yml | filetype:pem | filetype:key | filetype:crt | filetype:ssh",
        "site:{domain} filetype:tar.gz | filetype:tgz | filetype:zip | filetype:7z | filetype:rar | filetype:dump | filetype:dmp",
        "site:{domain} inurl:wp-content/uploads/ | inurl:wp-config.php.bak",
        "site:{domain} inurl:\"/.git\" | inurl:\"/.env\" | inurl:\"/id_rsa\" | inurl:\"/.htaccess\"",
    ],
    "admin_and_auth_panels": [
        "site:{domain} inurl:admin | inurl:login | inurl:signin | inurl:auth | inurl:dashboard | inurl:portal",
        "site:{domain} inurl:phpmyadmin | inurl:cpanel | inurl:webmail",
        "site:{domain} intitle:\"index of /\" \"admin\"",
        "site:{domain} inurl:oauth | inurl:sso | inurl:register | inurl:signup | inurl:reset | inurl:password",
    ],
    "api_and_developer_endpoints": [
        "site:{domain} inurl:api | inurl:v1 | inurl:v2 | inurl:v3 | inurl:graphql | inurl:gql",
        "site:{domain} inurl:swagger | inurl:openapi | inurl:actuator | inurl:debug | inurl:test | inurl:beta | inurl:staging",
        "site:{domain} inurl:webhook | inurl:callback | inurl:redirect_uri | inurl:url= | inurl:dest= | inurl:goto= | inurl:return=",
        "site:{domain} filetype:json inurl:swagger.json | inurl:openapi.json",
    ],
    "credential_and_secret_leaks": [
        "site:{domain} intext:\"password\" | intext:\"api_key\" | intext:\"apikey\" | intext:\"secret\" | intext:\"token\"",
        "site:{domain} intext:\"authorization: bearer\" | intext:\"AWS_SECRET_ACCESS_KEY\" | intext:\"BEGIN PRIVATE KEY\"",
        "site:docs.google.com/spreadsheets \"{domain}\"",
        "site:docs.google.com/spreadsheets \"password\" \"{domain}\"",
        "site:docs.google.com/spreadsheets \"@{domain}\"",
        "site:*.{domain} intext:\"docs.google.com/spreadsheets\"",
        "site:github.com \"{domain}\" \"API_KEY\"",
        "site:github.com \"{domain}\" \"Credentials\"",
    ],
    "cloud_and_infrastructure": [
        "site:s3.amazonaws.com \"{domain}\"",
        "site:blob.core.windows.net \"{domain}\"",
        "site:storage.googleapis.com \"{domain}\"",
        "site:firebaseio.com \"{domain}\"",
    ],
    "bug_bounty_and_scope": [
        "site:{domain} \"bug bounty\" | \"responsible disclosure\" | \"security.txt\"",
        "site:hackerone.com \"{domain}\"",
        "site:yeswehack.com \"{domain}\"",
        "site:standoff365.com \"{domain}\"",
    ]
}

# ── 2. Specialized OSINT & Recon Intelligence Hub ────────────────────────────
OSINT_SERVICES_DIRECTORY: Dict[str, Dict[str, str]] = {
    "c99_subdomain_finder": {
        "url": "https://subdomainfinder.c99.nl/",
        "category": "subdomains",
        "description": "Passive subdomain finder with extensive historical indexing."
    },
    "shrewdeye": {
        "url": "https://shrewdeye.app/",
        "category": "subdomains",
        "description": "Fast subdomain aggregation and discovery."
    },
    "securitytrails": {
        "url": "https://securitytrails.com/list/apex_domain/{domain}",
        "category": "dns_history",
        "description": "Historical DNS records and apex domain enumeration."
    },
    "censys": {
        "url": "https://search.censys.io/",
        "category": "origin_ip",
        "description": "Internet-wide scan database to discover real Origin IP behind Cloudflare/CDNs."
    },
    "shodan": {
        "url": "https://www.shodan.io/search?query=ssl%3A{domain}",
        "category": "infrastructure_ports",
        "description": "Search engine for internet-connected devices, open ports, and SSL certs."
    },
    "bgp_he_net": {
        "url": "https://bgp.he.net/",
        "category": "asn_cidr",
        "description": "BGP routing, autonomous system number (ASN), and IP prefix lookups."
    },
    "viewdns": {
        "url": "https://viewdns.info/reverseip/?host={domain}",
        "category": "reverse_ip",
        "description": "Reverse IP and reverse DNS lookup tool to find co-hosted domains."
    },
    "crt_sh": {
        "url": "https://crt.sh/?q=%25.{domain}&output=json",
        "category": "certificate_transparency",
        "description": "Public Certificate Transparency (CT) log query service."
    },
    "favihash": {
        "url": "https://favihash.com",
        "category": "technology_fingerprint",
        "description": "Identifies web servers and origins via Favicon hash lookup."
    },
    "netlas": {
        "url": "https://netlas.io/",
        "category": "infrastructure_recon",
        "description": "Internet intelligence engine for IP, domain, and certificate mapping."
    },
    "urlscan": {
        "url": "https://urlscan.io/search/#domain:{domain}",
        "category": "web_scans",
        "description": "Historical web page scan archive, DOM snapshots, and outbound HTTP requests."
    },
    "otx_alienvault": {
        "url": "https://otx.alienvault.com/indicator/domain/{domain}",
        "category": "threat_intelligence",
        "description": "Open Threat Exchange domain telemetry, passive DNS, and associated URLs."
    },
    "virustotal": {
        "url": "https://www.virustotal.com/gui/domain/{domain}",
        "category": "reputation_dns",
        "description": "Multi-engine malware and passive DNS historical domain resolutions."
    },
    "dnslytics": {
        "url": "https://search.dnslytics.com/cidr",
        "category": "asn_cidr",
        "description": "CIDR and IP block ownership intelligence."
    },
    "exifinfo": {
        "url": "https://exifinfo.org",
        "category": "metadata_osint",
        "description": "Online metadata and EXIF data analyzer for uploaded media and files."
    },
    "mail_meteor": {
        "url": "https://mailmeteor.com/email-checker",
        "category": "email_verification",
        "description": "Corporate email address verification and MX delivery validation."
    },
    "matthewfl_unpacker": {
        "url": "https://matthewfl.com/unPacker.html",
        "category": "js_deobfuscation",
        "description": "Deobfuscator and unpacker for packed client-side JavaScript."
    },
    "origin_ip_hunter": {
        "url": "https://github.com/rix4uni/originiphunter",
        "category": "origin_ip",
        "description": "Automated Origin IP hunter bypassing reverse proxy/WAF."
    }
}

# ── 3. Master Bug Bounty Wordlists Directory ─────────────────────────────────
MASTER_WORDLISTS = {
    "dns": [
        "/usr/share/wordlists/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt",
        "/usr/share/wordlists/seclists/Discovery/DNS/dns-Jhaddix.txt",
        "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt",
        "/usr/share/wordlists/commonspeak2-wordlists-master/subdomains/subdomains.txt",
        "/usr/share/wordlists/commonspeak2-wordlists-master/subdomains/fierce-hostlist.txt",
        "/usr/share/wordlists/best-dns-wordlist.txt"
    ],
    "web_content": [
        "/usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt",
        "/usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-files.txt",
        "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
        "/usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt",
        "/usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-files.txt",
        "/usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt"
    ],
    "kiterunner_routes": [
        "apiroutes-260227:10000",
        "parameters-260227:5000",
        "directories-260227:8000"
    ]
}

# ── 4. Full 13-Step Bug Bounty Playbook ───────────────────────────────────────
BUG_BOUNTY_13_STEP_WORKFLOW = [
    {
        "step": 1,
        "name": "Subdomain Gathering (Passive + Active + OSINT)",
        "tools": ["subfinder", "assetfinder", "amass", "theHarvester", "dnscan", "puredns", "dnsx", "ffuf"],
        "commands": [
            "subfinder -d {domain} -all -recursive -o subs_subfinder.txt",
            "echo {domain} | assetfinder -subs-only > subs_assetfinder.txt",
            "amass enum -d {domain} -o subs_amass.txt",
            "theHarvester -d {domain} -l 100 -b google,bing,duckduckgo,crtsh,hackertarget,otx,urlscan",
            "python dnscan.py -d {domain} -w wordlist.txt -t 300 -o subs_dnscan.txt",
            "puredns bruteforce wordlist.txt {domain} -r resolvers.txt -w subs_puredns.txt",
            "dnsx -silent -d {domain} -w wordlist.txt -o subs_dnsx.txt",
            "ffuf -u https://FUZZ.{domain} -w wordlist.txt -mc 200,301,302",
            "ffuf -u https://{domain} -H 'Host: FUZZ.{domain}' -w wordlist.txt"
        ],
        "rationale": "Comprehensive enumeration covering DNS bruteforce, virtual host headers, and passive multi-source OSINT."
    },
    {
        "step": 2,
        "name": "Deduplicate & Normalize Subdomains",
        "tools": ["anew", "sort", "uniq"],
        "commands": [
            "cat subs_*.txt | anew unique_subdomains.txt",
            "sort -u unique_subdomains.txt -o unique_subdomains.txt",
            "wc -l unique_subdomains.txt"
        ],
        "rationale": "Cleanse and deduplicate assets to avoid redundant downstream scanning."
    },
    {
        "step": 3,
        "name": "Port & Service Discovery",
        "tools": ["nmap", "naabu", "msfconsole"],
        "commands": [
            "nmap -iL unique_subdomains.txt -T4 -Pn -sV --open -o scan_nmap.txt",
            "naabu -list unique_subdomains.txt -p - -rate 2000 -o ports_naabu.txt"
        ],
        "rationale": "Identify open TCP/UDP services, grab software version banners, and check for outdated daemons."
    },
    {
        "step": 4,
        "name": "Subdomain Takeover Inspection",
        "tools": ["subzy", "dig"],
        "commands": [
            "subzy run --targets unique_subdomains.txt --vuln --hide_fails",
            "dig CNAME {domain}"
        ],
        "rationale": "Detect dangling CNAME records pointing to unclaimed third-party services (S3, GitHub Pages, Heroku, Azure)."
    },
    {
        "step": 5,
        "name": "Live Host Probing & Status Filtering",
        "tools": ["httpx"],
        "commands": [
            "cat unique_subdomains.txt | httpx -o httpx_all.txt",
            "cat httpx_all.txt | httpx -status-code -content-length -web-server -title -follow-redirects",
            "cat httpx_all.txt | httpx -mc 200 -o httpx200.txt"
        ],
        "rationale": "Identify active web servers with HTTP 200 OK, follow redirects, and fingerprint web servers."
    },
    {
        "step": 6,
        "name": "HTTP Request Smuggling Audit",
        "tools": ["smuggler.py"],
        "commands": [
            "python smuggler.py -u https://{domain}",
            "cat httpx200.txt | python smuggler.py"
        ],
        "rationale": "Probe reverse proxies and front-end/back-end discrepancies for CL.TE and TE.CL smuggling vulnerabilities."
    },
    {
        "step": 7,
        "name": "Sensitive Directory, File & 403 Bypass Fuzzing",
        "tools": ["dirsearch", "feroxbuster", "ffuf", "dontgo403", "403-bypass.sh"],
        "commands": [
            "dirsearch -l httpx200.txt -o dirsearch.txt -i 200 -e conf,config,bak,backup,swp,old,db,sql,asp,aspx,py,php,cache,log,zip,tar.gz,env,json,xml",
            "ffuf -u https://{domain}/FUZZ -w common.txt -H 'X-Forwarded-For: 127.0.0.1' -H 'X-Original-URL: /FUZZ'",
            "./dontgo403 -u https://{domain}/admin"
        ],
        "rationale": "Search for exposed backups, configuration files, and attempt headers/rewrite 403 bypasses."
    },
    {
        "step": 8,
        "name": "Vulnerability & Misconfiguration Triage",
        "tools": ["nuclei"],
        "commands": [
            "nuclei -l httpx200.txt -o nuclei_exposures.txt -t /root/nuclei-templates/",
            "nuclei -u https://{domain} -severity critical,high,medium -silent"
        ],
        "rationale": "Scan all active hosts against community-curated vulnerability, exposure, and CVE templates."
    },
    {
        "step": 9,
        "name": "Full Spectrum URL Discovery",
        "tools": ["waybackurls", "katana", "gospider", "waymore", "gauplus", "paramspider", "x8"],
        "commands": [
            "cat httpx200.txt | waybackurls >> allurls.txt",
            "katana -list httpx200.txt -jc -kf all -d 5 -headless -fx -aff -fs rdn -f url -silent -o katana.txt",
            "gospider -S httpx200.txt -t 20 -d 3 --js --sitemap --robots -o gospider_output",
            "waymore -i httpx200.txt -mode U -l 1000 -from 2021 -oU waymore.txt",
            "gauplus -t 200 -random-agent < httpx200.txt >> allurls.txt",
            "cat allurls.txt | anew unique_allurls.txt"
        ],
        "rationale": "Mine both historical archives (Wayback Machine, CommonCrawl) and active deep web crawler spiders."
    },
    {
        "step": 10,
        "name": "JavaScript Mining & Secret Extraction",
        "tools": ["subjs", "mantra", "jsecret", "jsleak", "SecretFinder.py", "jsluice", "trufflehog"],
        "commands": [
            "cat unique_allurls.txt | grep -Ei '\\.js($|\\?)' | anew js.txt",
            "cat js.txt | mantra",
            "python3 SecretFinder.py -i js.txt -o cli",
            "trufflehog filesystem js.txt --json > trufflehog_results.json",
            "nuclei -l js.txt -t /root/nuclei-templates/http/exposures/ -o nucleijs.txt"
        ],
        "rationale": "Extract endpoints, hardcoded credentials, cloud API keys, and authorization tokens from JavaScript."
    },
    {
        "step": 11,
        "name": "Parameter Mining & Extraction",
        "tools": ["arjun", "qsreplace", "param-miner", "x8"],
        "commands": [
            "cat unique_allurls.txt | grep -Ei '\\.php($|\\?)' | anew php.txt",
            "arjun -i php.txt >> arjun_get.txt",
            "arjun -i php.txt -m post -o arjun_post.json",
            "cat unique_allurls.txt | grep '=' | qsreplace 'FUZZ' | anew param_urls.txt"
        ],
        "rationale": "Identify GET and POST parameter reflection points for SQLi, XSS, SSRF, and IDOR attacks."
    },
    {
        "step": 12,
        "name": "WordPress & CMS Enumeration",
        "tools": ["wpscan"],
        "commands": [
            "wpscan --url https://{domain} --disable-tls-checks -e at,ap,u --plugins-detection aggressive",
            "curl -s https://{domain}/wp-json/wp/v2/users",
            "curl -s https://{domain}/wp-content/debug.log"
        ],
        "rationale": "Identify installed plugins, themes, user account enumeration, and debug log disclosures."
    },
    {
        "step": 13,
        "name": "Targeted Exploitation & Multi-Layer Verification",
        "tools": ["sqlmap", "HunterVerificationEngine"],
        "commands": [
            "sqlmap -u 'https://{domain}/file.php?id=*' --risk 3 --level 5 --random-agent --banner --batch --dbs --ignore-code 403",
            "sqlmap -u 'https://{domain}' --data 'id=*&name=*&x=*' --dbs --banner --batch"
        ],
        "rationale": "Conduct safe, verified probing with arithmetic reflection proofs and strict non-destructive constraints."
    }
]


class DorkingAndOSINTKnowledge:
    """
    محرك استخبارات الـ GHDB و الـ OSINT و المنهجية الشاملة (13-Step Workflow Engine):
    - يولد روابط الـ Google Dorks المخصصة لأي هدف مستهدف تلقائياً.
    - يقدم روابط مباشرة لكافة منصات الـ OSINT والـ Recon وتحديد الـ Origin IP.
    - يزود الـ Agent بكامل خطوات الـ 13-Step Bug Bounty Playbook.
    - يوفر قوائم Wordlists المعيارية (SecLists و Assetnote).
    """

    @classmethod
    def generate_dorks_for_target(cls, domain: str) -> Dict[str, List[str]]:
        """توليد قائمة كاملة من الـ Google Dorks المخصصة للنطاق المستهدف"""
        clean_domain = domain.lower().strip().replace("http://", "").replace("https://", "").strip("/")
        results = {}
        for cat_name, templates in GHDB_DORK_TEMPLATES.items():
            results[cat_name] = [tmpl.format(domain=clean_domain) for tmpl in templates]
        return results

    @classmethod
    def get_osint_lookup_directory(cls, domain: str) -> Dict[str, Dict[str, str]]:
        """الحصول على مصادر الـ OSINT مع الروابط المهيأة للهدف"""
        clean_domain = domain.lower().strip().replace("http://", "").replace("https://", "").strip("/")
        res = {}
        for service_key, info in OSINT_SERVICES_DIRECTORY.items():
            link = info["url"].format(domain=clean_domain)
            res[service_key] = {
                "name": service_key.replace("_", " ").title(),
                "url": link,
                "category": info["category"],
                "description": info["description"]
            }
        return res

    @classmethod
    def get_recon_playbook_steps(cls, domain: str) -> List[Dict[str, Any]]:
        """الحصول على خطوات فحص الـ Recon مع الأوامر المخصصة للهدف (13 خطوة كاملة)"""
        clean_domain = domain.lower().strip().replace("http://", "").replace("https://", "").strip("/")
        steps = []
        for s in BUG_BOUNTY_13_STEP_WORKFLOW:
            s_copy = dict(s)
            s_copy["commands"] = [cmd.format(domain=clean_domain) for cmd in s["commands"]]
            steps.append(s_copy)
        return steps

    @classmethod
    def get_wordlists_catalog(cls) -> Dict[str, List[str]]:
        """الحصول على مسارات الـ Wordlists الموصى بها"""
        return MASTER_WORDLISTS

    @classmethod
    def register_in_knowledge_base(cls, kb: Any) -> int:
        """تسجيل كافة تقنيات الـ GHDB والـ OSINT والـ 13-Step Workflow داخل قاعدة المعرفة المركزية للـ Agent"""
        count = 0

        # 1. GHDB Technique
        kb.save_technique(
            technique_name="Google Hacking Database (GHDB) Dorking",
            category="recon_osint",
            description="Automated Google dorking queries for sensitive files, admin panels, API keys, and cloud leaks.",
            tools=["google", "shodan", "censys"],
            steps=[
                "1. Run filetype: dorks for .env, .sql, .bak, .log, .conf, .tar.gz, .zip",
                "2. Run inurl: dorks for admin, login, api, graphql, swagger, oauth",
                "3. Run intext: dorks for credentials, api_key, authorization bearer",
                "4. Query site:docs.google.com/spreadsheets for exposed target spreadsheets",
                "5. Query site:github.com for target Credentials and API keys"
            ],
            affected_tech=["all_web"]
        )
        count += 1

        # 2. OSINT Hub Technique
        kb.save_technique(
            technique_name="External OSINT & Origin IP Enumeration",
            category="recon_osint",
            description="Discovery of subdomains, BGP/ASN infrastructure, and real Origin IPs behind CDNs using Shodan, Censys, C99, Shrewdeye, and ViewDNS.",
            tools=["censys", "shodan", "securitytrails", "crt.sh", "viewdns", "netlas", "favihash"],
            steps=[
                "1. Query crt.sh, C99, and SecurityTrails for historical subdomains",
                "2. Query Censys and Shodan with SSL certificate matching to discover real Origin IP",
                "3. Perform BGP ASN lookup on bgp.he.net and dnslytics for IP ranges and CIDRs",
                "4. Use Favicon hashing (favihash) and reverse IP lookups (viewdns)"
            ],
            affected_tech=["infrastructure"]
        )
        count += 1

        # 3. Complete 13-Step Workflow
        kb.save_technique(
            technique_name="Full 13-Step Bug Bounty Workflow Playbook",
            category="recon_automation",
            description="End-to-end bug bounty methodology: Subdomains -> Deduplication -> Nmap -> Subzy -> Httpx -> Smuggler -> Dirsearch -> Nuclei -> URLs -> JS Mining -> Arjun -> WordPress -> SQLMap.",
            tools=["subfinder", "nmap", "subzy", "httpx", "smuggler", "dirsearch", "nuclei", "katana", "waybackurls", "mantra", "arjun", "wpscan", "sqlmap"],
            steps=[
                "Step 1: Subfinder / Assetfinder / Amass / theHarvester / Dnsx / PureDNS",
                "Step 2: Anew / Sort deduplication",
                "Step 3: Nmap port and service banner discovery",
                "Step 4: Subzy subdomain takeover validation",
                "Step 5: Httpx alive verification & 200 OK filtering",
                "Step 6: Smuggler.py HTTP request smuggling probing",
                "Step 7: Dirsearch & FFUF sensitive extensions and 403 bypass",
                "Step 8: Nuclei comprehensive exposure scanning",
                "Step 9: Waybackurls / Katana / Gospider / Waymore URL gathering",
                "Step 10: Subjs / Mantra / SecretFinder / Trufflehog JS secret mining",
                "Step 11: Arjun GET and POST parameter discovery & qsreplace",
                "Step 12: WPScan & WordPress user/debug.log enumeration",
                "Step 13: SQLMap targeted verification and arithmetic injection proof"
            ],
            affected_tech=["all_web"]
        )
        count += 1

        if hasattr(kb, "flush_vectors"):
            kb.flush_vectors()

        return count
