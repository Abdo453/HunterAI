# HunterAI Master Reconnaissance & Attack Surface Methodology Playbook

> **Knowledge Base Document**  
> **Target Audience:** HunterAI Autonomous Brain, Qwen3 Orchestrator, WhiteRabbitNeo 8B, xploiter/pentester, Qwen 2.5 Coder, and Human Security Researchers.

This document serves as the canonical knowledge base for reconnaissance, asset discovery, content enumeration, parameter discovery, and attack surface mapping across all 20 phases.

---

## 🌐 Section 00: Specialized OSINT & Recon Intelligence Websites

| Platform | Category | Purpose / Capability |
| :--- | :--- | :--- |
| [c99 Subdomain Finder](https://subdomainfinder.c99.nl/) | Subdomains | Passive subdomain aggregator with historical indexing |
| [ShrewdEye](https://shrewdeye.app/) | Subdomains | Fast subdomain aggregation & discovery |
| [SecurityTrails](https://securitytrails.com/list/apex_domain/) | DNS History | Historical DNS records, subdomains, and apex mapping |
| [crt.sh](https://crt.sh) | CT Logs | Public Certificate Transparency log searches |
| [BGP HE](https://bgp.he.net/) | BGP / ASN | Autonomous System Number (ASN), routing prefixes & CIDR blocks |
| [Censys](https://search.censys.io/) | Origin IP | Internet-wide scans to discover true Origin IPs behind Cloudflare/WAF |
| [Shodan](https://www.shodan.io/) | Ports / IoT | Internet-connected devices, open ports, banners, and SSL certs |
| [Netlas](https://netlas.io/) | Infrastructure | Comprehensive IP, domain, and certificate mapping |
| [Favihash](https://www.favihash.com/) | Fingerprinting | Web server origin discovery via Favicon Murmur3 hash |
| [ViewDNS](https://viewdns.info/reverseip/?host=) | Reverse IP | Reverse IP lookup to uncover co-hosted sister domains |
| [DNSlytics](https://search.dnslytics.com/cidr) | ASN / CIDR | CIDR blocks and IP ownership tracking |
| [UltimateDomains](https://www.ultimatedomains.com/extract-domains.php) | Domain Extraction | Extracts apex root domains from large raw data blocks |
| [Wayback CDX API](https://web.archive.org/cdx/search/cdx) | Web History | Query Archive.org CDX index for endpoints and scripts |
| [URLScan](https://urlscan.io/) | Web Scans | Deep webpage snapshots, outbound connections, DOM structure |
| [AlienVault OTX](https://otx.alienvault.com/) | Threat Intel | Passive DNS and domain reputation data |
| [VirusTotal](https://www.virustotal.com/) | Reputation | Multi-engine malware and passive DNS resolutions |

---

## 1️⃣ Section 01: Passive Subdomain Enumeration

```bash
# 1. Subfinder
subfinder -d example.com -o Subs01.txt
subfinder -d example.com -all -recursive -o Subs01.txt
subfinder -dL targets.txt -all -recursive -o subs_all.txt

# 2. Assetfinder
echo example.com | assetfinder -subs-only > Subs02.txt
cat targets.txt | assetfinder -subs-only >> Subs02.txt

# 3. Amass
amass enum -passive -d example.com -o Subs03.txt
amass enum -d example.com -brute -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -o Subs03_brute.txt

# 4. Subenum
./subenum.sh -d example.com -u wayback,crt,abuseipdb,Findomain,Subfinder,Amass,Assetfinder -o Subs04.txt

# 5. Findomain
findomain -t example.com -u Subs05.txt
findomain -f targets.txt -u Subs05.txt

# 6. Chaos (ProjectDiscovery)
export PDCP_API_KEY="your_api_key_here"
chaos -d example.com -o Subs06.txt

# 7. GitHub Subdomains
github-subdomains -d example.com -t YOUR_GITHUB_TOKEN -o Subs_gh.txt

# 8. Certificate Transparency (crt.sh API)
curl -s "https://crt.sh/?q=%25.example.com&output=json" \
  | jq -r '.[].name_value' \
  | sed 's/\*\.//g' \
  | tr '\n' ',' | tr ',' '\n' \
  | grep -oE "[A-Za-z0-9._-]+\.example\.com" \
  | sort -u > Subs_crt.txt
```

---

## 2️⃣ Section 02: Active Subdomain Enumeration

```bash
# 1. dnscan
python3 dnscan.py -d example.com -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 300 -o Subs07.txt

# 2. puredns
wget https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt -O resolvers.txt
puredns bruteforce wordlist.txt example.com -r resolvers.txt -w puredns_subs.txt
puredns resolve all_potential_subs.txt -r resolvers.txt -w resolved_subs.txt

# 3. dnsx
dnsx -silent -d example.com -w wordlist.txt -o dnsx_subs.txt
cat potential_subs.txt | dnsx -silent -a -aaaa -cname -resp -o dnsx_resolved.txt
```

---

## 3️⃣ Section 03: Subdomain Fuzzing

```bash
ffuf -u https://FUZZ.example.com -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -mc 200,301,302,403
ffuf -u https://FUZZ.hacked.example.com -w wordlist.txt
ffuf -u https://FUZZ-example.com -w wordlist.txt
ffuf -u https://FUZZ-hacked.example.com -w wordlist.txt
ffuf -u https://hacked-FUZZ.example.com -w wordlist.txt
ffuf -u https://FUZZwww.example.com -w wordlist.txt
```

---

## 4️⃣ Section 04: Virtual Host (VHost) Enumeration

```bash
# Fuzz Host headers across IP or root domain
ffuf -u https://example.com -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.example.com" -fs 0
ffuf -u http://<TARGET_IP> -w wordlist.txt -H "Host: FUZZ.example.com" -mc 200,301,302,403
```

---

## 5️⃣ Section 05: Infrastructure Discovery (ASN, CIDR, Reverse DNS)

```bash
# 1. asnmap
asnmap -a AS17012 -silent
asnmap -org "Target Org" -silent -o cidrs.txt

# 2. whois
whois -h whois.radb.net -- '-i origin AS17012' | grep -Eo "([0-9.]+){4}/[0-9]+" | sort -u > cidrs.txt

# 3. hakrevdns
cat cidrs.txt | mapcidr -silent | hakrevdns -r 1.1.1.1 -o revdns_subs.txt
echo "192.168.1.0/24" | hakrevdns -r 1.1.1.1
hakrevdns -d example.com -R resolvers.txt

# 4. mapcidr
cat cidrs.txt | mapcidr -silent > ips.txt
mapcidr -cidr 192.168.0.0/16 -silent
```

---

## 6️⃣ Section 06: Data Merging & Deduplication Pipeline

```bash
# 1. anew
cat Subs*.txt | anew AllSubs.txt
cat new_candidates.txt | anew AllSubs.txt

# 2. sort
sort -u domains.txt -o unique_domains.txt
wc -l AllSubs.txt
```

---

## 7️⃣ Section 07: Alive Host Detection & Web Probing

```bash
cat AllSubs.txt | httpx -o AliveSubs.txt
cat AllSubs.txt | httpx -status-code -content-length -web-server -title -follow-redirects -o httpx_full.txt
cat AllSubs.txt | httpx -mc 200 -o AliveSubs_200.txt
cat AllSubs.txt | httpx -fc 400,404 -o AliveSubs_filtered.txt
cat AllSubs.txt | httpx -threads 100 -timeout 5 -o AliveSubs_fast.txt
```

---

## 8️⃣ Section 08: Subdomain Takeover Detection

```bash
# 1. subzy
subzy run --targets AllSubs.txt --hide_fails --vuln
subzy run --targets unique_subdomains.txt --vuln --hide_fails | grep -vi -E 'Akamai|AWS/S3|Airee\.ru|Anima|Bitbucket|Discourse|HatenaBlog|Help Juice|Help Scout|Helprace|Microsoft Azure|Smart JobBoard|Strikingly|Surge\.sh|SurveySparrow|Uberflip|Wordpress|Worksites'

# 2. dig verification
dig CNAME vulnerable-sub.example.com +short
```

---

## 9️⃣ Section 09: Network Port & Service Scanning

```bash
# 1. nmap
nmap -iL AliveSubs.txt -p 80,443,8080,8443,8000,8888,9000 -sV --open -oN quick_ports.txt
nmap -p- -sV -sC -T4 -Pn example.com -oN deep_scan.nmap

# 2. naabu
naabu -list AliveSubs.txt -p - -rate 2000 -o open_ports.txt
naabu -list AliveSubs.txt -top-ports 1000 -o top_ports.txt

# 3. rustscan
rustscan -a 192.168.1.1 -- -sC -sV -oN scan.nmap
```

---

## 🔟 Section 10: Directory & Web Content Discovery

```bash
# 1. dirsearch
dirsearch -u https://example.com -w /usr/share/wordlists/dirb/common.txt -t 100 -i 200 -e conf,config,bak,backup,swp,old,db,sql,asp,aspx,py,php,json,log,txt,zip,tar.gz
dirsearch -l AliveSubs.txt -o dirsearch_results.txt -i 200,301,302,403

# 2. feroxbuster
feroxbuster -u https://example.com -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt -t 200 -k -d 3 -e -x php,html,json,js,log,txt,bak,old,zip,tar,gz

# 3. ffuf
ffuf -u https://example.com/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -mc 200,401,403 -c
ffuf -u https://example.com/FUZZ -w wordlist.txt -H "Host: FUZZ.example.com"

# 4. gobuster
gobuster dir -u https://example.com -w /usr/share/wordlists/dirb/common.txt -x php,txt,html -t 50
```

---

## 1️⃣1️⃣ Section 11: Historical & Active URL Discovery

```bash
# 1. katana
katana -u AliveSubs.txt -jc -kf all -d 5 -headless -fx -aff -fs rdn -f url -silent > KTN_urls.txt
katana -list AliveSubs_200.txt -o katana_out.txt

# 2. waybackurls
cat AliveSubs.txt | waybackurls | sort -u > wayback_urls.txt
waybackurls https://example.com | grep -E "\.xls|\.xlsx|\.csv|\.sql|\.db|\.bak|\.backup|\.old|\.tar\.gz|\.tgz|\.zip|\.7z|\.rar|\.env|\.json|\.xml|\.pem|\.key|\.php|\.swp" > sensitive_urls.txt

# 3. gau & gauplus
cat AliveSubs.txt | gau --threads 100 > gau_urls.txt
gauplus -t 100 -random-agent < AliveSubs.txt > gauplus_urls.txt

# 4. gospider & hakrawler
gospider -S AliveSubs.txt -t 20 -d 3 --js --sitemap --robots -o gospider_out
cat AliveSubs.txt | hakrawler -subs -u -insecure > hakrawler_urls.txt

# 5. waymore
waymore -i AliveSubs.txt -mode U -l 1000 -from 2021 -oU waymore_urls.txt

# 6. CDX API
curl -s "https://web.archive.org/cdx/search/cdx?url=*.example.com/*&collapse=urlkey&output=text&fl=original&filter=original:.*.js$"
```

---

## 1️⃣2️⃣ Section 12: JavaScript Recon & Secret Mining

```bash
# 1. subjs
cat AllURLs.txt | subjs | sort -u > js_files.txt
cat AllURLs.txt | grep -i "\.js" | sort -u > js_files.txt

# 2. mantra / jsluice / jsleak
cat js_files.txt | mantra > mantra_secrets.txt
jsluice secrets js_files.txt
jsluice urls script.js
cat js_files.txt | xargs -P 20 -I {} jsleak -s -l -k -e {} >> jsleak_output.txt

# 3. SecretFinder
python3 SecretFinder.py -i https://example.com/bundle.js -o cli

# 4. trufflehog
trufflehog filesystem js_files.txt --json > trufflehog_results.json
trufflehog github --org=example-org --results=verified

# 5. Regex Extraction
grep -E "api[_-]?key|token|secret|password|bearer|auth|aws|s3" script.js
```

---

## 1️⃣3️⃣ Section 13: API Route & Endpoint Discovery

```bash
# Kiterunner (kr)
kr scan https://api.example.com -A=apiroutes-260227:10000 -x 8 -j 15 -v info
kr scan https://api.example.com -A=parameters-260227:5000 -x 5 -j 10 -v info
kr scan https://api.example.com -A=directories-260227:8000 -x 6 -j 12 -v info
kr scan targets.txt -A=directories-260227:8000 -x 6 -j 12 -v info
kr scan https://api.example.com -w /usr/share/wordlists/routes.txt -H 'x-access-token: 123'
```

---

## 1️⃣4️⃣ Section 14: Parameter Discovery & Mining

```bash
# 1. arjun
arjun -u https://example.com/test -m GET -o arjun_get.json
arjun -u https://example.com/test -m POST -o arjun_post.json
arjun -i AllURLs.txt -o arjun_all.json

# 2. paramspider
paramspider -d example.com -o PS_params.txt

# 3. x8
x8 -u "https://example.com/test" -w /usr/share/wordlists/parameters.txt -o x8_out.txt

# 4. qsreplace (Create Injection Targets)
cat AllURLs.txt | grep "=" | qsreplace "FUZZ" | anew ParamURLs.txt
cat AllURLs.txt | grep '=' | sed 's/=[^&]*/=/g' | sort -u > param_patterns.txt
```

---

## 1️⃣5️⃣ Section 15: Secrets, Sensitive Files & Dorking

```bash
# 1. originiphunter
echo "example.com" | originiphunter
cat domains.txt | originiphunter

# 2. Google Dorking
site:*.target.com intext:"docs.google.com/spreadsheets"
site:docs.google.com/spreadsheets "target.com"
site:docs.google.com/spreadsheets "password" "target.com"

# 3. Git Dorking
python3 GitDorker.py -tf tokens.txt -q example.com -d dorks/medium_dorks.txt -o git_leaks.txt

# 4. Wayback Sensitive Files
cat wayback_urls.txt | grep -E "\.env|\.git|\.htaccess|\.htpasswd|\.bak|\.backup|\.old|\.sql|\.db|\.zip|\.tar\.gz"
```

---

## 1️⃣6️⃣ Section 16: WordPress Vulnerability & User Enumeration

```bash
# 1. wpscan
wpscan --url https://target.com/blog/ -e vp,vt,u --disable-tls-checks
wpscan --url https://target.com --api-token <TOKEN> -e at -e ap -e u --plugins-detection aggressive

# 2. Sensitive WordPress Endpoints
/wp-json/wp/v2/users
/wp-json/?rest_route=/wp/v2/users/
/index.php?rest_route=/wp/v2/users
/author-sitemap.xml
/wp-content/debug.log
/wp-login.php?action=register
/wp-content/uploads/
```

---

## 1️⃣7️⃣ Section 17: Automated Vulnerability & Exposure Scanning

```bash
# 1. nuclei
nuclei -l AliveSubs_200.txt -t /root/nuclei-templates/http/exposures/ -o nuclei_exposures.txt
nuclei -l js_files.txt -t /root/nuclei-templates/http/exposures/ -o nuclei_js.txt
nuclei -u https://example.com -t /root/nuclei-templates/cves/ -severity critical,high -o nuclei_cves.txt

# 2. nikto
nikto -h https://example.com -Tuning 123b -output nikto_results.txt

# 3. HTTP Request Smuggler
python3 smuggler.py -u https://example.com

# 4. 403 Bypass Testing
./dontgo403 -u https://example.com/admin
./403-bypass.sh -u https://example.com/admin
```

---

## 1️⃣8️⃣ Section 18: System File Operations & Host Discovery

```bash
# 1. theHarvester
theHarvester -d example.com -l 200 -b google,bing,crtsh

# 2. sublist3r
sublist3r -d example.com -o sublist3r_subs.txt

# 3. Linux Configuration Audits
cat /etc/crontab
ftp -p <TARGET_IP> <PORT>
```

---

## 1️⃣9️⃣ Section 19: Exploitation & Verification Reference

```bash
# Metasploit Framework Basic Workflow
msfconsole -q
use <exploit_module>
set RHOSTS <target>
set LHOST <local_ip>
check
run
```

- **GTFOBins Reference:** [https://gtfobins.github.io/](https://gtfobins.github.io/) (Privilege escalation & binary security bypass)
- **RevShells Reference:** [https://www.revshells.com/](https://www.revshells.com/) (Reverse shell payload syntax generation)

---

## 2️⃣0️⃣ Section 20: Comprehensive Extensions & Sensitive Wordlists

Standard sensitive file extensions to fuzz:
```text
conf, config, bak, backup, swp, old, db, sql, asp, aspx, aspx~, asp~, py, py~,
rb, rb~, php, php~, bkp, cache, cgi, csv, html, inc, jar, js, json, jsp, jsp~,
lock, log, rar, sql.gz, sql.zip, sql.tar.gz, sql~, swp~, tar, tar.bz2, tar.gz,
txt, wadl, zip, .log, .xml, .js, .json, .env, .git, .yml, .yaml, .pem, .key
```
