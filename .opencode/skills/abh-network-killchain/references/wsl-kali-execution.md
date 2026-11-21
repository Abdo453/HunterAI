# Kali Execution via WSL — Windows Host

## Distros & Channels

Disto name on this host: `kali-linux`. Verify: `wsl -l -v`

Three execution channels, priority order:

### 1. MCP hunter-arsenal (preferred, structured output)
```
tools["hunter-arsenal"].kali_nmap({ target: "10.10.10.5", extra_args: ["-sV", "-p445"] })
```
Full list: 63 tools (`kali_masscan`, `kali_netexec`, `kali_subfinder`, `kali_enum4linux_ng`, ...).
Fallback for anything unlisted: `tools["hunter-arsenal"].kali_dispatch_tool`.

### 2. WSL direct (PowerShell)
```powershell
wsl -d kali-linux -- bash -lc "nmap -sV -p80,443 target.com"
wsl -d kali-linux -- bash -lc "netexec smb <ip> -u '' -p '' --shares"
```
Notes:
- Quote whole bash command; escape inner quotes with backslash.
- Long-running: split into a file, `nohup`, and poll: output goes to `artifacts/<target>/<phase>/`.
- Wordlists live at `/usr/share/wordlists/` inside WSL (rockyou needs gunzip once).

### 3. Local Windows agents (repo-native)
`python agents/nmap_agent.py ...`, `agents/netexec_agent.py`, `agents/masscan_agent.py` — when an existing agent already wraps the tool with its own parsing/output handling, prefer it over a raw shell call.

## Reliability Rules
- Prefer channel 1 → 3 → 2, in that order (structured > repo-agent > raw shell).
- Never report success without the tool's own output in the transcript.
- If a WSL call dies silently (timeout), retry once with a narrower scope (single port / single host) rather than skipping the phase.
- Save every raw result: `artifacts/<target>/<phase>/<tool>.txt` (the phase-playbooks references these paths).
