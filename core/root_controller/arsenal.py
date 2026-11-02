"""Arsenal coverage for the root controller.

The controller's tool surface is only meaningful if it is measured: which
tools the manifest claims, which of them exist on this machine, which are
gated behind an authorization requirement, and what it takes to close the gap.

This module reconciles ``tools_mcp.json`` (the manifest the controller ships)
against the real filesystem, optionally probing a WSL Kali sidecar, and emits
an install plan for whatever is missing.

Python 3.11, standard library only.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

__all__ = ["Arsenal", "ToolEntry", "INSTALL_HINTS", "default_probe"]

# Tool -> (kali package, arch package).  Both are the Debian/Arch names for the
# same upstream binary; the plan prints the Kali form and notes the Arch one.
INSTALL_HINTS: Dict[str, tuple[str, str]] = {
    "aircrack-ng": ("aircrack-ng", "aircrack-ng"),
    "arjun": ("arjun", "arjun"),
    "assetfinder": ("assetfinder", "assetfinder"),
    "binwalk": ("binwalk", "binwalk"),
    "checkov": ("checkov", "checkov"),
    "checksec": ("checksec", "checksec"),
    "dalfox": ("dalfox", "dalfox"),
    "dirsearch": ("dirsearch", "dirsearch"),
    "dnsx": ("dnsx", "dnsx"),
    "enum4linux-ng": ("enum4linux-ng", "enum4linux-ng"),
    "exiftool": ("libimage-exiftool-perl", "exiftool"),
    "feroxbuster": ("feroxbuster", "feroxbuster"),
    "ffuf": ("ffuf", "ffuf"),
    "file": ("file", "file"),
    "foremost": ("foremost", "foremost"),
    "gau": ("gau", "gau"),
    "gdb": ("gdb", "gdb"),
    "gobuster": ("gobuster", "gobuster"),
    "hakrawler": ("hakrawler", "hakrawler"),
    "hashcat": ("hashcat", "hashcat"),
    "httpx": ("httpx", "httpx"),
    "hydra": ("hydra", "hydra"),
    "john": ("john", "john"),
    "kismet": ("kismet", "kismet"),
    "kube-hunter": ("kube-hunter", "kube-hunter"),
    "masscan": ("masscan", "masscan"),
    "medusa": ("medusa", "medusa"),
    "metasploit-framework": ("metasploit-framework", "metasploit-framework"),
    "modbus-cli": ("pymodbus", "pymodbus"),
    "naabu": ("naabu", "naabu"),
    "netexec": ("netexec", "netexec"),
    "nikto": ("nikto", "nikto"),
    "nmap": ("nmap", "nmap"),
    "nuclei": ("nuclei", "nuclei"),
    "paramspider": ("paramspider", "paramspider"),
    "prowler": ("prowler", "prowler"),
    "radare2": ("radare2", "radare2"),
    "recon-ng": ("recon-ng", "recon-ng"),
    "responder": ("responder", "responder"),
    "shodan": ("shodan", "shodan"),
    "sherlock": ("sherlock", "sherlock"),
    "snmpwalk": ("snmp", "snmp"),
    "sqlmap": ("sqlmap", "sqlmap"),
    "ssh-audit": ("ssh-audit", "ssh-audit"),
    "sslscan": ("sslscan", "sslscan"),
    "steghide": ("steghide", "steghide"),
    "strings": ("binutils", "binutils"),
    "subfinder": ("subfinder", "subfinder"),
    "testssl.sh": ("testssl.sh", "testssl.sh"),
    "trivy": ("trivy", "trivy"),
    "vol": ("volatility3", "volatility"),
    "wafw00f": ("wafw00f", "wafw00f"),
    "waybackurls": ("waybackurls", "waybackurls"),
    "whatweb": ("whatweb", "whatweb"),
    "wifite": ("wifite", "wifite"),
    "wpscan": ("wpscan", "wpscan"),
    "zsteg": ("zsteg", "zsteg"),
}

# Tools that ship outside the Debian archive.
NPM_HINTS: Dict[str, str] = {
    "zigbee2mqtt": "zigbee2mqtt",
}

PIP_HINTS: Dict[str, str] = {
    "modbus-cli": "pymodbus",
}


def default_probe(name: str) -> Optional[str]:
    """Locate a binary on PATH; ``None`` when it is absent."""
    return shutil.which(name)


@dataclass
class ToolEntry:
    """One catalogueued tool and its real installation state."""

    name: str
    tier: str
    risk: str
    requires_authorization: bool
    action_class: str
    installed: bool = False
    path: str = ""
    package: str = ""
    arch_package: str = ""
    npm_package: str = ""
    pip_package: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "tier": self.tier,
            "risk": self.risk,
            "requires_authorization": self.requires_authorization,
            "action_class": self.action_class,
            "installed": self.installed,
            "path": self.path,
            "install": {
                "apt": self.package,
                "arch": self.arch_package,
                "npm": self.npm_package,
                "pip": self.pip_package,
            },
        }


@dataclass
class Arsenal:
    """Reconciles the tool manifest against what is actually installed."""

    manifest_path: Path
    probe: Callable[[str], Optional[str]] = default_probe
    tiers: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    entries: List[ToolEntry] = field(default_factory=list)
    constraints: Dict[str, List[str]] = field(default_factory=dict)

    @classmethod
    def load(
        cls,
        manifest_path: str,
        *,
        probe: Callable[[str], Optional[str]] = default_probe,
    ) -> "Arsenal":
        path = Path(manifest_path)
        if not path.exists():
            raise FileNotFoundError(f"tool manifest not found: {path}")
        data = json.loads(path.read_text(encoding="utf-8"))
        tiers = dict(data.get("tiers") or {})
        entries: List[ToolEntry] = []
        constraints: Dict[str, List[str]] = {}
        for tier_name, tier in tiers.items():
            constraints[tier_name] = list(tier.get("constraints") or [])
            for tool in tier.get("tools") or []:
                apt, arch = INSTALL_HINTS.get(tool, ("", ""))
                entries.append(
                    ToolEntry(
                        name=tool,
                        tier=tier_name,
                        risk=str(tier.get("risk", "medium")),
                        requires_authorization=bool(
                            tier.get("requires_authorization", True)
                        ),
                        action_class=str(tier.get("action_class", "active_test")),
                        package=apt,
                        arch_package=arch,
                        npm_package=NPM_HINTS.get(tool, ""),
                        pip_package=PIP_HINTS.get(tool, ""),
                    )
                )
        arsenal = cls(manifest_path=path, probe=probe, tiers=tiers, entries=entries)
        arsenal.rescan()
        return arsenal

    # -- scanning ----------------------------------------------------------
    def rescan(self) -> List[ToolEntry]:
        """Re-probe every catalogued tool."""
        for entry in self.entries:
            location = self.probe(entry.name)
            entry.installed = bool(location)
            entry.path = location or ""
        return self.entries

    def scan_wsl(self, timeout_s: float = 6.0) -> List[str]:
        """Probe a WSL sidecar for binaries missing from the Windows PATH.

        Returns the names newly resolved inside WSL.
        """
        found: List[str] = []
        for entry in self.entries:
            if entry.installed:
                continue
            try:
                completed = subprocess.run(
                    ["wsl.exe", "-e", "sh", "-lc", f"command -v {entry.name}"],
                    capture_output=True,
                    text=True,
                    timeout=timeout_s,
                )
            except (OSError, subprocess.SubprocessError):
                continue
            location = (completed.stdout or "").strip().splitlines()
            if completed.returncode == 0 and location:
                entry.installed = True
                entry.path = f"wsl:{location[0].strip()}"
                found.append(entry.name)
        return found

    # -- reporting ---------------------------------------------------------
    def coverage(self) -> Dict[str, Any]:
        per_tier: Dict[str, Dict[str, Any]] = {}
        for tier_name, tier in self.tiers.items():
            tier_entries = [e for e in self.entries if e.tier == tier_name]
            installed = [e for e in tier_entries if e.installed]
            per_tier[tier_name] = {
                "risk": tier.get("risk", "medium"),
                "action_class": tier.get("action_class", "active_test"),
                "requires_authorization": bool(
                    tier.get("requires_authorization", True)
                ),
                "total": len(tier_entries),
                "installed": len(installed),
                "missing": len(tier_entries) - len(installed),
                "constraints": list(tier.get("constraints") or []),
            }
        installed = [e for e in self.entries if e.installed]
        return {
            "total": len(self.entries),
            "installed": len(installed),
            "missing": len(self.entries) - len(installed),
            "coverage_pct": round(
                100.0 * len(installed) / len(self.entries), 1
            )
            if self.entries
            else 0.0,
            "manifest": str(self.manifest_path),
            "tiers": per_tier,
        }

    def missing(self) -> List[ToolEntry]:
        return [entry for entry in self.entries if not entry.installed]

    def plan(self) -> Dict[str, List[str]]:
        """Install plan for the missing tools, grouped by package manager."""
        apt: List[str] = []
        npm: List[str] = []
        pip: List[str] = []
        arch: List[str] = []
        for entry in self.missing():
            if entry.package:
                apt.append(entry.package)
            if entry.arch_package:
                arch.append(entry.arch_package)
            if entry.npm_package:
                npm.append(entry.npm_package)
            if entry.pip_package:
                pip.append(entry.pip_package)
        return {
            "apt": sorted(set(apt)),
            "arch": sorted(set(arch)),
            "npm": sorted(set(npm)),
            "pip": sorted(set(pip)),
        }

    def render(self) -> str:
        """Human-readable coverage table."""
        coverage = self.coverage()
        lines: List[str] = []
        lines.append(
            f"tool surface: {coverage['installed']}/{coverage['total']} installed "
            f"({coverage['coverage_pct']}%)"
        )
        lines.append("")
        for tier_name, tier in coverage["tiers"].items():
            lines.append(
                f"  {tier_name:<20} {tier['installed']:>2}/{tier['total']:<3} "
                f"risk={tier['risk']:<8} class={tier['action_class']:<14} "
                f"auth={'yes' if tier['requires_authorization'] else 'no'}"
            )
            for constraint in tier.get("constraints") or []:
                lines.append(f"      ! {constraint}")
        missing = self.missing()
        if missing:
            lines.append("")
            lines.append("missing:")
            for entry in missing:
                hint = entry.package or entry.npm_package or entry.pip_package or "-"
                lines.append(f"  - {entry.name:<20} {hint}")
        return "\n".join(lines)

    def rows(self) -> List[Dict[str, Any]]:
        return [entry.to_dict() for entry in self.entries]
