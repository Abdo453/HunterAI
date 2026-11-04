#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
install_opencode_skills.py — Professional OpenCode Skills Installer
====================================================================

Installs curated cybersecurity skills from `skills_library/` into
`.opencode/skills/<name>/SKILL.md` (the location OpenCode discovers).

Responsibilities:
  1. Profile-based selection (core / redteam / blueteam / cloud / web / web3 / ai-sec / grc / full)
  2. Name normalization to OpenCode rules (^[a-z0-9]+(-[a-z0-9]+)*$, max 64 chars)
  3. Frontmatter `name:` rewrite so skill name == directory name
  4. Dedupe across packs (pack prefix guarantees uniqueness)
  5. Active-skill cap (default 200) to avoid context rot
  6. MANIFEST.json for full provenance/traceability
  7. Idempotent + dry-run support

Usage:
    python tools/install_opencode_skills.py                      # core profile
    python tools/install_opencode_skills.py --profiles core,redteam
    python tools/install_opencode_skills.py --full --cap 9999
    python tools/install_opencode_skills.py --dry-run
    python tools/install_opencode_skills.py --clean --profiles core
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
LIBRARY = REPO_ROOT / "skills_library"
TARGET = REPO_ROOT / ".opencode" / "skills"
MAX_DESC_LEN = 1024
NAME_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")

# Pack registry: prefix, library subpath, SKILL.md glob style
PACKS = {
    "acs": {"name": "anthropic-cyber", "dir": LIBRARY / "anthropic-cyber", "url": "https://github.com/mukul975/Anthropic-Cybersecurity-Skills"},
    "tob": {"name": "trailofbits", "dir": LIBRARY / "trailofbits", "url": "https://github.com/trailofbits/skills"},
    "bri": {"name": "briiirussell", "dir": LIBRARY / "briiirussell", "url": "https://github.com/briiirussell/cybersecurity-skills"},
    "ant": {"name": "anthropics-official", "dir": LIBRARY / "anthropics", "url": "https://github.com/anthropics/skills"},
    "ms": {"name": "microsoft", "dir": LIBRARY / "microsoft", "url": "https://github.com/microsoft/skills"},
}

# ---------------------------------------------------------------------------
# Curated selection — hand-picked, ordered by priority for the cap
# ---------------------------------------------------------------------------

# [ACS] Web/AppSec offensive — the bug-bounty backbone
ACS_CORE = [
    # Web exploitation fundamentals
    "exploiting-sql-injection-vulnerabilities", "exploiting-sql-injection-with-sqlmap",
    "performing-second-order-sql-injection", "exploiting-nosql-injection-vulnerabilities",
    "testing-for-xss-vulnerabilities", "testing-for-xss-vulnerabilities-with-burpsuite",
    "testing-for-xxe-injection-vulnerabilities", "testing-for-xml-injection-vulnerabilities",
    "exploiting-insecure-deserialization", "exploiting-template-injection-vulnerabilities",
    "exploiting-type-juggling-vulnerabilities", "exploiting-prototype-pollution-in-javascript",
    # SSRF / smuggling / request attacks
    "exploiting-server-side-request-forgery", "performing-ssrf-vulnerability-exploitation",
    "performing-blind-ssrf-exploitation", "exploiting-http-request-smuggling",
    "performing-http-parameter-pollution-attack",
    # Access control / logic / IDOR
    "exploiting-idor-vulnerabilities", "exploiting-broken-function-level-authorization",
    "testing-for-broken-access-control", "testing-for-business-logic-vulnerabilities",
    # Cache / header / UI attacks
    "performing-web-cache-poisoning-attack", "performing-web-cache-deception-attack",
    "testing-for-host-header-injection", "testing-for-email-header-injection",
    "testing-cors-misconfiguration", "performing-csrf-attack-simulation",
    "performing-content-security-policy-bypass", "performing-clickjacking-attack-test",
    "performing-directory-traversal-testing",
    # JWT / OAuth / API
    "testing-for-json-web-token-vulnerabilities", "testing-jwt-token-security",
    "performing-jwt-none-algorithm-attack", "exploiting-jwt-algorithm-confusion-attack",
    "testing-oauth2-implementation-flaws", "exploiting-oauth-misconfiguration",
    "testing-api-authentication-weaknesses", "testing-api-for-broken-object-level-authorization",
    "testing-api-for-mass-assignment-vulnerability", "testing-api-security-with-owasp-top-10",
    "exploiting-mass-assignment-in-rest-apis", "exploiting-excessive-data-exposure-in-api",
    "exploiting-api-injection-vulnerabilities", "performing-api-rate-limiting-bypass",
    "testing-websocket-api-security", "exploiting-websocket-vulnerabilities",
    # GraphQL / micro-formats
    "performing-graphql-security-assessment", "performing-graphql-introspection-attack",
    "performing-graphql-depth-limit-attack",
    # Broken link hijack + recon/scan baseline
    "exploiting-broken-link-hijacking", "performing-subdomain-enumeration-with-subfinder",
    "performing-dns-enumeration-and-zone-transfer", "performing-security-headers-audit",
    "performing-web-application-vulnerability-triage",
    "performing-web-application-penetration-test",
    "performing-web-application-scanning-with-nikto", "scanning-network-with-nmap-advanced",
    "performing-ssl-tls-security-assessment", "integrating-dast-with-owasp-zap-in-pipeline",
    "performing-thick-client-application-penetration-test",
    "performing-soap-web-service-security-testing",
    # AD / Windows exploit paths
    "performing-active-directory-penetration-test", "performing-active-directory-bloodhound-analysis",
    "exploiting-active-directory-with-bloodhound", "exploiting-adcs-with-certipy",
    "exploiting-active-directory-certificate-services-esc1", "relaying-ntlm-for-adcs-esc8",
    "coercing-authentication-with-coercer-petitpotam", "conducting-domain-persistence-with-dcsync",
    "performing-kerberoasting-attack", "exploiting-kerberoasting-with-impacket",
    "exploiting-zerologon-vulnerability-cve-2020-1472", "exploiting-ms17-010-eternalblue-vulnerability",
    "exploiting-nopac-cve-2021-42278-42287", "performing-lateral-movement-with-wmiexec",
    "moving-laterally-with-netexec", "conducting-pass-the-ticket-attack",
    "performing-privilege-escalation-assessment",
    # Metasploit / primitives
    "exploiting-vulnerabilities-with-metasploit-framework",
    "exploiting-smb-vulnerabilities-with-metasploit",
    # Cloud offense
    "exploiting-aws-with-pacu", "performing-aws-privilege-escalation-assessment",
    "performing-aws-account-enumeration-with-scout-suite", "enumerating-cloud-with-cloudfox",
    "conducting-cloud-penetration-testing", "performing-kubernetes-penetration-testing",
    "auditing-aws-s3-bucket-permissions", "auditing-gcp-iam-permissions",
    "escaping-containers-to-host",
    # Mobile offense
    "conducting-mobile-app-penetration-test", "performing-android-app-static-analysis-with-mobsf",
    "performing-ios-app-security-assessment", "performing-mobile-app-certificate-pinning-bypass",
    "intercepting-mobile-traffic-with-burpsuite", "exploiting-deeplink-vulnerabilities",
    "testing-mobile-api-authentication", "testing-android-intents-for-vulnerabilities",
    "exploiting-insecure-data-storage-in-mobile",
    # OSINT
    "performing-open-source-intelligence-gathering", "performing-osint-with-spiderfoot",
    "conducting-external-reconnaissance-with-osint", "collecting-open-source-intelligence",
    "performing-ip-reputation-analysis-with-shodan", "monitoring-darkweb-sources",
    "performing-paste-site-monitoring-for-credentials",
    # C2 / red ops basics
    "operating-sliver-c2", "operating-havoc-c2", "performing-red-team-with-covenant",
    "building-c2-infrastructure-with-sliver-framework",
    "building-red-team-c2-infrastructure-with-havoc",
    "performing-initial-access-with-evilginx3", "performing-threat-emulation-with-atomic-red-team",
    "performing-hash-cracking-with-hashcat",
    # Web3
    "analyzing-ethereum-smart-contract-vulnerabilities", "auditing-foundry-smart-contract-security",
]

# [TOB] Trail of Bits — static analysis / fuzzing / crypto / web3 scanners
TOB_CORE = [
    "semgrep", "codeql", "sarif-parsing", "yara-rule-authoring",
    "vulnerability-triage-brocards", "variant-analysis", "burpsuite-project-parser",
    "supply-chain-risk-auditor", "agentic-actions-auditor", "audit-context-building",
    "entry-point-analyzer", "constant-time-analysis", "post-patch-validation",
    "github-triage", "second-opinion", "reproduce-bug", "validate-bug",
    # fuzzing suite
    "fuzzing-dictionary", "harness-writing", "libfuzzer", "cargo-fuzz", "aflpp",
    "libafl", "atheris", "ossfuzz", "ruzzy", "fuzzing-obstacles", "coverage-analysis",
    "address-sanitizer", "wycheproof", "constant-time-testing",
    "property-based-testing", "mutation-testing",
    # building-secure-contracts (multi-chain vuln scanners)
    "solana-vulnerability-scanner", "ton-vulnerability-scanner", "cosmos-vulnerability-scanner",
    "cairo-vulnerability-scanner", "substrate-vulnerability-scanner",
    "algorand-vulnerability-scanner", "token-integration-analyzer",
    "code-maturity-assessor", "guidelines-advisor", "secure-workflow-guide",
    "audit-prep-assistant",
]

# [BRI] briiirussell — methodology skills, offensive + defense core
BRI_CORE = [
    "web-pentest", "api-audit", "owasp-audit", "recon", "osint-recon",
    "prompt-injection", "business-logic-testing", "finding-triage", "cloud-audit",
    "secrets-audit", "dependency-audit", "container-audit", "mobile-audit",
    "crypto-audit", "vuln-research", "variant-analysis", "cicd-security",
    "iam-audit", "agent-supply-chain-audit", "fuzzing-harness",
    "native-code-review", "threat-modeling", "scanner-pipeline", "patch-sweep",
    "personal-opsec", "red-team-engagement", "breach-patterns",
    "incident-triage", "threat-hunting", "malware-triage", "disk-forensics",
]

# [ANT] Anthropic official — tooling skills useful for the agent itself
ANT_CORE = [
    "mcp-builder", "webapp-testing", "claude-api",
    "pdf", "docx", "xlsx", "pptx", "skill-creator",
]

CORE_LISTS = {
    "acs": ACS_CORE,
    "tob": TOB_CORE,
    "bri": BRI_CORE,
    "ant": ANT_CORE,
}

# ---------------------------------------------------------------------------
# Profile patterns (prefix/keyword rules applied to skill folder names)
# ---------------------------------------------------------------------------

PROFILE_PATTERNS = {
    "redteam": [
        ("acs", ("conducting-full-scope-red-team-engagement", "executing-red-team-engagement-planning",
                 "executing-red-team-exercise", "conducting-internal-network-penetration-test",
                 "performing-external-network-penetration-test", "conducting-network-penetration-test",
                 "performing-privilege-escalation-on-linux", "performing-cve-prioritization-with-kev-catalog",
                 "performing-binary-exploitation-analysis", "analyzing-heap-spray-exploitation",
                 "conducting-man-in-the-middle-attack-simulation", "performing-ssl-stripping-attack",
                 "performing-arp-spoofing-attack-simulation", "performing-packet-injection-attack",
                 "performing-vlan-hopping-attack", "performing-physical-intrusion-assessment",
                 "conducting-social-engineering-penetration-test",
                 "conducting-spearphishing-simulation-campaign", "performing-phishing-simulation-with-gophish",
                 "performing-red-team-phishing-with-gophish", "executing-phishing-simulation-campaign",
                 "attacking-entra-id-with-roadtools", "attacking-oauth-with-device-code-phishing",
                 "performing-active-directory-forest-trust-attack", "performing-active-directory-compromise-investigation",
                 "abusing-dpapi-for-credential-access", "abusing-shadow-credentials-for-privesc",
                 "extracting-credentials-from-memory-dump", "performing-credential-access-with-lazagne",
                 "post-exploiting-microsoft-graph-with-graphrunner",
                 "performing-wireless-network-penetration-test", "performing-wifi-password-cracking-with-aircrack",
                 "performing-wireless-security-assessment-with-kismet", "performing-bluetooth-security-assessment",
                 "exploiting-constrained-delegation-abuse", "exploiting-bgp-hijacking-vulnerabilities",
                 "exploiting-ipv6-vulnerabilities", "exploiting-ms17-010-eternalblue-vulnerability",
                 "performing-adversary-in-the-middle-phishing-detection",
                 "building-adversary-infrastructure-tracking-system",
                 "building-c2-redirector-infrastructure")),
        ("tob", ("regression-hunt", "reproduce-regression", "report-regressions",
                 "replay-regression", "prepare-regression", "adjudicate-regression", "hunt-regressions")),
    ],
    "blueteam": [
        ("acs", ("hunting-", "detecting-", "triaging-security", "investigating-",
                 "building-incident", "building-detection", "building-soc", "building-threat",
                 "building-ioc", "building-ioc-", "implementing-siem", "implementing-soar",
                 "implementing-endpoint-detection", "implementing-syslog", "implementing-log",
                 "implementing-ebpf", "implementing-velociraptor", "performing-alert-triage",
                 "performing-user-behavior-analytics", "correlating-security-events",
                 "implementing-zero-trust", "implementing-microsegmentation",
                 "implementing-network-segmentation", "configuring-windows-event-logging",
                 "configuring-snort-ids", "configuring-suricata", "configuring-host-based",
                 "performing-purple-team", "implementing-mitre", "implementing-diamond",
                 "implementing-continuous-security-validation", "hardening-", "deploying-honeytokens",
                 "deploying-decoy", "deploying-ransomware-canary", "implementing-honeypot",
                 "implementing-honeytokens", "implementing-canary", "implementing-deception",
                 "performing-deception-technology", "containing-active-breach",
                 "collecting-volatile-evidence")),
    ],
    "forensics": [
        ("acs", ("analyzing-memory", "performing-memory-forensics", "conducting-memory-forensics",
                 "performing-disk-forensics", "performing-sqlite-database-forensics",
                 "performing-network-forensics", "performing-cloud-forensics", "performing-linux-log-forensics",
                 "performing-cloud-log-forensics", "performing-timeline-reconstruction",
                 "generating-forensic-timelines", "acquiring-disk-image", "analyzing-disk-image",
                 "analyzing-mft", "analyzing-prefetch", "analyzing-windows-prefetch",
                 "analyzing-windows-registry", "analyzing-windows-amcache", "analyzing-windows-shellbag",
                 "analyzing-lnk-file", "analyzing-windows-lnk", "analyzing-browser-forensics",
                 "analyzing-outlook-pst", "analyzing-linux-system-artifacts", "analyzing-linux-audit-logs",
                 "analyzing-web-server-logs", "analyzing-dns-logs", "extracting-browser-history",
                 "extracting-windows-event-logs", "parsing-artifacts-with-eric-zimmerman",
                 "performing-windows-artifact-analysis", "performing-file-carving",
                 "recovering-deleted-files", "triaging-windows-with-kape", "hunting-evtx-with-chainsaw",
                 "building-super-timelines", "building-incident-timeline")),
    ],
    "cloud": [
        ("acs", ("auditing-aws", "auditing-azure", "auditing-gcp", "auditing-kubernetes",
                 "auditing-terraform", "auditing-cloud", "implementing-aws", "implementing-azure",
                 "implementing-gcp", "implementing-cloud", "implementing-kubernetes",
                 "performing-cloud", "scanning-container", "scanning-docker", "scanning-iac",
                 "scanning-kubernetes", "scanning-kubernetes-manifests", "detecting-aws",
                 "detecting-azure", "detecting-container", "detecting-cloud", "detecting-compromised-cloud",
                 "detecting-cryptomining", "detecting-shadow-it", "detecting-serverless",
                 "remediating-s3", "securing-aws", "securing-azure", "securing-kubernetes",
                 "securing-container", "securing-helm", "securing-serverless",
                 "hardening-docker-containers", "hardening-docker-daemon",
                 "benchmarking-kubernetes", "executing-active-directory-attack-simulation",
                 "implementing-pod-security", "implementing-network-policies-for-kubernetes",
                 "implementing-runtime-security", "implementing-policy-as-code",
                 "implementing-opa-gatekeeper", "performing-docker-bench",
                 "configuring-active-directory-tiered-model", "conducting-cloud-incident-response")),
    ],
    "malware-re": [
        ("acs", ("analyzing-android-malware", "analyzing-linux-elf-malware", "analyzing-linux-kernel-rootkits",
                 "analyzing-bootkit", "analyzing-uefi-bootkit", "analyzing-packed-malware",
                 "analyzing-malware-behavior", "analyzing-malware-family", "analyzing-malware-persistence",
                 "analyzing-malware-sandbox", "analyzing-golang-malware", "analyzing-network-covert-channels",
                 "analyzing-network-traffic-of-malware", "analyzing-macro-malware",
                 "analyzing-malicious-pdf", "analyzing-malicious-url", "analyzing-pdf-malware",
                 "analyzing-command-and-control", "analyzing-cobalt-strike", "analyzing-cobaltstrike",
                 "analyzing-powershell-empire", "analyzing-ransomware", "reverse-engineering-",
                 "deobfuscating-", "performing-static-malware", "performing-automated-malware",
                 "performing-dynamic-analysis", "performing-malware-ioc", "performing-malware-hash-enrichment",
                 "performing-malware-persistence", "performing-malware-triage", "performing-malware-triage-with-yara",
                 "extracting-iocs-from-malware", "extracting-config-from-agent",
                 "extracting-indicator-iocs-from-cobalt-strike", "reverse-engineering-ransomware",
                 "reverse-engineering-rust-malware", "reverse-engineering-dotnet-malware")),
    ],
    "iot-ot": [
        ("acs", ("performing-iot-security-assessment", "performing-ot-", "performing-ics-asset",
                 "performing-plc-firmware", "performing-s7comm", "performing-scada",
                 "performing-oil-gas", "performing-power-grid", "performing-firmware-extraction",
                 "performing-firmware-malware", "detecting-modbus", "detecting-dnp3",
                 "detecting-anomalies-in-industrial", "detecting-attacks-on-historian",
                 "detecting-attacks-on-scada", "detecting-stuxnet", "monitoring-scada",
                 "auditing-uefi-firmware", "implementing-iec-62443", "implementing-purdue-model",
                 "implementing-network-segmentation-for-ot", "implementing-conduit-security",
                 "implementing-patch-management-for-ot", "implementing-ot-incident-response",
                 "implementing-dragos", "implementing-ot-network-traffic", "implementing-ics-firewall",
                 "implementing-patch-management-for-ot-systems", "securing-historian-server",
                 "securing-remote-access-to-ot")),
    ],
    "web3": [
        ("acs", ("analyzing-ethereum", "auditing-foundry", "analyzing-ransomware-payment-wallets",
                 "analyzing-ransomware-leak-site")),
        ("tob", ("vulnerability-scanner", "token-integration-analyzer", "audit-prep-assistant",
                 "secure-workflow-guide", "code-maturity-assessor", "guidelines-advisor")),
    ],
    "ai-sec": [
        ("acs", ("red-teaming-llms", "orchestrating-llm-attacks", "continuous-llm-red-teaming",
                 "implementing-llm-guardrails", "defending-llms", "detecting-ai-model-prompt-injection",
                 "detecting-indirect-prompt-injection", "detecting-data-and-model-poisoning",
                 "detecting-model-extraction", "detecting-deepfake", "assessing-vector-and-embedding",
                 "testing-for-system-prompt-leakage", "testing-prompt-injection",
                 "detecting-business-email-compromise-with-ai", "performing-ai-driven-osint",
                 "securing-agentic-ai", "auditing-mcp-servers")),
        ("bri", ("ai-risk-management", "prompt-injection")),
    ],
    "grc": [
        ("acs", ("conducting-gdpr", "conducting-cyber-risk-assessment", "implementing-iso-27001",
                 "implementing-pci-dss", "implementing-hipaa", "implementing-nerc-cip",
                 "performing-nist-csf", "performing-soc2", "executing-nist-rmf",
                 "achieving-cmmc", "implementing-gdpr", "implementing-iec-62443",
                 "performing-privacy-impact-assessment", "conducting-domain-persistence-with-dcsync")),
        ("bri", ("hipaa-audit", "pci-audit", "csf-mapping", "control-audit", "privacy-engineering",
                 "security-comms", "soc-operations", "log-watch", "siem-detection", "log? none")),
    ],
}


def slugify(text: str) -> str:
    text = text.lower()
    text = re.sub(r"[^a-z0-9]+", "-", text).strip("-")
    text = re.sub(r"-{2,}", "-", text)
    return text[:64] or "ext-" + hashlib.md5(text.encode()).hexdigest()[:6]


def rewrite_frontmatter(path: Path, new_name: str) -> tuple[str, str]:
    """Rewrite the `name:` field in SKILL.md frontmatter. Returns (title, description)."""
    raw = path.read_text(encoding="utf-8", errors="replace")
    name_re = re.compile(r"^name:\s*.*$", re.M)
    desc_m = re.search(r"^description:\s*(.*(?:\n(?![a-zA-Z_][a-zA-Z0-9_-]*:).*)*)", raw, re.M)
    desc = (desc_m.group(1) if desc_m else "External skill")[:MAX_DESC_LEN].strip()

    if raw.startswith("---"):
        end = raw.find("\n---", 3)
        if end != -1:
            head, body = raw[:end], raw[end:]
            if name_re.search(head):
                head = name_re.sub(f"name: {new_name}", head, count=1)
            else:
                head = head + f"\nname: {new_name}\n"
            path.write_text(head + body, encoding="utf-8", errors="replace")
            return new_name, desc
    # no frontmatter — inject one
    fm = f"---\nname: {new_name}\ndescription: {desc}\n---\n\n"
    path.write_text(fm + raw, encoding="utf-8", errors="replace")
    return new_name, desc


def discover_skill_file(pack_dir: Path, skill_folder: Path) -> Path | None:
    """Locate the SKILL.md inside a candidate skill folder (case variants)."""
    for variant in ("SKILL.md", "skill.md", "Skill.md"):
        cand = skill_folder / variant
        if cand.is_file():
            return cand
    return None


def iter_pack_skills(pack_key: str, pack: dict) -> list[tuple[str, Path, Path]]:
    """Yield (basename, folder, SKILL.md) for each skill in a pack — excluding fixtures/templates."""
    base = pack["dir"]
    if not base.is_dir():
        return []
    out = []
    for sk in base.rglob("SKILL.md"):
        folder = sk.parent
        rel = sk.relative_to(base).as_posix().lower()
        # exclude test fixtures / templates / docs examples
        if "/tests/" in rel or "\\tests\\" in rel or "/fixtures/" in rel or "/template" in rel or "/docs/" in rel:
            continue
        # only accept proper skill dirs (leaf folder named after skill)
        out.append((folder.name, folder, sk))
    return out


def index_packs() -> dict[str, dict[str, tuple[Path, Path]]]:
    """Returns pack_key -> {basename: (folder, skillmd)}"""
    idx = {}
    for key, pack in PACKS.items():
        m = {}
        for basename, folder, sk in iter_pack_skills(key, pack):
            m[basename] = (folder, sk)
        idx[key] = m
    return idx


def select(profiles: list[str], idx) -> list[tuple[str, Path, Path, str]]:
    """Build the ordered install list: [(pack_key, folder, sk, basename)]"""
    selected: list[tuple[str, Path, Path, str]] = []
    chosen: set[tuple[str, str]] = set()

    if "core" in profiles:
        for key, names in CORE_LISTS.items():
            for n in names:
                if n in idx[key] and (key, n) not in chosen:
                    folder, sk = idx[key][n]
                    selected.append((key, folder, sk, n))
                    chosen.add((key, n))

    for prof in profiles:
        if prof == "core":
            continue
        for key, patterns in PROFILE_PATTERNS.get(prof, []):
            valid = [p for p in patterns if " " not in p]  # drop placeholder junk
            for basename, (folder, sk) in idx[key].items():
                for pat in valid:
                    if basename == pat or basename.startswith(pat) or pat in basename:
                        if (key, basename) not in chosen:
                            selected.append((key, folder, sk, basename))
                            chosen.add((key, basename))
                        break

    if "full" in profiles:
        for key, items in idx.items():
            for basename, (folder, sk) in items.items():
                if (key, basename) not in chosen:
                    selected.append((key, folder, sk, basename))
                    chosen.add((key, basename))

    return selected


def main() -> int:
    ap = argparse.ArgumentParser(description="Install curated cyber skills into .opencode/skills")
    ap.add_argument("--profiles", default="core",
                    help="comma list: core,redteam,blueteam,forensics,cloud,malware-re,iot-ot,web3,ai-sec,grc,full")
    ap.add_argument("--cap", type=int, default=200, help="max active skills (context-rot guard)")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--clean", action="store_true", help="remove installed skills first")
    args = ap.parse_args()

    profiles = [p.strip() for p in args.profiles.split(",") if p.strip()]
    unknown = [p for p in profiles if p not in set(PROFILE_PATTERNS) | {"core", "full"}]
    if unknown:
        print(f"[-] Unknown profile(s): {unknown}")
        return 2

    idx = index_packs()
    stats = {k: len(v) for k, v in idx.items()}
    print(f"[*] Library inventory: {stats}")

    chosen = select(profiles, idx)
    print(f"[*] Profiles {profiles} selected {len(chosen)} skills (cap={args.cap})")
    if len(chosen) > args.cap:
        print(f"[!] Cap exceeded — truncating to first {args.cap} (curated/priority order).")
        chosen = chosen[: args.cap]

    # Ensure no target dir is orphaned if name collisions occur across packs
    target = TARGET
    installed: list[dict] = []
    used_names: dict[str, str] = {}
    errors: list[str] = []

    for pack_key, folder, sk, basename in chosen:
        name = f"{pack_key}-{slugify(basename)}"
        if name in used_names:
            errors.append(f"duplicate normalized name {name} ({used_names[name]} vs {folder})")
            continue
        used_names[name] = str(folder)
        outdir = target / name
        if args.dry_run:
            print(f"  [dry] {name}  <-  {sk.relative_to(LIBRARY)}")
        else:
            if outdir.exists():
                shutil.rmtree(outdir)
            shutil.copytree(folder, outdir, ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"))
            title, desc = rewrite_frontmatter(outdir / "SKILL.md", name)
            if not NAME_RE.match(name):
                errors.append(f"BAD NAME: {name}")
            installed.append({
                "name": name, "title": title, "description": desc,
                "pack": PACKS[pack_key]["name"],
                "source": sk.relative_to(LIBRARY).as_posix(),
                "url": PACKS[pack_key]["url"] + "/blob/main/" + sk.relative_to(PACKS[pack_key]["dir"]).as_posix(),
            })

    if args.dry_run:
        print(f"[*] Dry run complete — no changes written.")
        return 0

    target.mkdir(parents=True, exist_ok=True)

    manifest = {
        "schema": "opencode-skills-manifest/1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "profiles": profiles,
        "cap": args.cap,
        "count": len(installed),
        "library_inventory": stats,
        "skills": installed,
        "errors": errors,
    }
    (target / "MANIFEST.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"[+] Installed {len(installed)} skills -> {target}")
    if errors:
        print(f"[!] {len(errors)} issue(s):")
        for e in errors[:10]:
            print("    -", e)
    return 0 if not errors else 1


if __name__ == "__main__":
    sys.exit(main())
