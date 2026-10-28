"""Structured Recon Methodology playbook.

The operator-supplied ``Recon_Methodology.txt`` is bundled verbatim at
``core/playbooks/data/recon_methodology.txt``.  This module exposes it in two
forms:

1. ``load_methodology_text`` / ``parse_methodology`` / ``command_inventory`` —
   the complete reference text and a best-effort parsed inventory.  Nothing in
   this layer executes a command.
2. ``EXECUTABLE_STAGES`` — a curated, risk-labelled subset that an agent may run
   through ``ToolManager``.  The full raw playbook remains the source of truth;
   the executable subset exists so an agent does not blindly shell out every
   line in a document.

Safety rules for the executable layer:
- every template uses explicit placeholders (``{domain}``, ``{url}``, ...);
- values are validated before substitution;
- commands are risk-labelled ``safe``, ``active`` or ``intrusive``;
- commands with missing tools or missing context are skipped, never fabricated.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urlparse

METHODOLOGY_PATH = Path(__file__).parent / "data" / "recon_methodology.txt"

_SEPARATOR_RE = re.compile(r"^-{10,}$")
_SECTION_RE = re.compile(r"^(?:-|STEP\(|kr\s+wordlists:)", re.IGNORECASE)
_STEP_RE = re.compile(r"^\(step\d+\):?$", re.IGNORECASE)
_LABELED_COMMAND_RE = re.compile(r"^([A-Za-z][A-Za-z0-9 &/_.-]{1,60}):\s+(.+)$")
_UNSAFE_VALUE_RE = re.compile(r"[;&|`$><\n\r\t\"'\\]")
# Spaces are allowed only because ``render_command`` double-quotes any value
# that contains whitespace.  Quotes/backslashes/shell metacharacters are still
# rejected by ``_UNSAFE_VALUE_RE``.
_SAFE_VALUE_RE = re.compile(r"^[A-Za-z0-9_ ./:@%+=,\-\[\]]+$")


# ---------------------------------------------------------------------------
# Raw playbook loading / parsing
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class MethodologySection:
    """One heading and its raw lines from the operator methodology."""

    index: int
    title: str
    lines: Tuple[str, ...]
    commands: Tuple[str, ...]

    def as_dict(self) -> Dict[str, object]:
        return {
            "index": self.index,
            "title": self.title,
            "line_count": len(self.lines),
            "command_count": len(self.commands),
        }


def load_methodology_text() -> str:
    """Return the complete bundled methodology text."""
    return METHODOLOGY_PATH.read_text(encoding="utf-8")


def _is_separator(line: str) -> bool:
    return bool(_SEPARATOR_RE.match(line.strip()))


def _is_section_heading(line: str) -> bool:
    stripped = line.strip()
    if not stripped or _is_separator(stripped):
        return False
    if stripped.startswith("-"):
        return True
    if stripped.upper().startswith("STEP(") or _STEP_RE.match(stripped):
        return True
    if stripped.lower().startswith("kr wordlists:"):
        return True
    # Labels such as ``API Discovery: cat ...`` are sub-headings with an inline
    # command.  Only treat them as headings when the remainder is a command.
    label_match = _LABELED_COMMAND_RE.match(stripped)
    if label_match and _normalize_command_line(label_match.group(2)):
        return True
    # A couple of prose headings in the source document.
    return stripped in {"What is Origin IP?", "Tools:"}


def _split_heading(line: str) -> Tuple[str, str]:
    """Split ``-Merge URLs: cat ...`` into (title, inline command)."""
    stripped = line.strip()
    if stripped.startswith("-"):
        stripped = stripped[1:].strip()
    if ":" in stripped:
        title, inline = stripped.split(":", 1)
        return title.strip(), inline.strip()
    return stripped.rstrip(":").strip(), ""


_COMMAND_FIRST_TOKENS = {
    "subfinder", "assetfinder", "amass", "subenum", "findomain", "chaos",
    "github-subdomains", "dnscan", "puredns", "dnsx", "ffuf", "asnmap",
    "whois", "hakrevdns", "magicrecon", "curl", "anew", "wc", "httpx",
    "waybackurls", "waymore", "gau", "gauplus", "hakrawler", "katana",
    "gospider", "paramspider", "x8", "cat", "grep", "urinteresting",
    "qsreplace", "sed", "subjs", "mantra", "jsecret", "jsleak", "python",
    "python3", "trufflehog", "arjun", "sqlmap", "nuclei", "paraminer",
    "naabu", "nmap", "bfac", "originiphunter", "dirb", "feroxbuster",
    "gobuster", "dirsearch", "kr", "sudo", "wget", "ping", "echo", "export",
    "sort", "tr", "xargs", "jq", "tee", "mapcidr", "dalfox", "subzy",
}


def _looks_like_command_text(text: str) -> bool:
    stripped = text.strip()
    if not stripped:
        return False
    if stripped.startswith(("http://", "https://", "site:")):
        return False
    if stripped.startswith(("What is ", "Example:", "Tools:", "Origin IP")):
        return False
    if stripped.endswith(":") and len(stripped) <= 50 and " " not in stripped:
        return False
    first = stripped.split()[0]
    if first in _COMMAND_FIRST_TOKENS or first.startswith("./"):
        return True
    if "|" in stripped:
        return True
    return False


def _normalize_command_line(line: str) -> Optional[str]:
    """Return the executable part of a line, or ``None`` for prose/resources.

    The source document mixes headings, prose, URLs and commands.  It also has
    lines such as ``API Discovery: cat ... | grep ...`` and ``ffuf: ffuf ...``;
    this helper strips the human label and returns only the command.
    """
    stripped = line.strip()
    if not stripped or _is_separator(stripped):
        return None
    if stripped.startswith(("http://", "https://", "site:")):
        return None
    # Continuation lines of a multi-line shell pipeline are part of the
    # preceding command, not standalone commands.
    if stripped.startswith(("|", "\\")):
        return None
    label_match = _LABELED_COMMAND_RE.match(stripped)
    if label_match:
        remainder = label_match.group(2).strip()
        return remainder if _looks_like_command_text(remainder) else None
    return stripped if _looks_like_command_text(stripped) else None


def _looks_like_command(line: str) -> bool:
    return _normalize_command_line(line) is not None


@lru_cache(maxsize=1)
def parse_methodology() -> Tuple[MethodologySection, ...]:
    """Parse the raw document into sections and command lines.

    The parser is intentionally forgiving: the document is human-authored and
    contains inline headings, prose and URLs.  It never treats prose as a
    command; it only inventories lines whose first token is a known tool.
    """
    text = load_methodology_text()
    sections: List[MethodologySection] = []
    current_title = "Overview"
    current_lines: List[str] = []
    index = 0

    def _flush() -> None:
        nonlocal index, current_lines, current_title
        if not current_lines and current_title == "Overview":
            return
        commands = tuple(
            command
            for line in current_lines
            if (command := _normalize_command_line(line))
        )
        sections.append(
            MethodologySection(
                index=index,
                title=current_title,
                lines=tuple(current_lines),
                commands=commands,
            )
        )
        index += 1
        current_lines = []

    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()
        if _is_section_heading(stripped):
            _flush()
            title, inline = _split_heading(stripped)
            current_title = title or f"Section {index + 1}"
            if inline:
                current_lines.append(inline)
            continue
        if stripped and not _is_separator(stripped):
            current_lines.append(stripped)
    _flush()
    return tuple(sections)


def command_inventory() -> Tuple[str, ...]:
    """Return every line the parser recognizes as a command, deduplicated."""
    seen = set()
    out: List[str] = []
    for section in parse_methodology():
        for command in section.commands:
            if command not in seen:
                seen.add(command)
                out.append(command)
    return tuple(out)


def methodology_summary() -> Dict[str, object]:
    """Return counts and tool coverage for the bundled methodology."""
    sections = parse_methodology()
    commands = command_inventory()
    tools = sorted({
        c.split()[0].lstrip("./")
        for c in commands
        if c.split() and c.split()[0].lstrip("./")
    })
    return {
        "path": str(METHODOLOGY_PATH),
        "bytes": METHODOLOGY_PATH.stat().st_size if METHODOLOGY_PATH.exists() else 0,
        "sections": len(sections),
        "commands": len(commands),
        "tools": tools,
        "section_titles": [s.title for s in sections],
    }


# ---------------------------------------------------------------------------
# Executable subset
# ---------------------------------------------------------------------------

RISK_ORDER = {"safe": 0, "active": 1, "intrusive": 2}


@dataclass(frozen=True)
class ExecutableCommand:
    key: str
    tool: str
    template: str
    purpose: str
    risk: str = "safe"
    requires: Tuple[str, ...] = ()
    requires_env: Tuple[str, ...] = ()
    requires_context: Tuple[str, ...] = ()
    timeout: int = 180
    output_hint: str = ""

    def as_dict(self) -> Dict[str, object]:
        return {
            "key": self.key,
            "tool": self.tool,
            "template": self.template,
            "purpose": self.purpose,
            "risk": self.risk,
            "requires": list(self.requires),
            "requires_env": list(self.requires_env),
            "requires_context": list(self.requires_context),
            "timeout": self.timeout,
            "output_hint": self.output_hint,
        }


@dataclass(frozen=True)
class ExecutableStage:
    key: str
    title: str
    objective: str
    commands: Tuple[ExecutableCommand, ...]

    def as_dict(self) -> Dict[str, object]:
        return {
            "key": self.key,
            "title": self.title,
            "objective": self.objective,
            "commands": [c.as_dict() for c in self.commands],
        }


def _cmd(key: str, tool: str, template: str, purpose: str, **kwargs) -> ExecutableCommand:
    return ExecutableCommand(key=key, tool=tool, template=template, purpose=purpose, **kwargs)


EXECUTABLE_STAGES: Tuple[ExecutableStage, ...] = (
    ExecutableStage(
        key="passive_subdomains",
        title="Passive subdomain enumeration",
        objective="Collect subdomains without brute-forcing the target.",
        commands=(
            _cmd("subfinder_basic", "subfinder", "subfinder -d {domain} -o {out}/Subs01.txt",
                 "Subfinder passive enumeration.", requires=("subfinder",), output_hint="Subs01.txt"),
            _cmd("subfinder_deep", "subfinder", "subfinder -d {domain} -all -recursive -o {out}/Subs01_all.txt",
                 "Subfinder all-source recursive enumeration.", requires=("subfinder",), output_hint="Subs01_all.txt"),
            _cmd("assetfinder", "assetfinder", "echo {domain} | assetfinder -subs-only > {out}/Subs02.txt",
                 "Assetfinder certificate/archive enumeration.", requires=("assetfinder",), output_hint="Subs02.txt"),
            _cmd("amass", "amass", "amass enum -d {domain} -o {out}/Subs03.txt",
                 "Amass enumeration.", risk="active", requires=("amass",), output_hint="Subs03.txt"),
            _cmd("findomain", "findomain", "findomain -t {domain} -u {out}/Subs05.txt",
                 "Findomain passive enumeration.", requires=("findomain",), output_hint="Subs05.txt"),
            _cmd("chaos", "chaos", "chaos -d {domain} -o {out}/Subs06.txt",
                 "ProjectDiscovery Chaos dataset.", requires=("chaos",), requires_env=("PDCP_API_KEY",),
                 output_hint="Subs06.txt"),
            _cmd("github_subdomains", "github-subdomains",
                 "github-subdomains -d {domain} -t {github_token} -o {out}/Subs_gh.txt",
                 "GitHub code search for subdomains.", requires=("github-subdomains",),
                 requires_env=("GITHUB_TOKEN",), requires_context=("github_token",), output_hint="Subs_gh.txt"),
        ),
    ),
    ExecutableStage(
        key="active_subdomains",
        title="Active subdomain enumeration",
        objective="Brute-force/resolve DNS names using operator wordlists.",
        commands=(
            _cmd(
                "resolvers_download",
                "wget",
                "wget -q -O {out}/resolvers.txt https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt",
                "Download a public resolver list for puredns/hakrevdns.",
                requires=("wget",),
                output_hint="resolvers.txt",
            ),
            _cmd("puredns", "puredns", "puredns bruteforce {wordlist} {domain} -r {resolvers} -w {out}/Subs07.txt",
                 "Mass DNS brute-force with puredns.", risk="active", requires=("puredns",),
                 requires_context=("wordlist", "resolvers"), output_hint="Subs07.txt"),
            _cmd("dnsx", "dnsx", "dnsx -silent -d {domain} -w {wordlist} -o {out}/Subs08.txt",
                 "DNS resolution/brute-force with dnsx.", risk="active", requires=("dnsx",),
                 requires_context=("wordlist",), output_hint="Subs08.txt"),
            _cmd("dnscan", "dnscan", "python3 dnscan.py -d {domain} -w {wordlist} -t 300 -o {out}/Subs09.txt",
                 "dnscan active enumeration.", risk="active", requires=("dnscan",),
                 requires_context=("wordlist",), output_hint="Subs09.txt"),
        ),
    ),
    ExecutableStage(
        key="subdomain_fuzzing",
        title="Subdomain fuzzing",
        objective="Fuzz subdomain labels and virtual hosts.",
        commands=(
            _cmd("ffuf_subdomain", "ffuf", "ffuf -u https://FUZZ.{domain} -w {wordlist} -mc 200,301,302,403 -o {out}/ffuf_subs.json",
                 "Fuzz a subdomain label.", risk="active", requires=("ffuf",), requires_context=("wordlist",),
                 output_hint="ffuf_subs.json"),
            _cmd("ffuf_vhost", "ffuf", "ffuf -u {url} -w {wordlist} -H 'Host: FUZZ.{domain}' -mc 200,301,302,403 -o {out}/ffuf_vhost.json",
                 "Fuzz virtual hosts through the Host header.", risk="active", requires=("ffuf",),
                 requires_context=("wordlist",), output_hint="ffuf_vhost.json"),
        ),
    ),
    ExecutableStage(
        key="infrastructure",
        title="Infrastructure / ASN discovery",
        objective="Map ASN, CIDR, reverse DNS and origin infrastructure.",
        commands=(
            _cmd("asnmap", "asnmap", "asnmap -a {asn} -silent -o {out}/cidrs.txt",
                 "Map an ASN to CIDRs.", requires=("asnmap",), requires_context=("asn",), output_hint="cidrs.txt"),
            _cmd("whois_radb", "whois", "whois -h whois.radb.net -- '-i origin {asn}'",
                 "Query RADB for an ASN's routes.", requires=("whois",), requires_context=("asn",)),
            _cmd("dnsx_ptr", "dnsx", "echo {cidr} | dnsx -silent -resp-only -ptr",
                 "Reverse DNS over a CIDR.", requires=("dnsx",), requires_context=("cidr",)),
            _cmd("hakrevdns", "hakrevdns", "hakrevdns -d {domain} -R {resolvers}",
                 "Reverse DNS from hostnames.", requires=("hakrevdns",), requires_context=("resolvers",)),
        ),
    ),
    ExecutableStage(
        key="merge",
        title="Merge and deduplicate",
        objective="Merge every subdomain source into one evidence file.",
        commands=(
            _cmd(
                "anew_subs",
                "anew",
                (
                    "cat {out}/Subs01.txt {out}/Subs01_all.txt {out}/Subs02.txt "
                    "{out}/Subs03.txt {out}/Subs05.txt {out}/Subs06.txt "
                    "{out}/Subs_gh.txt {out}/Subs07.txt {out}/Subs08.txt "
                    "{out}/Subs09.txt | anew {out}/AllSubs.txt"
                ),
                "Deduplicate subdomain outputs.",
                requires=("anew",),
                output_hint="AllSubs.txt",
            ),
            _cmd("count_subs", "wc", "wc -l {out}/AllSubs.txt",
                 "Count unique subdomains.", requires=("wc",), output_hint="AllSubs.txt"),
        ),
    ),
    ExecutableStage(
        key="alive_hosts",
        title="Alive host detection",
        objective="Probe discovered names over HTTP(S) and keep evidence.",
        commands=(
            _cmd("httpx_alive", "httpx",
                 "cat {out}/AllSubs.txt | httpx -status-code -content-length -web-server -title -follow-redirects -o {out}/AliveSubs.txt",
                 "Probe live hosts with status/title/tech metadata.", requires=("httpx",), output_hint="AliveSubs.txt"),
            _cmd("httpx_200", "httpx", "cat {out}/AllSubs.txt | httpx -match-code 200 -o {out}/AliveSubs_200.txt",
                 "Keep only HTTP 200 hosts.", requires=("httpx",), output_hint="AliveSubs_200.txt"),
            _cmd("httpx_filter", "httpx", "cat {out}/AllSubs.txt | httpx -filter-code 400 -o {out}/AliveSubs_filtered.txt",
                 "Filter out 400 responses.", requires=("httpx",), output_hint="AliveSubs_filtered.txt"),
        ),
    ),
    ExecutableStage(
        key="url_discovery",
        title="Historical and active URL discovery",
        objective="Collect URLs from archives, crawlers and JS-aware spiders.",
        commands=(
            _cmd("waybackurls", "waybackurls", "cat {out}/AliveSubs.txt | waybackurls > {out}/WB1.txt",
                 "Wayback Machine URLs.", requires=("waybackurls",), output_hint="WB1.txt"),
            _cmd("waymore", "waymore", "waymore -i {out}/AliveSubs.txt -mode U -l 1000 -from 2021 -oU {out}/WM1.txt",
                 "Waymore URL collection.", requires=("waymore",), output_hint="WM1.txt"),
            _cmd("gau", "gau", "cat {out}/AliveSubs.txt | gau --threads 200 > {out}/GAU1.txt",
                 "GAU archive URLs.", requires=("gau",), output_hint="GAU1.txt"),
            _cmd("gauplus", "gauplus", "gauplus -t 200 -random-agent < {out}/AliveSubs.txt > {out}/GAU2.txt",
                 "GAU+ archive URLs.", requires=("gauplus",), output_hint="GAU2.txt"),
            _cmd("hakrawler", "hakrawler", "cat {out}/AliveSubs.txt | hakrawler -subs -u -insecure > {out}/HK1.txt",
                 "Hakrawler crawl.", requires=("hakrawler",), output_hint="HK1.txt"),
            _cmd("katana", "katana",
                 "katana -u {out}/AliveSubs.txt -jc -kf all -d 5 -headless -fx -aff -fs rdn -f url -silent > {out}/KTN1.txt",
                 "Katana JS-aware crawl.", risk="active", requires=("katana",), output_hint="KTN1.txt"),
            _cmd("gospider", "gospider",
                 "gospider -S {out}/AliveSubs.txt -t 20 -d 3 --js --sitemap --robots -o {out}/GS1.txt",
                 "GoSpider crawl.", risk="active", requires=("gospider",), output_hint="GS1.txt"),
            _cmd("paramspider", "paramspider", "paramspider -d {domain} -o {out}/PS1.txt",
                 "ParamSpider URL/parameter discovery.", requires=("paramspider",), output_hint="PS1.txt"),
            _cmd("x8", "x8", "x8 -u {url} -o {out}/X81.txt",
                 "x8 hidden-parameter discovery.", risk="active", requires=("x8",), output_hint="X81.txt"),
        ),
    ),
    ExecutableStage(
        key="merge_urls",
        title="Merge URLs and filter live endpoints",
        objective="Normalize URL evidence and probe which endpoints answer.",
        commands=(
            _cmd("merge_urls", "anew",
                 "cat {out}/WB1.txt {out}/GAU1.txt {out}/GAU2.txt {out}/KTN1.txt {out}/HK1.txt {out}/GS1.txt {out}/PS1.txt {out}/X81.txt | anew {out}/AllURLs.txt",
                 "Merge all URL sources.", requires=("anew",), output_hint="AllURLs.txt"),
            _cmd("httpx_urls", "httpx", "cat {out}/AllURLs.txt | httpx -status-code -content-length -silent > {out}/LiveURLs.txt",
                 "Filter URLs that respond.", requires=("httpx",), output_hint="LiveURLs.txt"),
        ),
    ),
    ExecutableStage(
        key="parameter_mining",
        title="Parameter and JavaScript discovery",
        objective="Extract parameters, JS files and API/backend endpoints.",
        commands=(
            _cmd("qsreplace", "qsreplace", "cat {out}/AllURLs.txt | grep '=' | qsreplace 'FUZZ' | anew {out}/ParamURLs.txt",
                 "Mark every parameter value with FUZZ.", requires=("qsreplace", "grep"), output_hint="ParamURLs.txt"),
            _cmd("subjs", "subjs", "cat {out}/AllURLs.txt | subjs > {out}/js_urls.txt",
                 "Extract JavaScript URLs.", requires=("subjs",), output_hint="js_urls.txt"),
            _cmd("js_api", "grep", "cat {out}/AllURLs.txt | grep -Ei '\\.(json|xml|graphql|gql)(\\?|$)' | anew {out}/api_urls.txt",
                 "Extract API-looking URLs.", requires=("grep",), output_hint="api_urls.txt"),
            _cmd("js_backend", "grep", "cat {out}/AllURLs.txt | grep -Ei '\\.(php|asp|aspx|jsp|cfm|cgi)(\\?|$)' | anew {out}/backend_files.txt",
                 "Extract backend file URLs.", requires=("grep",), output_hint="backend_files.txt"),
            _cmd("js_login", "grep", "cat {out}/AllURLs.txt | grep -Ei 'login|signin|auth|oauth|reset|password' | anew {out}/login_flows.txt",
                 "Extract login/auth flows.", requires=("grep",), output_hint="login_flows.txt"),
            _cmd("js_upload", "grep", "cat {out}/AllURLs.txt | grep -Ei 'upload|file|download|image|media' | anew {out}/file_uploads.txt",
                 "Extract upload/file endpoints.", requires=("grep",), output_hint="file_uploads.txt"),
            _cmd("js_admin", "grep", "cat {out}/AllURLs.txt | grep -Ei 'admin|dashboard|internal|manage' | anew {out}/admin_panels.txt",
                 "Extract admin panels.", requires=("grep",), output_hint="admin_panels.txt"),
            _cmd("js_sensitive", "grep", "cat {out}/AllURLs.txt | grep -Ei '\\.(env|bak|config|sql|log)(\\?|$)' | anew {out}/sensitive_files.txt",
                 "Extract sensitive file URLs.", requires=("grep",), output_hint="sensitive_files.txt"),
            _cmd("js_idor", "grep", "cat {out}/AllURLs.txt | grep -Ei '[0-9]{2,}' | anew {out}/idor_targets.txt",
                 "Extract numeric-ID candidates.", requires=("grep",), output_hint="idor_targets.txt"),
            _cmd("js_interesting", "grep",
                 "cat {out}/AllURLs.txt | grep -Ei 'admin|login|signup|redirect|callback|auth|dev|test|beta|debug|staging|url=|r=|u=|goto=|return=|dest=' | anew {out}/interesting.txt",
                 "Extract high-value endpoints.", requires=("grep",), output_hint="interesting.txt"),
            _cmd("js_cloud", "grep", "cat {out}/AllURLs.txt | grep -Ei 'aws|s3|bucket|gcp|azure|vault|token|apikey|secret' | anew {out}/cloud_leaks.txt",
                 "Extract cloud/secret-looking URLs.", requires=("grep",), output_hint="cloud_leaks.txt"),
        ),
    ),
    ExecutableStage(
        key="secret_mining",
        title="JavaScript and repository secret mining",
        objective="Mine JS and git history for credentials without writing them to reports.",
        commands=(
            _cmd("mantra", "mantra", "cat {out}/js_urls.txt | mantra > {out}/mantra.txt",
                 "Mantra JS secret scan.", requires=("mantra",), output_hint="mantra.txt"),
            _cmd("jsecret", "jsecret", "cat {out}/js_urls.txt | jsecret > {out}/jsecret.txt",
                 "jsecret JS secret scan.", requires=("jsecret",), output_hint="jsecret.txt"),
            _cmd("jsleak", "jsleak", "cat {out}/js_urls.txt | xargs -P 20 -I {} jsleak -s -l -k -e {} >> {out}/jsleak_output.txt",
                 "jsleak JS secret scan.", requires=("jsleak",), output_hint="jsleak_output.txt"),
            _cmd("trufflehog_fs", "trufflehog", "trufflehog filesystem {out}/js_urls.txt --json > {out}/trufflehog_results.json",
                 "TruffleHog filesystem scan.", requires=("trufflehog",), output_hint="trufflehog_results.json"),
            _cmd("trufflehog_git", "trufflehog", "trufflehog git {repo} --results=verified",
                 "TruffleHog git history scan.", requires=("trufflehog",), requires_context=("repo",)),
        ),
    ),
    ExecutableStage(
        key="directory_discovery",
        title="Directory and content discovery",
        objective="Find hidden paths, backups and sensitive files.",
        commands=(
            _cmd("dirb", "dirb", "dirb {url}",
                 "Classic dirb scan.", risk="active", requires=("dirb",)),
            _cmd("feroxbuster", "feroxbuster",
                 "feroxbuster -u {url} -w {wordlist} -t 300 -k -d 3 -e php,html,json,js,log,txt,bak,old,zip,tar,gz -o {out}/ferox.txt",
                 "Recursive feroxbuster scan.", risk="active", requires=("feroxbuster",), requires_context=("wordlist",),
                 output_hint="ferox.txt"),
            _cmd("gobuster", "gobuster", "gobuster dir -u {url} -w {wordlist} -k -o {out}/gobuster.txt",
                 "Gobuster directory scan.", risk="active", requires=("gobuster",), requires_context=("wordlist",),
                 output_hint="gobuster.txt"),
            _cmd("dirsearch", "dirsearch", "dirsearch -u {url} -i 200 --full-url -o {out}/dirsearch.txt",
                 "Dirsearch sensitive-file scan.", risk="active", requires=("dirsearch",), output_hint="dirsearch.txt"),
            _cmd("ffuf_dir", "ffuf", "ffuf -u {url}/FUZZ -w {wordlist} -t 200 -mc 200,301,302,403 -o {out}/ffuf_dir.json",
                 "FFUF directory fuzz.", risk="active", requires=("ffuf",), requires_context=("wordlist",),
                 output_hint="ffuf_dir.json"),
        ),
    ),
    ExecutableStage(
        key="hidden_parameters",
        title="Hidden parameter discovery",
        objective="Discover parameters and PHP endpoints that are not in the HTML.",
        commands=(
            _cmd("arjun_get", "arjun", "arjun -u {url} -o {out}/arjun.json",
                 "Arjun GET parameter discovery.", risk="active", requires=("arjun",), output_hint="arjun.json"),
            _cmd("arjun_post", "arjun", "arjun -u {url} -m post -o {out}/arjun_post.json",
                 "Arjun POST parameter discovery.", risk="active", requires=("arjun",), output_hint="arjun_post.json"),
            _cmd("ffuf_param", "ffuf", "ffuf -u {url}?FUZZ=value -w {wordlist} -mc 200 -o {out}/ffuf_param.json",
                 "FFUF hidden parameter fuzz.", risk="active", requires=("ffuf",), requires_context=("wordlist",),
                 output_hint="ffuf_param.json"),
        ),
    ),
    ExecutableStage(
        key="ports",
        title="Port and service discovery",
        objective="Map exposed services on discovered hosts.",
        commands=(
            _cmd("naabu", "naabu", "naabu -list {out}/AliveSubs.txt -p - -rate 2000 -o {out}/ports.txt",
                 "Naabu full-port scan.", risk="active", requires=("naabu",), output_hint="ports.txt"),
            _cmd("nmap", "nmap", "nmap -iL {out}/AliveSubs.txt -T4 -Pn -oN {out}/nmap.txt",
                 "Nmap service scan.", risk="active", requires=("nmap",), output_hint="nmap.txt"),
        ),
    ),
    ExecutableStage(
        key="exposure_scan",
        title="Exposure and vulnerability scan",
        objective="Run read-only exposure templates and optional intrusive checks.",
        commands=(
            _cmd("nuclei_exposures", "nuclei", "nuclei -u {url} -t http/exposures -o {out}/nuclei_exposures.txt",
                 "Nuclei exposure templates.", risk="active", requires=("nuclei",), output_hint="nuclei_exposures.txt"),
            _cmd("sqlmap_probe", "sqlmap", "sqlmap -u '{url}/file.php?id=*' --dbs --banner --batch --random-agent",
                 "SQLMap verification; only with explicit intrusive authorization.", risk="intrusive",
                 requires=("sqlmap",), timeout=600),
        ),
    ),
    ExecutableStage(
        key="takeover_origin",
        title="Takeover, origin IP and backup checks",
        objective="Check dangling DNS, origin exposure and backup artifacts.",
        commands=(
            _cmd("subzy", "subzy", "subzy run --targets {out}/AllSubs.txt --vuln --hide_fails",
                 "Subdomain takeover check.", risk="active", requires=("subzy",)),
            _cmd("originiphunter", "originiphunter", "echo {domain} | originiphunter",
                 "Origin IP discovery.", requires=("originiphunter",)),
            _cmd("bfac", "bfac", "bfac --url {url} --detection-technique all --level 3 --exclude-status-codes 404,500",
                 "Backup file artifact check.", risk="active", requires=("bfac",)),
        ),
    ),
    ExecutableStage(
        key="api_discovery",
        title="API route discovery",
        objective="Discover API routes with kiterunner.",
        commands=(
            _cmd("kiterunner", "kiterunner", "kr scan {url} -A=apiroutes-251027:10000 -x 8 -j 15 -v info",
                 "Kiterunner API route scan.", risk="active", requires=("kiterunner",)),
        ),
    ),
)


# ---------------------------------------------------------------------------
# Rendering helpers
# ---------------------------------------------------------------------------

class UnsafeValueError(ValueError):
    """Raised when a value could break out of a shell command."""


def _safe_value(name: str, value: object) -> str:
    text = str(value)
    if not text or _UNSAFE_VALUE_RE.search(text):
        raise UnsafeValueError(f"unsafe value for {name!r}: {text!r}")
    if not _SAFE_VALUE_RE.match(text):
        raise UnsafeValueError(f"unsupported characters in {name!r}: {text!r}")
    return text


_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,63}$"
)


def _valid_host(host: str) -> bool:
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    return bool(_HOSTNAME_RE.match(host))


def validate_target(target: str) -> str:
    """Validate a recon target before it reaches a shell command.

    Accepts a hostname/IP, ``host:port``, or an HTTP(S) base URL.  Query
    strings, fragments, credentials and shell metacharacters are rejected.
    """
    raw = (target or "").strip()
    if not raw:
        raise ValueError("target is required")
    if _UNSAFE_VALUE_RE.search(raw):
        raise ValueError("target contains unsafe characters")
    if "://" in raw:
        parsed = urlparse(raw)
        if parsed.scheme.lower() not in ("http", "https"):
            raise ValueError("target scheme must be http or https")
        if parsed.username or parsed.password:
            raise ValueError("target must not contain credentials")
        if parsed.query or parsed.fragment:
            raise ValueError("target must be a base URL without query/fragment")
        host = parsed.hostname or ""
    else:
        if "@" in raw:
            raise ValueError("target must not contain credentials")
        host = raw.split("/")[0].split(":")[0]
    if not _valid_host(host):
        raise ValueError(f"invalid target host: {host!r}")
    return raw


def domain_of(target: str) -> str:
    """Extract a root domain from a URL, host or host:port."""
    raw = (target or "").strip().lower()
    if not raw:
        return ""
    if "://" in raw:
        raw = urlparse(raw).netloc
    raw = raw.split("/")[0].split("@")[-1].split(":")[0]
    return raw.strip(".")


def build_context(
    target: str,
    *,
    out_dir: Optional[str] = None,
    wordlist: str = "",
    resolvers: str = "",
    **overrides: object,
) -> Dict[str, str]:
    """Build the placeholder context for a target.

    Only values explicitly supplied by the operator are returned; no fake
    subdomains, ports or URLs are generated.
    """
    target = validate_target(target)
    domain = domain_of(target)
    if not domain:
        raise ValueError("target must contain a domain or host")
    url = target if target.lower().startswith(("http://", "https://")) else f"https://{target}"
    out = Path(out_dir or Path("data") / "recon_methodology" / domain)
    out.mkdir(parents=True, exist_ok=True)
    out_posix = out.as_posix()
    wordlist = str(wordlist or "").replace("\\", "/")
    resolvers = str(resolvers or "").replace("\\", "/") or f"{out_posix}/resolvers.txt"
    ctx: Dict[str, str] = {
        "target": target,
        "domain": domain,
        "url": url,
        "out": out_posix,
        "wordlist": wordlist,
        "resolvers": resolvers,
        "subs_file": f"{out_posix}/AllSubs.txt",
        "alive_file": f"{out_posix}/AliveSubs.txt",
        "all_urls_file": f"{out_posix}/AllURLs.txt",
        "js_urls_file": f"{out_posix}/js_urls.txt",
        "php_urls_file": f"{out_posix}/php_urls.txt",
        "request_file": f"{out_posix}/request.txt",
        "js_file": f"{out_posix}/app.js",
        "targets_file": f"{out_posix}/targets.txt",
        "repo": "",
        "asn": "",
        "cidr": "",
        "ip": "",
        "org": "",
        "api_key": "",
        "github_token": "",
        "headers_wordlist": f"{out_posix}/403-headers.txt",
        "wordlist1": wordlist,
        "wordlist2": wordlist,
        "usernames": "",
        "passwords": "",
        "dirs_wordlist": wordlist,
        "params_wordlist": wordlist,
    }
    for key, value in overrides.items():
        if value is not None:
            ctx[key] = str(value)
    return ctx


def render_command(template: str, context: Dict[str, str]) -> str:
    """Safely substitute placeholders into a command template.

    Values are validated and any value containing whitespace is wrapped in
    double quotes.  Internal quotes and shell metacharacters are rejected by
    ``_safe_value`` so the quoting cannot be escaped.
    """
    safe: Dict[str, str] = {}
    for key, value in context.items():
        if value in (None, ""):
            continue
        text = _safe_value(key, value)
        if any(ch.isspace() for ch in text):
            text = f'"{text}"'
        safe[key] = text
    try:
        return template.format_map(safe)
    except KeyError as exc:
        raise ValueError(f"missing placeholder {exc.args[0]!r}") from exc


def stage_by_key(key: str) -> Optional[ExecutableStage]:
    for stage in EXECUTABLE_STAGES:
        if stage.key == key:
            return stage
    return None


def selected_stages(keys: Optional[Iterable[str]] = None) -> Tuple[ExecutableStage, ...]:
    if not keys or keys == "all":
        return EXECUTABLE_STAGES
    if isinstance(keys, str):
        keys = [part.strip() for part in keys.split(",") if part.strip()]
    wanted = set(keys)
    return tuple(stage for stage in EXECUTABLE_STAGES if stage.key in wanted)


def executable_summary() -> Dict[str, object]:
    return {
        "stages": len(EXECUTABLE_STAGES),
        "commands": sum(len(s.commands) for s in EXECUTABLE_STAGES),
        "stage_keys": [s.key for s in EXECUTABLE_STAGES],
        "tools": sorted({c.tool for s in EXECUTABLE_STAGES for c in s.commands}),
    }
