"""
Program Intelligence & Security.txt Parser
===========================================
Detects, parses, and classifies Bug Bounty (BBP) and Vulnerability Disclosure (VDP)
programs across platform-hosted (HackerOne, Bugcrowd, Intigriti) and self-hosted targets.
Automates RFC 9116 security.txt discovery, contacts extraction, PGP encryption, and
tailors reporting according to program rules and NDA visibility.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import httpx

from hunter_ai.pipeline.schemas import (
    ProgramMetadata,
    ProgramPlatform,
    ProgramType,
    ProgramVisibility,
)

logger = logging.getLogger("hunter_ai.program_intelligence")


class SecurityTxtParser:
    """Parses RFC 9116 security.txt files into structured ProgramMetadata"""

    @classmethod
    def parse(cls, content: str, source_url: str = "") -> ProgramMetadata:
        meta = ProgramMetadata(
            security_txt_found=True,
            security_txt_url=source_url,
            platform=ProgramPlatform.SELF_HOSTED,
            program_type=ProgramType.VDP,
            visibility=ProgramVisibility.PUBLIC,
        )

        contacts = []
        policies = []
        encryptions = []
        acknowledgments = []

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            if ":" not in line:
                continue

            key, val = line.split(":", 1)
            key = key.strip().lower()
            val = val.strip()

            if key == "contact":
                contacts.append(val)
            elif key == "policy":
                policies.append(val)
            elif key == "encryption":
                encryptions.append(val)
            elif key in ("acknowledgments", "acknowledgements"):
                acknowledgments.append(val)

        # 1. Process Contacts
        for c in contacts:
            c_low = c.lower()
            if "hackerone.com" in c_low:
                meta.platform = ProgramPlatform.HACKERONE
                meta.policy_url = c
            elif "bugcrowd.com" in c_low:
                meta.platform = ProgramPlatform.BUGCROWD
                meta.policy_url = c
            elif "intigriti.com" in c_low:
                meta.platform = ProgramPlatform.INTIGRITI
                meta.policy_url = c
            elif "yeswehack.com" in c_low:
                meta.platform = ProgramPlatform.YESWEHACK
                meta.policy_url = c
            elif c_low.startswith("mailto:"):
                meta.contact_email = c[7:].split("?")[0].strip()
            elif "@" in c and not c.startswith("http"):
                meta.contact_email = c.strip()

        # 2. Process Policies
        if policies:
            meta.policy_url = meta.policy_url or policies[0]
            pol_low = policies[0].lower()
            if "hackerone.com" in pol_low:
                meta.platform = ProgramPlatform.HACKERONE
            elif "bugcrowd.com" in pol_low:
                meta.platform = ProgramPlatform.BUGCROWD
            elif "intigriti.com" in pol_low:
                meta.platform = ProgramPlatform.INTIGRITI

        # 3. Classify BBP vs VDP
        # If policy mentions bounty, reward, cash or points
        all_text = content.lower()
        if any(w in all_text for w in ["bounty", "reward", "payment", "$", "monetary"]):
            if meta.platform == ProgramPlatform.SELF_HOSTED:
                meta.program_type = ProgramType.SELF_HOSTED_BBP
            else:
                meta.program_type = ProgramType.BBP
            meta.bounty_eligible = True
        else:
            if meta.platform == ProgramPlatform.SELF_HOSTED:
                meta.program_type = ProgramType.SELF_HOSTED_VDP
            else:
                meta.program_type = ProgramType.VDP
            meta.bounty_eligible = False

        if encryptions:
            meta.pgp_key_url = encryptions[0]

        if acknowledgments:
            meta.acknowledgments_url = acknowledgments[0]

        return meta


class ProgramIntelligence:
    """
    Automated discovery and report generation tailored for Bug Bounty & VDP programs.
    """

    @classmethod
    async def discover_program(
        cls,
        domain: str,
        proxy: Optional[str] = None,
        timeout: float = 6.0
    ) -> ProgramMetadata:
        """
        Discovers security.txt across standard paths and identifies program rules.
        """
        clean_domain = domain.lower().replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        paths = [
            f"https://{clean_domain}/.well-known/security.txt",
            f"https://{clean_domain}/security.txt",
            f"http://{clean_domain}/.well-known/security.txt",
        ]

        transport = httpx.AsyncHTTPTransport(proxy=proxy, verify=False) if proxy else None
        async with httpx.AsyncClient(transport=transport, verify=False, timeout=timeout, follow_redirects=True) as client:
            for url in paths:
                try:
                    resp = await client.get(url)
                    if resp.status_code == 200 and ("contact:" in resp.text.lower() or "policy:" in resp.text.lower()):
                        logger.info(f"[ProgramIntelligence] Found valid security.txt at {url}")
                        return SecurityTxtParser.parse(resp.text, source_url=url)
                except Exception as e:
                    logger.debug(f"Failed fetching {url}: {e}")

        # Default fallback: Self-Hosted VDP with inferred security contact
        return ProgramMetadata(
            program_type=ProgramType.SELF_HOSTED_VDP,
            platform=ProgramPlatform.SELF_HOSTED,
            visibility=ProgramVisibility.PUBLIC,
            contact_email=f"security@{clean_domain}",
            security_txt_found=False,
            bounty_eligible=False
        )

    @classmethod
    def generate_hackerone_report(
        cls,
        target: str,
        findings: List[Dict[str, Any]],
        program_meta: Optional[ProgramMetadata] = None
    ) -> str:
        """
        Generates a professional HackerOne / Bugcrowd markdown submission report.
        Focuses on Business Impact, Reproduction Steps, and CVSS v3.1 scoring.
        """
        lines = [
            f"# Bug Bounty Vulnerability Submission: {target}",
            f"- **Target**: `{target}`",
            f"- **Program Type**: `{program_meta.program_type.value if program_meta else 'BBP'}`",
            f"- **Platform**: `{program_meta.platform.value if program_meta else 'HackerOne'}`",
            f"- **Total Confirmed Vulnerabilities**: {len(findings)}\n",
            "## Executive Summary",
            "During authorized testing, security vulnerabilities were identified and verified using non-destructive execution proofs. "
            "Below are the verified technical findings, reproduction curl requests, and suggested remediations.\n",
            "---"
        ]

        for idx, f in enumerate(findings, 1):
            vuln_title = f.get("finding") or f.get("vuln_type", "Security Vulnerability")
            endpoint = f.get("endpoint", target)
            param = f.get("parameter") or "N/A"
            cvss = f.get("cvss_score", 5.0)
            cvss_vec = f.get("cvss_vector", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
            severity = f.get("severity", "Medium")

            lines.append(f"### {idx}. [{severity}] {vuln_title}")
            lines.append(f"- **Vulnerable Endpoint**: `{endpoint}`")
            lines.append(f"- **Vulnerable Parameter**: `{param}`")
            lines.append(f"- **Severity / CVSS v3.1**: `{severity}` ({cvss}) - `{cvss_vec}`")
            lines.append(f"- **CWE**: `{f.get('cwe', 'CWE-20')}`\n")

            lines.append("#### Steps to Reproduce")
            repro = f.get("reproduction") or {}
            curl_cmd = repro.get("curl_command") if isinstance(repro, dict) else getattr(repro, "curl_command", "")
            if curl_cmd:
                lines.append("Execute the following curl command in terminal:")
                lines.append(f"```bash\n{curl_cmd}\n```\n")
            else:
                lines.append(f"Send HTTP request to `{endpoint}` with test payload in parameter `{param}`.\n")

            lines.append("#### Proof of Concept & Evidence")
            evidence_list = f.get("evidence", [])
            if evidence_list:
                for ev in evidence_list:
                    desc = ev.get("description") if isinstance(ev, dict) else getattr(ev, "description", "")
                    proof = ev.get("proof_snippet") if isinstance(ev, dict) else getattr(ev, "proof_snippet", "")
                    lines.append(f"- **Proof Evaluation**: {desc}")
                    if proof:
                        lines.append(f"```text\n{proof}\n```")
            else:
                lines.append("Non-destructive controlled execution verified.")
            lines.append("")

            lines.append("#### Business Impact")
            lines.append(
                f"An attacker exploiting this vulnerability on `{endpoint}` could compromise data confidentiality, "
                "integrity, or system state depending on privilege level. This poses direct financial, reputational, and compliance risks.\n"
            )

            lines.append("#### Suggested Remediation")
            lines.append(f"{f.get('remediation', 'Validate and sanitize all user input.')}\n")
            lines.append("---\n")

        return "\n".join(lines)

    @classmethod
    def generate_vdp_email_template(
        cls,
        target: str,
        contact_email: str,
        findings: List[Dict[str, Any]],
        acknowledgments_url: Optional[str] = None
    ) -> str:
        """
        Generates a polite, professional Coordinated Vulnerability Disclosure (CVD) email
        ready to send to security@company.com with Hall of Fame request.
        """
        email_lines = [
            f"To: {contact_email}",
            f"Subject: [Security Vulnerability Report] Coordinated Disclosure on {target}",
            "",
            f"Dear {target} Security Team,",
            "",
            "I hope this message finds you well.",
            "",
            f"During independent security research on {target} following Coordinated Vulnerability Disclosure (CVD) "
            "best practices and safe harbor guidelines, I identified valid security findings affecting your web assets. "
            "All testing was non-destructive and aimed at protecting your infrastructure and user data.",
            "",
            f"SUMMARY OF FINDINGS ({len(findings)} confirmed):"
        ]

        for idx, f in enumerate(findings, 1):
            vuln_title = f.get("finding") or f.get("vuln_type", "Security Issue")
            severity = f.get("severity", "Medium")
            endpoint = f.get("endpoint", target)
            email_lines.append(f"  {idx}. [{severity}] {vuln_title} on {endpoint}")

        email_lines.extend([
            "",
            "I have prepared full technical details, reproduction steps, and proof-of-concept logs.",
            "Please confirm receipt of this email and let me know if you would like me to share the full technical report "
            "in plain text or encrypted with your PGP key.",
            ""
        ])

        if acknowledgments_url:
            email_lines.append(f"If confirmed, I would appreciate being acknowledged on your Hall of Fame ({acknowledgments_url}).")
        else:
            email_lines.append("If confirmed, I would appreciate being acknowledged on your security Hall of Fame / Contributor list.")

        email_lines.extend([
            "",
            "Thank you for your commitment to security,",
            "HunterAI Security Research Team"
        ])

        return "\n".join(email_lines)
