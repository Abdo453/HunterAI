"""
HunterAI V14.0 — Cloud Metadata Boundary Auditor
=================================================
Performs STATIC inspection of cloud config files, Terraform HCL snippets,
and HTTP-header maps captured from pentesting sessions.

CONSTITUTIONAL CONSTRAINT: This module NEVER probes live IMDS endpoints
(169.254.169.254). All analysis is purely static.

Audit coverage:
    AWS  — IMDSv1 vs IMDSv2 (http_tokens=required), hop-limit <= 1
    GCP  — Metadata-Flavor: Google header requirement
    Azure— api-version query-param + Metadata: true header
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class IMDSProvider(str, Enum):
    AWS     = "aws"
    GCP     = "gcp"
    AZURE   = "azure"
    DO      = "digitalocean"
    UNKNOWN = "unknown"


class IMDSRiskLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


@dataclass
class IMDSFinding:
    check_id:    str
    description: str
    evidence:    str
    risk_level:  IMDSRiskLevel
    remediation: str


@dataclass
class CloudIMDSAuditReport:
    provider:             IMDSProvider
    is_imdsv1_exposed:    bool
    hop_limit_unsafe:     bool
    missing_auth_header:  bool
    risk_level:           IMDSRiskLevel
    findings:             List[IMDSFinding] = field(default_factory=list)
    remediation_summary:  str = ""
    raw_config:           Dict[str, Any] = field(default_factory=dict)


class CloudMetadataBoundaryAuditor:
    """Static auditor for cloud IMDS configurations."""

    def audit_aws_imds_config(
        self,
        config: Dict[str, Any],
        source_label: str = "<config>",
    ) -> CloudIMDSAuditReport:
        findings: List[IMDSFinding] = []

        http_tokens = str(config.get("http_tokens", "optional")).lower()
        imdsv1_exposed = http_tokens != "required"
        if imdsv1_exposed:
            findings.append(IMDSFinding(
                check_id="AWS-IMDS-001",
                description=(
                    "IMDSv1 is enabled (http_tokens != 'required'). "
                    "SSRF can reach /latest/meta-data/iam/security-credentials/ "
                    "without a PUT token pre-auth step."
                ),
                evidence=f"http_tokens = '{http_tokens}' in {source_label}",
                risk_level=IMDSRiskLevel.CRITICAL,
                remediation=(
                    "Set http_tokens = \"required\" in your Terraform "
                    "aws_instance.metadata_options block."
                ),
            ))

        hop_limit = int(config.get("http_put_response_hop_limit", 1))
        hop_unsafe = hop_limit > 1
        if hop_unsafe:
            findings.append(IMDSFinding(
                check_id="AWS-IMDS-002",
                description=(
                    f"IMDSv2 hop-limit is {hop_limit} (>1). "
                    "Allows containerised workloads to reach the metadata endpoint."
                ),
                evidence=f"http_put_response_hop_limit = {hop_limit} in {source_label}",
                risk_level=IMDSRiskLevel.HIGH,
                remediation="Set http_put_response_hop_limit = 1.",
            ))

        if any(f.risk_level == IMDSRiskLevel.CRITICAL for f in findings):
            overall = IMDSRiskLevel.CRITICAL
        elif any(f.risk_level == IMDSRiskLevel.HIGH for f in findings):
            overall = IMDSRiskLevel.HIGH
        elif findings:
            overall = IMDSRiskLevel.MEDIUM
        else:
            overall = IMDSRiskLevel.INFO

        return CloudIMDSAuditReport(
            provider=IMDSProvider.AWS,
            is_imdsv1_exposed=imdsv1_exposed,
            hop_limit_unsafe=hop_unsafe,
            missing_auth_header=False,
            risk_level=overall,
            findings=findings,
            remediation_summary=(
                "Enforce IMDSv2 with hop-limit=1 on all EC2 instances."
                if findings else "AWS IMDS configuration appears secure."
            ),
            raw_config=config,
        )

    def audit_gcp_metadata_headers(
        self,
        headers: Dict[str, str],
        source_label: str = "<headers>",
    ) -> CloudIMDSAuditReport:
        findings: List[IMDSFinding] = []
        normalised = {k.lower(): v for k, v in headers.items()}
        flavor = normalised.get("metadata-flavor", "")
        missing = flavor.strip() != "Google"

        if missing:
            findings.append(IMDSFinding(
                check_id="GCP-IMDS-001",
                description=(
                    "Metadata-Flavor: Google header is absent or incorrect. "
                    "A crafted SSRF request that injects this header can read "
                    "service-account tokens from the GCP metadata endpoint."
                ),
                evidence=f"'Metadata-Flavor' = '{flavor}' in {source_label}",
                risk_level=IMDSRiskLevel.HIGH,
                remediation=(
                    "Ensure application code blocks outbound requests to "
                    "169.254.169.254 except from the GCP metadata client library."
                ),
            ))

        overall = IMDSRiskLevel.HIGH if missing else IMDSRiskLevel.INFO

        return CloudIMDSAuditReport(
            provider=IMDSProvider.GCP,
            is_imdsv1_exposed=False,
            hop_limit_unsafe=False,
            missing_auth_header=missing,
            risk_level=overall,
            findings=findings,
            remediation_summary=(
                "Add 'Metadata-Flavor: Google' protection at the GCP VM."
                if missing else "GCP metadata header configuration appears secure."
            ),
            raw_config=dict(headers),
        )

    def audit_azure_imds_config(
        self,
        config: Dict[str, Any],
        source_label: str = "<config>",
    ) -> CloudIMDSAuditReport:
        findings: List[IMDSFinding] = []
        headers_cfg = {k.lower(): v for k, v in config.get("headers", {}).items()}
        metadata_hdr = headers_cfg.get("metadata", "")
        api_version = config.get("api_version", config.get("api-version", ""))

        if str(metadata_hdr).lower() != "true":
            findings.append(IMDSFinding(
                check_id="AZURE-IMDS-001",
                description=(
                    "'Metadata: true' header is not set. "
                    "Azure IMDS enforces this as an anti-SSRF control; "
                    "validate that your SSRF test vectors include header injection."
                ),
                evidence=f"'Metadata' header = '{metadata_hdr}' in {source_label}",
                risk_level=IMDSRiskLevel.MEDIUM,
                remediation=(
                    "Deploy Azure Private Endpoints and restrict outbound to "
                    "169.254.169.254 via NSG deny rules."
                ),
            ))

        if not str(api_version).strip():
            findings.append(IMDSFinding(
                check_id="AZURE-IMDS-002",
                description="api-version parameter is missing from the IMDS request config.",
                evidence=f"api_version = '{api_version}' in {source_label}",
                risk_level=IMDSRiskLevel.LOW,
                remediation="Always specify ?api-version=2021-02-01 (or later).",
            ))

        overall = IMDSRiskLevel.MEDIUM if findings else IMDSRiskLevel.INFO

        return CloudIMDSAuditReport(
            provider=IMDSProvider.AZURE,
            is_imdsv1_exposed=False,
            hop_limit_unsafe=False,
            missing_auth_header=bool(findings),
            risk_level=overall,
            findings=findings,
            remediation_summary=(
                "Harden Azure IMDS by enforcing NSG deny rules and validating header gates."
                if findings else "Azure IMDS configuration appears secure."
            ),
            raw_config=config,
        )

    @staticmethod
    def parse_terraform_imds_block(hcl_text: str) -> Dict[str, Any]:
        """Extract IMDS fields from a Terraform HCL string (static parsing)."""
        config: Dict[str, Any] = {}
        m = re.search(r'http_tokens\s*=\s*"([^"]+)"', hcl_text)
        if m:
            config["http_tokens"] = m.group(1)
        m = re.search(r'http_put_response_hop_limit\s*=\s*(\d+)', hcl_text)
        if m:
            config["http_put_response_hop_limit"] = int(m.group(1))
        return config

    def audit_all_providers(
        self,
        aws_config:   Optional[Dict[str, Any]] = None,
        gcp_headers:  Optional[Dict[str, str]]  = None,
        azure_config: Optional[Dict[str, Any]] = None,
    ) -> List[CloudIMDSAuditReport]:
        reports: List[CloudIMDSAuditReport] = []
        if aws_config is not None:
            reports.append(self.audit_aws_imds_config(aws_config))
        if gcp_headers is not None:
            reports.append(self.audit_gcp_metadata_headers(gcp_headers))
        if azure_config is not None:
            reports.append(self.audit_azure_imds_config(azure_config))
        return reports
