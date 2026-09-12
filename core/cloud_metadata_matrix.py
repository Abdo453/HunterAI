"""
Multi-Cloud Metadata & SSRF Audit Matrix
Covers endpoints, headers, and security mitigations for AWS, GCP, Azure, Alibaba, DigitalOcean, and Oracle.
Inspired by 0xN0RMXL/BugBountySkills Cloud & SSRF knowledge base.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class CloudMetadataProfile:
    cloud_provider: str
    endpoint_url: str
    required_headers: Dict[str, str]
    imds_version: str
    sensitive_paths: List[str]
    remediation: str


CLOUD_METADATA_REGISTRY: Dict[str, CloudMetadataProfile] = {
    "aws_imdsv1": CloudMetadataProfile(
        cloud_provider="Amazon Web Services (AWS)",
        endpoint_url="http://169.254.169.254/latest/meta-data/",
        required_headers={},
        imds_version="IMDSv1 (Legacy)",
        sensitive_paths=[
            "iam/security-credentials/",
            "identity-credentials/ec2/security-credentials/ec2-instance",
            "user-data",
            "hostname"
        ],
        remediation="Require IMDSv2 globally using AWS CLI: `aws ec2 modify-instance-metadata-options --http-tokens required --http-endpoint enabled`."
    ),
    "aws_imdsv2": CloudMetadataProfile(
        cloud_provider="Amazon Web Services (AWS)",
        endpoint_url="http://169.254.169.254/latest/meta-data/",
        required_headers={"X-aws-ec2-metadata-token": "<TOKEN_FROM_PUT_REQUEST>"},
        imds_version="IMDSv2 (Secured)",
        sensitive_paths=["iam/security-credentials/"],
        remediation="Ensure hop limit is set to 1 (`--http-put-response-hop-limit 1`) to prevent container/reverse-proxy exfiltration."
    ),
    "gcp_metadata": CloudMetadataProfile(
        cloud_provider="Google Cloud Platform (GCP)",
        endpoint_url="http://metadata.google.internal/computeMetadata/v1/?recursive=true&alt=json",
        required_headers={"Metadata-Flavor": "Google"},
        imds_version="GCP Compute Metadata v1",
        sensitive_paths=[
            "instance/service-accounts/default/token",
            "instance/attributes/kube-env",
            "instance/attributes/ssh-keys"
        ],
        remediation="Enforce `Metadata-Flavor: Google` validation on proxies and restrict workload identity permissions."
    ),
    "azure_imds": CloudMetadataProfile(
        cloud_provider="Microsoft Azure",
        endpoint_url="http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        required_headers={"Metadata": "true"},
        imds_version="Azure IMDS",
        sensitive_paths=[
            "identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
        ],
        remediation="Require the `Metadata: true` header and ensure Azure Managed Identities possess minimal role assignments."
    ),
    "digitalocean_metadata": CloudMetadataProfile(
        cloud_provider="DigitalOcean",
        endpoint_url="http://169.254.169.254/v1.json",
        required_headers={},
        imds_version="DigitalOcean Droplet Metadata",
        sensitive_paths=["v1/user-data", "v1/auth_key"],
        remediation="Isolate droplet internal interfaces and avoid passing sensitive credentials in cloud-init user-data scripts."
    ),
    "alibaba_metadata": CloudMetadataProfile(
        cloud_provider="Alibaba Cloud",
        endpoint_url="http://100.100.100.200/latest/meta-data/",
        required_headers={},
        imds_version="Alibaba ECS Metadata",
        sensitive_paths=["ram/security-credentials/"],
        remediation="Enable metadata token verification and restrict RAM role permissions to least privilege."
    ),
    "oracle_oci": CloudMetadataProfile(
        cloud_provider="Oracle Cloud Infrastructure (OCI)",
        endpoint_url="http://169.254.169.254/opc/v1/instance/",
        required_headers={"Authorization": "Bearer Oracle"},
        imds_version="OCI Instance Metadata",
        sensitive_paths=["opc/v1/identity/"],
        remediation="Configure network security groups (NSGs) to block outbound access to 169.254.169.254 from untrusted tenant workloads."
    ),
}


class CloudMetadataMatrix:
    """
    يوفر قاعدة بيانات ومصفوفة تدقيق خدمات الـ Cloud Metadata لمنع الـ SSRF وتأمين البنية السحابية
    """

    @staticmethod
    def get_profile(provider_key: str) -> Optional[CloudMetadataProfile]:
        k = provider_key.lower().replace(" ", "_")
        for key, prof in CLOUD_METADATA_REGISTRY.items():
            if key in k or k in key or prof.cloud_provider.lower() in k:
                return prof
        return None

    @staticmethod
    def list_all_profiles() -> List[CloudMetadataProfile]:
        return list(CLOUD_METADATA_REGISTRY.values())
