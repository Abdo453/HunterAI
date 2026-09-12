"""
Enterprise Perimeter & Identity Matrix
Attack surface classification and posture analysis for enterprise edge, identity providers, and cloud metadata.
Inspired by Claude-BugHunter's enterprise identity & infrastructure attack matrices.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class PerimeterAsset:
    asset_type: str                   # identity_sso | ssl_vpn | cloud_metadata | enterprise_platform
    vendor_platform: str              # Okta | EntraID | Fortinet | Citrix | Cisco | VMware | AWS
    indicators: List[str]
    audit_focus: List[str]
    remediation_guidance: str


ENTERPRISE_PROFILES: Dict[str, PerimeterAsset] = {
    "okta_sso": PerimeterAsset(
        asset_type="identity_sso",
        vendor_platform="Okta Identity Cloud",
        indicators=["okta.com", "oktapreview.com", "login.okta.com", "/oauth2/v1/authorize"],
        audit_focus=[
            "Inspect OAuth redirect_uri matching rules for wildcard bypasses.",
            "Verify SAML assertion signature validation and replay defenses.",
            "Check for unauthenticated user enumeration via login endpoints."
        ],
        remediation_guidance="Enforce exact-match redirect URIs, strict PKCE, and multi-factor authentication policies."
    ),
    "entra_id": PerimeterAsset(
        asset_type="identity_sso",
        vendor_platform="Microsoft Entra ID / M365",
        indicators=["login.microsoftonline.com", "sts.windows.net", "aadcdn.msauth.net", "autodiscover"],
        audit_focus=[
            "Inspect tenant federation settings and OpenID Connect configurations.",
            "Check for exposed administrative consent permissions.",
            "Verify legacy authentication protocol disablement (e.g. Basic Auth / POP3 / IMAP)."
        ],
        remediation_guidance="Disable legacy auth protocols, enforce Conditional Access Policies, and restrict app registrations."
    ),
    "ssl_vpn_fortinet": PerimeterAsset(
        asset_type="ssl_vpn",
        vendor_platform="Fortinet FortiOS SSL-VPN",
        indicators=["/remote/login", "fortigate", "fgt_lang", "/sslvpn/portal.html"],
        audit_focus=[
            "Check software version against known published advisory lists.",
            "Verify SAML/MFA enforcement on VPN portals.",
            "Inspect management interface exposure on WAN interfaces."
        ],
        remediation_guidance="Upgrade FortiOS to the latest patched firmware and isolate admin access from public WAN."
    ),
    "ssl_vpn_citrix": PerimeterAsset(
        asset_type="ssl_vpn",
        vendor_platform="Citrix ADC / NetScaler Gateway",
        indicators=["/vpn/index.html", "/citrix/", "ns_af", "citrix gateway"],
        audit_focus=[
            "Verify patching against memory safety and authentication bypass advisories.",
            "Inspect exposed AAA and management endpoints.",
            "Audit session timeout configurations."
        ],
        remediation_guidance="Apply Citrix security hotfixes immediately and enforce multi-factor authentication on all gateway VIPs."
    ),
    "ssl_vpn_cisco": PerimeterAsset(
        asset_type="ssl_vpn",
        vendor_platform="Cisco ASA / AnyConnect / Secure Firewall",
        indicators=["/+CSCOE+/", "/+CSCOT+/", "cisco anyconnect", "webvpn"],
        audit_focus=[
            "Audit version against Cisco security advisories.",
            "Check for default certificate usage or weak SSL cipher suites.",
            "Verify client posture assessment enforcement."
        ],
        remediation_guidance="Update ASA/FTD software to recommended train and disable vulnerable legacy SSL services."
    ),
    "vmware_vcenter": PerimeterAsset(
        asset_type="enterprise_platform",
        vendor_platform="VMware vCenter / vSphere / Horizon",
        indicators=["/ui/login", "/vsphere-client/", "vmware", "/horizon/"],
        audit_focus=[
            "Ensure management web interfaces are NOT directly exposed to the public Internet.",
            "Verify patching of vCenter server plugins and appliances.",
            "Audit SSO identity federation integrations."
        ],
        remediation_guidance="Completely isolate VMware management ports (443, 902, 5480) behind internal bastion/VPN."
    ),
    "aws_cloud_surface": PerimeterAsset(
        asset_type="cloud_metadata",
        vendor_platform="Amazon Web Services (AWS)",
        indicators=["169.254.169.254", "amazonaws.com", "s3.amazonaws.com", "s3-website"],
        audit_focus=[
            "Verify IMDSv2 enforcement (Hop count = 1) across EC2 instances to neutralize SSRF.",
            "Audit public S3 bucket ACLs and Object Ownership policies.",
            "Inspect IAM role trust policies for cross-account AssumeRole risks."
        ],
        remediation_guidance="Enforce IMDSv2 globally, enable S3 Block Public Access, and audit cloud identity least-privilege."
    ),
}


class EnterprisePerimeterMatrix:
    """
    يقوم بتحليل وتصنيف الأصول المكتشفة في سطح الهجوم وربطها بمصفوفة حماية المؤسسات والهويات السحابية
    """

    @staticmethod
    def identify_profile(url_or_banner: str) -> Optional[PerimeterAsset]:
        """تحديد نوع الأصل المؤسسي بناءً على الرابط أو البانر المكتشف"""
        text = url_or_banner.lower()
        for key, asset in ENTERPRISE_PROFILES.items():
            if any(ind.lower() in text for ind in asset.indicators):
                return asset
        return None

    @staticmethod
    def get_all_profiles() -> List[PerimeterAsset]:
        return list(ENTERPRISE_PROFILES.values())
