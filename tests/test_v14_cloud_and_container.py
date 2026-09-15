"""
HunterAI V14.0 — Cloud Metadata Boundary & Container Isolation Tests
=====================================================================
pytest suite — 12 tests covering:
    - AWS IMDSv1 exposure detection
    - AWS hop-limit unsafe detection
    - AWS secure config (no findings)
    - Terraform HCL parsing
    - GCP missing Metadata-Flavor header
    - GCP correct header (no findings)
    - Azure missing Metadata header
    - Azure secure config (no findings)
    - Dockerfile root-user detection
    - Dockerfile docker.sock detection
    - Docker-compose privileged + CAP_SYS_ADMIN detection
    - K8s hostPID / hostNetwork / allowPrivilegeEscalation detection
    - Remediation: hardened Dockerfile snippet
    - Remediation: K8s security context snippet
    - Remediation: Terraform IMDSv2 policy snippet
"""

import pytest

from core.cloud.cloud_boundary_agent import (
    CloudMetadataBoundaryAuditor,
    IMDSProvider,
    IMDSRiskLevel,
)
from core.container.container_security_auditor import (
    ContainerSecurityAuditor,
    ContainerFindingCategory,
    ContainerRiskLevel,
)
from core.remediation.cloud_container_remediation import (
    CloudContainerRemediationEngine,
)


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def cloud_auditor():
    return CloudMetadataBoundaryAuditor()


@pytest.fixture
def container_auditor():
    return ContainerSecurityAuditor()


@pytest.fixture
def remediation_engine():
    return CloudContainerRemediationEngine()


# ─────────────────────────────────────────────────────────────────────────────
# AWS IMDS Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestAWSIMDS:

    def test_imdsv1_exposed_is_critical(self, cloud_auditor):
        """IMDSv1 (http_tokens=optional) must be flagged CRITICAL."""
        report = cloud_auditor.audit_aws_imds_config({"http_tokens": "optional"})
        assert report.provider == IMDSProvider.AWS
        assert report.is_imdsv1_exposed is True
        assert report.risk_level == IMDSRiskLevel.CRITICAL
        check_ids = [f.check_id for f in report.findings]
        assert "AWS-IMDS-001" in check_ids

    def test_hop_limit_above_one_is_high(self, cloud_auditor):
        """hop_limit=2 with IMDSv2 enforced must produce HIGH finding."""
        report = cloud_auditor.audit_aws_imds_config({
            "http_tokens": "required",
            "http_put_response_hop_limit": 2,
        })
        assert report.hop_limit_unsafe is True
        assert report.risk_level == IMDSRiskLevel.HIGH
        check_ids = [f.check_id for f in report.findings]
        assert "AWS-IMDS-002" in check_ids

    def test_secure_aws_config_no_findings(self, cloud_auditor):
        """IMDSv2 enforced + hop_limit=1 must produce zero findings."""
        report = cloud_auditor.audit_aws_imds_config({
            "http_tokens": "required",
            "http_put_response_hop_limit": 1,
        })
        assert not report.is_imdsv1_exposed
        assert not report.hop_limit_unsafe
        assert report.findings == []
        assert report.risk_level == IMDSRiskLevel.INFO

    def test_terraform_hcl_parser_vulnerable(self, cloud_auditor):
        """Terraform HCL parser extracts http_tokens and hop_limit correctly."""
        hcl = """
        metadata_options {
          http_tokens                 = "optional"
          http_put_response_hop_limit = 3
        }
        """
        config = CloudMetadataBoundaryAuditor.parse_terraform_imds_block(hcl)
        assert config["http_tokens"] == "optional"
        assert config["http_put_response_hop_limit"] == 3

        report = cloud_auditor.audit_aws_imds_config(config)
        assert report.is_imdsv1_exposed is True


# ─────────────────────────────────────────────────────────────────────────────
# GCP IMDS Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestGCPIMDS:

    def test_missing_metadata_flavor_is_high(self, cloud_auditor):
        """Missing Metadata-Flavor header → HIGH finding."""
        report = cloud_auditor.audit_gcp_metadata_headers(
            {"Content-Type": "application/json"}
        )
        assert report.provider == IMDSProvider.GCP
        assert report.missing_auth_header is True
        assert report.risk_level == IMDSRiskLevel.HIGH
        assert any(f.check_id == "GCP-IMDS-001" for f in report.findings)

    def test_correct_gcp_header_no_findings(self, cloud_auditor):
        """Correct Metadata-Flavor: Google header → INFO / zero findings."""
        report = cloud_auditor.audit_gcp_metadata_headers(
            {"Metadata-Flavor": "Google", "Content-Type": "application/json"}
        )
        assert report.missing_auth_header is False
        assert report.findings == []
        assert report.risk_level == IMDSRiskLevel.INFO


# ─────────────────────────────────────────────────────────────────────────────
# Azure IMDS Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestAzureIMDS:

    def test_missing_metadata_header_is_medium(self, cloud_auditor):
        """Azure config missing Metadata: true header → MEDIUM finding."""
        report = cloud_auditor.audit_azure_imds_config({
            "headers": {"Content-Type": "application/json"},
            "api_version": "2021-02-01",
        })
        assert report.provider == IMDSProvider.AZURE
        assert report.missing_auth_header is True
        assert any(f.check_id == "AZURE-IMDS-001" for f in report.findings)

    def test_secure_azure_config_no_findings(self, cloud_auditor):
        """Azure config with correct headers and api_version → INFO / zero findings."""
        report = cloud_auditor.audit_azure_imds_config({
            "headers": {"Metadata": "true"},
            "api_version": "2021-02-01",
        })
        assert report.findings == []
        assert report.risk_level == IMDSRiskLevel.INFO


# ─────────────────────────────────────────────────────────────────────────────
# Container Auditor Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestDockerfileAuditor:

    def test_detects_root_user_directive(self, container_auditor):
        """USER root in Dockerfile must produce HIGH ROOT_USER finding."""
        dockerfile = (
            "FROM python:3.11-slim\n"
            "RUN pip install flask\n"
            "USER root\n"
            "CMD ['python', 'app.py']\n"
        )
        findings = container_auditor.audit_dockerfile(dockerfile)
        cats = [f.category for f in findings]
        assert ContainerFindingCategory.ROOT_USER in cats
        severities = [f.risk_level for f in findings]
        assert ContainerRiskLevel.HIGH in severities

    def test_detects_docker_socket_in_dockerfile(self, container_auditor):
        """docker.sock reference in Dockerfile must be CRITICAL."""
        dockerfile = (
            "FROM docker:latest\n"
            "VOLUME /var/run/docker.sock\n"
            "CMD ['dockerd']\n"
        )
        findings = container_auditor.audit_dockerfile(dockerfile)
        critical = [f for f in findings if f.risk_level == ContainerRiskLevel.CRITICAL]
        assert len(critical) >= 1
        assert any(f.category == ContainerFindingCategory.SOCKET_ESCAPE for f in critical)

    def test_no_user_directive_flags_root(self, container_auditor):
        """Dockerfile without USER directive must produce a ROOT_USER finding."""
        dockerfile = (
            "FROM python:3.11-slim\n"
            "RUN pip install flask\n"
            "CMD ['python', 'app.py']\n"
        )
        findings = container_auditor.audit_dockerfile(dockerfile)
        root_findings = [f for f in findings if f.category == ContainerFindingCategory.ROOT_USER]
        assert len(root_findings) >= 1


class TestComposeAuditor:

    def test_detects_privileged_and_cap_sys_admin(self, container_auditor):
        """Compose YAML with privileged:true and CAP_SYS_ADMIN must produce CRITICAL + HIGH."""
        compose_yaml = """
version: "3.9"
services:
  app:
    image: myapp:latest
    privileged: true
    cap_add:
      - CAP_SYS_ADMIN
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
"""
        findings = container_auditor.audit_compose_manifest(compose_yaml)
        check_ids = {f.check_id for f in findings}
        assert "COMPOSE-001" in check_ids   # docker.sock
        assert "COMPOSE-002" in check_ids   # privileged
        assert "COMPOSE-003" in check_ids   # CAP_SYS_ADMIN


class TestK8sManifestAuditor:

    def test_detects_host_namespaces_and_priv_esc(self, container_auditor):
        """K8s manifest with hostPID/hostNetwork/allowPrivilegeEscalation must be flagged."""
        k8s_yaml = """
apiVersion: v1
kind: Pod
spec:
  hostPID: true
  hostNetwork: true
  hostIPC: true
  containers:
  - name: app
    image: myapp:latest
    securityContext:
      privileged: true
      allowPrivilegeEscalation: true
"""
        findings = container_auditor.audit_k8s_manifest(k8s_yaml)
        check_ids = {f.check_id for f in findings}
        assert "K8S-002" in check_ids   # privileged
        assert "K8S-005" in check_ids   # hostPID
        assert "K8S-006" in check_ids   # hostNetwork
        assert "K8S-007" in check_ids   # hostIPC
        assert "K8S-008" in check_ids   # allowPrivilegeEscalation


# ─────────────────────────────────────────────────────────────────────────────
# Remediation Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestCloudContainerRemediation:

    def test_hardened_dockerfile_non_root(self):
        """Hardened Dockerfile snippet must NOT contain 'USER root'."""
        result = CloudContainerRemediationEngine.generate_hardened_dockerfile()
        assert "USER root" not in result.code_snippet
        assert "USER 0" not in result.code_snippet
        assert "useradd" in result.code_snippet or "adduser" in result.code_snippet

    def test_k8s_security_context_restricted(self):
        """K8s snippet must include 'allowPrivilegeEscalation: false' and 'privileged: false'."""
        result = CloudContainerRemediationEngine.generate_k8s_security_context()
        assert "allowPrivilegeEscalation: false" in result.code_snippet
        assert "privileged:               false" in result.code_snippet
        assert 'drop: ["ALL"]' in result.code_snippet
        assert "hostPID:     false" in result.code_snippet
        assert "hostNetwork: false" in result.code_snippet

    def test_terraform_imds_policy_requires_v2(self):
        """Terraform snippet must set http_tokens = required and hop_limit = 1."""
        result = CloudContainerRemediationEngine.generate_terraform_imds_policy()
        assert 'http_tokens                 = "required"' in result.code_snippet
        assert "http_put_response_hop_limit = 1" in result.code_snippet
        assert result.artifact_type == "terraform_hcl"
