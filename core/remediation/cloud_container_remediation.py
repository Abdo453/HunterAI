"""
HunterAI V14.0 — Cloud & Container Remediation Engine
======================================================
Generates hardened Dockerfiles, Kubernetes PodSecurityStandards Restricted
profiles, and Terraform IMDSv2 policy snippets as remediation artifacts.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class RemediationResult:
    vulnerability_remediated: str
    artifact_type: str          # "dockerfile" | "k8s_yaml" | "terraform_hcl"
    code_snippet: str
    notes: str


class CloudContainerRemediationEngine:
    """
    Generates ready-to-apply remediation artifacts for cloud metadata
    and container security misconfigurations.
    """

    @staticmethod
    def generate_hardened_dockerfile(
        base_image: str = "python:3.11-slim",
        app_user: str = "appuser",
        app_uid: int = 1000,
    ) -> RemediationResult:
        """
        Return a hardened Dockerfile template that:
        - Drops all Linux capabilities
        - Runs as non-root user
        - Uses read-only root filesystem flag
        - Avoids docker.sock mounts
        """
        snippet = f"""# ── HunterAI V14.0 Hardened Dockerfile Template ──────────────────────────
FROM {base_image}

# Install only required packages; clean cache in same layer
RUN apt-get update && apt-get install -y --no-install-recommends \\
        ca-certificates \\
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd --gid {app_uid} {app_user} \\
 && useradd  --uid {app_uid} --gid {app_uid} \\
             --no-create-home --shell /usr/sbin/nologin \\
             {app_user}

WORKDIR /app
COPY --chown={app_user}:{app_user} . .

RUN pip install --no-cache-dir -r requirements.txt

# Drop to non-root before starting the process
USER {app_uid}

# Recommended: run container with --read-only --cap-drop ALL --security-opt no-new-privileges
ENTRYPOINT ["python", "main.py"]
"""
        return RemediationResult(
            vulnerability_remediated="Root container user / missing USER directive",
            artifact_type="dockerfile",
            code_snippet=snippet,
            notes=(
                "Deploy with: docker run --read-only --cap-drop ALL "
                "--security-opt no-new-privileges <image>"
            ),
        )

    @staticmethod
    def generate_k8s_security_context(
        app_name: str = "my-app",
    ) -> RemediationResult:
        """
        Return a Kubernetes PodSecurityStandards 'Restricted' compliant
        securityContext block for a Pod/Deployment spec.
        """
        snippet = f"""# ── HunterAI V14.0 K8s PodSecurityStandards Restricted Profile ──────────
apiVersion: v1
kind: Pod
metadata:
  name: {app_name}
  labels:
    app: {app_name}
  annotations:
    # Enforce PSS Restricted profile at namespace level:
    # kubectl label namespace my-ns pod-security.kubernetes.io/enforce=restricted
spec:
  hostPID:     false
  hostIPC:     false
  hostNetwork: false
  securityContext:
    runAsNonRoot:        true
    runAsUser:           1000
    runAsGroup:          1000
    fsGroup:             1000
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: {app_name}
    image: my-registry/{app_name}:latest
    securityContext:
      allowPrivilegeEscalation: false
      privileged:               false
      readOnlyRootFilesystem:   true
      capabilities:
        drop: ["ALL"]
    # No docker.sock volume mounts
    volumeMounts:
    - name: tmp-dir
      mountPath: /tmp
  volumes:
  - name: tmp-dir
    emptyDir: {{}}
"""
        return RemediationResult(
            vulnerability_remediated=(
                "privileged mode / hostPID / hostNetwork / hostIPC / "
                "CAP_SYS_ADMIN / allowPrivilegeEscalation"
            ),
            artifact_type="k8s_yaml",
            code_snippet=snippet,
            notes=(
                "Apply PSS Restricted at the namespace level: "
                "kubectl label namespace <ns> "
                "pod-security.kubernetes.io/enforce=restricted"
            ),
        )

    @staticmethod
    def generate_terraform_imds_policy(
        instance_resource_name: str = "app_server",
    ) -> RemediationResult:
        """
        Return a Terraform aws_instance metadata_options block enforcing IMDSv2
        with hop-limit = 1 (prevents container / proxy escapes).
        """
        snippet = f"""# ── HunterAI V14.0 Terraform IMDSv2 Enforcement Policy ──────────────────
resource "aws_instance" "{instance_resource_name}" {{
  # ... other instance config ...

  metadata_options {{
    # REQUIRED: Enforce IMDSv2 (token-based requests only)
    http_tokens                 = "required"

    # REQUIRED: Keep hop-limit at 1 so containerised workloads
    # cannot reach the metadata endpoint from nested namespaces
    http_put_response_hop_limit = 1

    # Optionally expose instance tags via IMDS (safe with IMDSv2)
    instance_metadata_tags      = "enabled"
  }}

  # Deny IMDSv1 via SCP (apply at AWS Organisation level):
  # Condition: ec2:MetadataHttpTokens = required
}}

# Additional: SCP to deny IMDSv1 org-wide
# resource "aws_organizations_policy" "deny_imdsv1" {{
#   name    = "DenyIMDSv1"
#   content = jsonencode({{
#     Version   = "2012-10-17"
#     Statement = [{{
#       Sid      = "DenyIMDSv1"
#       Effect   = "Deny"
#       Action   = "ec2:RunInstances"
#       Resource = "arn:aws:ec2:*:*:instance/*"
#       Condition = {{
#         StringNotEquals = {{
#           "ec2:MetadataHttpTokens" = "required"
#         }}
#       }}
#     }}]
#   }})
# }}
"""
        return RemediationResult(
            vulnerability_remediated=(
                "IMDSv1 exposure / hop-limit > 1 on AWS EC2 metadata endpoint"
            ),
            artifact_type="terraform_hcl",
            code_snippet=snippet,
            notes=(
                "Apply 'terraform apply' after review. "
                "Also enforce via AWS SCP at the Organization level to prevent "
                "future IMDSv1-enabled instance launches."
            ),
        )
