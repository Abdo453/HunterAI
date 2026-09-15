"""
HunterAI V14.0 — Container Security & Breakout Auditor
=======================================================
Performs STATIC inspection of Dockerfiles, docker-compose YAML, and
Kubernetes manifests to detect container escape / privilege escalation
misconfiguration patterns.

Detection patterns:
    - docker.sock mount          (container → host socket escape)
    - privileged: true           (full host kernel access)
    - CAP_SYS_ADMIN              (near-privileged; ns/cgroup escapes)
    - hostPID / hostNetwork / hostIPC  (host namespace sharing)
    - Running as root            (UID 0 or no USER directive in Dockerfile)
    - writable /proc / /sys mounts
    - SYS_PTRACE capability      (process injection)
    - allowPrivilegeEscalation: true
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class ContainerRiskLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


class ContainerFindingCategory(str, Enum):
    SOCKET_ESCAPE          = "socket_escape"
    PRIVILEGED_MODE        = "privileged_mode"
    DANGEROUS_CAPABILITY   = "dangerous_capability"
    HOST_NAMESPACE         = "host_namespace"
    ROOT_USER              = "root_user"
    WRITABLE_SENSITIVE     = "writable_sensitive_mount"
    PRIVILEGE_ESCALATION   = "privilege_escalation"


@dataclass
class ContainerBreakoutFinding:
    check_id:    str
    category:    ContainerFindingCategory
    description: str
    evidence:    str
    risk_level:  ContainerRiskLevel
    remediation: str
    line_number: Optional[int] = None


# ─── Detection Patterns ───────────────────────────────────────────────────────

_SOCKET_MOUNT_RE      = re.compile(r"docker\.sock", re.IGNORECASE)
_PRIVILEGED_RE        = re.compile(r"privileged\s*:\s*true", re.IGNORECASE)
_CAP_SYS_ADMIN_RE     = re.compile(r"CAP_SYS_ADMIN", re.IGNORECASE)
_CAP_SYS_PTRACE_RE    = re.compile(r"CAP_SYS_PTRACE|SYS_PTRACE", re.IGNORECASE)
_HOST_PID_RE          = re.compile(r"hostPID\s*:\s*true", re.IGNORECASE)
_HOST_NET_RE          = re.compile(r"hostNetwork\s*:\s*true", re.IGNORECASE)
_HOST_IPC_RE          = re.compile(r"hostIPC\s*:\s*true", re.IGNORECASE)
_PRIV_ESC_RE          = re.compile(r"allowPrivilegeEscalation\s*:\s*true", re.IGNORECASE)
_USER_ROOT_RE         = re.compile(r"^\s*USER\s+(0|root)\s*$", re.MULTILINE | re.IGNORECASE)
_NO_USER_RE           = re.compile(r"FROM\s+\S+", re.IGNORECASE)   # used alongside USER check
_WRITABLE_PROC_RE     = re.compile(r"/proc\b.*?:rw|/sys\b.*?:rw", re.IGNORECASE)


# ─── Auditor ─────────────────────────────────────────────────────────────────

class ContainerSecurityAuditor:
    """
    Static auditor for container configurations.

    Usage::

        auditor = ContainerSecurityAuditor()

        # Audit a Dockerfile string
        findings = auditor.audit_dockerfile(dockerfile_content)

        # Audit a docker-compose.yml string
        findings = auditor.audit_compose_manifest(compose_yaml)

        # Audit a Kubernetes manifest YAML string
        findings = auditor.audit_k8s_manifest(k8s_yaml)
    """

    # ── Dockerfile ────────────────────────────────────────────────────────────

    def audit_dockerfile(self, content: str) -> List[ContainerBreakoutFinding]:
        """Inspect a Dockerfile string for container breakout misconfigurations."""
        findings: List[ContainerBreakoutFinding] = []
        lines = content.splitlines()

        has_user_directive = False
        user_is_root       = False

        for lineno, line in enumerate(lines, start=1):
            # USER 0 or USER root
            if _USER_ROOT_RE.match(line):
                has_user_directive = True
                user_is_root = True
                findings.append(ContainerBreakoutFinding(
                    check_id="DOCKER-001",
                    category=ContainerFindingCategory.ROOT_USER,
                    description=(
                        "Container process runs as root (UID 0). "
                        "A container escape gives the attacker host-root access."
                    ),
                    evidence=f"Line {lineno}: {line.strip()}",
                    risk_level=ContainerRiskLevel.HIGH,
                    remediation=(
                        "Add 'RUN useradd -u 1000 appuser && USER appuser' "
                        "before the CMD/ENTRYPOINT instruction."
                    ),
                    line_number=lineno,
                ))
            elif re.match(r"^\s*USER\s+", line, re.IGNORECASE):
                has_user_directive = True

            # docker.sock mount in RUN / COPY / VOLUME
            if _SOCKET_MOUNT_RE.search(line):
                findings.append(ContainerBreakoutFinding(
                    check_id="DOCKER-002",
                    category=ContainerFindingCategory.SOCKET_ESCAPE,
                    description=(
                        "Docker socket (/var/run/docker.sock) referenced in Dockerfile. "
                        "Mounting the Docker socket grants full host root access."
                    ),
                    evidence=f"Line {lineno}: {line.strip()}",
                    risk_level=ContainerRiskLevel.CRITICAL,
                    remediation=(
                        "Remove the docker.sock reference. "
                        "Use Docker-in-Docker (dind) sidecar or Kaniko for CI builds."
                    ),
                    line_number=lineno,
                ))

        # No USER directive at all → image defaults to root
        if not has_user_directive and _NO_USER_RE.search(content):
            findings.append(ContainerBreakoutFinding(
                check_id="DOCKER-003",
                category=ContainerFindingCategory.ROOT_USER,
                description=(
                    "Dockerfile has no USER directive — container runs as root by default."
                ),
                evidence="No USER instruction found in Dockerfile.",
                risk_level=ContainerRiskLevel.HIGH,
                remediation=(
                    "Add 'RUN adduser -D appuser && USER appuser' before CMD."
                ),
            ))

        return findings

    # ── Docker Compose ────────────────────────────────────────────────────────

    def audit_compose_manifest(self, content: str) -> List[ContainerBreakoutFinding]:
        """Inspect a docker-compose YAML string for container breakout risks."""
        findings: List[ContainerBreakoutFinding] = []
        lines = content.splitlines()

        for lineno, line in enumerate(lines, start=1):
            if _SOCKET_MOUNT_RE.search(line):
                findings.append(ContainerBreakoutFinding(
                    check_id="COMPOSE-001",
                    category=ContainerFindingCategory.SOCKET_ESCAPE,
                    description=(
                        "Docker socket (/var/run/docker.sock) is mounted into the container. "
                        "Any process inside can control the Docker daemon and escape to host."
                    ),
                    evidence=f"Line {lineno}: {line.strip()}",
                    risk_level=ContainerRiskLevel.CRITICAL,
                    remediation=(
                        "Remove the docker.sock volume mount. "
                        "Use rootless Docker or Podman for daemon-free container builds."
                    ),
                    line_number=lineno,
                ))

            if _PRIVILEGED_RE.search(line):
                findings.append(ContainerBreakoutFinding(
                    check_id="COMPOSE-002",
                    category=ContainerFindingCategory.PRIVILEGED_MODE,
                    description=(
                        "privileged: true gives the container full access to host devices "
                        "and all Linux capabilities, equivalent to root on the host."
                    ),
                    evidence=f"Line {lineno}: {line.strip()}",
                    risk_level=ContainerRiskLevel.CRITICAL,
                    remediation=(
                        "Remove 'privileged: true'. "
                        "Drop all capabilities and add only specific ones needed: "
                        "'cap_drop: [ALL]' with 'cap_add: [NET_BIND_SERVICE]'."
                    ),
                    line_number=lineno,
                ))

            if _CAP_SYS_ADMIN_RE.search(line):
                findings.append(ContainerBreakoutFinding(
                    check_id="COMPOSE-003",
                    category=ContainerFindingCategory.DANGEROUS_CAPABILITY,
                    description=(
                        "CAP_SYS_ADMIN is granted. This capability enables namespace "
                        "creation, cgroup escapes, and direct filesystem manipulation."
                    ),
                    evidence=f"Line {lineno}: {line.strip()}",
                    risk_level=ContainerRiskLevel.HIGH,
                    remediation="Remove CAP_SYS_ADMIN from cap_add.",
                    line_number=lineno,
                ))

            if _WRITABLE_PROC_RE.search(line):
                findings.append(ContainerBreakoutFinding(
                    check_id="COMPOSE-004",
                    category=ContainerFindingCategory.WRITABLE_SENSITIVE,
                    description=(
                        "Writable /proc or /sys mount detected. "
                        "Attackers can modify kernel parameters or escape via procfs."
                    ),
                    evidence=f"Line {lineno}: {line.strip()}",
                    risk_level=ContainerRiskLevel.HIGH,
                    remediation="Mount /proc and /sys as read-only (ro).",
                    line_number=lineno,
                ))

        return findings

    # ── Kubernetes Manifest ───────────────────────────────────────────────────

    def audit_k8s_manifest(self, content: str) -> List[ContainerBreakoutFinding]:
        """Inspect a Kubernetes Pod/Deployment YAML string for security risks."""
        findings: List[ContainerBreakoutFinding] = []
        lines = content.splitlines()

        for lineno, line in enumerate(lines, start=1):
            if _SOCKET_MOUNT_RE.search(line):
                findings.append(ContainerBreakoutFinding(
                    check_id="K8S-001",
                    category=ContainerFindingCategory.SOCKET_ESCAPE,
                    description=(
                        "Docker socket (/var/run/docker.sock) is mounted in a K8s Pod. "
                        "This gives container-root full cluster control."
                    ),
                    evidence=f"Line {lineno}: {line.strip()}",
                    risk_level=ContainerRiskLevel.CRITICAL,
                    remediation=(
                        "Remove the hostPath /var/run/docker.sock volume. "
                        "Use containerd or CRI-O which don't expose a Docker socket."
                    ),
                    line_number=lineno,
                ))

            if _PRIVILEGED_RE.search(line):
                findings.append(ContainerBreakoutFinding(
                    check_id="K8S-002",
                    category=ContainerFindingCategory.PRIVILEGED_MODE,
                    description=(
                        "securityContext.privileged: true found. "
                        "Privileged pods bypass all Kubernetes security policies."
                    ),
                    evidence=f"Line {lineno}: {line.strip()}",
                    risk_level=ContainerRiskLevel.CRITICAL,
                    remediation=(
                        "Set 'privileged: false' and enforce PodSecurityStandards "
                        "'restricted' profile via the Kubernetes API admission controller."
                    ),
                    line_number=lineno,
                ))

            if _CAP_SYS_ADMIN_RE.search(line):
                findings.append(ContainerBreakoutFinding(
                    check_id="K8S-003",
                    category=ContainerFindingCategory.DANGEROUS_CAPABILITY,
                    description="CAP_SYS_ADMIN in K8s securityContext capabilities.add.",
                    evidence=f"Line {lineno}: {line.strip()}",
                    risk_level=ContainerRiskLevel.HIGH,
                    remediation=(
                        "Remove CAP_SYS_ADMIN. Use 'capabilities.drop: [ALL]' "
                        "in the container securityContext."
                    ),
                    line_number=lineno,
                ))

            if _CAP_SYS_PTRACE_RE.search(line):
                findings.append(ContainerBreakoutFinding(
                    check_id="K8S-004",
                    category=ContainerFindingCategory.DANGEROUS_CAPABILITY,
                    description=(
                        "SYS_PTRACE capability enables process injection into other "
                        "containers sharing the PID namespace."
                    ),
                    evidence=f"Line {lineno}: {line.strip()}",
                    risk_level=ContainerRiskLevel.HIGH,
                    remediation="Remove SYS_PTRACE unless required for a debugger sidecar.",
                    line_number=lineno,
                ))

            if _HOST_PID_RE.search(line):
                findings.append(ContainerBreakoutFinding(
                    check_id="K8S-005",
                    category=ContainerFindingCategory.HOST_NAMESPACE,
                    description=(
                        "hostPID: true shares the host PID namespace. "
                        "Container processes can see and signal all host processes."
                    ),
                    evidence=f"Line {lineno}: {line.strip()}",
                    risk_level=ContainerRiskLevel.HIGH,
                    remediation="Set 'hostPID: false' (the default).",
                    line_number=lineno,
                ))

            if _HOST_NET_RE.search(line):
                findings.append(ContainerBreakoutFinding(
                    check_id="K8S-006",
                    category=ContainerFindingCategory.HOST_NAMESPACE,
                    description=(
                        "hostNetwork: true shares the host network stack. "
                        "Container can sniff/spoof all node network traffic, "
                        "including cloud metadata traffic to 169.254.169.254."
                    ),
                    evidence=f"Line {lineno}: {line.strip()}",
                    risk_level=ContainerRiskLevel.HIGH,
                    remediation="Set 'hostNetwork: false' (the default).",
                    line_number=lineno,
                ))

            if _HOST_IPC_RE.search(line):
                findings.append(ContainerBreakoutFinding(
                    check_id="K8S-007",
                    category=ContainerFindingCategory.HOST_NAMESPACE,
                    description=(
                        "hostIPC: true shares the host IPC namespace. "
                        "Container can read/write shared memory used by other processes."
                    ),
                    evidence=f"Line {lineno}: {line.strip()}",
                    risk_level=ContainerRiskLevel.MEDIUM,
                    remediation="Set 'hostIPC: false' (the default).",
                    line_number=lineno,
                ))

            if _PRIV_ESC_RE.search(line):
                findings.append(ContainerBreakoutFinding(
                    check_id="K8S-008",
                    category=ContainerFindingCategory.PRIVILEGE_ESCALATION,
                    description=(
                        "allowPrivilegeEscalation: true permits setuid binaries "
                        "to gain elevated privileges inside the container."
                    ),
                    evidence=f"Line {lineno}: {line.strip()}",
                    risk_level=ContainerRiskLevel.HIGH,
                    remediation=(
                        "Set 'allowPrivilegeEscalation: false' in the container "
                        "securityContext to comply with PSS Restricted profile."
                    ),
                    line_number=lineno,
                ))

        return findings

    def summarise_findings(
        self, findings: List[ContainerBreakoutFinding]
    ) -> dict:
        """Return a risk summary dict for reporting."""
        counts = {r.value: 0 for r in ContainerRiskLevel}
        for f in findings:
            counts[f.risk_level.value] += 1
        return {
            "total": len(findings),
            "by_severity": counts,
            "highest_risk": (
                findings[0].risk_level.value if findings else "NONE"
            ),
        }
