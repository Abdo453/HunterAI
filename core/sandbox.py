"""
صندوق الرمل (Sandbox) — مرحلة G + Phase 4 Hardening.
====================================================
Adapted Docker worker capability allowlist and startup isolation probe from
PentAGI ``backend/pkg/docker/worker_spec.go`` & ``sandbox.go`` (commit ``cffed94``, MIT License).

ضوابط أمنية:
- لا تُمرر سلسلة أوامر shell — تُستخدم مصفوفات وسيطات (argv) فقط.
- دليل عمل مقيد (working directory) لمنع الوصول للملفات خارجه.
- متغيرات بيئة محدودة (متوافقة مع Linux و Windows) دون تسريب الأسرار.
- في ``DockerSandbox``:
  * ``CapDrop: ["ALL"]`` + قائمة ``CapAdd`` صريحة (لا ``SYS_ADMIN`` ولا ``SYS_MODULE`` ولا ``MKNOD``)
  * ``security_opt=["no-new-privileges:true"]`` و ``pids_limit`` و ``read_only=True``
  * قائمة صور مسموح بها عبر ``DOCKER_ALLOWED_IMAGES``
  * منع مطلق لـ ``network_mode="host"`` أو ربط ``docker.sock`` أو الجذر ``/``
  * تنفيذ غير حاجز عبر ``asyncio.to_thread`` ودعم حاوية مخصصة لكل engagement وفحص عزل عند البدء
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

logger = logging.getLogger(__name__)


# Explicit PentAGI MIT worker capability allowlist (Docker default 14 minus MKNOD + SYS_PTRACE).
# NEVER add SYS_ADMIN, SYS_MODULE, SYS_RAWIO, or SYS_BOOT.
BASE_WORKER_CAPABILITIES: Tuple[str, ...] = (
    "CHOWN",
    "DAC_OVERRIDE",
    "FSETID",
    "FOWNER",
    "NET_RAW",
    "SETGID",
    "SETUID",
    "SETFCAP",
    "SETPCAP",
    "NET_BIND_SERVICE",
    "SYS_CHROOT",
    "KILL",
    "AUDIT_WRITE",
    "SYS_PTRACE",
)

FORBIDDEN_CAPABILITIES: Set[str] = {
    "SYS_ADMIN",
    "SYS_MODULE",
    "SYS_RAWIO",
    "SYS_BOOT",
    "MKNOD",
    "ALL",
}

FORBIDDEN_NETWORK_MODES: Set[str] = {"host"}

DEFAULT_ALLOWED_DOCKER_IMAGES: Tuple[str, ...] = (
    "hunterai-worker:kali",
    "hunterai-worker:latest",
    "kalilinux/kali-rolling",
    "python:3.11-slim",
    "python:3.12-slim",
    "alpine:latest",
)

DEFAULT_PIDS_LIMIT = 256
MAX_SANDBOX_REPORT_BYTES = 256 * 1024


def worker_capabilities(*, docker_net_admin: bool = False) -> List[str]:
    """Return explicit capability allowlist paired with ``CapDrop: ["ALL"]``."""
    caps = list(BASE_WORKER_CAPABILITIES)
    if docker_net_admin:
        caps.append("NET_ADMIN")
    return caps


def get_allowed_docker_images(explicit: Optional[Sequence[str]] = None) -> Set[str]:
    """Resolve allowed Docker images from explicit arg or ``DOCKER_ALLOWED_IMAGES`` env."""
    if explicit is not None:
        return {str(img).strip() for img in explicit if str(img).strip()}
    raw_env = os.getenv("DOCKER_ALLOWED_IMAGES", "").strip()
    if raw_env:
        return {item.strip() for item in raw_env.split(",") if item.strip()}
    return set(DEFAULT_ALLOWED_DOCKER_IMAGES)


def validate_docker_mounts(volumes: Optional[Dict[str, Any]]) -> None:
    """Reject any bind mount referencing ``docker.sock``, Docker named pipe, or host root."""
    if not volumes:
        return
    for host_path in volumes.keys():
        norm = str(host_path).strip().lower().replace("\\", "/")
        if (
            "docker.sock" in norm
            or "docker_engine" in norm
            or norm in ("/", "/etc", "/proc", "/sys", "/dev", "/var/run", "c:/", "c:")
        ):
            raise PermissionError(
                f"Forbidden Docker volume mount rejected (container escape vector): {host_path!r}"
            )


@dataclass
class SandboxProbeReport:
    """Parsed JSONL report from startup sandbox isolation verification."""
    daemon_id: str = ""
    authz: List[str] = field(default_factory=list)
    total: int = 0
    passed: int = 0
    failed: List[str] = field(default_factory=list)
    ok: bool = False
    error: Optional[str] = None


def parse_sandbox_report(raw_output: str | bytes) -> SandboxProbeReport:
    """Parse JSONL lines emitted by a sandbox isolation probe (fail-closed on non-JSON)."""
    text = raw_output.decode("utf-8", errors="replace") if isinstance(raw_output, bytes) else str(raw_output)
    if len(text.encode("utf-8", errors="replace")) > MAX_SANDBOX_REPORT_BYTES:
        raise ValueError(f"Sandbox probe report exceeded {MAX_SANDBOX_REPORT_BYTES} bytes")

    report = SandboxProbeReport()
    saw_info = False
    saw_summary = False

    for raw_line in text.strip().splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Probe emitted non-JSON line: {exc}") from exc
        if not isinstance(obj, dict):
            raise ValueError("Probe JSON line must be an object")

        kind = obj.get("kind")
        if kind == "fatal":
            raise ValueError(f"Probe fatal error: {obj.get('reason', 'unknown')}")
        elif kind == "info":
            body = obj.get("body") or {}
            report.daemon_id = str(body.get("ID") or "")
            plugins = body.get("Plugins") or {}
            report.authz = list(plugins.get("Authorization") or [])
            saw_info = True
        elif kind == "check":
            if obj.get("result") != "pass":
                group = str(obj.get("group") or "unknown")
                cid = str(obj.get("id") or "unknown")
                report.failed.append(f"{group}/{cid}")
        elif kind == "summary":
            report.total = int(obj.get("total") or 0)
            report.passed = int(obj.get("passed") or 0)
            saw_summary = True

    if not saw_info:
        raise ValueError("Probe did not report daemon info")
    if not saw_summary:
        raise ValueError("Probe did not emit summary")
    if not report.daemon_id:
        raise ValueError("Sandbox daemon reported no identity")

    report.ok = len(report.failed) == 0
    return report


@dataclass
class SandboxResult:
    ok: bool
    command: List[str]
    stdout: str = ""
    stderr: str = ""
    exit_code: Optional[int] = None
    duration_s: float = 0.0
    error: Optional[str] = None
    error_category: Optional[str] = None
    artefact_reference: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class Sandbox(ABC):
    """واجهة صندوق الرمل — كل تنفيذ أمان يُمرر عبر هذه الواجهة."""

    @abstractmethod
    async def run(
        self,
        command: List[str],
        *,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        timeout_s: float = 60.0,
        max_output_bytes: int = 1_000_000,
    ) -> SandboxResult:
        """تنفيذ أمر كمصفوفة وسيطات (لا shell string) في بيئة معزولة."""
        raise NotImplementedError

    @abstractmethod
    async def health_check(self) -> bool:
        """فحص ما إذا كان صندوق الرمل متاحاً."""
        raise NotImplementedError


class LocalSandbox(Sandbox):
    """
    صندوق رمل محلي يُنفذ الأوامر عبر asyncio.create_subprocess_exec (بلا shell).
    متوافق مع Linux و Windows.
    """

    _SAFE_ENV_VARS = {
        "PATH", "HOME", "USER", "LANG", "LC_ALL", "TMPDIR", "TEMP", "TMP",
        # Cross-platform Windows runtime essentials (required for Python/sockets/DNS/Go tools on Win32)
        "SYSTEMROOT", "COMSPEC", "PATHEXT", "WINDIR", "USERPROFILE", "APPDATA", "LOCALAPPDATA",
    }

    def __init__(
        self,
        *,
        allowed_workdir: Optional[str] = None,
        extra_env: Optional[Dict[str, str]] = None,
        default_timeout_s: float = 60.0,
    ):
        self.allowed_workdir = os.path.abspath(
            allowed_workdir or os.path.join("data", "sandbox_workdir")
        )
        os.makedirs(self.allowed_workdir, exist_ok=True)
        self.extra_env = dict(extra_env or {})
        self.default_timeout_s = default_timeout_s

    def _resolve_cwd(self, cwd: Optional[str]) -> str:
        """يضمن أن دليل العمل داخل الدليل المسموح (fail-closed)."""
        target = os.path.abspath(cwd or self.allowed_workdir)
        allowed = os.path.abspath(self.allowed_workdir)
        if not (target == allowed or target.startswith(allowed + os.sep)):
            raise PermissionError(f"دليل العمل خارج النطاق المسموح: {cwd}")
        return target

    def _build_env(self, env: Optional[Dict[str, str]]) -> Dict[str, str]:
        """بيئة محدودة: متغيرات آمنة من النظام + ما يُصرح به صراحةً فقط."""
        new_env: Dict[str, str] = {}
        # On Windows os.environ keys are case-insensitive; look up safely
        for var in self._SAFE_ENV_VARS:
            val = os.environ.get(var)
            if val:
                new_env[var] = val
        new_env.update(self.extra_env)
        if env:
            for key, val in env.items():
                kl = key.lower()
                if any(s in kl for s in ("secret", "key", "token", "password", "api_", "credential")):
                    continue
                new_env[key] = val
        return new_env

    async def run(
        self,
        command: List[str],
        *,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        timeout_s: float = 60.0,
        max_output_bytes: int = 1_000_000,
    ) -> SandboxResult:
        if not command:
            return SandboxResult(
                ok=False, command=[], error="أمر فارغ",
                error_category="VALIDATION")
        exe = command[0]
        if not shutil.which(exe) and not os.path.isabs(exe):
            return SandboxResult(
                ok=False, command=command,
                error=f"الملف التنفيذي غير موجود: {exe}",
                error_category="TOOL_UNAVAILABLE")

        resolved_cwd = self._resolve_cwd(cwd)
        sandbox_env = self._build_env(env)
        start = time.time()

        try:
            proc = await asyncio.create_subprocess_exec(
                *command,
                cwd=resolved_cwd,
                env=sandbox_env,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except Exception as exc:  # noqa: BLE001
            return SandboxResult(
                ok=False, command=command,
                error=str(exc), error_category="EXECUTION_ERROR",
                metadata={"duration_s": time.time() - start})

        try:
            out, err = await asyncio.wait_for(
                proc.communicate(), timeout=timeout_s)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            dur = time.time() - start
            return SandboxResult(
                ok=False, command=command,
                error=f"انتهت المهلة بعد {timeout_s}s",
                error_category="TIMEOUT",
                duration_s=dur,
                metadata={"cwd": resolved_cwd, "timeout_s": timeout_s})

        dur = time.time() - start
        stdout_limited = out[:max_output_bytes] if out else b""
        stderr_limited = err[:max_output_bytes] if err else b""
        if len(out or b"") > max_output_bytes:
            stdout_limited += b"\n...[output truncated]..."
        if len(err or b"") > max_output_bytes:
            stderr_limited += b"\n...[output truncated]..."

        ret = proc.returncode or 0
        return SandboxResult(
            ok=(ret == 0),
            command=command,
            stdout=stdout_limited.decode("utf-8", errors="replace"),
            stderr=stderr_limited.decode("utf-8", errors="replace"),
            exit_code=ret,
            duration_s=round(dur, 3),
            error=stderr_limited.decode("utf-8", errors="replace") if ret != 0 else None,
            error_category=("NONZERO_EXIT" if ret != 0 else None),
            metadata={
                "cwd": resolved_cwd,
                "timeout_s": timeout_s,
                "max_output_bytes": max_output_bytes,
            },
        )

    async def health_check(self) -> bool:
        try:
            result = await self.run(
                [shutil.which("python") or "python", "-c", "print('ok')"],
                timeout_s=10.0,
                max_output_bytes=64,
            )
            return result.ok
        except Exception:  # noqa: BLE001
            return False


class DockerSandbox(Sandbox):
    """
    Hardened, non-blocking Docker sandbox (adapted from PentAGI MIT ``worker_spec.go``
    and ``sandbox.go``).

    Invariants:
    - NEVER mounts host ``docker.sock`` or root filesystem.
    - NEVER allows ``network_mode="host"``.
    - Always applies ``cap_drop=["ALL"]``, explicit ``cap_add`` allowlist,
      ``security_opt=["no-new-privileges:true"]``, ``pids_limit``, and ``read_only=True``.
    - Enforces ``DOCKER_ALLOWED_IMAGES`` allowlist.
    - Offloads all blocking Docker SDK calls via ``asyncio.to_thread``.
    - Supports persistent container-per-engagement lifecycle + startup isolation probe.
    """

    def __init__(
        self,
        *,
        image: str = "hunterai-worker:kali",
        allowed_workdir: Optional[str] = None,
        network_mode: str = "none",
        default_timeout_s: float = 300.0,
        docker_client: Optional[Any] = None,
        allowed_images: Optional[Sequence[str]] = None,
        pids_limit: int = DEFAULT_PIDS_LIMIT,
        mem_limit: str = "512m",
        docker_net_admin: bool = False,
        volumes: Optional[Dict[str, Any]] = None,
    ):
        net_clean = (network_mode or "none").strip().lower()
        if net_clean in FORBIDDEN_NETWORK_MODES:
            raise PermissionError(
                f"DockerSandbox forbids network_mode={network_mode!r} (host network isolation invariant)"
            )
        validate_docker_mounts(volumes)

        self.image = image
        self.allowed_workdir = allowed_workdir or "/worker"
        self.network_mode = network_mode
        self.default_timeout_s = default_timeout_s
        self._docker = docker_client
        self.allowed_images = get_allowed_docker_images(allowed_images)
        self.pids_limit = max(16, int(pids_limit))
        self.mem_limit = mem_limit
        self.docker_net_admin = bool(docker_net_admin)
        self.volumes = dict(volumes or {})
        self._engagement_containers: Dict[str, Any] = {}

    def _validate_image(self, image: str) -> None:
        if self.allowed_images and image not in self.allowed_images:
            raise PermissionError(
                f"Docker image {image!r} is not in DOCKER_ALLOWED_IMAGES allowlist"
            )

    def build_container_kwargs(
        self,
        *,
        command: Optional[List[str]] = None,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        volumes: Optional[Dict[str, Any]] = None,
        name: Optional[str] = None,
        entrypoint: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Construct hardened Docker container run parameters (single source of truth)."""
        if (self.network_mode or "").strip().lower() in FORBIDDEN_NETWORK_MODES:
            raise PermissionError("DockerSandbox forbids network_mode='host'")
        merged_volumes = dict(self.volumes)
        if volumes:
            merged_volumes.update(volumes)
        validate_docker_mounts(merged_volumes)

        caps = worker_capabilities(docker_net_admin=self.docker_net_admin)
        kwargs: Dict[str, Any] = {
            "working_dir": cwd or self.allowed_workdir,
            "environment": dict(env or {}),
            "network_mode": self.network_mode,
            "detach": True,
            "mem_limit": self.mem_limit,
            "pids_limit": self.pids_limit,
            "read_only": True,
            "cap_drop": ["ALL"],
            "cap_add": caps,
            "security_opt": ["no-new-privileges:true"],
            "tmpfs": {"/tmp": "noexec,nosuid,size=100m"},
        }
        if command is not None:
            kwargs["command"] = command
        if entrypoint is not None:
            kwargs["entrypoint"] = entrypoint
        if merged_volumes:
            kwargs["volumes"] = merged_volumes
        if name:
            kwargs["name"] = name
        return kwargs

    def _get_client(self):
        if self._docker is not None:
            return self._docker
        try:
            import docker  # type: ignore
            return docker.from_env()
        except ImportError:
            raise RuntimeError(
                "حزمة 'docker' غير مثبتة. ثبتّها للتشغيل على الخادم."
            )

    def _run_sync(
        self,
        client: Any,
        command: List[str],
        *,
        cwd: Optional[str],
        env: Optional[Dict[str, str]],
        timeout_s: float,
        max_output_bytes: int,
        start: float,
    ) -> SandboxResult:
        kwargs = self.build_container_kwargs(command=command, cwd=cwd, env=env)
        container = None
        try:
            container = client.containers.run(self.image, **kwargs)
            try:
                result = container.wait(timeout=timeout_s)
            except Exception:
                try:
                    container.kill()
                except Exception:
                    pass
                result = {"StatusCode": -1}

            logs = container.logs(stdout=True, stderr=True)
            if isinstance(logs, bytes):
                stdout = logs.decode("utf-8", errors="replace")[:max_output_bytes]
            else:
                stdout = str(logs)[:max_output_bytes]
            ret = int(result.get("StatusCode", -1)) if isinstance(result, dict) else -1
            return SandboxResult(
                ok=(ret == 0),
                command=command,
                stdout=stdout,
                exit_code=ret,
                duration_s=round(time.time() - start, 3),
                artefact_reference=getattr(container, "id", None),
                metadata={
                    "image": self.image,
                    "container": getattr(container, "id", None),
                    "cap_drop": kwargs["cap_drop"],
                    "security_opt": kwargs["security_opt"],
                    "pids_limit": kwargs["pids_limit"],
                },
            )
        finally:
            if container is not None:
                try:
                    container.remove(force=True)
                except Exception:  # noqa: BLE001
                    pass

    async def run(
        self,
        command: List[str],
        *,
        cwd: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        timeout_s: float = 60.0,
        max_output_bytes: int = 1_000_000,
    ) -> SandboxResult:
        start = time.time()
        try:
            client = await asyncio.to_thread(self._get_client)
        except Exception as exc:  # noqa: BLE001
            return SandboxResult(
                ok=False, command=command,
                error=str(exc), error_category="SANDBOX_UNAVAILABLE",
                metadata={"duration_s": time.time() - start})

        try:
            self._validate_image(self.image)
        except PermissionError as exc:
            return SandboxResult(
                ok=False, command=command,
                error=str(exc), error_category="POLICY_DENIED",
                metadata={"duration_s": time.time() - start})

        try:
            return await asyncio.to_thread(
                self._run_sync,
                client,
                command,
                cwd=cwd,
                env=env,
                timeout_s=timeout_s,
                max_output_bytes=max_output_bytes,
                start=start,
            )
        except PermissionError as exc:
            return SandboxResult(
                ok=False, command=command,
                error=str(exc), error_category="POLICY_DENIED",
                metadata={"duration_s": time.time() - start})
        except Exception as exc:  # noqa: BLE001
            return SandboxResult(
                ok=False, command=command,
                error=str(exc), error_category="EXECUTION_ERROR",
                metadata={"duration_s": time.time() - start})

    # ── Container-per-engagement lifecycle (non-blocking via asyncio.to_thread) ──

    async def start_engagement_container(
        self,
        engagement_id: str,
        *,
        env: Optional[Dict[str, str]] = None,
    ) -> str:
        """Start (or reuse) an isolated persistent worker container for ``engagement_id``."""
        if engagement_id in self._engagement_containers:
            return str(getattr(self._engagement_containers[engagement_id], "id", engagement_id))

        client = await asyncio.to_thread(self._get_client)
        self._validate_image(self.image)
        safe_name = f"hunterai-eng-{engagement_id[:24]}-{uuid.uuid4().hex[:6]}"
        kwargs = self.build_container_kwargs(
            entrypoint=["tail", "-f", "/dev/null"],
            env=env,
            name=safe_name,
        )
        container = await asyncio.to_thread(client.containers.run, self.image, **kwargs)
        self._engagement_containers[engagement_id] = container
        return str(getattr(container, "id", safe_name))

    async def exec_in_engagement(
        self,
        engagement_id: str,
        command: List[str],
        *,
        cwd: Optional[str] = None,
        max_output_bytes: int = 1_000_000,
    ) -> SandboxResult:
        """Execute an argv command inside an engagement's isolated worker container."""
        start = time.time()
        container = self._engagement_containers.get(engagement_id)
        if container is None:
            try:
                await self.start_engagement_container(engagement_id)
                container = self._engagement_containers[engagement_id]
            except PermissionError as exc:
                return SandboxResult(ok=False, command=command, error=str(exc), error_category="POLICY_DENIED")
            except Exception as exc:
                return SandboxResult(ok=False, command=command, error=str(exc), error_category="SANDBOX_UNAVAILABLE")

        try:
            exec_res = await asyncio.to_thread(
                container.exec_run,
                command,
                workdir=cwd or self.allowed_workdir,
                demux=True,
            )
            exit_code = int(getattr(exec_res, "exit_code", 0) or 0)
            output = getattr(exec_res, "output", (b"", b""))
            if isinstance(output, tuple) and len(output) == 2:
                raw_out, raw_err = output[0] or b"", output[1] or b""
            else:
                raw_out, raw_err = (output or b""), b""
            stdout = (raw_out.decode("utf-8", errors="replace") if isinstance(raw_out, bytes) else str(raw_out))[:max_output_bytes]
            stderr = (raw_err.decode("utf-8", errors="replace") if isinstance(raw_err, bytes) else str(raw_err))[:max_output_bytes]
            return SandboxResult(
                ok=(exit_code == 0),
                command=command,
                stdout=stdout,
                stderr=stderr,
                exit_code=exit_code,
                duration_s=round(time.time() - start, 3),
                artefact_reference=getattr(container, "id", None),
                metadata={"engagement_id": engagement_id, "image": self.image},
            )
        except Exception as exc:
            return SandboxResult(
                ok=False,
                command=command,
                error=str(exc),
                error_category="EXECUTION_ERROR",
                duration_s=round(time.time() - start, 3),
            )

    async def stop_engagement_container(self, engagement_id: str) -> bool:
        """Stop and remove the engagement's worker container."""
        container = self._engagement_containers.pop(engagement_id, None)
        if container is None:
            return False
        try:
            await asyncio.to_thread(container.remove, force=True)
            return True
        except Exception:  # noqa: BLE001
            return False

    async def probe_sandbox(self) -> SandboxProbeReport:
        """Startup sandbox probe verifying isolation invariants (never mounts docker.sock or host net)."""
        probe_cmd = [
            "python3", "-c",
            (
                "import json, os; "
                "print(json.dumps({'kind':'info','body':{'ID':os.uname().nodename,'Plugins':{'Authorization':[]}}})); "
                "print(json.dumps({'kind':'check','id':'no-docker-sock','group':'isolation','expect':'deny','result':'pass' if not os.path.exists('/var/run/docker.sock') else 'fail'})); "
                "print(json.dumps({'kind':'summary','total':1,'passed':0 if os.path.exists('/var/run/docker.sock') else 1,'failed':1 if os.path.exists('/var/run/docker.sock') else 0}))"
            ),
        ]
        res = await self.run(probe_cmd, timeout_s=15.0, max_output_bytes=MAX_SANDBOX_REPORT_BYTES)
        if not res.ok:
            return SandboxProbeReport(ok=False, error=res.error or res.error_category or "probe failed")
        try:
            return parse_sandbox_report(res.stdout)
        except Exception as exc:
            return SandboxProbeReport(ok=False, error=str(exc))

    async def health_check(self) -> bool:
        try:
            res = await self.run(
                ["python", "-c", "print('ok')"],
                timeout_s=15.0,
                max_output_bytes=128,
            )
            return res.ok
        except Exception:  # noqa: BLE001
            return False
