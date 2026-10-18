"""
Tests for the TLS audit and SMB/AD enumeration Skills (skills/).
===============================================================
كل الاختبارات Offline — لا أدوات حقيقية ولا شبكة.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pytest

from core.skill_registry import SkillRegistry
from skills.analysis.tls_audit.skill import TlsAuditSkill
from skills.base_skill import SkillContext
from skills.recon.smb_enum.skill import SmbEnumSkill


# ════════════════════════════════════════════════════════════════════════════
# Fakes
# ════════════════════════════════════════════════════════════════════════════

class FakeToolResult:
    def __init__(self, stdout: str = "", stderr: str = "", returncode: int = 0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode

    @property
    def output(self) -> str:
        return self.stdout or self.stderr


class FakeToolManager:
    def __init__(self, available: Optional[set] = None,
                 responses: Optional[List[Tuple[str, str]]] = None):
        self._available = set(available or set())
        self._responses = responses or []

    def is_available(self, name: str) -> bool:
        return name in self._available

    def resolve_binary(self, name: str) -> str:
        return name

    def _match(self, cmd: str) -> str:
        for needle, out in self._responses:
            if needle in cmd:
                return out
        return ""

    async def execute(self, command: Any, *args: Any, timeout: int = 300, **kwargs: Any) -> FakeToolResult:
        cmd = command if isinstance(command, str) else " ".join(str(c) for c in command)
        return FakeToolResult(stdout=self._match(cmd))


class FakeWorkspace:
    def __init__(self, root: Path):
        self.root = root
        self.logs: List[str] = []

    def get_workspace_path(self, target: str, session_id: str = "") -> Path:
        safe = target.replace("://", "_").replace("/", "_").replace(":", "_")
        p = self.root / "workspaces" / safe / session_id
        p.mkdir(parents=True, exist_ok=True)
        return p

    def write_file(self, target: str, category: str, filename: str, content: str, session_id: str) -> Path:
        p = self.get_workspace_path(target, session_id) / category / filename
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return p

    def append_log(self, target: str, session_id: str, message: str) -> None:
        self.logs.append(message)


def _ctx(tmp_path: Path, tm: FakeToolManager, target: str = "10.0.0.5") -> SkillContext:
    return SkillContext(
        target=target,
        session_id="sess_test",
        workspace=FakeWorkspace(tmp_path),
        tool_manager=tm,
    )


# ════════════════════════════════════════════════════════════════════════════
# Registry discovery + DAG wiring
# ════════════════════════════════════════════════════════════════════════════

def test_new_skills_discovered_with_correct_categories():
    registry = SkillRegistry()
    registry.discover(force=True)
    names = registry.list_names()
    assert "tls_audit" in names
    assert "smb_enum" in names

    tls = registry.instantiate("tls_audit")
    assert tls is not None and tls.category == "analysis"
    smb = registry.instantiate("smb_enum")
    assert smb is not None and smb.category == "recon"


def test_dag_wiring_unlocks_service_audits():
    registry = SkillRegistry()
    registry.discover(force=True)
    unlocked_by_portscan = {m.name for m in registry.get_skills_unlocked_by("port_scan")}
    assert {"ssh_audit", "tls_audit", "smb_enum"}.issubset(unlocked_by_portscan)

    unlocked_by_tech = {m.name for m in registry.get_skills_unlocked_by("tech_detection")}
    assert "waf_detection" in unlocked_by_tech


# ════════════════════════════════════════════════════════════════════════════
# TLS audit skill
# ════════════════════════════════════════════════════════════════════════════

TESTSSL_OUT = """ SSLv2      not offered (OK)
 SSLv3      not offered (OK)
 TLS 1      offered (deprecated)
 TLS 1.1    offered (deprecated)
 TLS 1.2    offered (OK)
 TLS 1.3    offered (OK)
 Heartbleed (CVE-2014-0160)                not vulnerable (OK)
 CCS (CVE-2014-0224)                       VULNERABLE
"""

SSLSCAN_OUT = """  SSL/TLS Protocols:
SSLv3     disabled
TLSv1.0   enabled
TLSv1.1   disabled
TLSv1.2   enabled
TLSv1.3   enabled

  Supported Server Cipher(s):
Preferred TLSv1.3  128 bits  TLS_AES_128_GCM_SHA256
Accepted  TLSv1.2  112 bits  DES-CBC3-SHA
"""

OPENSSL_OUT = """CONNECTED(00000003)
---
Protocol version: TLSv1.0
Ciphersuite: DES-CBC3-SHA
Verification: OK
"""


@pytest.mark.asyncio
async def test_tls_audit_with_testssl(tmp_path):
    tm = FakeToolManager(available={"testssl.sh"}, responses=[("testssl.sh", TESTSSL_OUT)])
    ctx = _ctx(tmp_path, tm)
    res = await TlsAuditSkill().run(ctx)

    assert res.success is True
    assert res.tool_used == "testssl.sh"
    kinds = [f["title"] for f in res.findings]
    assert any("obsolete protocol" in k.lower() and "tls 1" in k.lower() for k in kinds)
    assert any("vulnerability" in k.lower() for k in kinds)
    # لا تُصنّف TLS 1.2/1.3 كبروتوكولات مهجورة
    assert not any("tls 1.2" in k.lower() or "tls 1.3" in k.lower() for k in kinds)
    assert all(f["status"] == "candidate" and f["evidence_level"] == "E0" for f in res.findings)
    assert "tls_audit.txt" in res.output_files
    assert "tls_audit_findings.json" in res.output_files


@pytest.mark.asyncio
async def test_tls_audit_with_sslscan(tmp_path):
    tm = FakeToolManager(available={"sslscan"}, responses=[("sslscan", SSLSCAN_OUT)])
    ctx = _ctx(tmp_path, tm)
    res = await TlsAuditSkill().run(ctx)

    assert res.tool_used == "sslscan"
    kinds = [f["title"] for f in res.findings]
    assert any("tlsv1.0" in k.lower() for k in kinds)
    assert any("weak tls cipher" in k.lower() for k in kinds)
    payload = json.loads(Path(res.output_files["tls_audit_findings.json"]).read_text(encoding="utf-8"))
    assert len(payload) == 2


@pytest.mark.asyncio
async def test_tls_audit_with_openssl(tmp_path):
    tm = FakeToolManager(available={"openssl"}, responses=[("openssl s_client", OPENSSL_OUT)])
    ctx = _ctx(tmp_path, tm)
    res = await TlsAuditSkill().run(ctx)

    assert res.tool_used == "openssl"
    kinds = [f["title"].lower() for f in res.findings]
    assert any("obsolete protocol" in k for k in kinds)
    assert any("weak tls cipher" in k for k in kinds)


@pytest.mark.asyncio
async def test_tls_audit_no_tool(tmp_path):
    tm = FakeToolManager(available=set(), responses=[])
    res = await TlsAuditSkill().run(_ctx(tmp_path, tm))
    assert res.success is False
    assert any("No TLS auditing tool" in e for e in res.errors)


# ════════════════════════════════════════════════════════════════════════════
# SMB enumeration skill
# ════════════════════════════════════════════════════════════════════════════

NETEXEC_OUT = """SMB         10.0.0.5        445    DC01             [*] Windows Server 2019 Build 17763 x64 (name:DC01) (domain:corp.local) (signing:False) (SMBv1:True)
SMB         10.0.0.5        445    DC01             [+] corp.local\\:
SMB         10.0.0.5        445    DC01             [*] Enumerated shares
SMB         10.0.0.5        445    DC01             Share           Permissions     Remark
SMB         10.0.0.5        445    DC01             -----           -----------     ------
SMB         10.0.0.5        445    DC01             ADMIN$                          Remote Admin
SMB         10.0.0.5        445    DC01             C$                              Default share
SMB         10.0.0.5        445    DC01             IPC$                            Remote IPC
SMB         10.0.0.5        445    DC01             Users           READ
"""

ENUM4LINUX_OUT = """Target ........... 10.0.0.5
[+] Domain: CORP
[+] Domain SID: S-1-5-21-1234
[+] Getting OS info
[+] Share Enumeration
\tSharename       Type      Comment
\t---------       ----      -------
\tADMIN$          Disk      Remote Admin
\tIPC$            IPC       Remote IPC
\tPublic          Disk
"""

SMBCLIENT_OUT = """\tSharename       Type      Comment
\t---------       ----      -------
\tADMIN$          Disk      Remote Admin
\tIPC$            IPC       Remote IPC
"""


@pytest.mark.asyncio
async def test_smb_enum_with_netexec(tmp_path):
    tm = FakeToolManager(available={"netexec"}, responses=[("netexec smb", NETEXEC_OUT)])
    ctx = _ctx(tmp_path, tm)
    res = await SmbEnumSkill().run(ctx)

    assert res.success is True
    assert res.tool_used == "netexec"
    titles = [f["title"].lower() for f in res.findings]
    assert any("signing" in t for t in titles)
    assert any("smbv1" in t for t in titles)
    assert any("null" in t or "anonymous" in t for t in titles)
    assert all(f["status"] == "candidate" and f["evidence_level"] == "E0" for f in res.findings)

    payload = json.loads(Path(res.output_files["smb_enum_findings.json"]).read_text(encoding="utf-8"))
    assert "ADMIN$" in payload["shares"]
    assert "Users" in payload["shares"]
    assert any("corp.local" in d for d in payload["domain_info"])


@pytest.mark.asyncio
async def test_smb_enum_with_enum4linux(tmp_path):
    tm = FakeToolManager(available={"enum4linux-ng"}, responses=[("enum4linux-ng", ENUM4LINUX_OUT)])
    ctx = _ctx(tmp_path, tm)
    res = await SmbEnumSkill().run(ctx)

    assert res.tool_used == "enum4linux-ng"
    payload = json.loads(Path(res.output_files["smb_enum_findings.json"]).read_text(encoding="utf-8"))
    assert {"ADMIN$", "IPC$", "Public"}.issubset(set(payload["shares"]))
    assert any("CORP" in d for d in payload["domain_info"])


@pytest.mark.asyncio
async def test_smb_enum_with_smbclient(tmp_path):
    tm = FakeToolManager(available={"smbclient"}, responses=[("smbclient -N -L", SMBCLIENT_OUT)])
    ctx = _ctx(tmp_path, tm)
    res = await SmbEnumSkill().run(ctx)

    assert res.tool_used == "smbclient"
    payload = json.loads(Path(res.output_files["smb_enum_findings.json"]).read_text(encoding="utf-8"))
    assert {"ADMIN$", "IPC$"}.issubset(set(payload["shares"]))


@pytest.mark.asyncio
async def test_smb_enum_no_tool(tmp_path):
    tm = FakeToolManager(available=set(), responses=[])
    res = await SmbEnumSkill().run(_ctx(tmp_path, tm))
    assert res.success is False
    assert any("No SMB enumeration tool" in e for e in res.errors)


def test_builtin_contracts_include_new_skills():
    from core.skills.skill_contract import BUILTIN_CONTRACTS

    assert "tls_audit" in BUILTIN_CONTRACTS
    assert "smb_enum" in BUILTIN_CONTRACTS
    assert BUILTIN_CONTRACTS["tls_audit"].validate_inputs({"target_domain": "10.0.0.5"})
