"""
Tests for the new SSH audit and WAF detection Skills (skills/).
================================================================
كل الاختبارات Offline — لا أدوات حقيقية ولا شبكة (FakeToolManager + FakeWorkspace).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import pytest

from core.skill_registry import SkillRegistry
from skills.analysis.ssh_audit.skill import SshAuditSkill
from skills.base_skill import SkillContext
from skills.recon.waf_detection.skill import WafDetectionSkill


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
    """بديل حتمي لـ ToolManager: يعيد مخرجات جاهزة حسب أول تطابق للنص."""

    def __init__(
        self,
        available: Optional[set] = None,
        responses: Optional[List[Tuple[str, str]]] = None,
    ):
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
        self._files: Dict[str, Path] = {}

    def get_workspace_path(self, target: str, session_id: str = "") -> Path:
        safe = target.replace("://", "_").replace("/", "_").replace(":", "_")
        p = self.root / "workspaces" / safe / session_id
        p.mkdir(parents=True, exist_ok=True)
        return p

    def write_file(self, target: str, category: str, filename: str, content: str, session_id: str) -> Path:
        p = self.get_workspace_path(target, session_id) / category / filename
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        self._files[f"{category}/{filename}"] = p
        return p

    def append_log(self, target: str, session_id: str, message: str) -> None:
        self.logs.append(message)


def _ctx(tmp_path: Path, tm: FakeToolManager, target: str = "app.target.com") -> SkillContext:
    return SkillContext(
        target=target,
        session_id="sess_test",
        workspace=FakeWorkspace(tmp_path),
        tool_manager=tm,
    )


# ════════════════════════════════════════════════════════════════════════════
# Registry discovery
# ════════════════════════════════════════════════════════════════════════════

def test_new_skills_discovered_with_correct_categories():
    registry = SkillRegistry()
    registry.discover(force=True)
    names = registry.list_names()
    assert "waf_detection" in names
    assert "ssh_audit" in names

    waf = registry.instantiate("waf_detection")
    assert waf is not None
    assert waf.category == "recon"

    ssh = registry.instantiate("ssh_audit")
    assert ssh is not None
    assert ssh.category == "analysis"


# ════════════════════════════════════════════════════════════════════════════
# WAF detection skill
# ════════════════════════════════════════════════════════════════════════════

WAFW00F_HIT = (
    "\x1b[1;34m[+] The site http://app.target.com is behind Cloudflare "
    "(Cloudflare Inc.) WAF.\x1b[0m\n[-] Number of requests: 7"
)


@pytest.mark.asyncio
async def test_waf_detection_with_wafw00f(tmp_path):
    tm = FakeToolManager(
        available={"wafw00f"},
        responses=[("wafw00f http://app.target.com", WAFW00F_HIT)],
    )
    ctx = _ctx(tmp_path, tm)
    res = await WafDetectionSkill().run(ctx)

    assert res.success is True
    assert res.tool_used == "wafw00f"
    assert any("Cloudflare" in f["title"] for f in res.findings)
    # Creed: never auto-confirmed.
    assert all(f["status"] == "candidate" and f["evidence_level"] == "E0" for f in res.findings)
    assert "waf_detection.txt" in res.output_files
    assert "Cloudflare" in Path(res.output_files["waf_detection.txt"]).read_text(encoding="utf-8")


@pytest.mark.asyncio
async def test_waf_detection_heuristic_fallback(tmp_path):
    """بدون wafw00f: يكتشف Imperva من رأس Set-Cookie عبر curl."""
    tm = FakeToolManager(
        available={"curl"},
        responses=[(
            "curl -s -I",
            "HTTP/1.1 200 OK\r\nSet-Cookie: incap_ses_123=abc; path=/\r\nX-CDN: Incapsula\r\n",
        )],
    )
    ctx = _ctx(tmp_path, tm)
    res = await WafDetectionSkill().run(ctx)

    assert res.success is True
    assert res.tool_used == "curl"
    assert any("Imperva" in f["title"] for f in res.findings)


@pytest.mark.asyncio
async def test_waf_detection_none_detected(tmp_path):
    tm = FakeToolManager(
        available={"wafw00f"},
        responses=[("wafw00f", "[-] No WAF detected by the generic detection")],
    )
    ctx = _ctx(tmp_path, tm)
    res = await WafDetectionSkill().run(ctx)

    assert res.success is True
    assert any(f["title"].startswith("No WAF Detected") for f in res.findings)


@pytest.mark.asyncio
async def test_waf_detection_no_tool_output_fails(tmp_path):
    """لا توجد أدوات ولا مخرجات → فشل صريح وليس نجاحًا صامتًا."""
    tm = FakeToolManager(available=set(), responses=[])
    ctx = _ctx(tmp_path, tm)
    res = await WafDetectionSkill().run(ctx)
    assert res.success is False
    assert res.errors


# ════════════════════════════════════════════════════════════════════════════
# SSH audit skill
# ════════════════════════════════════════════════════════════════════════════

SSH_AUDIT_JSON = json.dumps({
    "banner": {"raw": "SSH-2.0-OpenSSH_7.4", "protocol": "2.0",
               "software": "OpenSSH_7.4", "comments": ""},
    "compression": [],
    "kex": [
        {"algorithm": "curve25519-sha256", "notes": {}},
        {"algorithm": "diffie-hellman-group1-sha1",
         "notes": {"fail": "removed (in server) since OpenSSH 6.9"}},
    ],
    "key": [
        {"algorithm": "ssh-ed25519", "notes": {}},
        {"algorithm": "ssh-rsa", "notes": {"warn": "using weak hashing algorithm"}},
    ],
    "enc": [
        {"algorithm": "chacha20-poly1305@openssh.com", "notes": {}},
        {"algorithm": "3des-cbc", "notes": {"fail": "removed (in server) since OpenSSH 7.6"}},
    ],
    "mac": [
        {"algorithm": "hmac-sha2-256", "notes": {}},
        {"algorithm": "hmac-md5", "notes": {"warn": "using weak MAC"}},
    ],
})

SSH_AUDIT_TEXT = (
    "(kex) diffie-hellman-group1-sha1 -- [fail] removed (in server) since OpenSSH 6.9\n"
    "(enc) 3des-cbc                    -- [warn] using weak cipher mode\n"
    "(kex) curve25519-sha256           -- [info] available since OpenSSH 7.4\n"
)

NMAP_ALGOS = """PORT   STATE SERVICE
22/tcp open  ssh
| ssh2-enum-algos:
|   kex_algorithms: (10)
|       curve25519-sha256
|       diffie-hellman-group1-sha1
|   encryption_algorithms: (9)
|       aes128-ctr
|       3des-cbc
|   mac_algorithms: (8)
|       hmac-sha2-256
|       hmac-md5
"""


@pytest.mark.asyncio
async def test_ssh_audit_json_parsing(tmp_path):
    tm = FakeToolManager(
        available={"ssh-audit"},
        responses=[("ssh-audit -j", SSH_AUDIT_JSON)],
    )
    ctx = _ctx(tmp_path, tm)
    res = await SshAuditSkill().run(ctx)

    assert res.success is True
    assert res.tool_used == "ssh-audit"

    # banner (Info) + 4 weak algorithms
    weak = [f for f in res.findings if f["type"] == "ssh_weak_algorithm"]
    assert len(weak) == 4, [f["title"] for f in res.findings]
    levels = sorted(f["severity"] for f in weak)
    assert levels == ["HIGH", "HIGH", "MEDIUM", "MEDIUM"]

    # candidate-only creed
    assert all(f["status"] == "candidate" and f["evidence_level"] == "E0" for f in res.findings)

    assert "ssh_audit.txt" in res.output_files
    assert "ssh_audit_findings.json" in res.output_files
    payload = json.loads(Path(res.output_files["ssh_audit_findings.json"]).read_text(encoding="utf-8"))
    assert len(payload) == 4


@pytest.mark.asyncio
async def test_ssh_audit_text_parsing_skips_info(tmp_path):
    """نص غير JSON: يُحلل fail/warn فقط وتُتجاهل ملاحظات info."""
    tm = FakeToolManager(
        available={"ssh-audit"},
        responses=[("ssh-audit -j", SSH_AUDIT_TEXT)],
    )
    ctx = _ctx(tmp_path, tm)
    res = await SshAuditSkill().run(ctx)

    assert res.success is True
    weak = [f for f in res.findings if f["type"] == "ssh_weak_algorithm"]
    assert len(weak) == 2
    algos = sorted(f["title"] for f in weak)
    assert any("diffie-hellman-group1-sha1" in t for t in algos)
    assert any("3des-cbc" in t for t in algos)


@pytest.mark.asyncio
async def test_ssh_audit_nmap_fallback(tmp_path):
    tm = FakeToolManager(
        available={"nmap"},
        responses=[("nmap -Pn", NMAP_ALGOS)],
    )
    ctx = _ctx(tmp_path, tm)
    res = await SshAuditSkill().run(ctx)

    assert res.success is True
    assert res.tool_used == "nmap"
    weak = [f for f in res.findings if f["type"] == "ssh_weak_algorithm"]
    assert len(weak) == 3, [f["title"] for f in res.findings]


@pytest.mark.asyncio
async def test_ssh_audit_no_tool_available(tmp_path):
    tm = FakeToolManager(available=set(), responses=[])
    ctx = _ctx(tmp_path, tm)
    res = await SshAuditSkill().run(ctx)
    assert res.success is False
    assert any("No SSH auditing tool" in e for e in res.errors)


def test_builtin_contracts_include_new_skills():
    from core.skills.skill_contract import BUILTIN_CONTRACTS

    assert "waf_detection" in BUILTIN_CONTRACTS
    assert "ssh_audit" in BUILTIN_CONTRACTS
    assert BUILTIN_CONTRACTS["ssh_audit"].validate_inputs({"target_domain": "app.target.com"})
