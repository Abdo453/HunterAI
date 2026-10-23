# -*- coding: utf-8 -*-
"""
إدارة أدوات النظام — Tool Management (Phase 6)
==============================================
حلقة مغلقة بين بوابة الجاهزية والتثبيت المُتحقَّق منه:

  1. build_installation_plan(): يبني خطة تثبيت مرتبة من تقرير الـ Readiness
     (المفقود → أمر التثبيت + قناة go/apt/pipx) — دالة نقية لا تنفذ شيئًا.
  2. apply_plan(): لا يُنفّذ أي أمر بدون approved=True صريح. وبعد كل خطوة
     يتحقق بـ probe الحقيقي — "مثبتة" تعني READY بالإثبات، لا نجاح exit code.
  3. حفظ/تحميل الخطة كـ artifact قابل للتدقيق في data/readiness/.

القاعدة الصارمة: لا تثبيت صامت. لا تعتبر النتيجة "مثبتة" بنجاح الأمر وحده —
الإثبات وحده هو الـ probe (نفس منطق BYOW في بوابة الجاهزية).
"""
from __future__ import annotations

import json
import logging
import sys
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

log = logging.getLogger("hunter_ai.tool_mgmt")

PLAN_ARTIFACT_NAME = "tool_installation_plan.json"

# قناة التثبيت لكل أداة — مصدر الحقيقة الوحيد (موحّد من ToolManager.INSTALL_MAP
# مع fc/v2 params الصحيحة وإضافات الـ manifest كاملة)
INSTALL_CHANNELS: Dict[str, Tuple[str, str]] = {
    # tool -> (channel, command)
    "subfinder": ("go", "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
    "httpx": ("go", "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"),
    "katana": ("go", "go install -v github.com/projectdiscovery/katana/cmd/katana@latest"),
    "nuclei": ("go", "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"),
    "ffuf": ("go", "go install -v github.com/ffuf/ffuf/v2@latest"),
    "anew": ("go", "go install -v github.com/tomnomnom/anew@latest"),
    "gau": ("go", "go install -v github.com/lc/gau/v2/cmd/gau@latest"),
    "qsreplace": ("go", "go install -v github.com/tomnomnom/qsreplace@latest"),
    "masscan": ("apt", "sudo apt update && sudo apt install -y masscan"),
    "nmap": ("apt", "sudo apt update && sudo apt install -y nmap"),
    "gobuster": ("apt", "sudo apt update && sudo apt install -y gobuster"),
    "nikto": ("apt", "sudo apt update && sudo apt install -y nikto"),
    "hydra": ("apt", "sudo apt update && sudo apt install -y hydra"),
    "sqlmap": ("pipx", "pipx install sqlmap"),
    "wpscan": ("gem", "sudo gem install wpscan"),
    "arjun": ("pip", "pip install arjun"),
    "dirsearch": ("pip", "pip install dirsearch"),
    "wafw00f": ("pip", "pip install wafw00f"),
    "trufflehog": ("source", "git clone https://github.com/trufflesecurity/trufflehog && cd trufflehog && go build"),
}

CHANNEL_ORDER = ("apt", "go", "pip", "pipx", "gem", "source")


class NotApprovedError(RuntimeError):
    """يُرفع عند محاولة apply بدون موافقة صريحة — لا تثبيت صامت أبدًا."""


@dataclass
class InstallStep:
    tool: str
    channel: str
    command: str
    required: bool = False          # مطلوب بواسطة environment/manifest.json
    probed_after: Optional[str] = None   # READY | MISSING | UNHEALTHY (بعد المحاولة)
    executed: bool = False
    verified: bool = False          # True فقط إذا الـ probe أرجع READY بعد التنفيذ
    note: str = ""
    decided_at: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class InstallPlan:
    target_platform: str            # "windows" | "kali" | "wsl" | autre
    steps: List[InstallStep] = field(default_factory=list)
    prerequisites: List[str] = field(default_factory=list)   # مثل: تثبيت توزيعة Kali في WSL
    created_at: float = field(default_factory=time.time)
    approved: bool = False
    notes: List[str] = field(default_factory=list)

    @property
    def summary(self) -> Dict[str, int]:
        return {
            "steps": len(self.steps),
            "required_missing": sum(1 for s in self.steps if s.required and not s.verified),
            "verified": sum(1 for s in self.steps if s.verified),
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_platform": self.target_platform,
            "created_at": self.created_at,
            "approved": self.approved,
            "summary": self.summary,
            "prerequisites": self.prerequisites,
            "steps": [s.to_dict() for s in self.steps],
            "notes": self.notes,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)


def build_installation_plan(
    missing_tools: List[str],
    required_tools: List[str],
    target_platform: str = "windows",
) -> InstallPlan:
    """
    يبني خطة مُرتبة من المفقود: apt ثم go ثم pip/pipx — كل خطوة تحمل
    هل الأداة required (بوابة strict تمنع بدونها).
    أدوات بلا قناة معروفة تُحتفظ كملاحظات — لا تُختلق أوامر مجهولة.
    """
    plan = InstallPlan(target_platform=target_platform)
    missing = [t for t in dict.fromkeys(missing_tools or []) if t]
    required = set(required_tools or [])

    if target_platform in ("windows",) and any(m in INSTALL_CHANNELS for m in missing):
        plan.prerequisites.append(
            "Windows host: الأدوات تعمل في Kali/WSL — ثبّت توزيعة أولًا "
            "(wsl --install -d kali-linux) أو استخدم Windows-native البديل المتاح"
        )

    unknown = [t for t in missing if t not in INSTALL_CHANNELS]
    known = [t for t in missing if t in INSTALL_CHANNELS]
    known.sort(key=lambda t: (CHANNEL_ORDER.index(INSTALL_CHANNELS[t][0]), t))

    for tool in known:
        channel, command = INSTALL_CHANNELS[tool]
        plan.steps.append(InstallStep(
            tool=tool, channel=channel, command=command,
            required=tool in required,
        ))
    if unknown:
        plan.notes.append(f"أدوات مفقودة بلا قناة معروفة مونّحتلها أوامر مختلقة: {', '.join(unknown)}")
    return plan


def apply_plan(
    plan: InstallPlan,
    *,
    approved: bool = False,
    executor: Optional[Callable[[str], int]] = None,
    probe_fn: Optional[Callable[..., Any]] = None,
) -> InstallPlan:
    """
    تنفيذ الخطة مع تحقق قوي:
    - approved=False → NotApprovedError (لا تثبيت صامت أبدًا).
    - executor: ينفّذ الأمر ويرجع exit code — الافتراضي subprocess بسيط.
    - probe_fn: probe الجاهزية الحقيقي — عنصر مطلوب للتحقق. إن لم يُزوَّد
      فمن scripts.verify_kali_toolchain.probe (نفس مصدر بوابة الجاهزية).
    - خطوة تتثبت verified=True فقط إن رجع الـ probe READY — نجاح أمر
      التثبيت وحده لا يعني شيئًا.
    """
    if not approved:
        raise NotApprovedError("apply_plan يتطلب approved=True صريحة — لا تثبيت صامت أبدًا")

    if probe_fn is None:
        from scripts.verify_kali_toolchain import probe as probe_fn

    if executor is None:
        import subprocess

        def executor(command: str) -> int:
            return subprocess.call(command, shell=isinstance(command, str) and command.count("sudo") < 0)

    for step in plan.steps:
        if step.verified:
            continue
        try:
            exit_code = executor(step.command)
            step.executed = True
            # الإثبات الحقيقي: probe بعد التنفيذ — لا نعتمد على exit code إطلاقًا
            result = probe_fn(step.tool)
            status = getattr(result, "status", result.get("status") if isinstance(result, dict) else None)
            step.probed_after = str(status or "UNKNOWN")
            step.verified = (step.probed_after == "READY")
            step.decided_at = time.time()
            step.note = f"executor exit={exit_code}; probe after={step.probed_after}"
        except Exception as exc:  # noqa: BLE001
            step.executed = False
            step.probed_after = getattr(step, "probed_after", None) or "ERROR"
            step.verified = False
            step.note = f"executor failed: {exc}"
            log.error("Install step failed for %s: %s", step.tool, exc)
        plan.notes.append(f"[{step.tool}] {step.note}")
    plan.approved = True
    return plan


def save_installation_plan(plan: InstallPlan, out_dir: Optional[Path] = None) -> Path:
    out_dir = out_dir or Path("data") / "readiness"
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / PLAN_ARTIFACT_NAME
    path.write_text(plan.to_json() + "\n", encoding="utf-8")
    return path


def load_installation_plan(path: Path) -> InstallPlan:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    plan = InstallPlan(
        target_platform=raw.get("target_platform", "unknown"),
        prerequisites=list(raw.get("prerequisites", [])),
        approved=bool(raw.get("approved", False)),
        notes=list(raw.get("notes", [])),
    )
    plan.steps = [
        InstallStep(
            tool=s.get("tool", ""), channel=s.get("channel", ""),
            command=s.get("command", ""), required=bool(s.get("required")),
            probed_after=s.get("probed_after"), executed=bool(s.get("executed")),
            verified=bool(s.get("verified")), note=s.get("note", ""),
            decided_at=s.get("decided_at"),
        )
        for s in raw.get("steps", [])
    ]
    return plan


def plan_from_readiness_artifact(report_path: Path,
                                 target_platform: str = "windows") -> InstallPlan:
    """
    يبني خطة مباشرة من تقرير جاهزية حقيقي (data/readiness/*.json):
    المفقود = نتائج MISSING (كلها، الكترونًا عالمًا multiple)، Required من الـ
    environment manifest — يفضل أن يُمرر مسبقًا عبر checker.
    """
    raw = json.loads(Path(report_path).read_text(encoding="utf-8"))
    missing = [r.get("name") for r in raw.get("results", [])
               if r.get("status") == "MISSING" and r.get("component") == "kali_tool"]
    blocked = [b.get("name") for b in raw.get("blocked", [])]
    plan = build_installation_plan(
        missing_tools=missing,
        required_tools=sorted(set(missing) & set(blocked)),
        target_platform=target_platform,
    )
    plan.notes.append(
        f"built from readiness report: {report_path} (strict_ready={raw.get('strict_ready')})"
    )
    return plan


if __name__ == "__main__":  # pragma: no cover - CLI
    import argparse
    import io

    parser = argparse.ArgumentParser(description="Tool installation plan (Phase 6)")
    parser.add_argument("--from-report", required=True,
                        help="مسار تقرير جاهزية JSON (من python -m core.readiness)")
    parser.add_argument("--platform", default="windows", choices=["windows", "kali", "wsl"])
    parser.add_argument("--output", default=None, help="مجلد حفظ الخطة (default data/readiness)")
    args = parser.parse_args()

    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
    plan = plan_from_readiness_artifact(Path(args.from_report), target_platform=args.platform)
    out = save_installation_plan(plan, Path(args.output) if args.output else None)
    d = plan.to_dict()
    print(f"plan saved: {out}")
    print(f"platform={d['target_platform']} | steps={d['summary']['steps']} | "
          f"required_missing={d['summary']['required_missing']} | approved={d['approved']}")
    for s in d["steps"]:
        mark = "✅" if s["verified"] else "⬜"
        req = "REQUIRED" if s["required"] else "optional"
        print(f"  {mark} {s['tool']:12} [{s['channel']}] {req} :: {s['command'][:80]}")
    for p in d["prerequisites"]:
        print(f"  ⚠️ prerequisite: {p}")
    for n in d["notes"]:
        print(f"  ℹ️ {n}")
