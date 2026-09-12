"""
Base Skill — الكلاس الأساسي لكل Skill في النظام
كل Skill ترث من BaseSkill وتنفّذ execute() مع دعم التوقيت الأقصى (Timeout) والتصنيف الهيكلي للأخطاء
"""
from __future__ import annotations

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from tools.tool_manager import ToolManager
from core.workspace_manager import WorkspaceManager

logger = logging.getLogger(__name__)


@dataclass
class StructuredError:
    category: str                      # timeout | missing_tool | network | parsing | runtime
    message: str
    tool: str = ""
    timestamp: float = field(default_factory=time.time)

    def __str__(self) -> str:
        return f"[{self.category.upper()}] {self.message}"


@dataclass
class SkillContext:
    """السياق الذي يُمرَّر لكل Skill عند التنفيذ"""
    target: str
    session_id: str
    workspace: WorkspaceManager
    tool_manager: ToolManager
    state_files: Dict[str, str] = field(default_factory=dict)    # skill_name -> file_path
    extra: Dict[str, Any] = field(default_factory=dict)
    mode: str = "full"
    retry_attempt: int = 0

    def read_skill_output(self, skill_name: str, filename: str) -> Optional[str]:
        """يقرأ output ملف من Skill تانية"""
        file_path = self.state_files.get(skill_name, {})
        if isinstance(file_path, dict):
            file_path = file_path.get(filename, "")
        if file_path and Path(file_path).exists():
            return Path(file_path).read_text(encoding="utf-8")
        return None

    def get_workspace_path(self) -> Path:
        return self.workspace.get_workspace_path(self.target, self.session_id)


@dataclass
class SkillResult:
    """نتيجة تنفيذ الـ Skill"""
    skill_name: str
    success: bool
    output_files: Dict[str, str] = field(default_factory=dict)  # filename -> filepath
    findings: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    structured_errors: List[StructuredError] = field(default_factory=list)
    raw_output: Dict[str, str] = field(default_factory=dict)
    duration: float = 0.0
    tool_used: str = ""
    next_skills: List[str] = field(default_factory=list)         # override recommended next skills

    @property
    def has_findings(self) -> bool:
        return len(self.findings) > 0

    def add_finding(
        self,
        title: str,
        evidence: str,
        severity: str = "Medium",
        vuln_type: str = "",
        tool: str = "",
        url: str = "",
        recommendation: str = "",
        cvss_score: Optional[float] = None,
    ) -> None:
        self.findings.append({
            "title": title,
            "evidence": evidence,
            "severity": severity,
            "type": vuln_type,
            "tool": tool or self.tool_used,
            "url": url,
            "recommendation": recommendation,
            "cvss_score": cvss_score,
        })

    def add_error(self, category: str, message: str, tool: str = "") -> None:
        err = StructuredError(category=category, message=message, tool=tool)
        self.structured_errors.append(err)
        self.errors.append(str(err))

    def merge(self, other: "SkillResult") -> None:
        """يدمج نتيجة Skill أخرى (Fallback tool)"""
        self.findings.extend(other.findings)
        self.output_files.update(other.output_files)
        self.raw_output.update(other.raw_output)
        if other.errors:
            self.errors.extend(other.errors)
        if other.structured_errors:
            self.structured_errors.extend(other.structured_errors)
        if other.tool_used and not self.tool_used:
            self.tool_used = other.tool_used


class BaseSkill(ABC):
    """
    الكلاس الأساسي لكل Skill مع تحديد سقف زمني وأخطاء مهيكلة.
    """

    name: str = "base_skill"
    category: str = "general"
    description: str = ""
    tools_required: List[str] = []
    fallback_tools: List[str] = []
    timeout_seconds: float = 180.0
    max_retries: int = 2

    def __init__(self):
        self.logger = logging.getLogger(f"skill.{self.name}")

    @abstractmethod
    async def execute(self, ctx: SkillContext) -> SkillResult:
        """تنفيذ الـ Skill الرئيسي"""
        pass

    async def run(self, ctx: SkillContext) -> SkillResult:
        """
        يلف الـ execute بـ timeout صارم، timing، وتصنيف هيكلي للأخطاء
        """
        t0 = time.time()
        result = SkillResult(skill_name=self.name, success=False, tool_used=self.name)
        try:
            self.logger.info(f"[{self.name}] Starting on target: {ctx.target} (timeout={self.timeout_seconds}s)")
            ctx.workspace.append_log(
                ctx.target, ctx.session_id,
                f"[START] Skill: {self.name} | Target: {ctx.target} | Attempt: {ctx.retry_attempt + 1}"
            )

            # Enforce strict per-skill timeout
            result = await asyncio.wait_for(
                self.execute(ctx),
                timeout=self.timeout_seconds
            )
            result.skill_name = self.name
            result.duration = time.time() - t0

            ctx.workspace.append_log(
                ctx.target, ctx.session_id,
                f"[DONE] Skill: {self.name} | "
                f"Findings: {len(result.findings)} | "
                f"Files: {list(result.output_files.keys())} | "
                f"Duration: {result.duration:.1f}s"
            )
            self.logger.info(
                f"[{self.name}] Done — findings={len(result.findings)}, "
                f"files={len(result.output_files)}, duration={result.duration:.1f}s"
            )

        except asyncio.TimeoutError:
            result.success = False
            result.duration = time.time() - t0
            result.add_error("timeout", f"Skill exceeded execution timeout of {self.timeout_seconds} seconds")
            self.logger.warning(f"[{self.name}] Timed out after {self.timeout_seconds}s")
            ctx.workspace.append_log(
                ctx.target, ctx.session_id,
                f"[TIMEOUT] Skill: {self.name} exceeded {self.timeout_seconds}s limit"
            )

        except Exception as exc:
            result.success = False
            result.duration = time.time() - t0
            result.add_error("runtime", str(exc))
            self.logger.error(f"[{self.name}] Failed: {exc}", exc_info=True)
            ctx.workspace.append_log(
                ctx.target, ctx.session_id,
                f"[ERROR] Skill: {self.name} | Error: {exc}"
            )

        return result

    def get_first_available_tool(self, tool_manager: ToolManager) -> Optional[str]:
        """يرجع أول أداة متاحة من الـ required أو الـ fallback"""
        for tool in self.tools_required:
            if tool_manager.is_available(tool):
                return tool
        for tool in self.fallback_tools:
            if tool_manager.is_available(tool):
                return tool
        return None

    def __repr__(self) -> str:
        return f"<Skill: {self.name} [{self.category}]>"
