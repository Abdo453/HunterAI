"""
Triage Gate & VRT Classification Skill
Evaluates all current mission findings against the 7-Question Gate and standard VRT taxonomy.
"""
from __future__ import annotations

from core.seven_question_gate import SevenQuestionGate
from core.evidence_sanitizer import EvidenceSanitizer
from skills.base_skill import BaseSkill, SkillContext, SkillResult


class TriageGateSkill(BaseSkill):
    name = "triage_gate"
    category = "analysis"
    description = "7-Question Gate and VRT triage assessment"
    tools_required = []
    fallback_tools = []

    async def execute(self, ctx: SkillContext) -> SkillResult:
        result = SkillResult(skill_name=self.name, success=True, tool_used="seven_question_gate")

        from core.mission_state import MissionState
        state_file = ctx.workspace.get_state_file(ctx.target, ctx.session_id)
        findings = []

        if state_file.exists():
            try:
                state = MissionState.load(state_file)
                findings = state.findings
            except Exception:
                pass

        lines = [
            f"# 🛡️ 7-Question Gate Triage Summary: {ctx.target}",
            f"**Total Findings Evaluated:** {len(findings)}",
            "",
            "---",
            "",
        ]

        if not findings:
            lines.append("No active findings to triage at this phase.")
        else:
            for idx, f in enumerate(findings, 1):
                gate_res = SevenQuestionGate.evaluate_finding(f)
                sanitized_statement = EvidenceSanitizer.sanitize(gate_res.triage_statement)
                lines.append(f"## Finding #{idx}")
                lines.append(sanitized_statement)
                lines.append("\n---\n")

        content = "\n".join(lines)
        p = ctx.workspace.write_file(
            ctx.target, "analysis", "triage_gate_report.md", content, ctx.session_id
        )
        result.output_files["triage_gate_report.md"] = str(p)

        return result
