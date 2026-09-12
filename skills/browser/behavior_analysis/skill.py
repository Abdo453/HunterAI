"""
Browser Behavior Analysis Skill
Simulates user behavior (clicking navigation tabs, Load More, dropdowns) and maps dynamic DOM state transitions.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from core.browser.playwright_engine import PlaywrightEngine
from skills.base_skill import BaseSkill, SkillContext, SkillResult


class BehaviorAnalysisSkill(BaseSkill):
    name = "behavior_analysis"
    category = "browser"
    description = "Simulate user interaction and map dynamic application state graph"
    timeout_seconds = 120.0
    max_retries = 2

    async def execute(self, ctx: SkillContext) -> SkillResult:
        result = SkillResult(skill_name=self.name, success=True, tool_used="behavior_simulator")

        target_url = ctx.target if ctx.target.startswith("http") else f"https://{ctx.target}"
        engine = PlaywrightEngine(headless=True, timeout_seconds=45.0)

        inspection = await engine.inspect_url(
            url=target_url,
            simulate_interactions=True,
            auth_credentials=ctx.extra.get("auth", {})
        )

        actions = inspection.interactive_actions

        # 1. behavior_actions.json
        p_json = ctx.workspace.write_file(
            ctx.target, "browser", "behavior_actions.json",
            json.dumps(actions, indent=2),
            ctx.session_id
        )
        result.output_files["behavior_actions.json"] = str(p_json)

        # 2. state_graph.txt (Textual Application State Graph)
        graph_lines = [
            f"# Application State & Behavior Graph for {ctx.target}",
            f"**Initial State:** Root Page (`{inspection.title}`)",
            f"**Observed Transitions:** {len(actions)} interactive events",
            "",
            "```text",
            f"[{inspection.title or 'Homepage'}]",
        ]

        for idx, act in enumerate(actions, 1):
            btn_name = act.get("text") or act.get("target")
            graph_lines.extend([
                "  │",
                f"  ├─► [User Click: \"{btn_name}\"]",
                f"  │     └─► Dynamic DOM State #{idx}",
            ])

        graph_lines.extend([
            "```",
            "",
            "---",
            "",
            "## Discovered Semantic Nodes (Accessibility Tree)",
            f"Accessibility tree captured {len(inspection.accessibility_snapshot.get('children', []))} top-level interactive children."
        ])

        p_graph = ctx.workspace.write_file(
            ctx.target, "browser", "state_graph.txt",
            "\n".join(graph_lines),
            ctx.session_id
        )
        result.output_files["state_graph.txt"] = str(p_graph)

        result.add_finding(
            title=f"Application State Graph Mapped ({len(actions)} Interactive Transitions)",
            evidence=f"Simulated {len(actions)} DOM clicks and observed state changes on {target_url}.",
            severity="Info",
            vuln_type="behavior_graph",
            recommendation="Review interactive state changes to ensure sensitive operations require re-authentication."
        )

        return result
