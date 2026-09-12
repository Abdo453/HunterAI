"""
HunterAI Runtime: Persistent Working Memory
============================================
Maintains persistent agent state on disk in `.agent/` directory:
- state.json: high-level mission state, target, active iteration, token counters
- hypotheses.json: full serialized HypothesisTree
- observations.json: structured observations extracted from traffic/responses
- decisions.json: reasoning trail of decisions made
- failed_tests.json: failed attempts with why they failed (WAF, syntax, auth)
- findings.json: confirmed, reproducible findings
- mission.md: human-readable executive log

Allows long-running missions to survive context window limits and system restarts.
"""
from __future__ import annotations

import os
import json
import time
from pathlib import Path
from typing import Dict, List, Optional, Any

from hunter_ai.runtime.hypothesis_tree import HypothesisTree


class PersistentWorkingMemory:
    """
    Manages persistent memory inside the `.agent/` working directory.
    """

    def __init__(self, agent_dir: str = ".agent"):
        self.dir = Path(agent_dir)
        self.dir.mkdir(parents=True, exist_ok=True)

        self.state_file = self.dir / "state.json"
        self.hypotheses_file = self.dir / "hypotheses.json"
        self.observations_file = self.dir / "observations.json"
        self.decisions_file = self.dir / "decisions.json"
        self.failed_tests_file = self.dir / "failed_tests.json"
        self.findings_file = self.dir / "findings.json"
        self.mission_md_file = self.dir / "mission.md"

        self._init_files()

    def _init_files(self):
        """Initializes empty JSON arrays or dicts if files don't already exist"""
        if not self.state_file.exists():
            self._write_json(self.state_file, {
                "mission_id": f"mission_{int(time.time())}",
                "target": "",
                "status": "IDLE",
                "current_step": 0,
                "max_steps": 30,
                "current_focus_endpoint": "",
                "auth_state": "NONE",
                "waf_detected": False,
                "tokens_estimated": 0,
                "created_at": time.time(),
                "updated_at": time.time()
            })

        for p, default_val in [
            (self.hypotheses_file, {"root_name": "AttackSurface", "next_index": 1, "nodes": {}}),
            (self.observations_file, []),
            (self.decisions_file, []),
            (self.failed_tests_file, []),
            (self.findings_file, [])
        ]:
            if not p.exists():
                self._write_json(p, default_val)

        if not self.mission_md_file.exists():
            with open(self.mission_md_file, "w", encoding="utf-8") as f:
                f.write("# HunterAI Autonomous Mission Log\n\nMission initialized.\n")

    def _read_json(self, path: Path) -> Any:
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def _write_json(self, path: Path, data: Any):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    # ── State Management ───────────────────────────────────────────────────────
    def get_state(self) -> Dict[str, Any]:
        return self._read_json(self.state_file)

    def update_state(self, **kwargs):
        state = self.get_state()
        state.update(kwargs)
        state["updated_at"] = time.time()
        self._write_json(self.state_file, state)

    # ── Hypothesis Tree Persistence ───────────────────────────────────────────
    def save_hypotheses(self, tree: HypothesisTree):
        self._write_json(self.hypotheses_file, tree.serialize())

    def load_hypotheses(self) -> HypothesisTree:
        data = self._read_json(self.hypotheses_file)
        if not data or "nodes" not in data:
            return HypothesisTree()
        return HypothesisTree.deserialize(data)

    # ── Observations ──────────────────────────────────────────────────────────
    def record_observation(self, observation: Dict[str, Any]):
        obs = self._read_json(self.observations_file)
        if not isinstance(obs, list):
            obs = []
        observation["timestamp"] = time.time()
        obs.append(observation)
        self._write_json(self.observations_file, obs)

    def get_observations(self, limit: int = 20) -> List[Dict[str, Any]]:
        obs = self._read_json(self.observations_file)
        return obs[-limit:] if isinstance(obs, list) else []

    # ── Decisions ─────────────────────────────────────────────────────────────
    def record_decision(self, rationale: str, action: str, parameters: Dict[str, Any]):
        dec = self._read_json(self.decisions_file)
        if not isinstance(dec, list):
            dec = []
        dec.append({
            "step": self.get_state().get("current_step", 0),
            "rationale": rationale,
            "action": action,
            "parameters": parameters,
            "timestamp": time.time()
        })
        self._write_json(self.decisions_file, dec)

    # ── Failed Tests (Root Cause Tracking) ────────────────────────────────────
    def record_failed_test(self, test_name: str, payload: str, endpoint: str, failure_reason: str, alternative_action: str):
        failed = self._read_json(self.failed_tests_file)
        if not isinstance(failed, list):
            failed = []
        failed.append({
            "test_name": test_name,
            "payload": payload,
            "endpoint": endpoint,
            "failure_reason": failure_reason,
            "alternative_action": alternative_action,
            "timestamp": time.time()
        })
        self._write_json(self.failed_tests_file, failed)

    def get_failed_tests(self, limit: int = 10) -> List[Dict[str, Any]]:
        failed = self._read_json(self.failed_tests_file)
        return failed[-limit:] if isinstance(failed, list) else []

    # ── Findings ──────────────────────────────────────────────────────────────
    def record_finding(self, finding: Dict[str, Any]):
        findings = self._read_json(self.findings_file)
        if not isinstance(findings, list):
            findings = []
        finding["finding_id"] = finding.get("finding_id", f"FND_{len(findings) + 1}")
        finding["recorded_at"] = time.time()
        findings.append(finding)
        self._write_json(self.findings_file, findings)

    def get_findings(self) -> List[Dict[str, Any]]:
        findings = self._read_json(self.findings_file)
        return findings if isinstance(findings, list) else []

    # ── Markdown Log Append ───────────────────────────────────────────────────
    def append_mission_log(self, text: str):
        with open(self.mission_md_file, "a", encoding="utf-8") as f:
            f.write(f"\n- **[{time.strftime('%H:%M:%S')}]** {text}")

    # ── Token-Compact Working Context ─────────────────────────────────────────
    def get_compact_working_context(self, max_tokens: int = 4000) -> Dict[str, Any]:
        """
        Creates a structured, compact representation of the working memory
        specifically formatted for consumption by LLM prompts.
        """
        state = self.get_state()
        tree = self.load_hypotheses()
        recent_obs = self.get_observations(limit=5)
        recent_failures = self.get_failed_tests(limit=3)
        findings = self.get_findings()

        return {
            "mission": {
                "target": state.get("target"),
                "status": state.get("status"),
                "step": state.get("current_step"),
                "focus_endpoint": state.get("current_focus_endpoint"),
                "waf_present": state.get("waf_detected")
            },
            "active_hypotheses": tree.to_compact_summary(max_items=4),
            "recent_observations": recent_obs,
            "failed_attempts": recent_failures,
            "confirmed_findings_count": len(findings)
        }
