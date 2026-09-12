"""
HunterAI Engagement & Artifact Management System
Implements the Artifact-Based Recon Architecture:
- Structured storage under data/engagements/{TARGET}/{TIMESTAMP}/
- 15 numbered stage subdirectories (00_scope to 14_reports)
- Triple Artifact Pattern for every tool: {tool}.raw.txt, {tool}.parsed.json, {tool}.meta.json
- Run preservation with latest.txt pointer
- Authoritative manifest.json, timeline.json, run.log, and lineage_graph.json
"""
from __future__ import annotations

import json
import logging
import os
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from hunter_ai.pipeline.schemas import (
    DataLineageRecord,
    ScanManifest,
    StageExecutionRecord,
    ToolExecutionMeta,
)

logger = logging.getLogger("hunter_ai.engagement_manager")

STAGE_DIRECTORIES = [
    "00_scope",
    "01_osint",
    "02_subdomains",
    "03_dns",
    "04_alive",
    "05_ports",
    "06_content",
    "07_urls",
    "08_parameters",
    "09_javascript",
    "10_api",
    "11_technology",
    "12_vulnerabilities",
    "13_evidence",
    "14_reports",
]


class EngagementManager:
    """
    Manages the persistent file-driven engagement hierarchy for a target.
    Ensures zero overwriting of previous scans, authoritative manifests, and complete evidence traceability.
    """

    def __init__(
        self,
        target: str,
        domain: Optional[str] = None,
        session_id: Optional[str] = None,
        base_dir: Optional[Union[str, Path]] = None,
        workflow: str = "full",
    ):
        self.target = target.strip()
        if not domain:
            from urllib.parse import urlparse
            p = urlparse(self.target if "://" in self.target else f"http://{self.target}")
            self.domain = (p.hostname or self.target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]).strip().lower()
        else:
            self.domain = domain.strip().lower()
        self.session_id = session_id or f"hunter_{int(time.time())}"
        self.workflow = workflow

        # Clean target folder name (e.g., app.target.com -> app_target_com)
        clean_target = re.sub(r'[^a-zA-Z0-9_\-]', '_', self.domain).strip('_')
        self.clean_target = clean_target

        # Base directories
        workspace_root = os.getcwd()
        base_engagements = str(base_dir) if base_dir else os.path.join(workspace_root, "data", "engagements")
        self.base_engagements_dir = os.path.abspath(base_engagements)
        self.target_dir = os.path.join(self.base_engagements_dir, clean_target)

        # Unique timestamped directory for this scan run
        self.run_timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        self.timestamp = self.run_timestamp
        self.run_dir = os.path.join(self.target_dir, self.run_timestamp)
        os.makedirs(self.run_dir, exist_ok=True)

        self.stages = STAGE_DIRECTORIES

        # Initialize all 15 stage subdirectories
        for stage in STAGE_DIRECTORIES:
            os.makedirs(os.path.join(self.run_dir, stage), exist_ok=True)

        # Update latest.txt pointer
        self._update_latest_pointer()

        # Files in run root
        self.manifest_path = os.path.join(self.run_dir, "manifest.json")
        self.timeline_path = os.path.join(self.run_dir, "timeline.json")
        self.run_log_path = os.path.join(self.run_dir, "run.log")
        self.lineage_path = os.path.join(self.run_dir, "lineage_graph.json")

        self.manifest_file = Path(self.manifest_path)
        self.timeline_file = Path(self.timeline_path)
        self.run_log_file = Path(self.run_log_path)
        self.lineage_file = Path(self.lineage_path)

        # In-memory trackers
        self.timeline_events: List[Dict[str, Any]] = []
        self.lineage_records: List[DataLineageRecord] = []

        # Initialize Manifest
        stages_init = {
            s: StageExecutionRecord(stage_name=s, status="pending")
            for s in STAGE_DIRECTORIES
        }
        self.manifest = ScanManifest(
            target=self.target,
            domain=self.domain,
            session_id=self.session_id,
            started_at=datetime.utcnow().isoformat() + "Z",
            workflow=self.workflow,
            status="running",
            engagement_dir=self.run_dir,
            stages=stages_init,
            summary={}
        )
        self._save_manifest()
        self.log(f"Initialized engagement session {self.session_id} for {self.domain} at {self.run_dir}")

    def _update_latest_pointer(self):
        """Maintains latest.txt in target root pointing to newest timestamped run"""
        try:
            latest_file = os.path.join(self.target_dir, "latest.txt")
            with open(latest_file, "w", encoding="utf-8") as f:
                f.write(self.run_timestamp + "\n")
                f.write(self.run_dir + "\n")
        except Exception as e:
            logger.debug(f"Could not write latest.txt pointer: {e}")

    def _save_manifest(self):
        """Atomically persist manifest.json"""
        try:
            with open(self.manifest_path, "w", encoding="utf-8") as f:
                json.dump(self.manifest.model_dump(), f, indent=2, default=str)
        except Exception as e:
            logger.error(f"Error persisting manifest.json: {e}")

    def _save_timeline(self):
        """Atomically persist timeline.json"""
        try:
            with open(self.timeline_path, "w", encoding="utf-8") as f:
                json.dump(self.timeline_events, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"Error persisting timeline.json: {e}")

    def _save_lineage(self):
        """Atomically persist lineage_graph.json as indexed asset graph"""
        try:
            lineage_dict = {
                r.asset_id: {
                    "asset_id": r.asset_id,
                    "asset_value": r.asset_value,
                    "asset_type": r.asset_type,
                    "tool": r.discovered_by_tool,
                    "stage": r.stage,
                    "parent_id": r.parent_asset_id,
                    "timestamp": r.timestamp,
                    "metadata": r.metadata,
                }
                for r in self.lineage_records
            }
            with open(self.lineage_path, "w", encoding="utf-8") as f:
                json.dump(lineage_dict, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"Error persisting lineage_graph.json: {e}")

    def log(self, message: str):
        """Appends timestamped message to run.log"""
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = f"[{ts}] {message}\n"
        try:
            with open(self.run_log_path, "a", encoding="utf-8") as f:
                f.write(entry)
        except Exception:
            pass

    def record_timeline_event(self, stage: str, event: str, message: str, **kwargs):
        """Appends event to timeline.json and logs it"""
        evt = {
            "timestamp": time.time(),
            "iso_time": datetime.utcnow().isoformat() + "Z",
            "stage": stage,
            "event": event,
            "message": message,
            **kwargs,
        }
        self.timeline_events.append(evt)
        self._save_timeline()
        self.log(f"[{stage.upper()}] ({event}) {message}")

    def record_lineage(
        self,
        asset_id: str,
        asset_value: str,
        asset_type: str,
        tool: str,
        stage: str,
        parent_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> DataLineageRecord:
        """Records data lineage proving asset origin and provenance"""
        rec = DataLineageRecord(
            asset_id=asset_id,
            asset_value=asset_value,
            asset_type=asset_type,
            discovered_by_tool=tool,
            stage=stage,
            parent_asset_id=parent_id,
            timestamp=time.time(),
            metadata=metadata or {},
        )
        self.lineage_records.append(rec)
        self._save_lineage()
        self.record_timeline_event(
            stage=stage,
            event="asset_discovered",
            message=f"Discovered {asset_type}: {asset_value} (via {tool})",
            asset_id=asset_id,
            parent_id=parent_id
        )
        return rec

    def get_stage_dir(self, stage: str) -> str:
        """Returns the absolute directory for a given stage, ensuring it exists"""
        # Match standard stage prefix or exact name
        target_dir = None
        for s in STAGE_DIRECTORIES:
            if stage in s or s in stage:
                target_dir = os.path.join(self.run_dir, s)
                break
        if not target_dir:
            target_dir = os.path.join(self.run_dir, stage)
        os.makedirs(target_dir, exist_ok=True)
        return target_dir

    def get_stage_path(self, stage: str) -> Path:
        """Returns Path object for a stage directory"""
        return Path(self.get_stage_dir(stage))

    def save_tool_artifact(
        self,
        stage: str = "",
        tool_name: str = "",
        command: str = "",
        raw_output: str = "",
        parsed_data: Any = None,
        input_source: Optional[str] = None,
        next_stage: Optional[str] = None,
        duration: float = 0.0,
        status: str = "success",
        error: Optional[str] = None,
        **kwargs
    ) -> ToolExecutionMeta:
        """
        Implements the Triple Artifact Pattern:
        1. {tool_name}.raw.txt -> Full verbatim stdout/stderr & execution header
        2. {tool_name}.parsed.json -> Structured JSON results
        3. {tool_name}.meta.json -> Metadata containing tool, command, timing, counts, input/output
        """
        stage = kwargs.get("stage_name", stage)
        command = kwargs.get("command_used", command)
        if "duration_ms" in kwargs and not duration:
            duration = kwargs["duration_ms"] / 1000.0

        stage_dir = self.get_stage_dir(stage)
        now_iso = datetime.utcnow().isoformat() + "Z"

        # 1. Save Raw Output .raw.txt
        raw_filename = f"{tool_name}.raw.txt"
        raw_path = os.path.join(stage_dir, raw_filename)
        banner = (
            f"================================================================================\n"
            f"HunterAI Tool Execution Log\n"
            f"Tool:       {tool_name}\n"
            f"Target:     {self.domain}\n"
            f"Stage:      {stage}\n"
            f"Command:    {command}\n"
            f"Timestamp:  {now_iso}\n"
            f"Duration:   {duration:.2f}s\n"
            f"Status:     {status.upper()}\n"
            f"Input:      {input_source or 'direct'}\n"
            f"================================================================================\n\n"
            f"[--- RAW OUTPUT ---]\n"
            f"{raw_output}\n"
        )
        if error:
            banner += f"\n[--- ERROR ---]\n{error}\n"

        with open(raw_path, "w", encoding="utf-8", errors="replace") as f:
            f.write(banner)

        # 2. Save Parsed Output .parsed.json
        parsed_filename = f"{tool_name}.parsed.json"
        parsed_path = os.path.join(stage_dir, parsed_filename)
        with open(parsed_path, "w", encoding="utf-8", errors="replace") as f:
            if isinstance(parsed_data, (dict, list)):
                json.dump(parsed_data, f, indent=2, default=str)
            else:
                json.dump({"data": str(parsed_data)}, f, indent=2)

        # Determine item count
        item_count = len(parsed_data) if isinstance(parsed_data, (list, dict, set)) else (1 if parsed_data else 0)

        # 3. Save Metadata .meta.json
        meta_filename = f"{tool_name}.meta.json"
        meta_path = os.path.join(stage_dir, meta_filename)
        meta = ToolExecutionMeta(
            tool=tool_name,
            target=self.domain,
            stage=stage,
            command=command,
            started_at=now_iso,
            finished_at=now_iso,
            duration_seconds=round(duration, 2),
            status=status,
            raw_output_file=raw_path,
            parsed_output_file=parsed_path,
            metadata_file=meta_path,
            item_count=item_count,
            input_source=input_source,
            next_stage=next_stage,
            error=error,
        )
        meta_dict = meta.model_dump()
        meta_dict["tool_name"] = tool_name
        meta_dict["metadata_file"] = meta_path
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(meta_dict, f, indent=2)

        # Register in manifest
        stage_key = next((s for s in STAGE_DIRECTORIES if s in stage or stage in s), stage)
        st_rec = self.manifest.stages.get(stage_key)
        if st_rec:
            for fp in [raw_path, parsed_path, meta_path]:
                if fp not in st_rec.output_files:
                    st_rec.output_files.append(fp)
            if tool_name not in st_rec.tools_used:
                st_rec.tools_used.append(tool_name)
            st_rec.item_count += item_count
            self._save_manifest()

        self.record_timeline_event(
            stage=stage,
            event="tool_complete",
            message=f"Tool '{tool_name}' completed ({item_count} items in {duration:.2f}s)",
            tool=tool_name,
            raw_file=raw_path,
            parsed_file=parsed_path,
            count=item_count,
        )

        return meta

    def save_stage_file(self, stage: str, filename: str, content: Any) -> str:
        """Saves a structured file within the stage directory and records it in the manifest"""
        stage_dir = self.get_stage_dir(stage)
        file_path = os.path.join(stage_dir, filename)
        try:
            with open(file_path, "w", encoding="utf-8", errors="replace") as f:
                if isinstance(content, (dict, list)):
                    json.dump(content, f, indent=2, default=str)
                else:
                    f.write(str(content))

            # Record in manifest
            stage_key = next((s for s in STAGE_DIRECTORIES if s in stage or stage in s), stage)
            st_rec = self.manifest.stages.get(stage_key)
            if st_rec and file_path not in st_rec.output_files:
                st_rec.output_files.append(file_path)
                self._save_manifest()

            return file_path
        except Exception as e:
            logger.error(f"Failed to save stage file {filename} in {stage}: {e}")
            return file_path

    def read_stage_file(self, stage: str, filename: str) -> Optional[str]:
        """Reads content of a stage file if it exists"""
        stage_dir = self.get_stage_dir(stage)
        p = os.path.join(stage_dir, filename)
        if os.path.isfile(p):
            try:
                with open(p, "r", encoding="utf-8", errors="replace") as f:
                    return f.read()
            except Exception:
                return None
        return None

    def read_stage_json(self, stage: str, filename: str) -> Optional[Any]:
        """Reads and parses JSON content of a stage file"""
        content = self.read_stage_file(stage, filename)
        if content:
            try:
                return json.loads(content)
            except Exception:
                return None
        return None

    def start_stage(self, stage_name: str, input_files: Optional[List[str]] = None):
        """Marks a stage as running in the manifest"""
        stage_key = next((s for s in STAGE_DIRECTORIES if s in stage_name or stage_name in s), stage_name)
        st_rec = self.manifest.stages.get(stage_key)
        if st_rec:
            st_rec.status = "running"
            st_rec.started_at = datetime.utcnow().isoformat() + "Z"
            if input_files:
                st_rec.input_files.extend(input_files)
            self._save_manifest()
        self.record_timeline_event(stage_name, "stage_start", f"Stage '{stage_name}' started")

    def complete_stage(self, stage_name: str, item_count: int = 0):
        """Marks a stage as completed in the manifest"""
        stage_key = next((s for s in STAGE_DIRECTORIES if s in stage_name or stage_name in s), stage_name)
        st_rec = self.manifest.stages.get(stage_key)
        if st_rec:
            st_rec.status = "completed"
            st_rec.finished_at = datetime.utcnow().isoformat() + "Z"
            if item_count > 0:
                st_rec.item_count = item_count
            self._save_manifest()
        self.record_timeline_event(stage_name, "stage_complete", f"Stage '{stage_name}' completed with {item_count} items")

    def finalize(self, summary_counts: Optional[Dict[str, int]] = None, **kwargs):
        """Finalizes the scan manifest with summary metrics"""
        self.manifest.status = "completed"
        self.manifest.finished_at = datetime.utcnow().isoformat() + "Z"
        summary = summary_counts.copy() if summary_counts else {}
        summary.update(kwargs)
        self.manifest.summary = summary
        self._save_manifest()
        self.record_timeline_event("14_reports", "engagement_complete", f"Engagement finished. Summary: {summary}")
        self.log(f"Engagement finalized successfully at {self.run_dir}")
        return self.manifest

    def get_previous_run_dir(self) -> Optional[str]:
        """Locates the prior engagement run directory strictly preceding the current one"""
        if not os.path.exists(self.target_dir):
            return None
        all_runs = []
        for entry in os.listdir(self.target_dir):
            p = os.path.join(self.target_dir, entry)
            if os.path.isdir(p) and entry != self.run_timestamp:
                all_runs.append(entry)
        if not all_runs:
            return None
        all_runs.sort()
        older_runs = [r for r in all_runs if r < self.run_timestamp]
        if older_runs:
            return os.path.join(self.target_dir, older_runs[-1])
        return os.path.join(self.target_dir, all_runs[-1])

