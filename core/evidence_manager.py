"""
Evidence Manager — مدير الأدلة والبراهين
يتتبع كل دليل مرتبط بكل ثغرة مع منع التكرار (Hash Deduplication) وربط CVSS Score
"""
from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.cvss_calculator import CVSSCalculator
from core.vrt_mapper import VRTMapper


@dataclass
class Evidence:
    evidence_id: str
    title: str
    content: str
    tool: str
    severity: str                      # Critical | High | Medium | Low | Info
    vuln_type: str = ""                # xss | sqli | ssrf | idor | ...
    target: str = ""
    url: str = ""
    parameter: str = ""
    payload: str = ""
    response_snippet: str = ""
    confidence: float = 0.0            # 0.0 – 1.0
    cvss_score: float = 0.0            # Derived CVSS Base Score
    finding_ids: List[str] = field(default_factory=list)
    sources: List[str] = field(default_factory=list) # List of tools that observed this
    timestamp: float = field(default_factory=time.time)
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_markdown(self) -> str:
        lines = [
            f"## [{self.severity} / CVSS {self.cvss_score:.1f}] {self.title}",
            f"- **ID:** `{self.evidence_id}`",
            f"- **Tool(s):** {', '.join(self.sources) if self.sources else self.tool}",
            f"- **Type:** {self.vuln_type or 'N/A'}",
            f"- **Target:** {self.target or 'N/A'}",
            f"- **URL:** {self.url or 'N/A'}",
            f"- **Parameter:** {self.parameter or 'N/A'}",
            f"- **Payload:** `{self.payload or 'N/A'}`",
            f"- **Confidence:** {self.confidence:.0%}",
            "",
            "### Evidence Content",
            "```",
            self.content[:2000],
            "```",
        ]
        if self.response_snippet:
            lines += ["", "### Response Snippet", "```", self.response_snippet[:500], "```"]
        return "\n".join(lines)


class EvidenceManager:
    """
    يتتبع كل الأدلة ويربطها بالـ Findings مع منع التكرار وتحديث مصادر الملاحظة
    """

    def __init__(self):
        self._store: Dict[str, Evidence] = {}
        self._fingerprints: Dict[str, str] = {} # fingerprint -> evidence_id

    def _generate_fingerprint(self, title: str, url: str, vuln_type: str, parameter: str = "") -> str:
        """توليد بصمة فريدة للثغرة لمنع تكرار الأدلة المتطابقة من أدوات مختلفة"""
        norm_title = "".join(c.lower() for c in title if c.isalnum())
        norm_url = url.split("?")[0].rstrip("/").lower()
        norm_type = vuln_type.lower().strip()
        norm_param = parameter.lower().strip()
        raw = f"{norm_type}:{norm_url}:{norm_title}:{norm_param}"
        return hashlib.md5(raw.encode("utf-8")).hexdigest()[:16]

    # ── CRUD & Deduplication ─────────────────────────────────────

    def add_evidence(
        self,
        title: str,
        content: str,
        tool: str,
        severity: str = "Medium",
        vuln_type: str = "",
        target: str = "",
        url: str = "",
        parameter: str = "",
        payload: str = "",
        response_snippet: str = "",
        confidence: float = 0.5,
        cvss_score: Optional[float] = None,
    ) -> str:
        """يضيف دليل جديد أو يدمجه مع دليل موجود لو كان مكرراً"""
        fp = self._generate_fingerprint(title, url, vuln_type, parameter)

        # Check if already exists
        if fp in self._fingerprints:
            existing_id = self._fingerprints[fp]
            existing = self._store[existing_id]
            # Merge sources and append new content if richer
            if tool and tool not in existing.sources:
                existing.sources.append(tool)
            if len(content) > len(existing.content):
                existing.content = content
            existing.confidence = max(existing.confidence, confidence)
            return existing_id

        # Calculate CVSS score if not explicitly given
        if cvss_score is None or cvss_score == 0.0:
            vrt = VRTMapper.lookup(vuln_type)
            calculated_cvss = CVSSCalculator.derive_from_vrt(vrt.vrt_id, severity)
        else:
            calculated_cvss = cvss_score

        eid = f"ev_{str(uuid.uuid4())[:8]}"
        ev = Evidence(
            evidence_id=eid,
            title=title,
            content=content,
            tool=tool,
            severity=severity,
            vuln_type=vuln_type,
            target=target,
            url=url,
            parameter=parameter,
            payload=payload,
            response_snippet=response_snippet,
            confidence=confidence,
            cvss_score=calculated_cvss,
            sources=[tool] if tool else []
        )
        self._store[eid] = ev
        self._fingerprints[fp] = eid
        return eid

    def get_evidence(self, evidence_id: str) -> Optional[Evidence]:
        return self._store.get(evidence_id)

    def link_to_finding(self, evidence_id: str, finding_id: str) -> None:
        """يربط دليل بـ finding"""
        ev = self._store.get(evidence_id)
        if ev and finding_id not in ev.finding_ids:
            ev.finding_ids.append(finding_id)

    def get_all(self) -> List[Evidence]:
        return list(self._store.values())

    def get_by_severity(self, severity: str) -> List[Evidence]:
        return [e for e in self._store.values() if e.severity.lower() == severity.lower()]

    def get_by_vuln_type(self, vuln_type: str) -> List[Evidence]:
        return [e for e in self._store.values() if e.vuln_type.lower() == vuln_type.lower()]

    def get_critical_and_high(self) -> List[Evidence]:
        return [e for e in self._store.values() if e.severity in ("Critical", "High") or e.cvss_score >= 7.0]

    # ── Persistence ──────────────────────────────────────────────

    def save(self, path: Path) -> None:
        """حفظ كل الأدلة في JSON"""
        path.parent.mkdir(parents=True, exist_ok=True)
        data = {eid: ev.to_dict() for eid, ev in self._store.items()}
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=False)

    def load(self, path: Path) -> None:
        """تحميل الأدلة من JSON"""
        if not path.exists():
            return
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        for eid, ev_data in data.items():
            ev = Evidence(**ev_data)
            self._store[eid] = ev
            fp = self._generate_fingerprint(ev.title, ev.url, ev.vuln_type, ev.parameter)
            self._fingerprints[fp] = eid

    # ── Export ───────────────────────────────────────────────────

    def export_markdown(self) -> str:
        """يصدّر كل الأدلة في Markdown مرتبة حسب الـ CVSS والخطورة"""
        if not self._store:
            return "# Evidence Report\n\nNo evidence collected.\n"

        sorted_evidence = sorted(
            self._store.values(),
            key=lambda e: (-e.cvss_score, e.timestamp)
        )

        lines = ["# Evidence Bundle\n"]
        for ev in sorted_evidence:
            lines.append(ev.to_markdown())
            lines.append("\n---\n")
        return "\n".join(lines)

    def export_bundle(self, evidence_folder: Path) -> List[Path]:
        """يكتب ملف لكل دليل في مجلد evidence"""
        evidence_folder.mkdir(parents=True, exist_ok=True)
        written: List[Path] = []

        for eid, ev in self._store.items():
            fname = f"{eid}_{ev.vuln_type or 'evidence'}.md"
            path = evidence_folder / fname
            path.write_text(ev.to_markdown(), encoding="utf-8")
            written.append(path)

        # Write index
        index_path = evidence_folder / "index.md"
        index_lines = ["# Evidence Index\n", "| ID | Title | Severity | CVSS | Type | Tool(s) |\n", "|---|---|---|---|---|---|\n"]
        for ev in sorted(self._store.values(), key=lambda e: -e.cvss_score):
            tools_str = ", ".join(ev.sources) if ev.sources else ev.tool
            index_lines.append(f"| `{ev.evidence_id}` | {ev.title} | {ev.severity} | {ev.cvss_score:.1f} | {ev.vuln_type} | {tools_str} |\n")
        index_path.write_text("".join(index_lines), encoding="utf-8")
        written.append(index_path)

        return written

    def summary(self) -> Dict[str, Any]:
        counts: Dict[str, int] = {}
        for ev in self._store.values():
            counts[ev.severity] = counts.get(ev.severity, 0) + 1
        return {
            "total": len(self._store),
            "by_severity": counts,
            "critical": counts.get("Critical", 0),
            "high": counts.get("High", 0),
            "deduplicated_count": len(self._fingerprints),
        }
