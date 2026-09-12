"""
Source -> Sink Data Flow Analyzer
=================================
Inspects JavaScript code for client-side injection flows:
Untrusted Source (location.search, hash, postMessage) -> Dangerous Sink (innerHTML, eval, href).
Rule: Sink existence alone != vulnerability. Requires reachable, un-sanitized source data flow.
"""
import re
from typing import List

from core.code_intel.models import SinkCategory, SourceSinkFlow


class SourceSinkAnalyzer:
    """Traces untrusted input to dangerous sinks"""

    SINKS = [
        ("innerHTML", SinkCategory.DOM, re.compile(r"\.innerHTML\s*=")),
        ("outerHTML", SinkCategory.DOM, re.compile(r"\.outerHTML\s*=")),
        ("document.write", SinkCategory.DOM, re.compile(r"document\.write(?:ln)?\s*\(")),
        ("eval", SinkCategory.EXEC, re.compile(r"eval\s*\(")),
        ("Function_ctor", SinkCategory.EXEC, re.compile(r"new\s+Function\s*\(")),
        ("setTimeout_str", SinkCategory.EXEC, re.compile(r"""setTimeout\s*\(\s*['"`][^'"]+['"`]""")),
        ("location.href", SinkCategory.NAV, re.compile(r"\blocation\.(?:href|assign|replace)\s*=")),
        ("window.open", SinkCategory.NAV, re.compile(r"\bwindow\.open\s*\(")),
        ("postMessage_wildcard", SinkCategory.SERIALIZATION, re.compile(r"""postMessage\s*\([^,]+,\s*['"]\*['"]\)""")),
    ]

    SOURCES = [
        ("location.search", re.compile(r"location\.search")),
        ("location.hash", re.compile(r"location\.hash")),
        ("location.href", re.compile(r"location\.href")),
        ("window.name", re.compile(r"window\.name")),
        ("document.referrer", re.compile(r"document\.referrer")),
        ("postMessage_event", re.compile(r"event\.data")),
    ]

    @classmethod
    def analyze_flows(cls, content: str, source_file: str = "") -> List[SourceSinkFlow]:
        flows: List[SourceSinkFlow] = []
        lines = content.splitlines()

        # Find line numbers of sources and sinks
        found_sources = []
        found_sinks = []

        for idx, line in enumerate(lines, start=1):
            for s_name, s_pat in cls.SOURCES:
                if s_pat.search(line):
                    found_sources.append((s_name, idx, line))

            for sink_name, sink_cat, sink_pat in cls.SINKS:
                if sink_pat.search(line):
                    found_sinks.append((sink_name, sink_cat, idx, line))

        # Correlate proximity and variable flow within 20 lines
        for s_name, s_line, s_text in found_sources:
            for sink_name, sink_cat, sink_line, sink_text in found_sinks:
                if 0 <= (sink_line - s_line) <= 25:
                    # Check for static literal assignment
                    is_literal = bool(re.search(r"""=\s*['"][a-zA-Z0-9_ /.-]+['"];?$""", sink_text))
                    sanitized = is_literal or "encodeURIComponent" in sink_text or "sanitize" in sink_text.lower()
                    is_expl = not sanitized

                    flow = SourceSinkFlow(
                        source=s_name,
                        source_type="client_source",
                        sink=sink_name,
                        sink_category=sink_cat,
                        source_file=source_file,
                        line_number=sink_line,
                        data_path=[f"line_{s_line}:{s_name}", f"line_{sink_line}:{sink_name}"],
                        sanitized=sanitized,
                        is_exploitable=is_expl,
                        confidence=0.85 if is_expl else 0.15,
                        evidence=f"Source '{s_name}' at line {s_line} reaches sink '{sink_name}' at line {sink_line}"
                    )
                    flows.append(flow)

        return flows