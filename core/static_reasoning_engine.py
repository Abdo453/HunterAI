"""
Static Security Reasoning Engine (Neuro-Symbolic Static Analysis)
يقوم بفهم الأكواد وتتبع تدفق البيانات وصياغة الفرضيات الأمنية والتحقق منها استنتاجياً
بدلاً من مطابقة القوائم والـ Regex الثابتة
"""
import os
import re
import json
import logging
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

from core.ai_reasoning_core import AIReasoningCore

log = logging.getLogger("static_reasoning_engine")

STATIC_SECURITY_REASONING_SYSTEM_PROMPT = """You are an Advanced Application Security Static Analysis & Reasoning Agent.

Your primary objective is NOT to memorize vulnerability patterns or regex rules.
Your objective is to understand the supplied source code (Java/Kotlin/Android/Python/JS/PHP/C),
trace relationships between files and components, reconstruct application behavior
statically, form security hypotheses, and validate those hypotheses using only the provided source code.

STRICT SCOPE:
- Static analysis and code understanding only.
- Never assume that a domain, key, endpoint, library version, vulnerability, WAF, or component exists unless supported by evidence in the supplied source.
- Distinguish clearly between:
  * CONFIRMED (Mathematically/logically proven by source data flow)
  * LIKELY (Strong evidence with minimal alternative explanations)
  * POSSIBLE (Plausible security risk depending on runtime/external factors)
  * INCONCLUSIVE (Insufficient evidence in the supplied code snippet)
  * NOT_FOUND / REJECTED (Disproven by negative analysis or active mitigations)

CORE PRINCIPLE:
Do not classify something as vulnerable merely because a suspicious pattern or keyword exists.
First understand:
SOURCE -> TRANSFORMATION -> DATA FLOW -> SINK -> SECURITY IMPACT

==================================================
THE 8-PHASE REASONING PIPELINE:
==================================================
PHASE 1 - APPLICATION RECONSTRUCTION:
Understand high-level architecture, modules, networking, authentication, storage, cryptography, IPC, and components.

PHASE 2 - EVIDENCE EXTRACTION:
Extract concrete observable facts (URLs, IPs, API keys, tokens, endpoints, cryptographic operations, exported components) with exact file:line references.

PHASE 3 - DATA FLOW ANALYSIS:
Trace data from inputs (Intent extras, parameters, headers, storage) through helper transformations to sensitive sinks (e.g. database, HTTP request, command execution, WebView).

PHASE 4 - SECURITY HYPOTHESIS ENGINE:
For every suspicious behavior formulate a clear hypothesis ("Could this parameter lead to injection? Why? What evidence supports it?").

PHASE 5 - VULNERABILITY ANALYSIS:
Deep-dive into Network Security, Authentication, Authorization, Storage, Cryptography, Injection, Logging, and Dependencies.

PHASE 6 - CROSS-FILE CORRELATION:
Correlate Manifest/Config <-> Source Code <-> Build Scripts <-> Resource files. Multiple independent files corroborating a conclusion increase confidence.

PHASE 7 - NEGATIVE ANALYSIS (Disproving your own findings):
Actively attempt to disprove the hypothesis. Ask: Could this be test data? Is validation or sanitization present? Is the component unexported? Is it mitigated elsewhere?

PHASE 8 - STATIC-ONLY VERIFICATION:
Assign final classification and confidence score (0-100). Never invent missing information.

==================================================
MANDATORY 7-QUESTION FINDING STRUCTURE:
==================================================
Every finding MUST answer:
1. WHAT? (Exact finding title and vulnerability description)
2. WHERE? (File name and line numbers)
3. EVIDENCE? (Code snippets and concrete observable facts)
4. HOW DID YOU INFER IT? (Step-by-step reasoning and data flow logic)
5. WHAT ALTERNATIVES EXIST? (Negative analysis / counter-evidence)
6. CONFIDENCE? (0-100 numerical score)
7. WHAT WOULD CONFIRM IT / STATIC REMEDIATION? (Exact defensive fix)

==================================================
OUTPUT FORMAT:
Return a valid JSON array of findings matching the schema:
[
  {
    "finding": "Title of finding",
    "classification": "CONFIRMED | LIKELY | POSSIBLE | INCONCLUSIVE | REJECTED",
    "source_location": "FileName.ext:line_number",
    "evidence": "Concrete code snippet or extracted fact",
    "data_flow": "Source -> Transform -> Sink path",
    "reasoning": "Step-by-step logic supporting the deduction",
    "counter_evidence": "Disproving factors or alternative benign explanations",
    "security_impact": "Impact description",
    "confidence": 0-100,
    "requires_runtime_validation": true/false,
    "static_remediation": "Prescribed secure code fix"
  }
]
"""


class StaticFinding(BaseModel):
    finding: str
    classification: str = Field(description="CONFIRMED | LIKELY | POSSIBLE | INCONCLUSIVE | REJECTED")
    source_location: str
    evidence: str
    data_flow: str
    reasoning: str
    counter_evidence: Optional[str] = ""
    security_impact: str
    confidence: int = Field(ge=0, le=100)
    requires_runtime_validation: bool = False
    static_remediation: str


class ReasoningMemoryItem(BaseModel):
    observation: str
    evidence: List[str]
    hypothesis: str
    reasoning: List[str]
    counter_evidence: List[str] = []
    confidence: int
    classification: str
    requires_runtime_validation: bool = False


class StaticSecurityReasoningEngine:
    """محرك الاستنتاج الأمني الثابت للأكواد والمصادر البرمجية"""

    def __init__(self):
        self.system_prompt = STATIC_SECURITY_REASONING_SYSTEM_PROMPT
        self.reasoning_memory: List[Dict[str, Any]] = []

    async def analyze_source(
        self,
        source_code: str,
        target_name: str = "Component",
        additional_context: str = ""
    ) -> Dict[str, Any]:
        """
        تشغيل دورة الاستنتاج الأمني الشاملة (8-Phase Pipeline)
        """
        user_prompt = f"""Target Component / File: {target_name}
Context: {additional_context or 'Static code analysis'}

Analyze the following source code using the 8-phase reasoning methodology:

```
{source_code}
```

Apply Data Flow Analysis, Hypothesis Generation, and Negative Analysis to produce your findings strictly in the specified JSON array format."""

        raw_response = await AIReasoningCore.ask_ai(user_prompt, system_prompt=self.system_prompt)
        findings = self._parse_json_findings(raw_response)

        # Build Reasoning Memory items
        memory_items = []
        for f in findings:
            mem = ReasoningMemoryItem(
                observation=f.finding,
                evidence=[f.source_location, f.evidence],
                hypothesis=f"Potential {f.finding} vulnerability in {f.source_location}",
                reasoning=[f.reasoning, f"Data Flow: {f.data_flow}"],
                counter_evidence=[f.counter_evidence] if f.counter_evidence else [],
                confidence=f.confidence,
                classification=f.classification,
                requires_runtime_validation=f.requires_runtime_validation
            )
            self.reasoning_memory.append(mem.model_dump())
            memory_items.append(mem.model_dump())

        return {
            "target": target_name,
            "total_findings": len(findings),
            "findings": [f.model_dump() for f in findings],
            "reasoning_memory": memory_items,
            "raw_analysis": raw_response
        }

    def _parse_json_findings(self, text: str) -> List[StaticFinding]:
        if not text:
            return []
        findings = []
        try:
            start = text.find("[")
            end = text.rfind("]")
            if start != -1 and end != -1:
                data = json.loads(text[start:end+1])
                for item in data:
                    try:
                        findings.append(StaticFinding(**item))
                    except Exception as fe:
                        log.debug(f"Skipping malformed finding item: {fe}")
        except Exception as e:
            log.warning(f"Failed to parse reasoning JSON findings: {e}")
        return findings
