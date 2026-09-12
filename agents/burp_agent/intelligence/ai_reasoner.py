"""
Deep Contextual AI Threat Reasoner for BurpAgent (Ollama Qwen2.5-Coder / xploiter)
"""
import json
import logging
from typing import Optional, Dict, Any
from agents.burp_agent.storage.models import HTTPRequestModel, HTTPResponseModel, AIAnalysisModel
from agents.burp_agent.memory.application_memory import ApplicationMemory

log = logging.getLogger("burp_agent.ai_reasoner")


class AIReasoner:
    """محلل التهديدات الذكي الذي يقرأ سياق التطبيق والطلب لتوليد استنتاجات عميقة"""

    def __init__(self, ollama_client=None, memory: Optional[ApplicationMemory] = None):
        self.ollama = ollama_client
        self.memory = memory or ApplicationMemory()

    async def analyze_request_context(
        self,
        req: HTTPRequestModel,
        resp: Optional[HTTPResponseModel] = None
    ) -> Optional[AIAnalysisModel]:
        """تجهيز السياق الكامل واستدعاء نموذج الذكاء الاصطناعي لتحليل الثغرة"""
        context = {
            "target": req.host,
            "method": req.method,
            "url": req.url,
            "path": req.path,
            "parameters": [{"name": p.name, "value": p.value, "location": str(p.location)} for p in req.parameters],
            "headers": req.headers,
            "body_snippet": req.body[:1500] if req.body else None,
            "response_status": resp.status_code if resp else None,
            "response_snippet": resp.body[:1500] if (resp and resp.body) else None,
            "application_memory": self.memory.get_context_for_ai()
        }

        prompt = f"""You are an elite Senior Application Security Researcher.
Analyze the following HTTP transaction within its observed application context:

{json.dumps(context, indent=2)}

TASK:
1. Identify high-risk vulnerabilities (IDOR, Broken Object Level Auth, Privilege Escalation, Mass Assignment, Injection, SSRF).
2. Look closely at parameters ({[p.name for p in req.parameters]}) and user identifier controls.
3. Suggest the concrete attack path and remediation code.

Output JSON format strictly:
{{
  "is_vulnerable": true,
  "vulnerability_types": ["IDOR", "Privilege Escalation"],
  "confidence": 0.88,
  "analysis_summary": "Detailed technical explanation...",
  "suggested_attack_path": "Transition from user role to admin endpoint...",
  "remediation": "Validate server-side session ownership..."
}}
"""
        try:
            raw_output = None
            if self.ollama:
                raw_output = await self.ollama.generate(prompt=prompt, model="qwen2.5-coder:14b")

            if not raw_output:
                # Heuristic fallback
                is_idor = any(p.is_user_controlled_id for p in req.parameters)
                is_role = any(p.is_role_indicator for p in req.parameters)
                vulns = []
                if is_idor: vulns.append("Possible IDOR")
                if is_role: vulns.append("Privilege Escalation Risk")

                return AIAnalysisModel(
                    request_id=req.id,
                    model_name="HeuristicReasoner",
                    prompt_summary=f"{req.method} {req.path}",
                    analysis_text=f"Observed user controlled parameters: {[p.name for p in req.parameters if p.is_user_controlled_id or p.is_role_indicator]}",
                    suggested_vulns=vulns,
                    confidence_score=0.75 if vulns else 0.20,
                    attack_path_suggested="Test modifying parameter with another user ID" if is_idor else None,
                    created_at=req.timestamp
                )

            # Parse JSON from model
            parsed = json.loads(raw_output)
            return AIAnalysisModel(
                request_id=req.id,
                model_name="qwen2.5-coder:14b",
                prompt_summary=f"{req.method} {req.path}",
                analysis_text=parsed.get("analysis_summary", raw_output[:300]),
                suggested_vulns=parsed.get("vulnerability_types", []),
                confidence_score=float(parsed.get("confidence", 0.8)),
                attack_path_suggested=parsed.get("suggested_attack_path"),
                created_at=req.timestamp
            )

        except Exception as e:
            log.warning(f"[AIReasoner] Reasoning failed: {e}")
            return None
