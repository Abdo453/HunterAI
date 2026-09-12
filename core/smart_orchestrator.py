"""
New Orchestrator — يستخدم Router + Resource Manager + Memory
هذا هو الـ Orchestrator الجديد الذكي
"""
import asyncio
import json
import time
import uuid
import os
import logging
from typing import Optional, Callable, Dict, Any, List, Tuple

from models.ollama_manager import OllamaManager
from orchestrator.resource_manager import ResourceManager
from orchestrator.router import ModelRouter
from orchestrator.task_classifier import TaskClassifier
from memory.task_memory import TaskMemory, TaskRecord
from core.session_manager import SessionManager
from core.report_engine import ReportEngine
from tools.tool_manager import ToolManager

log = logging.getLogger("smart_orchestrator")


class SmartOrchestrator:
    """
    الـ Orchestrator الذكي الجديد
    
    المبادئ:
    1. موديل محلي واحد فقط على GPU في أي وقت
    2. API models تشتغل بالتوازي بدون قيود
    3. كل شيء يمر عبر الـ Router
    4. الذاكرة محفوظة عبر الجلسة
    """

    def __init__(self, progress_callback: Optional[Callable] = None):
        self.cb = progress_callback

        # Core components
        ollama_host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
        self.ollama = OllamaManager(host=ollama_host)
        self.resource_manager = ResourceManager(self.ollama)
        self.router = ModelRouter(self.resource_manager, progress_callback)
        self.classifier = TaskClassifier()
        self.memory = TaskMemory()

        # Pentest components (للاستخدام مع الـ agents)
        self.sessions = SessionManager()
        self.tools = ToolManager()

        log.info(f"SmartOrchestrator initialized | Ollama: {ollama_host}")

    async def _emit(self, event: str, data: dict):
        if self.cb:
            try:
                await self.cb({"event": event, **data})
            except Exception:
                pass

    async def chat(self, user_input: str, selected_model: str = "auto") -> Dict[str, Any]:
        """
        المحادثة الرئيسية — يستقبل سؤال/مهمة وموديل اختياري ويرجع نتيجة
        """
        t0 = time.time()

        # تسجيل في الذاكرة
        self.memory.add_user_message(user_input)
        context = self.memory.get_context(max_messages=4)

        await self._emit("chat_start", {
            "input": user_input[:100],
            "selected_model": selected_model,
            "gpu_free": self.resource_manager.is_gpu_free()
        })

        if selected_model == "auto" or not selected_model:
            # توجيه تلقائي عبر الـ Router
            result = await self.router.route(user_input, context)
            final = result.get("final", "")
            route = result.get("route", "UNKNOWN")
            models_used = result.get("models_used", [])
        elif selected_model.startswith("local:"):
            # تشغيل موديل محلي محدد يدوياً على الـ GPU
            model_name = selected_model.replace("local:", "").strip()
            from orchestrator.router import PROMPTS
            sys_p = "You are a helpful expert security and coding AI assistant."
            if "whiterabbit" in model_name.lower():
                sys_p = PROMPTS.get("whiterabbitneo", sys_p)
            elif "xploiter" in model_name.lower():
                sys_p = PROMPTS.get("xploiter", sys_p)
            elif "qwen" in model_name.lower():
                sys_p = PROMPTS.get("qwen", sys_p)

            await self._emit("task_classified", {
                "task_type": "MANUAL",
                "confidence": 1.0,
                "reasoning": f"Manual model selected by user: {model_name}",
                "models": [model_name],
            })
            await self._emit("step", {"step": 1, "model": model_name, "action": "Generating response..."})

            messages = [
                {"role": "system", "content": sys_p},
                {"role": "user", "content": f"Context:\n{context}\n\nTask: {user_input}" if context else user_input}
            ]
            final = await self.resource_manager.run_local_model(
                model_name=model_name,
                messages=messages,
                temperature=0.3,
                progress_cb=self.cb
            )
            route = f"MANUAL:{model_name.split('/')[-1].split(':')[0]}"
            models_used = [model_name]
            await self._emit("step_done", {"step": 1, "model": model_name, "chars": len(final)})
            await self._emit("route_done", {"route": route, "models_used": 1})

        elif selected_model.startswith("api:"):
            # تشغيل موديل API محدد يدوياً (OpenRouter)
            api_model = selected_model.replace("api:", "").strip()
            await self._emit("task_classified", {
                "task_type": "MANUAL_API",
                "confidence": 1.0,
                "reasoning": f"Manual Cloud API model selected: {api_model}",
                "models": [api_model],
            })
            await self._emit("step", {"step": 1, "model": api_model, "action": "Querying Cloud API..."})

            final = await self._call_openrouter_direct(api_model, user_input, context)
            route = f"API:{api_model.split('/')[-1]}"
            models_used = [api_model]
            await self._emit("step_done", {"step": 1, "model": api_model, "chars": len(final)})
            await self._emit("route_done", {"route": route, "models_used": 1})
        else:
            result = await self.router.route(user_input, context)
            final = result.get("final", "")
            route = result.get("route", "UNKNOWN")
            models_used = result.get("models_used", [])

        duration = time.time() - t0

        # حفظ في الذاكرة
        self.memory.add_assistant_message(final, metadata={"route": route, "model": selected_model})

        # حفظ المهمة
        task = TaskRecord(
            id=str(uuid.uuid4())[:8],
            timestamp=str(time.time()),
            user_input=user_input,
            task_type=route,
            route=route,
            models_used=models_used,
            final_answer=final[:500],
            duration_seconds=round(duration, 2),
            metadata={"gpu_status": self.resource_manager.status, "selected_model": selected_model}
        )
        self.memory.add_task(task)

        await self._emit("chat_done", {
            "route": route,
            "duration": round(duration, 2),
            "gpu_status": self.resource_manager.status,
            "chars": len(final),
            "model_used": selected_model
        })

        return {
            "answer": final,
            "route": route,
            "duration": round(duration, 2),
            "gpu_status": self.resource_manager.status,
            "memory": self.memory.summary(),
            "selected_model": selected_model
        }

    async def _call_openrouter_direct(self, model_id: str, prompt: str, context: str = "") -> str:
        """استدعاء OpenRouter مباشرة لموديل محدد مع دفق الرموز Streaming"""
        import httpx, json
        key = os.getenv("OPENROUTER_API_KEY", "")
        if not key:
            return "Error: OPENROUTER_API_KEY is not configured in .env"
        
        messages = [
            {"role": "system", "content": "You are an expert AI assistant specializing in software engineering, cybersecurity, and problem-solving. Provide accurate, clean, and well-explained answers."}
        ]
        if context:
            messages.append({"role": "user", "content": f"Previous context:\n{context}\n\nTask: {prompt}"})
        else:
            messages.append({"role": "user", "content": prompt})

        full_content = []
        try:
            async with httpx.AsyncClient(timeout=60) as client:
                async with client.stream(
                    "POST",
                    "https://openrouter.ai/api/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {key}",
                        "HTTP-Referer": "https://pentestai.local",
                        "X-Title": "PentestAI Unified",
                    },
                    json={
                        "model": model_id,
                        "messages": messages,
                        "temperature": 0.3,
                        "max_tokens": 4000,
                        "stream": True
                    }
                ) as resp:
                    resp.raise_for_status()
                    async for line in resp.aiter_lines():
                        if not line or not line.startswith("data: "):
                            continue
                        data_str = line[6:].strip()
                        if data_str == "[DONE]":
                            break
                        try:
                            chunk = json.loads(data_str)
                            delta = chunk.get("choices", [{}])[0].get("delta", {}).get("content", "")
                            if delta:
                                full_content.append(delta)
                                await self._emit("chat_token", {"token": delta, "model": model_id})
                        except Exception:
                            continue
            return "".join(full_content)
        except Exception as e:
            log.error(f"OpenRouter direct call error: {e}")
            return f"Error connecting to OpenRouter ({model_id}): {str(e)}"

    async def _call_all_active_apis(self, prompt: str) -> List[Dict[str, str]]:
        """تشغيل كافة الـ Cloud APIs المتوفرة بالتوازي للحصول على استشارات ومراجعات أمنية سريعة وبث النتائج لحظياً"""
        tasks = []

        # 1. Gemini
        if os.getenv("GEMINI_API_KEY"):
            from models.api.gemini_provider import GeminiProvider
            gem_model = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")
            gm = GeminiProvider(model=gem_model)
            tasks.append((gm.generate(prompt), "gemini", f"Google Gemini ({gem_model})"))


        # 2. OpenRouter
        if os.getenv("OPENROUTER_API_KEY"):
            from models.api.openrouter_provider import OpenRouterProvider
            p = OpenRouterProvider(model="meta-llama/llama-3.3-70b-instruct")
            tasks.append((p.generate(prompt), "openrouter", "OpenRouter (Llama 3.3 70B)"))

        # 3. Taskade
        if os.getenv("TASKADE_API_KEY"):
            from models.api.taskade_provider import TaskadeProvider
            tk = TaskadeProvider()
            tasks.append((tk.generate(prompt), "taskade", "Taskade Cyber Agent"))

        # 4. Groq
        if os.getenv("GROQ_API_KEY"):
            from models.api.groq_provider import GroqProvider
            g = GroqProvider()
            tasks.append((g.generate(prompt), "groq", "Groq (Llama 3.3 70B)"))

        # 5. OpenAI
        if os.getenv("OPENAI_API_KEY"):
            from models.api.openai_provider import OpenAIProvider
            o = OpenAIProvider(model="gpt-4o")
            tasks.append((o.generate(prompt), "openai", "OpenAI (GPT-4o)"))

        # 6. DeepSeek
        if os.getenv("DEEPSEEK_API_KEY"):
            from models.api.deepseek_provider import DeepSeekProvider
            ds = DeepSeekProvider()
            tasks.append((ds.generate(prompt), "deepseek", "DeepSeek-V3"))

        # 7. Anthropic / Claude
        if os.getenv("ANTHROPIC_API_KEY"):
            from models.api.anthropic_provider import AnthropicProvider
            ant_model = os.getenv("ANTHROPIC_MODEL", "claude-3-5-sonnet-20241022")
            ant = AnthropicProvider(model=ant_model)
            tasks.append((ant.generate(prompt), "anthropic", f"Anthropic ({ant_model})"))

        if not tasks:
            return []

        await self._emit("api_start", {
            "models": [name for _, _, name in tasks]
        })

        async def _run_one(coro, key, display_name):
            try:
                await self._emit("api_model_active", {"key": key, "name": display_name})
                resp = await coro
                content = getattr(resp, "content", "") if resp else ""
                if content:
                    await self._emit("api_response", {
                        "key": key,
                        "api": display_name,
                        "summary": content[:400],
                        "full": content
                    })
                    return {"key": key, "api": display_name, "content": content}
            except Exception as e:
                log.warning(f"Error calling {display_name}: {e}")
                await self._emit("api_model_error", {"key": key, "name": display_name, "error": str(e)})
            return None

        results = await asyncio.gather(*[_run_one(c, k, n) for c, k, n in tasks])
        valid_results = [r for r in results if r is not None]
        await self._emit("api_done", {"count": len(valid_results)})
        return valid_results

    async def run_scan(self, target: str, mode: str = "bugbounty_full",
                       use_browser: bool = False, use_proxy: bool = False,
                       burp_proxy: str = "127.0.0.1:8080",
                       auth: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Pentest scan — يستخدم الـ agents + Router للتحليل مع توجيه البروكسي والمصادقة
        """
        session = self.sessions.create_session(target, mode)
        proxy_url = f"http://{burp_proxy}" if use_proxy else None
        if use_proxy:
            os.environ["HTTP_PROXY"] = proxy_url
            os.environ["HTTPS_PROXY"] = proxy_url
            os.environ["NO_PROXY"] = "localhost,127.0.0.1,192.168.1.0/24,192.168.0.0/16,10.0.0.0/8,::1"
            os.environ["no_proxy"] = os.environ["NO_PROXY"]

        await self._emit("session_created", {
            "session_id": session.id, "target": target, "mode": mode, "proxy": proxy_url,
            "authenticated": bool(auth and (auth.get("username") or auth.get("cookie")))
        })

        # ── Phase 1: استراتيجية عبر Router ──
        await self._emit("phase", {"phase": "strategy", "message": f"Building attack strategy | Proxy: {proxy_url or 'Direct'}{' | 🔐 Auth Configured' if auth and (auth.get('username') or auth.get('cookie')) else ''}..."})

        strategy_prompt = (
            f"Security Assessment & Vulnerability Pentest for Target: {target}\n"
            f"Mode: {mode}\n"
            f"Authentication: {json.dumps(auth or {})}\n"
            f"1. Attack surface and vulnerability prioritization\n"
            f"2. Security toolchain recommendations\n"
            f"3. Risk assessment and methodology"
        )

        from orchestrator.task_classifier import ClassificationResult, TaskType
        sec_cl = ClassificationResult(
            task_type=TaskType.SECURITY,
            confidence=0.95,
            reasoning="Automated Pentest Scan",
            security_score=1.0,
            coding_score=0.0,
            suggested_models=["WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B:latest", "xploiter/pentester:latest"],
            use_local_first=True
        )

        # تشغيل الـ Cloud APIs بالتوازي مع الموديلات المحلية
        api_future = asyncio.create_task(self._call_all_active_apis(strategy_prompt))
        strategy_result = await self.router._security_route(strategy_prompt, "", sec_cl)
        strategy = strategy_result.get("final", "")

        api_results = await api_future
        if api_results:
            api_notes = "\n\n".join([f"### 🌐 Cloud API ({r['api']}):\n{r['content'][:600]}" for r in api_results])
            strategy += f"\n\n{api_notes}"

        await self._emit("strategy_ready", {
            "route": "SECURITY + CLOUD APIs" if api_results else "SECURITY",
            "summary": strategy[:250]
        })

        # ── Phase 2: AutonomousBrain — OODA Loop (Decide → Act → Verify) ──
        await self._emit("phase", {
            "phase": "scanning",
            "message": "AutonomousBrain: WhiteRabbitNeo deciding → tools executing → xploiter verifying..."
        })

        from core.brain.autonomous_brain import AutonomousBrain
        from agents.base_agent import AgentResult

        brain = AutonomousBrain(self.resource_manager, self.tools, self.cb)
        await self._emit("agent_start", {"agent": "AutonomousBrain"})

        agent_results = []
        try:
            brain_result = await brain.run_scan(
                target=target,
                mode=mode,
                auth=auth,
                proxy=proxy_url,
                use_browser=use_browser,
                use_proxy=use_proxy
            )
            r_obj = AgentResult(agent_name="AutonomousBrain", target=target)
            r_obj.findings = brain_result.get("findings", [])
            agent_results.append(r_obj)
            await self._emit("agent_done", {
                "agent": "AutonomousBrain",
                "findings": len(r_obj.findings),
                "params_audited": brain_result.get("params_audited", []),
                "plan": brain_result.get("plan", {}),
            })
        except Exception as e:
            log.error(f"AutonomousBrain error: {e}", exc_info=True)
            await self._emit("agent_error", {"agent": "AutonomousBrain", "error": str(e)})

        # ── Phase 3: تحليل النتائج وكتابة الترقيع عبر Qwen Coder (14B) + Cloud APIs ──
        if agent_results:
            await self._emit("phase", {"phase": "analysis", "message": "Qwen Coder & Cloud APIs analyzing findings & remediation..."})

            raw_results = "\n\n".join([
                f"[{r.agent_name}] Findings: {len(r.findings)}\n" +
                "\n".join([f"  - {f.get('title','')} ({f.get('severity','')})" for f in r.findings[:5]])
                for r in agent_results
            ])

            analysis_prompt = (
                f"Analyze these penetration testing results for {target}:\n{raw_results}\n\n"
                f"Provide: Code remediation patch, secure coding advice, and vulnerability analysis."
            )

            cod_cl = ClassificationResult(
                task_type=TaskType.CODING,
                confidence=0.95,
                reasoning="Vulnerability Remediation & Code Analysis",
                security_score=0.2,
                coding_score=0.8,
                suggested_models=["qwen2.5-coder:14b"],
                use_local_first=True
            )
            api_analysis_future = asyncio.create_task(self._call_all_active_apis(analysis_prompt))
            analysis_result = await self.router._coding_route(analysis_prompt, strategy[:200], cod_cl)
            analysis = analysis_result.get("final", "")

            api_analysis_res = await api_analysis_future
            if api_analysis_res:
                api_notes = "\n\n".join([f"### 🌐 Cloud API Remediation Review ({r['api']}):\n{r['content'][:600]}" for r in api_analysis_res])
                analysis += f"\n\n{api_notes}"
        else:
            analysis = strategy

        # ── Phase 4: Save + Report ──
        from core.session_manager import Finding
        import uuid as uuid_mod
        SEV_CVSS = {"Critical": 9.5, "High": 7.5, "Medium": 5.5, "Low": 2.5, "Info": 0.0}

        for ar in agent_results:
            for fd in ar.findings:
                sev = fd.get("severity", "Info")
                f = Finding(
                    id=str(uuid_mod.uuid4())[:8],
                    title=fd.get("title", ""),
                    description=fd.get("title", ""),
                    severity=sev,
                    cvss_score=SEV_CVSS.get(sev, 0.0),
                    tool=fd.get("tool", ""),
                    evidence=fd.get("evidence", ""),
                    recommendation=fd.get("recommendation", "Review and patch.")
                )
                self.sessions.add_finding(session, f)

        await self._emit("phase", {"phase": "reporting", "message": "Generating report..."})
        session = self.sessions.load(session.id)
        reports = ReportEngine().generate_all(session)
        self.sessions.complete(session)

        # Taskade export
        if os.getenv("TASKADE_API_KEY") and session.findings:
            try:
                from models.api.taskade_provider import TaskadeProvider
                tp = TaskadeProvider()
                findings_dicts = [{"title": f.title, "severity": f.severity, "tool": f.tool}
                                  for f in session.findings]
                taskade_url = await tp.export_findings_to_taskade(session.id, findings_dicts)
                reports["taskade"] = taskade_url
            except Exception as e:
                log.warning(f"Taskade export failed: {e}")

        summary = {
            "session_id": session.id,
            "target": target,
            "mode": mode,
            "total_findings": len(session.findings),
            "critical": sum(1 for f in session.findings if f.severity == "Critical"),
            "high": sum(1 for f in session.findings if f.severity == "High"),
            "medium": sum(1 for f in session.findings if f.severity == "Medium"),
            "low": sum(1 for f in session.findings if f.severity == "Low"),
            "reports": reports,
            "gpu_status": self.resource_manager.status,
            "analysis": analysis[:500]
        }

        await self._emit("scan_complete", summary)
        return summary

    @property
    def gpu_status(self) -> dict:
        return self.resource_manager.status

    @property
    def memory_summary(self) -> dict:
        return self.memory.summary()
