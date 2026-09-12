"""
Ollama Manager — إدارة تحميل وتفريغ الموديلات المحلية
يستخدم OLLAMA_KEEP_ALIVE=0 لضمان تفريغ الموديل من الـ GPU بعد الاستخدام
"""
import asyncio
import httpx
import os
import logging
from typing import Optional

log = logging.getLogger("ollama_manager")

def normalize_ollama_host(h: str) -> str:
    if not h:
        return "http://127.0.0.1:11434"
    h = str(h).strip().rstrip("/")
    if not h.startswith("http://") and not h.startswith("https://"):
        h = f"http://{h}"
    # 0.0.0.0 is for binding, clients must connect to 127.0.0.1
    h = h.replace("://0.0.0.0:", "://127.0.0.1:")
    return h


OLLAMA_HOST = normalize_ollama_host(os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434"))


class OllamaManager:
    """
    مدير الموديلات المحلية — يضمن:
    1. موديل واحد فقط محمّل في الـ GPU في أي وقت
    2. تفريغ الموديل بعد الاستخدام مباشرة
    3. مراقبة حالة الموديلات
    """

    def __init__(self, host: str = None):
        self.host = normalize_ollama_host(host or OLLAMA_HOST)
        self._current_loaded: Optional[str] = None

    async def get_active_host(self) -> str:
        """فحص واكتشاف عنوان Ollama النشط تلقائياً (سواء IP الشبكة أو 127.0.0.1)"""
        candidates = [
            self.host,
            "http://192.168.1.3:11434",
            "http://127.0.0.1:11434",
            "http://localhost:11434",
            "http://10.0.2.2:11434"
        ]
        for cand in dict.fromkeys(candidates):
            if not cand:
                continue
            try:
                async with httpx.AsyncClient(timeout=1.5, trust_env=False) as c:
                    r = await c.get(f"{cand}/api/tags")
                    if r.status_code == 200:
                        self.host = cand
                        return cand
            except Exception:
                continue
        return self.host


    async def get_loaded_models(self) -> list:
        """GET /api/ps — موديلات محمّلة حالياً في الذاكرة"""
        host = await self.get_active_host()
        try:
            async with httpx.AsyncClient(timeout=5, trust_env=False) as c:
                r = await c.get(f"{host}/api/ps")
                if r.status_code == 200:
                    return r.json().get("models", [])
        except Exception:
            pass
        return []


    async def unload_model(self, model_name: str) -> bool:
        """
        تفريغ موديل من الـ GPU
        trick: نرسل generate بـ keep_alive=0 يفرغه فوراً
        """
        log.info(f"[UNLOAD] {model_name}")
        payload = {
            "model": model_name,
            "prompt": "",
            "keep_alive": 0,
            "stream": False
        }
        try:
            async with httpx.AsyncClient(timeout=10, trust_env=False) as c:
                await c.post(f"{self.host}/api/generate", json=payload)
            self._current_loaded = None
            log.info(f"[UNLOAD] Done: {model_name}")
            return True
        except Exception as e:
            log.warning(f"[UNLOAD] Failed {model_name}: {e}")
            return False

    async def unload_all(self):
        """تفريغ كل الموديلات المحمّلة"""
        loaded = await self.get_loaded_models()
        for m in loaded:
            await self.unload_model(m.get("name", ""))
        self._current_loaded = None

    async def preload_model(self, model_name: str) -> bool:
        """
        تحميل موديل مسبقاً في الذاكرة بدون توليد
        keep_alive=-1 يخليه في الذاكرة indefinitely
        """
        log.info(f"[PRELOAD] {model_name}")
        payload = {
            "model": model_name,
            "prompt": "",
            "keep_alive": -1,
            "stream": False
        }
        try:
            async with httpx.AsyncClient(timeout=60, trust_env=False) as c:
                r = await c.post(f"{self.host}/api/generate", json=payload)
                if r.status_code == 200:
                    self._current_loaded = model_name
                    log.info(f"[PRELOAD] Ready: {model_name}")
                    return True
        except Exception as e:
            log.warning(f"[PRELOAD] Failed {model_name}: {e}")
        return False

    async def chat(self, model_name: str, messages: list, keep_alive: int = 0,
                   temperature: float = 0.3, num_ctx: int = 4096) -> str:
        """
        استدعاء موديل + تفريغه بعد الانتهاء (keep_alive=0)
        """
        payload = {
            "model": model_name,
            "messages": messages,
            "stream": False,
            "keep_alive": keep_alive,  # 0 = unload after this call
            "options": {
                "temperature": temperature,
                "num_ctx": num_ctx
            }
        }
        try:
            async with httpx.AsyncClient(timeout=180, trust_env=False) as c:
                r = await c.post(f"{self.host}/api/chat", json=payload)
                r.raise_for_status()
                content = r.json().get("message", {}).get("content", "")
                if keep_alive == 0:
                    self._current_loaded = None
                else:
                    self._current_loaded = model_name
                return content
        except Exception as e:
            log.error(f"[CHAT] {model_name} error: {e}")
            return ""

    async def chat_stream(self, model_name: str, messages: list, keep_alive: int = 0,
                          temperature: float = 0.3, num_ctx: int = 4096,
                          token_cb = None) -> str:
        """
        استدعاء موديل مع دفق الرموز (Streaming Tokens) بشكل فوري لحظي
        """
        import json
        payload = {
            "model": model_name,
            "messages": messages,
            "stream": True,
            "keep_alive": keep_alive,
            "options": {
                "temperature": temperature,
                "num_ctx": num_ctx
            }
        }
        full_content = []

        host = await self.get_active_host()
        try:
            async with httpx.AsyncClient(timeout=180, trust_env=False) as c:
                async with c.stream("POST", f"{host}/api/chat", json=payload) as r:

                    r.raise_for_status()
                    async for line in r.aiter_lines():
                        if not line:
                            continue
                        try:
                            chunk = json.loads(line)
                            delta = chunk.get("message", {}).get("content", "")
                            if delta:
                                full_content.append(delta)
                                if token_cb:
                                    await token_cb(delta)
                            if chunk.get("done", False):
                                break
                        except Exception:
                            continue
            result = "".join(full_content)
            if keep_alive == 0:
                self._current_loaded = None
            else:
                self._current_loaded = model_name
            return result
        except Exception as e:
            log.error(f"[CHAT_STREAM] {model_name} error: {e}")
            return "".join(full_content)

    async def is_model_available(self, model_name: str) -> bool:
        """تحقق من وجود الموديل في Ollama"""
        host = await self.get_active_host()
        try:
            async with httpx.AsyncClient(timeout=5, trust_env=False) as c:
                r = await c.get(f"{host}/api/tags")
                if r.status_code == 200:
                    models = [m["name"].lower() for m in r.json().get("models", [])]
                    # مقارنة مرنة
                    name_lower = model_name.lower()
                    return any(
                        name_lower in m or m in name_lower or
                        name_lower.split(":")[0] in m.split(":")[0]
                        for m in models
                    )
        except Exception:
            pass
        return False

    async def list_available(self) -> list:
        """قائمة كل الموديلات المتاحة"""
        host = await self.get_active_host()
        try:
            async with httpx.AsyncClient(timeout=5, trust_env=False) as c:
                r = await c.get(f"{host}/api/tags")
                if r.status_code == 200:
                    return [m["name"] for m in r.json().get("models", [])]
        except Exception:
            pass
        return []


    @property
    def current_loaded(self) -> Optional[str]:
        return self._current_loaded
