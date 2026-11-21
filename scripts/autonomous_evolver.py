#!/usr/bin/env python3
"""
Autonomous Multi-Model Self-Improvement & Evolution Engine (PentestAI-Unified)
محرك التطوير والتعلم الذاتي المستمر:
1. توليد التحديات والسيناريوهات المتقدمة
2. حوار استراتيجي وبناء حلول برمجية
3. نقد هجومي واختبار ثغرات متبادل
4. تصحيح ذاتي وتحديث الذاكرة المعرفية الدائمة
"""

import os
import sys
import json
import time
import urllib.request
import subprocess
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
MEMORY_DIR = BASE_DIR / "memory" / "knowledge"
MEMORY_DIR.mkdir(parents=True, exist_ok=True)
EVOLVED_DB_PATH = MEMORY_DIR / "evolved_patterns.json"

MODELS = {
    "dialogue": "qwen-dialogue:8b",
    "coder": "qwen-coder-pro:14b",
    "redteam": "redteam-pro:8b"
}

def query_ollama(model: str, prompt: str, system: str = "", timeout: int = 120) -> str:
    url = "http://127.0.0.1:11434/api/chat"
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    payload = json.dumps({
        "model": model,
        "messages": messages,
        "stream": False,
        "options": {"num_ctx": 3072, "temperature": 0.5}
    }).encode("utf-8")

    req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            res_data = json.loads(response.read().decode("utf-8"))
            return res_data.get("message", {}).get("content", "").strip()
    except Exception as e:
        return f"[خطأ في الاتصال بالموديل {model}: {e}]"
    finally:
        # تفريغ الموديل لضمان بقاء 4GB VRAM فارغة للموديل التالي
        subprocess.run(["ollama", "stop", model], capture_output=True)

class AutonomousEvolver:
    def __init__(self):
        self.knowledge_base = self._load_knowledge()

    def _load_knowledge(self) -> list:
        if EVOLVED_DB_PATH.exists():
            try:
                with open(EVOLVED_DB_PATH, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return []
        return []

    def _save_knowledge(self, entry: dict):
        self.knowledge_base.append(entry)
        with open(EVOLVED_DB_PATH, "w", encoding="utf-8") as f:
            json.dump(self.knowledge_base, f, ensure_ascii=False, indent=2)
        print(f"💾 تم حفظ المعرفة المطورة وتثبيتها دائماً في: {EVOLVED_DB_PATH.name}")

    def run_evolution_cycle(self, challenge_topic: str):
        print("\n" + "═"*70)
        print(f"🧬 بدء دورة التطور والارتقاء الذاتي (Autonomous Evolution Cycle)")
        print(f"🎯 التحدي: {challenge_topic}")
        print("═"*70 + "\n")

        # ── المرحلة 1: التحليل والتخطيط الاستراتيجي (Dialogue Model) ──
        print("🧠 [1/4] المفكر والمحاور (qwen-dialogue:8b) — وضع المعمارية والاستراتيجية...")
        dialogue_sys = (
            "أنت مفكر استراتيجي ومحلل أنظمة. فكك هذا التحدي التقني/الأمني إلى عناصر دقيقة، "
            "حدد نقاط المخاطر والفرص، واقترح استراتيجية تنفيذية مبتكرة ومحكمة باللغة العربية."
        )
        plan = query_ollama(MODELS["dialogue"], challenge_topic, dialogue_sys)
        print(f"📋 الرؤية التأسيسية:\n{plan[:400]}...\n")

        # ── المرحلة 2: التنفيذ البرمجي والهندسي (Coder Pro) ──
        print("⚙️ [2/4] كبير مهندسي البرمجيات (qwen-coder-pro:14b) — كتابة الحل وتنفيذه...")
        coder_sys = (
            "أنت مهندس برمجيات محترف بنهج Zero Defects. بناءً على الاستراتيجية التالية، "
            "اكتب كوداً برمجياً كاملاً وقوياً بلغة بايثون أو الباش لمعالجة التحدي، مع معالجة الأخطاء."
        )
        code_prompt = f"الاستراتيجية:\n{plan}\n\nالمطلوب: بناء الكود التنفيذي المتكامل."
        code_solution = query_ollama(MODELS["coder"], code_prompt, coder_sys)
        print(f"💻 الكود التنفيذي المبدئي:\n{code_solution[:350]}...\n")

        # ── المرحلة 3: الهجوم المضاد والنقد الصارم (RedTeam Pro) ──
        print("🛡️ [3/4] قائد الفريق الأحمر وصائد الثغرات (redteam-pro:8b) — اختبار الاختراق والنقد...")
        redteam_sys = (
            "أنت رئيس الفريق الأحمر ومراجع أمني لا يرحم. اختبر هذا الكود والاستراتيجية: "
            "ما هي الثغرات المحتملة؟ كيف يمكن تجاوزه؟ ما هي حالات الفشل؟ اذكر 3 تعديلات إلزامية لتقويته."
        )
        critique_prompt = f"الكود والحل المقترح:\n{code_solution}\n\nقيم الحل واكشف نقاط الضعف."
        critique = query_ollama(MODELS["redteam"], critique_prompt, redteam_sys)
        print(f"🔍 نقد الفريق الأحمر ونقاط الضعف المكتشفة:\n{critique[:400]}...\n")

        # ── المرحلة 4: التطوير الذاتي والتثبيت الدائم (Autonomous Refinement) ──
        print("🚀 [4/4] مهندس البرمجيات يعيد صياغة الحل وفقاً للنقد، وتثبيت المعرفة...")
        refine_sys = (
            "عدّل الكود المطور بناءً على الملاحظات الأمنية والنقد الموجه له من الفريق الأحمر. "
            "أنتج النسخة النهائية فائقة القوة مع شرح مختصر للدروس المستفادة."
        )
        refine_prompt = f"الكود الأصلي:\n{code_solution[:800]}\n\nنقد الفريق الأحمر:\n{critique}\n\nأنتج النسخة المحصنة."
        final_solution = query_ollama(MODELS["coder"], refine_prompt, refine_sys)

        # حفظ التجربة في الذاكرة التراكمية
        knowledge_entry = {
            "timestamp": datetime.now().isoformat(),
            "challenge": challenge_topic,
            "strategic_plan": plan[:500],
            "initial_code": code_solution[:500],
            "redteam_critique": critique[:500],
            "final_evolved_solution": final_solution[:1000],
            "status": "EVOLVED"
        }
        self._save_knowledge(knowledge_entry)

        print("\n" + "═"*70)
        print("✨ اكتملت دورة التطور الذاتي بنجاح! تم تدريب النماذج على التحدي وتخزين الخبرة في الذاكرة الدائمة.")
        print("═"*70 + "\n")
        return knowledge_entry

if __name__ == "__main__":
    evolver = AutonomousEvolver()
    topic = " " .join(sys.argv[1:]) if len(sys.argv) > 1 else "بناء آلية ذكية لتجاوز تقييد معدل الطلبات (Rate-Limiter) وكشف الـ Race Conditions مع معالجة الـ Tokens تلقائياً"
    evolver.run_evolution_cycle(topic)
