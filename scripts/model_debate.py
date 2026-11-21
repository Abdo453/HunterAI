#!/usr/bin/env python3
"""
Multi-Model Collaborative Debate & Dialogue System
يدير نقاشاً تفاعلياً وتفكيراً مشتركاً بين النماذج المحلية في Ollama.
"""

import sys
import json
import urllib.request

MODELS = {
    "thinker": {
        "name": "qwen-dialogue:8b",
        "role_ar": "المحلل الاستراتيجي وموجه المتصفح (AI Browser Navigator)",
        "role_desc": "قيادة المتصفح، استكشاف واجهات التطبيق، تحليل المسارات، والتخطيط الاستراتيجي."
    },
    "engineer": {
        "name": "qwen-coder-pro:14b",
        "role_ar": "كبير مهندسي البرمجيات والأكواد (Script & Exploit Engineer)",
        "role_desc": "كتابة سكربتات الاستغلال، أتمتة الأدوات، تحليل الشفرة المصدرية، وتوليد كود خالي من الأخطاء."
    },
    "critic": {
        "name": "redteam-pro:8b",
        "role_ar": "قائد الفريق الأحمر ومراقب Burp Suite (Traffic & Vulnerability Lead)",
        "role_desc": "اعتراض وتحليل حركة المرور بـ Burp Suite، كشف ثغرات المنطق، كسر الـ WAF، وتقييم الأثر."
    }
}

def call_ollama(model: str, prompt: str, system: str = "") -> str:
    url = "http://127.0.0.1:11434/api/chat"
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})
    
    payload = json.dumps({
        "model": model,
        "messages": messages,
        "stream": False,
        "options": {"num_ctx": 3072, "temperature": 0.7}
    }).encode("utf-8")
    
    req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=90) as response:
            res_data = json.loads(response.read().decode("utf-8"))
            return res_data.get("message", {}).get("content", "").strip()
    except Exception as e:
        return f"[خطأ في الاتصال بالنموذج {model}: {e}]"

def run_debate(topic: str, rounds: int = 1):
    print("\n" + "═"*60)
    print(f"🎯 موضوع الحوار والنقاش: {topic}")
    print("═"*60 + "\n")
    
    # الجولة 1: المفكر يبدأ بالتحليل والرؤية
    print(f"🧠 [1. {MODELS['thinker']['role_ar']} - {MODELS['thinker']['name']}]:")
    thinker_system = (
        "أنت محاور فصيح وعميق التفكير. افتتح النقاش حول الموضوع التالي ببيان بليغ "
        "وتحليل منطقي لأبعاده وجوهره، باللغة العربية الفصحى."
    )
    thought_output = call_ollama(MODELS["thinker"]["name"], topic, thinker_system)
    print(thought_output + "\n")
    print("-" * 50)
    
    # الجولة 2: المهندس يقدم الحل العملي والتطبيقي
    print(f"⚙️ [2. {MODELS['engineer']['role_ar']} - {MODELS['engineer']['name']}]:")
    engineer_system = (
        f"بناءً على طرح المفكر:\n{thought_output}\n\n"
        "قدم خطة تنفيذية تفصيلية، حلولاً برمجية أو خطوات عملية واضحة لتطبيق هذه الرؤية."
    )
    engineer_output = call_ollama(MODELS["engineer"]["name"], "كيف نحول هذه الفكرة إلى واقع تطبيقي دقيق؟", engineer_system)
    print(engineer_output + "\n")
    print("-" * 50)
    
    # الجولة 3: الناقد يراجع ويطور المخرجات
    print(f"🛡️ [3. {MODELS['critic']['role_ar']} - {MODELS['critic']['name']}]:")
    critic_system = (
        f"الرؤية والحل المطروح:\n{engineer_output}\n\n"
        "قم بمراجعة ونقد هذا الطرح بموضوعية ودقة. ما هي المخاطر، نقاط الضعف، وكيف نطور هذا الحل ليكون متكاملاً؟"
    )
    critic_output = call_ollama(MODELS["critic"]["name"], "قيم هذا الحل وانقده لتطويره بأعلى جودة.", critic_system)
    print(critic_output + "\n")
    print("═"*60)
    print("✅ اكتملت جلسة التفكير والنقاش المشترك بين النماذج بنجاح!")
    print("═"*60 + "\n")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        user_topic = " ".join(sys.argv[1:])
    else:
        user_topic = "كيف نبني نظام ذكاء اصطناعي محلي متعدد الوكلاء يتعلم ذاتياً ويتفادى الثغرات؟"
    run_debate(user_topic)
