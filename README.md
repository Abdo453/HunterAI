<div align="center">

# 🔥 PentestAI Unified

### نظام اختبار الاختراق المتكامل بالذكاء الاصطناعي
**3 موديلات محلية تتناقش مع بعض | 150+ أداة أمنية | Taskade Integration | Web UI + CLI**

</div>

---

## ⚡ الموديلات الـ 3

| الموديل | الدور | الحجم |
|---------|-------|-------|
| `xploiter/pentester:latest` | 🎯 خبير استراتيجية الـ pentest | 1.6 GB |
| `qwen2.5-coder:14b` | 💻 كاتب الـ exploits وتحليل الكود | ~9 GB |
| `WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B` | 🐇 متخصص offensive security | 4.7 GB |

### كيف يتناقشوا:
```
جولة 1: كل موديل يحلل الهدف باستقلالية
جولة 2: كل موديل يقرأ آراء الباقيين ويعلق ويضيف
جولة 3: WhiteRabbitNeo يلخص ويقرر الاستراتيجية النهائية
      ↓
الأدوات تتنفذ تلقائياً بناء على الاستراتيجية
      ↓
تقرير شامل بالثغرات + CVSS Score + Taskade Export
```

---

## 🚀 التشغيل السريع

```bash
# 1. تثبيت المتطلبات
pip install -r requirements.txt

# 2. .env جاهز بـ Taskade API
# (الملف موجود بالفعل مع TASKADE_API_KEY)

# 3. تشغيل Web UI
python main.py

# أو CLI
python main.py --cli

# أو scan مباشر
python main.py --target https://example.com --mode full
```

ثم افتح: **http://localhost:7070**

---

## 🛠️ المميزات

| الميزة | التفاصيل |
|--------|----------|
| 🤖 **Model Council** | 3 موديلات تتناقش في 3 جولات |
| 🌐 **Browser Testing** | Selenium + BurpSuite/ZAP proxy |
| 🛠️ **150+ أداة** | nmap, nuclei, sqlmap, gobuster, dalfox... |
| 📊 **CVSS Reports** | HTML + JSON مع CVSS 3.1 scoring |
| 📋 **Taskade Export** | النتائج تتصدر لـ Taskade تلقائياً |
| 💻 **Web UI + CLI** | Dashboard + Rich Terminal |
| 🔌 **Multi-API** | OpenAI + Groq + Claude + Gemini + DeepSeek + OpenRouter |

---

## 📁 هيكل المشروع

```
PentestAI-Unified/
├── core/
│   ├── orchestrator.py      ← المدير الرئيسي
│   ├── model_council.py     ← نظام تناقش الموديلات الـ 3
│   ├── session_manager.py   ← حفظ الجلسات
│   └── report_engine.py     ← تقارير CVSS
├── models/
│   ├── local/
│   │   ├── pentester_model.py      ← xploiter/pentester
│   │   ├── qwen_coder.py           ← qwen2.5-coder:14b
│   │   └── whiterabbitneo_model.py ← WhiteRabbitNeo
│   └── api/
│       ├── taskade_provider.py     ← Taskade AI + Export
│       ├── openai_provider.py
│       ├── groq_provider.py
│       ├── anthropic_provider.py
│       ├── gemini_provider.py
│       ├── deepseek_provider.py
│       └── openrouter_provider.py
├── agents/
│   ├── recon_agent.py       ← Port scan + subdomain + tech
│   ├── web_agent.py         ← Fuzzing + SQLi + XSS + nuclei
│   ├── browser_agent.py     ← Selenium + proxy
│   └── report_agent.py      ← تقارير + Taskade export
├── tools/
│   ├── tool_manager.py      ← مدير ذكي مع caching
│   ├── network_tools.py     ← nmap, masscan, rustscan
│   ├── web_tools.py         ← gobuster, nuclei, sqlmap, dalfox
│   ├── osint_tools.py       ← subfinder, amass, sherlock
│   └── browser_tools.py     ← Selenium controller
├── ui/
│   ├── web/                 ← FastAPI + WebSocket Dashboard
│   └── cli/                 ← Rich CLI
├── config/
│   ├── models.yaml          ← إعدادات الموديلات
│   ├── tools.yaml           ← إعدادات الأدوات
│   └── settings.yaml
├── data/
│   ├── sessions/            ← جلسات الـ pentest
│   └── reports/             ← التقارير HTML + JSON
├── .env                     ← Taskade key جاهز ✅
├── main.py
└── requirements.txt
```

---

## 🎯 Scan Modes

| Mode | الوصف |
|------|-------|
| `recon` | Port scan + subdomain enum + tech detection |
| `web` | Directory fuzzing + nuclei + SQLi + XSS |
| `full` | كل شيء (recon + web + reporting + Taskade) |
| `ctf` | CTF-focused |

---

## 📋 Taskade Integration

النظام يصدر النتائج تلقائياً لـ Taskade كـ project منظم:
- 🔴 Critical findings في الأول
- 🟠 High findings
- 🟡 Medium findings
- 🟢 Low findings

**API Key:** مُعَدَّل في `.env` تلقائياً ✅

---

## 🔌 إضافة API Models

أضف المفاتيح في `.env`:

```bash
GROQ_API_KEY=your_key        # مجاني وسريع جداً
OPENAI_API_KEY=your_key      # GPT-4o
ANTHROPIC_API_KEY=your_key   # Claude
GEMINI_API_KEY=your_key      # Gemini
DEEPSEEK_API_KEY=your_key    # DeepSeek
OPENROUTER_API_KEY=your_key  # أي موديل
```

الموديلات تنضم للـ Model Council تلقائياً بعد إضافة المفاتيح!

---

## ⚠️ ملاحظة قانونية
هذا النظام مخصص للاستخدام **القانوني** في اختبار الاختراق على أنظمة تملكها أو لديك إذن كتابي باختبارها.
