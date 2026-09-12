# ============================================================
# النظام الكامل — ملخص شامل
# ============================================================

# الـ Architecture النهائية:

## 🧠 Orchestrator + Model Router
```
User Request
     │
TaskClassifier → SECURITY | CODING | MIXED
     │
ModelRouter
├── SECURITY → WhiteRabbitNeo (GPU) → FREE → Xploiter (GPU) → FREE
├── CODING   → Qwen (GPU) → [Security API بالتوازي لو احتاج]
└── MIXED    → Security API ‖ Qwen (GPU) → Integrate
```

## 🔍 Confidence Check Protocol (AUTO)
```
Model يقول "not sure" / "possibly" / "appears to"
     │
     └──→ Trigger Confidence Check:
          ┌─────────────────────────────┐
          │  OpenRouter API (بالتوازي): │
          │  • GPT-4o          90%     │
          │  • Claude 3.5      ??      │
          │  • Gemini Flash    ??      │
          │  • Llama 70B       80%     │
          │  • Mistral Large   90%     │
          └─────────────────────────────┘
          + Browser/BurpSuite (اختياري)
               │
          Score = weighted average
               │
          ≥65% → CONFIRMED 🔴
          30-65% → UNCERTAIN 🟡
          <30% → FALSE_POSITIVE 🟢
```

## 🎯 TargetProfile Confidence Gating (HexStrike + PentestGPT)
```
DISCOVER → ENUMERATE → TEST → [confidence ≥ 65%? + evidence?] → EXPLOIT → VERIFY
                                    NO → more TESTing
```

## 📊 OpenRouter Models الفعّالة حالياً:
- ✅ GPT-4o         → 90% (5.4s)
- ✅ Llama 70B      → 80% (2.8s) 
- ✅ Mistral Large  → 90% (4.6s)
- ❓ Claude 3.5     → needs correct model ID
- ❓ Gemini Flash   → needs correct model ID

## 🚀 تشغيل:
```bash
cd E:\Agant\PentestAI-Unified
python main.py
# ثم: http://localhost:7070
```

## ⚙️ تفعيل Browser Verification:
في `.env` عدّل:
```
USE_BROWSER_VERIFY=true
USE_PROXY=true       # لو BurpSuite شغال
```
