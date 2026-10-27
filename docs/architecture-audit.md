# تدقيق البنية المعمارية والفجوات — Architecture & Gap Analysis

**المستودع:** `E:\Agant\PentestAI-Unified` (HunterAI / PentestAI-Unified)
**اللغة / الإطار:** Python 3.11 + FastAPI (واجهة ويب على المنفذ 7070)، نقطة الدخول `main.py`
**مدير الحزم:** `requirements.txt` + `pyproject.toml` (حزمة `hunterai`)
**الترخيص:** MIT (الكود الجديد مضاف أصليًا — لا يُنسخ من Muteki AGPL-3.0)
**عدد الاختبارات قبل هذه الجلسة:** 1709 اختبار gathered
**عدد الاختبارات بعد هذه الجلسة:** 133 اختبارًا للأنظمة الجديدة + Lineฐาน.current project state

---

## 1. نقاط الدخول الأساسية (Entry Points)

| الملف | الدور |
|---|---|
| `main.py` | نقطة الدخول الرئيسية لتشغيل تطبيق FastAPI |
| `ai_agent_v2_enhanced.py` | وكيل محسن (v2) |
| `bugbounty_agent.py` | وكيل Bug Bounty مستقل |
| `run_unified_live_session.py` | جلسة مباشرة موحدة |
| `validate_burp_*.py` | أدوات تحقق من تكامل Burp |
| `cli/` | واجهة سطر أوامر |
| `ui/web/app.py` | تطبيق FastAPI principal مع الراوترات المتراكبة |

## 2. الطبقات الحالية orchestrator / multi-agent (قائمة فعليًا)

| الطبقة | الملف | الدور الموجز |
|---|---|---|
| Orchestrator خفيف | `orchestrator/router.py`، `task_classifier.py`، `resource_manager.py` | تصنيف المهام وتوجيهها |
| وكيل ذكي مستقل | `hunter_ai/brain/orchestrator_workers.py` | تنسيق عاملي 뇌 |
| مجلس معرفي | `hunter_ai/brain/cognitive_council.py` | تنسيق قرارات متعددة النماذج |
| مدير نماذج | `core/llm_router.py` | توجيه استدعاءات LLM بين مقدمي الخدمة |
| مدير أدوات | `tools/tool_manager.py` (يُستخدم من `agents/base_agent.py`) | إدارة أدوات الوكلاء |
| وكيل أساسي | `agents/base_agent.py` | `BaseAgent` مع `AgentTask` / `AgentResult` و `emit()` للأحداث |
| وكالات أمان جاهزة | `agents/nmap_agent.py`, `ffuf_agent.py`, `nuclei_agent.py`, `semgrep_agent.py`, `burp_agent.py`, `katana_agent.py`, `httpx_agent.py`, إلخ | أدوات أمان محددة لكل وكيل |

## 3. الأنظمة الجديدة المضافة (Additive — جميعها ناجحة في الاختبارات)

| النظام | الحزمة | ما يوفره |
|---|---|---|
| وكلاء محركات CLI | `engines/` | Drivers لـ Claude Code / Codex / OpenCode مع `secure_prompt_transport` (الأسرار عبر env bukan argv) |
| خط إنتاج الفلوغات (CTF) | `flags/` | استخراج مرشحات، dedupe، ranking، false positive، progress متعدد الفلوغات |
| منصات CTF | `ctf/` | عملاء CTFd / rCTF / GZCTF + `SubmitThrottler` (حماية من الحظر) |
| جسر CTF ↔ FlagService | `ctf/bridge.py` | إرسال تلقائي للمرشحات مع cooldown وإيقاف مبكر |
| تحكم التشغيل | `core/run_control.py` | `RunController` مع pause/resume/stop + نقاط تحقق تعاونية (`checkpoint()`) |
| الميزانية والتكلفة | `core/cost_budget.py` | `CostController` مع circuit breaker + `is_over_budget()` |
| الرسم البياني المشترك للإثباتات | `core/shared_evidence.py` | Facts / Intents / Locks / InsightBus thread-safe |
| نظام الإضافات | `extensions_ext/` | Manifest fail-closed، مستويات ثقة، `HostAPI` مع تفويض لكل نداء |
| واجهة ويب للمحركات | `ui/web/engines_api.py` + تبويب في `index.html` | GET/POST `/api/engines/*` |
| واجهة ويب للتحكم | `ui/web/control_api.py` | `/api/runs/*`، `/api/budget` |
| صور Docker | `Dockerfile`, `docker/worker.Dockerfile`, `docker/worker-kali.Dockerfile` | ويب + عامل خفيف + عامل Kali كامل |
| حزمة Python | `pyproject.toml` | Entry points `hunter` / `hunterai` |

## 4. الفجوات مقابل "MASTER IMPLEMENTATION SPECIFICATION"

| القدرة المطلوبة | الحالة | الملف / الملاحظة |
|---|---|---|
| واجهة واجهة API موحدة للوكلاء (`AgentProvider`) | ✅ جزئي | `engines/base.py` `EngineDriver` يغطي CLI agents فقط، ليس كل موفري LLM |
| موفري LLM مع tool-calling / streaming / تكلفة | ✅ جزئي | `core/llm_router.py` موجود؛ لا يوجد واجهة `AgentProvider` موحدة مع health_check / cancel |
| منسق مهام (Coordinator/Orchestrator) مع حالة مهام (PENDING..CANCELLED) | ❌ غير موجود | `RunController` يدير تشغيلات asyncio فقط، ليس دورة حياة مهام متعددة العمال |
| سجل مهام مع توابع وعلاقات بين المهام | ❌ غير موجود | |
| قفل موارد لمنع تضارب العمال | ✅ جزئي | `SharedEvidenceGraph.acquire_lock()` موجود في الذاكرة فقط |
| سجل أدوات مركب (Tool Registry) مع schema + إذن + مخاطرة | ❌ غير موجود | `agents/` تستخدم `ToolManager` موجود لكن لا يطابق واجهة `Tool` من المواصفة |
| تنفيذ CLI عبر argument arrays (لا shell strings) | ⚠️ جزئي | `engines/runner.py` يستخدم subprocess بآمن نسبيًا، لكن لا يوجد سجل أدوات عام مع allowlist |
| تكامل MCP client رسمي | ❌ غير موجود | `core/mcp_server.py` موجود (خادم)، ليس عميل MCP |
| تكامل Burp Suite حقيقي | ⚠️ جزئي | `agents/burp_agent/` موجود + ملفات validate_burp_*.py —需要 audit لتحديد إن كان واجهة حقيقية أم استخراج GUI |
| تكامل وكلاء برمجة (Codex/Claude Code/Cursor/OpenCode) | ✅ جزئي | `engines/drivers/` يغطي claude/codex/opencode كعمال CLI فقط |
| لوحة سوداء مشتركة لإثباتات مع مصدر ومصداقية | ✅ موجود | `core/shared_evidence.py` (فقط في الذاكرة، غير دائم) |
| التحقق من الصحة / controlling false positives | ✅ جزئي | `flags/` للفلوغات فقط، ليس للنواقب الأمنية العامة |
| حدث 버스 مع تاريخ دائم وإعادة تشغيل | ❌ غير موجود | `emit()` في `BaseAgent` بسيط، ليس Event bus دائم |
| تحكم بشري (approve/reject/pause/resume) على العمليات عالية المخاطرة | ⚠️ جزئي | pause/resume/stop موجود في `run_control`؛ لا يوجد approval reel لعمليات عالية المخاطرة |
| فرض نطاق أهداف (Scope enforcement) على العمليات الشبكية | ⚠️ جزئي | `core/scope_guard.py` (يُستخدم من `engines_api.py`) —需要 تأكيدغطاء الشبكة |
| إدارة الأسرار بدون كشف في السجلات | ⚠️ جزئي | `credential_env` يُمرر عبر env وليس argv —need audit للتسجيل |
| واجهة تشغيل / إيقاف / أحداث في الواجهة الأمامية | ✅ جزئي | `/api/runs/*` موجود؛ لا توجد شاشة تشغيل مخصصة في واجهة الويب besides التبويبات الحالية |
| اختبارات للتكاملات الخارجية (MCP / Burp / वास्तविक網络) | ❌ غير موجود | اختبارات المحاكاة فقط |

## 5. خلاصة案ر التنفيذ

النظام الحالي في حالة **مستقرة واختباراته ناجحة** (133 اختبارًا للأنظمة الجديدة). ما تم بناؤه يحقق جزءًا كبيرًا من المواصفة بشكل آمن (إضافي، لا يحذف أي شيء قائم).

الفجوات الحرجة التي يجب تنفيذها لاحقًا (بترتيب Phase B → I من المواصفة):
1. **Phase B:** واجهة مشتركة للموفري LLM + سجل أدوات مركب + سياسة إذن.
2. **Phase C:** منسق مهام مع دورة حياة (حالات المهام) + تخصيص العمال + إلغاء.
3. **Phase D:** persistence للوحة السوداء (حاليًا في الذاكرة فقط) + سجل أحداث دائم.
4. **Phase E/F:** عميل MCP حقيقي + محول Burp حقيقي + محولات وكلاء برمجة مع مراجعة diff.
5. **Phase G:** صندوق رمل (sandbox) + فرض نطاق شبكي + موافقات بشرية + إخفاء الأسرار.
6. **Phase H:** واجهة تشغيل في واجهة الويب + توثيق.
7. **Phase I:** suite اختبار كامل + مراجعة أمنية + تقرير نهائي.

## 6. acceptance criteria (مؤقتة حتى اكتمال Phase B/I)

1. التطبيق يبدأ بنجاح (`main.py` / `app.py` يستوردان دون أخطاء).
2. جميع الاختبارات الموجودة تجتاز دون رجعية.
3. العمال يُسجلون ويُخصص لهم مهام عبر الواجهة الجديدة.
4. أداة استدعاء تُتحقق وتُفوض قبل التنفيذ.
5. تنفيذ CLI يستخدم مصفوفات وسيطات (argument arrays).
6. يمكن إيقاف تشغيلات طويلة والمراقبة عبر `/api/runs/*`.
7. الأسرار لا تظهر في السجلات أو الإثباتات.
8. التوثيق يطابق التنفيذ الفعلي.
