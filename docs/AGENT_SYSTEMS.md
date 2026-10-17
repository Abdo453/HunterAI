# أنظمة الوكلاء والتكامل (Agent & Integration Systems)

> **المرحلة:** تكامل مميزات Project Muteki في HunterAI — أُنجز بالكامل.
> **الترخيص:** كل الكود هنا أصلي (MIT)، منفَّذ بنفس المعمارية والمفاهيم
> **بدون** نسخ أي كود من Muteki (المرخّص AGPL-3.0) تماشيًا مع ترخيص هذا المشروع.

هذه الوثيقة تشرح الأنظمة السبعة المضافة حديثًا، وكيفية استخدامها.

---

## 1. وكلاء المحركات (CLI Engine Workers) — `engines/`

يشغّل وكلاء CLI خارجيين (Claude Code / Codex / OpenCode) كـ **Workers**
جنبًا إلى جنب مع نماذجك المحلية، ضمن حوكمة HunterAI.

| الملف | الدور |
|---|---|
| `engines/types.py` | أنواع مشتركة: `LaunchContext`, `EngineResult`, `StreamStep` |
| `engines/base.py` | `EngineDriver` المجرّد — عقد argv + تطبيع + فحص صحة |
| `engines/drivers/` | محركات محدّدة: `claude`, `codex`, `opencode` |
| `engines/registry.py` | السجل + أغلفة personal profiles/endpoints |
| `engines/runner.py` | تشغيل subprocess غير متزامن (بثّ + timeout + إلغاء) |
| `engines/worker.py` | `EngineWorker` — يربط المحرك بـ ScopeGuard + PolicyGate |
| `engines/selfcheck.py` | فحص صحة شامل (probe حقيقي بجولة واحدة) |

### خصائص أمنية
- **الأسرار عبر `env` وليس `argv`** (لا تظهر في جدول العمليات).
- **`build_worker_env`** يمرّر بيئة أساس صغيرة فقط (لا يرث كل env).
- كل مهمة تمرّ عبر **ScopeGuard** (الهدف في النطاق؟) و**PolicyGate** (الفئة مصرّح؟) — **fail-closed**.
- المحركات تعلن قدراتها (`secure_prompt_transport`, `offline_web_isolation`...) ليختارها الـ scheduler.

### الاستخدام (REST)
```http
GET  /api/engines                 # قائمة المحركات وقدراتها
POST /api/engines/selfcheck       # {"engines": ["claude"]} (اختياري)
POST /api/engines/run             # تشغيل مهمة واحدة
```
مثال على `POST /api/engines/run`:
```json
{
  "engine": "claude",
  "target": "https://lab.example.com",
  "prompt": "افحص /login بحثًا عن SQL injection",
  "in_scope": ["lab.example.com"],
  "model": "claude-sonnet-4-5",
  "web_access": true
}
```

### الواجهة
تبويب **"⚙️ وكلاء المحركات (CLI Engines)"** في الويب: عرض المحركات +
Self-check + نموذج تشغيل مهمة.

---

## 2. نظام الفلوغات (CTF Flag Pipeline) — `flags/`

- `extractor.py`: استخراج مرشّحات من نص عشوائي (قوالب صريحة + أنماط شائعة
  `flag{}` / `htb{}` / `ctf{}`... + مؤشرات سياق ترفع/تخفض الثقة).
- `store.py`: مخزن مع **dedupe** (بالبصمة SHA-256) + ranking + **false positive**.
- `service.py`: خدمة موحدة — `ingest()` → تحقق → تخزين، و`progress()` لتتابع
  **multi-flag**.

التكامل: `EngineWorker` يستخرج الفلوغات تلقائيًا من مخرجات المحرك عند تحديد
`flag_format` في `EngineWorkerConfig`.

```python
from flags import FlagService
svc = FlagService(flag_format=r"flag\{[a-f0-9]{32}\}", expected_count=3)
svc.ingest(monitor_output)
if svc.progress().complete:
    ...
```

---

## 3. تحكم التشغيل والميزانية — `core/run_control.py`, `core/cost_budget.py`

### Run Controller
يحل مشكلة `asyncio.create_task` بدون تحكّم: تسجيل كل تشغيل مع
**pause / resume / stop** فوري + نقاط تحقق تعاونية (`checkpoint()`).

```http
GET  /api/runs                          # ?active_only=true&kind=mission
POST /api/runs/{id}/pause|resume|stop
```

### Cost Budget
`CostController` بأسعار النماذج (USD لكل 1M tokens) و**circuit breaker**:

```http
GET  /api/budget       # لقطة التكلفة والسقوف
POST /api/budget       # {"per_run_usd": 5.0, "per_day_usd": 20.0}
```
كل استدعاء LLM يمرّ من `charge_call()`؛ الـ scheduler يفحص
`is_over_budget(scope)` قبل كل استدعاء جديد (fail-closed عند التجاوز).

---

## 4. تكامل منصات CTF — `ctf/`

- `base.py`: واجهة `CTFPlatform` الموحدة (auth / list_challenges / submit).
- `ctfd.py`, `rctf.py`, `gzctf.py`: عملاء المنصات الثلاث.
- `throttler.py`: **حماية من الحظر** (min-interval + نافذة معدّل + Retry-After).
- `bridge.py`: `FlagSubmitter` — يرسل مرشّحات `FlagService` للمنصة ويحدّث
  حالتها (accepted/wrong/duplicate/throttled) مع إيقاف مبكر عند اكتمال الهدف.

```python
from ctf import CTFdPlatform, FlagSubmitter
from flags import FlagService
svc = FlagService(expected_count=1); svc.ingest(text)
sub = FlagSubmitter(svc, CTFdPlatform(url, token), challenge_title="Web 100")
summary = sub.submit_pending()   # يحترم cooldown تلقائيًا
```

---

## 5. Docker والحززم — `Dockerfile`, `docker/`, `pyproject.toml`

- **`Dockerfile`**: صورة الويب (Python 3.11 + Playwright + nmap) — تصلح
  `docker-compose build`.
- **`docker/worker.Dockerfile`**: عامل خفيف بأدوات أساسية.
- **`docker/worker-kali.Dockerfile`**: عامل بقاعدة **Kali Rolling** كاملة.
- **`pyproject.toml`**: حزمة `hunterai` + entry points `hunter` / `hunterai`.

```bash
docker compose up --build                  # ويب فقط
docker compose --profile worker up         # + عامل خفيف
docker compose --profile worker-kali up    # + عامل Kali
```

---

## 6. نظام الإضافات — `extensions_ext/`

إضافات بـ **manifest صارم (fail-closed)** + **مستويات ثقة** + **صلاحيات مقيّدة**.

| الملف | الدور |
|---|---|
| `manifest.py` | قراءة/تحقق `plugin.json` (يرفض أي صلاحية/اسم/مسار غير صالح) |
| `trust.py` | تقييم ثقة (HIGH/MEDIUM/LOW/NONE) — يُشطب قبل التفعيل |
| `loader.py` | تحميل معزول + `HostAPI` تتحقق من الصلاحية في كل نداء |
| `registry.py` | تثبيت/تفعيل/تعطيل/قائمة |

**الصلاحيات المتاحة**: `read_workspace`, `write_workspace`, `call_llm`,
`run_tool`, `network`, `read_env` — أي غير معروفة تُرفض. محاولات التجاوز
(path traversal / صلاحية مرفوضة) تُرمي `PermissionDenied`.

```python
from extensions_ext import ExtensionRegistry, TrustLevel
reg = ExtensionRegistry(min_trust=TrustLevel.LOW)
reg.install("path/to/ext"); reg.enable("my-ext")
```

---

## 7. الرسم البياني المشترك للإثباتات — `core/shared_evidence.py`

يوحّد التعاون بين الوكلاء (بدل الـ blackboards المكررة):
- **Facts**: حقائق مُتحقَّق منها تُدمج حسب `confidence` (الأقوى يفوز).
- **Intents**: نوايا خطة تمنع تكرار العمل بين الوكلاء.
- **Locks**: أقفال موارد thread-safe (واحد فقط يفوز بالقفل).
- **InsightBus**: نشر اكتشافات فورية للمشتركين.

```python
from core.shared_evidence import SharedEvidenceGraph, Fact
g = SharedEvidenceGraph(min_confidence=0.5)
g.add_fact(Fact(key="vuln:sqli:/login", value="confirmed", source="nmap", confidence=0.9))
if g.acquire_lock("target:web1", "worker-a"): ...
```

---

## الاختبارات

كل الأنظمة مغطاة بـ **120 اختبار** (كلها ناجحة):

```bash
pytest tests/test_engines_cli_workers.py tests/test_flags_pipeline.py \
       tests/test_run_control_and_budget.py tests/test_ctf_platforms.py \
       tests/test_ctf_flag_bridge.py tests/test_extensions_system.py \
       tests/test_shared_evidence_graph.py
```

---

## خطة تنظيف التكرار (مُقسَّمة — لم تُنفَّذ بعد)

المشروع يعاني من تكرار **قائم** لا علاقة له بالأنظمة الجديدة أعلاه
(التي كلها إضافية). التكرار المُشاهَد:

1. **4 طبقات orchestration**: `hunter_ai/brain/orchestrator_workers.py`,
   `core/multi_agent/orchestrator.py`, `core/swarm/swarm_coordinator.py`,
   `core/system/task_scheduler.py`.
2. **3 dashboards**: `ui/web/app.py`, `ui/web/dashboard.py`, `ui/tui/hunter_os.py`.
3. **2 skill frameworks**: `agents/skills/`, `skills/`.

**التوصية**: دمج `core/shared_evidence.py` (الجديد) كطبقة معرفة مشتركة
اختيارية أولاً، ثم توحيد طبقات orchestration تدريجيًا مع تشغيل الـ 185 ملف
اختبار بعد كل خطوة. **هذا refactor محفوف — يحتاج مراجعة يدوية لكل طبقة
ولم يُنفَّذ تلقائيًا لتجنّب كسر السلوك القائم.**
