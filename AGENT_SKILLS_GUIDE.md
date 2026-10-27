# دليل مهارات الوكيل الشامل — Agent Skills Guide (المربع الكامل)
**اللغة:** العربية · الغرض: توثيق كل المهارات المضافة، كيف يفكر الوكيل، كيف يستخدم الأدوات، الأفكار، وسير العمل المستقل.

---

## فهرس المحتويات
1. [فكرة المهارات والفئات](#1-فكرة-المهارات)
2. [كيف يفكر الوكيل؟ (الحلقة الرباعية ReAct)](#2-كيف-يفكر-الوكيل)
3. [كيف يستخدم الوكيل الأدوات؟ (مخطط الأدوات)](#3-كيف-يستخدم-الوكيل-الأدوات)
4. [قائمة المهارات الكاملة (42 مهارة)](#4-قائمة-المهارات-الكاملة)
5. [التفاصيل التقنية لكل مهارة جديدة](#5-تفاصيل-المهارات-الجديدة)
6. [سجل المهارات الديناميكي (Skill Registry)](#6-سجل-المهارات-الديناميكي)
7. [الحلقة الذاتية المستقلة (Autonomous Loop)](#7-الحلقة الذاتية-المستقلة)
8. [ذاكرة الصيد (/remember و /memory-gc)](#8-ذاكرة-الصيد)
9. [مساعد النموذج اللغوي (LLM Brain)](#9-مساعد-النموذج-اللغوي)
10. [سير العمل المقترح ( End-to-End )](#10-سير-العمل-المقترح)
11. [أمثلة كود سريعة](#11-أمثلة-كود-سريعة)
12. [إضافة مهارة جديدة (قالب)](#12-إضافة-مهارة-جديدة)
13. [القواعد الذهبية (تطبق دائماً)](#13-القواعد-الذهبية)

---

## 1. فكرة المهارات والفئات

تمت إضافة مجموعة متكاملة من مهارات الوكيل تحت `skills/` tutte ترث من `BaseSkill` وتنّفذ `execute(ctx)`. كل مهارة لها:
- ملف `skill.py` يحتوي المنطق.
- ملف `skill.yaml` يحتوي البيانات الوصفية (الفئة، الأدوات المطلوبة، البدائل، المهلة، المهارات التالية).
- ملف `__init__.py` للتصدير.

الفئات الأساسية:
| الفئة | الغرض |
|-------|-------|
| `agent_core` | pensée، تخطيط الأدوات، سلسلة الاستغلال، الحلقة الذاتية، الذاكرة، مساعده النموذج |
| `recon` | استطلاع نطاقات فرعية، مضيفين حيويين، منافذ، تقنيات، WAF، معاملات مخفية |
| `web` | IDOR، SSRF، SQLi آمن، XSS انعكاسي، تجاوز 403/401 |
| `analysis` | ترتيب سطح الهجوم، منطق العمل، استحواذ نطاقات، أسرار، سحابة |
| `web3` | فحص التوكن (Rug Pull)، تدقيق العقود الذكية |
| `reporting` | إنشاء التقرير النهائي |
| `browser` | التحكم بالمتصفح، تحليل الشبكة والسلوك |

---

## 2. كيف يفكر الوكيل؟ (الحلقة الرباعية ReAct)

المهارة `agent_reasoning_loop` تطبق نمط **ReAct** (Reason + Act) بأربع خطوات تُسجل جميعها في `thinking_trace.json`:

### الخطوة 1 — Observe (الرصد)
يقرأ الوكيل:
- الهدف والمرحلة الحالية (`recon`, `scan`, `analyze`, `exploit`, `report`).
- الأدوات المثبتة والمتاحة عبر `ToolManager`.
- الثغرات المسجلة حتى الآن.
- إشارات مثيرة في الاستجابات (`id=`, `url=`, `price=`, `.env`, `admin`, `swagger`, …).

### الخطوة 2 — Think (اتخاذ القرار)
باستخدام قواعد أولوية (التأثير أولًا per AGENTS.md):
- معرّفات تسلسلية (`id=`, `user_id=`, `order=`) → `idor_tester`.
- معلمات URL خارجية (`url=`, `callback=`, `webhook=`) → `ssrf_hunter` أو زحف بـ `katana`.
- معاملات مالية (`price=`, `coupon=`) → `logic_flaw_hunter`.
- ملفات حساسة (`.git/`, `.env`, `config`) → `secrets_hunter`.
- قشرة استغلال → `takeover_confirm`.
- مرحلة `recon` بدون دليل → تبدأ بـ `subfinder` ثم `httpx`.

إن توفّر نموذج لغوي عبر `ctx.extra["llm"]`، يثري `agent_llm_brain` القرار بتفسير نصي؛ وإلا يعمل مهارات `reasoning_loop` و `llm_brain` بشكل كامل **بدون اتصال (offline)** باستخدام heuristics.

الناتج: `confidence` (0–1) + `next_tool`/`next_skill` + `reasoning` + `next_skills`.

### الخطوة 3 — Act (التخطيط للتنفيذ)
يحوّل القرار إلى إجراء ملموس: الأداة المختارة + المهارات التالية المقترحة. إن كانت الثقة `≥ 0.7`، يسجل Finding مبدئي للمراجعة لاحقًا.

### الخطوة 4 — Reflect (التقييم الذاتي)
ينقد القرار:
- هل الأداة تدخلية (`sqlmap`, `ffuf`)؟ → يحذّر من التحقق من النطاق أولًا.
- هل الثقة منخفضة؟ → يفضل الاستطلاع السلبي أولًا.
- المخرج: `verdict` = `proceed` أو `proceed_with_caution`.

كل دورة تُحفظ في `thinking_trace.json` لمراجعة سبب كل قرار لاحقًا.

---

## 3. كيف يستخدم الوكيل الأدوات؟ (مخطط الأدوات)

المهارة `agent_tool_planner` تجيب عن سؤال: "أداة nào تُستخدم، ومتى، وبأي ترتيب؟"

منطق الاختيار:
1. **المرحلة (phase):** `recon → scan → analyze → exploit → report`.
2. **مستوى المخاطرة (risk):** يبدأ بأدوات `low` (سلبية، قراءة فقط) ثم `medium`، ولا يستخدم `high` إلا إذا صادّق المستخدم (`max_risk: high`) والنطاق مصرّح به.
3. **النطاق (scope):** يتحقق من `StrictScopeEngine` قبل أي أداة فعّالة.
4. **التوفر:** يختار أول أداة مثبتة؛ إن غابت، ينتقل للبديل المسجل (مثلاً `subfinder → amass → crt_sh → waybackurls`).
5. **المخرج:** `tool_plan.json` (الخطة الكاملة) و `next_tool.json` (الأداة التالية للتنفيذ الفوري).

لا ينفذ الوكيل أي أداة مباشرة؛ يختار اسم الأداة فقط، وتنفيذها يمر عبر `ToolManager` / `ToolRouter` مع بوابات المرحلة والمخاطرة والنطاق.

---

## 4. قائمة المهارات الكاملة (42 مهارة)

المهارات الجديدة (المضافة) مصنفة:

### agent_core (الوكيل الأساسي)
| المهارة | المسار | الغرض |
|--------|--------|-------|
| Reasoning Loop | `skills/agent_core/reasoning_loop/` | حلقة تفكير ReAct تقرر الخطوة التالية |
| Tool Planner | `skills/agent_core/tool_planner/` | يختار الأداة لكل مرحلة مع بديل آمن |
| Chain Builder | `skills/agent_core/chain_builder/` | يبني سلاسل استغلال A→B→C |
| Skill Registry | `skills/agent_core/skill_registry/` | يكتشف المهارات من skill.yaml وينفّذها بالاسم |
| LLM Brain | `skills/agent_core/llm_brain/` | يثري القرارات بالنموذج اللغوي (بدون اتصال احتياطي) |
| Hunt Memory | `skills/agent_core/hunt_memory/` | /remember و /memory-gc لذاكرة الصيد |
| Autonomous Loop | `skills/agent_core/autonomous_loop/` | حلقة مستقلة: خطة → أداة → تحقق → سلسلة → تقرير → ذاكرة |

### analysis (التحليل)
| المهارة | المسار | الغرض |
|--------|--------|-------|
| Attack Surface Ranker | `skills/analysis/attack_surface_ranker/` | يرتب الأصول حسب القيمة وسهولة الاستغلال |
| Logic Flaw Hunter | `skills/analysis/logic_flaw_hunter/` | ثغرات منطق العمل (سعر، كوبون، تجاوز التحقق) |
| Takeover Confirm | `skills/analysis/takeover_confirm/` | يؤكد استحواذ النطاقات عبر بصمات CNAME |
| Secrets Hunter | `skills/analysis/secrets_hunter/` | البحث عن مفاتيح وأسرار مسربة |
| Cloud Recon | `skills/analysis/cloud_recon/` | حاويات سحابة عامة مكشوفة (S3, Azure, GCS) |

### web (ثغرات الويب)
| المهارة | المسار | الغرض |
|--------|--------|-------|
| IDOR Tester | `skills/web/idor_tester/` | معرّفات تسلسلية (مقارنة استجابات) |
| SSRF Hunter | `skills/web/ssrf_hunter/` | معلمات طلبات التزوير من الخادم |
| SQLi Hunter | `skills/web/sqli_hunter/` | SQLi آمن عبر المقارنة التفاضلية (قراءة فقط) |
| XSS Hunter | `skills/web/xss_hunter/` | XSS انعكاسي عبر علامة فريدة |
| Bypass 403 | `skills/web/bypass_403/` | تجاوز 403/401 (رؤوس وهمية، طرق HTTP بديلة) |

### recon (الاستطلاع)
| المهارة | المسار | الغرض |
|--------|--------|-------|
| Param Discover | `skills/recon/param_discover/` | معاملات HTTP مخفية (arjun/paramspider/Wayback) |

### web3 (العقود الذكية والتوكن)
| المهارة | المسار | الغرض |
|--------|--------|-------|
| Token Scan | `skills/web3/token_scan/` | أنماط Rug Pull في التوكنات |
| Web3 Audit | `skills/web3/web3_audit/` | تدقيق أولي لعقود Solidity |

المهارات الموجودة سابقًا في المستودع تُكتشف تلقائيًا أيضًا عبر السجل (subdomain_enum, live_host_detection, port_scan, dns_enum, tech_detection, waf_detection, smb_enum, crawling, endpoint_discovery, js_analysis, parameter_discovery, api_surface_audit, cloud_metadata_audit, ssh_audit, tls_audit, perimeter_matrix, triage_gate, behavior_analysis, browser_recon, network_intelligence, form_intelligence, report_generator).

---

## 5. التفاصيل التقنية لكل مهارة جديدة

### 5.1 Reasoning Loop (`agent_reasoning_loop`)
- **مدخلات:** `target`, `phase`, `findings_so_far`, `goal`.
- **مخرجات:** `thinking_trace.json`, `next_action.json`.
- **المنطق:** Observe → Think → Act → Reflect. يستخدم Heuristics أوليًا، يمكن enrichment بـ LLM.

### 5.2 Tool Planner (`agent_tool_planner`)
- **مدخلات:** `target`, `phase`, `max_risk` (low|medium|high), `scope_authorized`.
- **مخرجات:** `tool_plan.json`, `next_tool.json`.
- **المنطق:** فلترة حسب المرحلة + المخاطرة + النطاق + التوفر + البدائل.

### 5.3 Chain Builder (`agent_chain_builder`)
- **مدخلات:** `target`, `findings` (قائمة الثغرات المؤكدة).
- **مخرجات:** `exploit_chains.json`.
- **أمثلة على السلاسل:** `subdomain_takeover → session_cookie_theft → Account takeover`، `ssrf → internal_network_access → metadata exposure`، `idor → data_exfiltration`.

### 5.4 Attack Surface Ranker (`attack_surface_ranker`)
- يُقيّم كل أصل بناءً على التقنية، المنافذ المفتوحة الحساسة، غياب WAF، الثغرات السابقة، المسارات الحساسة (`/admin`, `/api/`, `/.env`).
- **مخرج:** `surface_ranking.json` مع أولوية `critical/high/medium/low`.

### 5.5 IDOR Tester / SSRF Hunter / SQLi Hunter / XSS Hunter / Bypass 403
كلها مهارات **قراءة فقط (read-only)** لا modify بيانات:
- تقارن استجابة طبيعية مقابل حقنة آمنة وتسجل الفارق (differential).
- تسجل `severity` و `evidence` و `recommendation` لكل مرشح.
- تُحيل المرشحين إلى `validation_gate` قبل الإبلاغ.

### 5.6 Secrets Hunter / Cloud Recon / Param Discover
- **Secrets Hunter:** أنماط regex للمفاتيح (AWS, GitHub, Stripe, Slack, JWT, Private Key) أو trufflehog/gileaks إن توفّرا.
- **Cloud Recon:** يختبر عناوين S3/Azure/GCS شائعة للنطاق ويسجل الحاويات المفتوحة.
- **Param Discover:** arjun/paramspider إن توفّرا، fallback إلى Wayback Machine CDX.

### 5.7 Token Scan / Web3 Audit
- **Token Scan:**-score مخاطر التوكن بناءً على مينت غير محدود، رسوم عالية، سيطرة المالك، عدم إمكانية التنصل من الملكية.
- **Web3 Audit:** أنماط reentrancy، tx.origin، missing access control، delegatecall، overflow الإشارات.

---

## 6. سجل المهارات الديناميكي (Skill Registry)

`skills/agent_core/skill_registry/` يتيح للوكيل اكتشاف كل المهارات تلقائيًا من ملفات `skill.yaml`:

```python
from skills.agent_core.skill_registry import SKILL_REGISTRY

# عرض كل المهارات
summary = SKILL_REGISTRY.summary()
print(summary["total"], summary["by_category"])

# تنفيذ مهارة بالاسم
result = await SKILL_REGISTRY.run("attack_surface_ranker", ctx)

# جلب كائن المهارة
skill = SKILL_REGISTRY.get("idor_tester")
```

المسح_recursive يستخدم `rglob("skill.yaml")` ليشمل كل الفئات.

---

## 7. الحلقة الذاتية المستقلة (Autonomous Loop)

`agent_autonomous_loop` تنفّذ دورة 사냥 كاملة دون تدخل يدوي:

```
recon (surface ranker)
  → scan (tool planner)
  → analyze (idor/ssrf/sqlxss/secrets/takeover)
  → exploit (chain builder A→B→C)
  → validate (البوابة السباعية hunter_ai.validation_gate)
  → report (report_generator)
  → remember (تسجيل في ذاكرة الصيد)
```

**مدخلات:** `target`, `phases` (قائمة مراحل)، `max_risk`, `scope_authorized`.
**مخرج:** `autonomous_hunt.json` يحتوي التتبع الكامل (`trace`) والثغرات المثبتة (`proven_findings`).

---

## 8. ذاكرة الصيد (/remember و /memory-gc)

`agent_hunt_memory` تُنفذ أوامر الذاكرة:
- **remember:** `action="remember"`, `note="..."` → يسجل سطر JSONL في `memory/<target>.jsonl`.
- **gc:** `action="gc"` → يدوّر الملفات ويحتفظ بأحدث ملف لكل هدف.
- **list:** `action="list"` → يعرض ملفات الذاكرة.

```python
await SKILL_REGISTRY.run("hunt_memory", Ctx(action="remember", note="id=5 suspect on /order", target="example.com"))
```

---

## 9. مساعد النموذج اللغوي (LLM Brain)

`agent_llm_brain` يثري اتخاذ القرار:
- إن توفّر `llm` في `ctx.extra["llm"]`، يرسل مPrompt ويحلل إجابة JSON.
- إن لم يتوفر، يستخدم **heuristics** دون اتصال (offline-safe).
- **مخرج:** `llm_decision.json` يحتوي `tool`, `skill`, `reasoning`, `confidence`, `next_skills`, `source`.

---

## 10. سير العمل المقترح (End-to-End)

```text
target.com
   │
   ▼
subdomain_enum → live_host_detection → httpx → tech_detection
   └───────────────────────────────────────┘
                      │
                      ▼
           attack_surface_ranker  (يُرتّب الأصول الأعلى أولوية)
                      │
                      ▼
           agent_tool_planner  (يختار الأداة التالية + بديل)
                      │
        ┌─────────────┼─────────────┐
        ▼             ▼             ▼
   idor_tester   ssrf_hunter   sqli_hunter
   xss_hunter    bypass_403    secrets_hunter
   takeover_confirm   logic_flaw_hunter
        │             │             │
        └─────────────┴─────────────┘
                      │
                      ▼
           agent_chain_builder  (سلاسل A→B→C)
                      │
                      ▼
           agent_reasoning_loop  (يُقيّم الخطوة التالية + trace)
                      │
                      ▼
           validation_gate  (البوابة السباعية — PROVEN فقط)
                      │
                      ▼
           report_generator  (تقرير جاهز للإرسال)
                      │
                      ▼
           hunt_memory (remember)
```

---

## 11. أمثلة كود سريعة

```python
import asyncio, json
from pathlib import Path
from skills.base_skill import SkillContext
from skills.agent_core.skill_registry import SKILL_REGISTRY

class FakeTM:
    def is_available(self, c): return c in ("subfinder","httpx","katana","arjun")

class FakeWS:
    def get_workspace_path(self, t, s): return Path(f"/tmp/ws/{t}/{s}")
    def write_file(self, *a, **k):
        p = Path("/tmp") / k.get("filename","out"); p.write_text(k["content"], encoding="utf-8"); return p
    def append_log(self, *a, **k): pass

class Ctx:
    def __init__(self, **kw):
        self.target="example.com"; self.session_id="s1"; self.retry_attempt=0
        self.tool_manager=FakeTM(); self.workspace=FakeWS(); self.extra=kw

async def main():
    ctx = Ctx(phase="recon", max_risk="medium", scope_authorized=True)

    # 1. ترتيب سطح الهجوم
    r = await SKILL_REGISTRY.run("attack_surface_ranker", ctx)
    ranking = json.loads(r.raw_output["ranking"])
    top = ranking["ranking"][0]["asset"]
    print("Top asset:", top)

    # 2. تخطيط الأداة
    p = await SKILL_REGISTRY.run("agent_tool_planner", ctx)
    plan = json.loads(p.raw_output["tool_plan"])
    print("Next tool:", plan["next_tool"]["tool"])

    # 3. حلقة التفكير
    think = await SKILL_REGISTRY.run("agent_reasoning_loop",
        Ctx(phase="analyze", findings_so_far=[{"type":"idor","evidence":"id=5"}], goal="find idor"))
    action = json.loads(think.raw_output["next_action"])
    print("Next skill:", action["skill"], "| confidence:", action["confidence"])

    # 4. اختبار IDOR
    idor = await SKILL_REGISTRY.run("idor_tester",
        Ctx(urls=["https://example.com/order?id=123"]))
    print("IDOR candidates:", len(json.loads(idor.raw_output["candidates"])))

    # 5. سلسلة استغلال
    cb = await SKILL_REGISTRY.run("agent_chain_builder",
        Ctx(findings=[{"type":"subdomain_takeover","title":"dangling CNAME"}]))
    print("Chains:", len(json.loads(cb.raw_output["chains"])))

asyncio.run(main())
```

---

## 12. إضافة مهارة جديدة (قالب)

كل مهارة جديدة تتبع `BaseSkill`:

```python
from skills.base_skill import BaseSkill, SkillContext, SkillResult

class MyNewSkill(BaseSkill):
    name = "my_new_skill"
    category = "web"            # recon | scan | web | analysis | agent_core | reporting | web3
    description = "وصف مختصر للمهارة"
    tools_required = ["nmap"]   # الأدوات الأساسية
    fallback_tools = ["naabu"]  # بدائل
    timeout_seconds = 120.0
    max_retries = 2

    async def execute(self, ctx: SkillContext) -> SkillResult:
        result = SkillResult(skill_name=self.name, success=True, tool_used=self.name)
        # المنطق باستخدام ctx.tool_manager و ctx.workspace
        result.add_finding(title="...", evidence="...", severity="Medium", ...)
        return result
```

ثم:
1. أنشئ مجلد `skills/<category>/<name>/` مع `skill.py` + `skill.yaml` + `__init__.py`.
2. صِدر المهارة في `skills/__init__.py` و `skills/<category>/__init__.py`.
3. سيعثر عليها `SkillRegistry` تلقائيًا من `skill.yaml`.

ملف `skill.yaml` مثال:
```yaml
name: my_new_skill
category: web
description: "وصف المهارة"
version: "1.0"
input:
  - target: str
output:
  - result.json
depends_on: []
next_skills:
  - validation_gate
fallback_skills: []
tools_required: []
fallback_tools: []
timeout_seconds: 60
max_retries: 1
enabled: true
```

---

## 13. القواعد الذهبية (تطبق دائماً)

1. **اقرأ النطاق قبل لمس أي أصل** — لا شيء خارج النطاق المصرّح به.
2. **لا ثغرات نظرية فقط** — "هل يمكن للمهاجم فعل هذا الآن؟" (البوابة السباعية).
3. **شغّل البوابة السباعية قبل كتابة أي تقرير** — نتيجة `PROVEN` فقط تُرسل.
4. **اقتل النتائج الضعيفة سريعًا** — N/A يضر بنسبة الصالحية.
5. **تأثير أولًا** — اختبر أسوأ العواقب أولاً.
6. **سجل كل قرار** — `thinking_trace.json` يُحفظ لكل دورة تفكير.
7. **5-minute rule** — أي أداة لا تُنجز خلال 5 دقائق، انتقل إلى التالية.

---

> الملف المرجعي لكل من يضيف مهارات أو يطور الوكيل: `AGENT_SKILLS_GUIDE.md` + كود المهارات تحت `skills/`.
