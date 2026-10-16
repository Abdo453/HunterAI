# HunterAI — تقرير تدقيق التنفيذ الفعلي (المرحلة صفر)

> **تاريخ التدقيق:** 2026-10-16
> **النطاق:** `E:\Agant\PentestAI-Unified` — مراجعة الكود المصدري والتشغيل الفعلي فقط.
> **القاعدة الحاكمة:** كل حكم في هذا التقرير مبني على قراءة ملف بسطر محدد أو على تنفيذ فعلي. لا يوجد حكم مبني على وثيقة أو README.
> **رموز الحكم:** `EXISTS` موجود ويعمل · `PARTIAL` موجود جزئيًا · `MOCKED` محاكاة/بيانات ثابتة · `MISSING` غير موجود · `UNVERIFIED` لا يوجد دليل كافٍ.

---

## 1. الملخّص التنفيذي

**توزيع الأحكام على 95 مكوّنًا مدقَّقًا في 9 محاور:**

| الحكم | العدد | الدلالة |
|---|---|---|
| `EXISTS` | 20 | يعمل فعليًا |
| `PARTIAL` | 28 | موجود لكن ناقص أو غير موصول |
| `MOCKED` | 24 | محاكاة أو بيانات ثابتة تُقدَّم كأنها نتائج |
| `MISSING` | 23 | غير موجود أو كود ميت |
| `UNVERIFIED` | 0 | لم يتبقَّ شيء بلا دليل |

المحاور التسعة: نقاط الدخول · الوكلاء · الأدوات · النماذج المحلية · السكوب والحوكمة · الذاكرة وEvent Bus · المحكمة والرسوم البيانية · الاختبارات · العقود.

المشروع **ليس** مشروعًا وهميًا: يوجد تنفيذ حقيقي لخط أنابيب استطلاع كامل، ونظام تنفيذ أدوات عبر subprocess، و14 مهارة اختبار تستخدم `httpx` فعليًا، ومحكمة أدلة مكتوبة بجدية، ودليل تغطية، وعقود مهام. خط الأنابيب **يعمل فعليًا من البداية للنهاية** على هذا الجهاز وأنتج تقارير وتصديرًا لسطح المكتب.

لكن ظهرت **ثلاث نتائج حاكمة** تغيّر ترتيب الأولويات:

### 🔴 النتيجة 1 — محكمة الأدلة تتحقق من *شكل* الادعاء، لا من *مصدر* الدليل

`FindingQualificationGate.evaluate_candidate()` تمرر `verifier_result` الآتي من المستدعي مباشرة إلى `EvidenceCourt.adjudicate()`، والمحكمة تعتبر الدليل "قطعيًا" إذا وُجد أي من أعلام منطقية يمررها المستدعي نفسه (`core/evidence_court.py:331-343`).

**تجربة عملية نُفّذت على هذا المستودع:**

| الحالة | المُدخل | النتيجة |
|---|---|---|
| أ) مسار الماسحات في خط الأنابيب (`{"reproduced": True, "is_reflection": False}`) | نفس ما يمرره `pipeline_orchestrator.py` لنواة/دالفوكس/نيكتو/سابزي | ❌ `UNVERIFIED` — لا يقبل أبدًا |
| ب) نفس الادعاء + إضافة `canary_confirmed=True` | علم منطقي واحد إضافي من المستدعي | ✅ `CONFIRMED` |
| ج) **ادعاء مُختلق بالكامل**، `raw_evidence=""`، `source_tool="llm_hallucination"` + علمان منطقيان | لا أداة عملت، لا دليل موجود | ✅ **`CONFIRMED`** مع "Evidence Chain كاملة" |

النتيجة: النظام في نفس الوقت **عاجز عن تأكيد أي شيء عبر مساره الخاص**، و**قادر على تأكيد أي شيء** لو مرر المستدعي (بما فيه مكوّن مدفوع بنموذج لغوي) العَلَم الصحيح. هذا يناقض الادعاء المركزي في `ARCHITECTURE.md:86-91`.

### 🔴 النتيجة 2 — خط الأنابيب الرئيسي لا يمكنه إنتاج finding مؤكَّد

- كل استدعاءات `FindingQualificationGate.evaluate_candidate()` في خط الأنابيب (6 مواضع) تمرر `verifier_result={"reproduced": True, "is_reflection": False}` فقط، بلا أي علم إثبات قطعي → المحكمة ترجع `UNVERIFIED` دائمًا → `is_q=False` → لا شيء يُضاف إلى `self.findings`.
- كتلة "TRANSITION TO VERIFICATION" بالكامل (`pipeline_orchestrator.py:1787-2124`، نحو 340 سطرًا) تعتمد على `raw_probe_findings` المُعرَّف كقائمة فارغة في `pipeline_orchestrator.py:1558` و**لا يُضاف إليه أي عنصر في الملف كله** → الكتلة كود ميت.

**تأكيد تجريبي:** تشغيل فعلي `python main.py -t https://example.com --mode recon --dry-run --allow-no-ai` انتهى بـ `status: completed` و**`Confirmed Findings: 0`**، وهو ما يطابق سجل `.agent/mission.md` الذي يسجّل "Total verified findings: 0" في كل مهمة.

### 🔴 النتيجة 3 — مسار تأكيد ثانٍ يتجاوز المحكمة تمامًا

`InvestigationController._promote_to_evidence_court()` — رغم اسمه — **لا يستدعي `EvidenceCourt` إطلاقًا**؛ يبني `HunterFinding(status=CONFIRMED, reproducible=True)` مباشرة ويضيفه إلى `orc.findings` (`hunter_ai/pipeline/investigation_controller.py:632-668`)، اعتمادًا على العلم `confirmed` الراجع من المهارة (`:733-739`).

فالنتيجة: المحكمة ليست على مسار التأكيد الوحيد، بل هناك مسار متوازٍ غير محكوم. و`qualification_gate.py:8-10` ينص صراحة على أن "كل finding مؤكَّد يجب أن يملك سلسلة أدلة متصلة مُصادق عليها من المحكمة".

---

## 2. المنهجية

| الخطوة | ما نُفّذ فعليًا |
|---|---|
| قراءة الكود | 6 مدقّقين متوازيين على 6 محاور + تدقيق مباشر للمسار الحرج |
| تشغيل الاختبارات | `pytest tests` كاملًا (نتائج في §3) |
| تشغيل التصديق | `python certify.py` |
| تشغيل E2E | `python main.py -t https://example.com --mode recon --dry-run --allow-no-ai` |
| تشغيل جلسة حيّة | `python run_unified_live_session.py` (هدف محلي مُدار داخل العملية) |
| تجارب موجّهة | اختبار بوابة التأكيد بثلاث حالات (الجدول أعلاه) |
| تحليل مرجعي | فحص أي مكوّن من `core/` لا يُستدعى من أي مكان |

---

## 3. الحالة المقاسة فعليًا (لا منقولة)

| المقياس | النتيجة الفعلية | الملاحظة |
|---|---|---|
| `pytest tests` | **1052 نجح / 12 فشل** + **5 ملفات تفشل في التحميل** (1064 متجمّع) | مدة 7:52 د |
| سبب أعطال التحميل | `ImportError: cannot import name 'CoverageStatus'` | انظر §5.1 |
| `python certify.py` | **15/15 نجحت في 7.18 ثانية** | البوابات سريعة جدًا لدرجة تشكّل مؤشرًا على أنها فحوص سطحية |
| خط الأنابيب E2E | `status: completed` · 1 نطاق فرعي · 1 مضيف حيّ · **0 findings** | يعمل فعلًا وينتج artifacts |
| `run_unified_live_session.py` | ✅ نجح: Metamorphic Triad → `CONFIRMED` → تصدير إلى Burp | الهارنس حقيقي ويعمل على هدف محلي |
| `tests/test_agent_teams_benchmark.py` | **7/10** عند تشغيله، و**0 اختبار** عند جمعه بـ pytest | ليس ملف pytest |
| أثر جانبي | تشغيل الاختبارات و`certify.py` يعدّلان ملفات متتبَّعة في git | `PRE_KALI_CERTIFICATION.md` + 6 قواعد بيانات + `data/memory/*.json` |

---

## 4. جدول الأحكام حسب المكوّن

### 4.1 نقاط الدخول والواجهات

| المكوّن | المسار | الحكم | الدليل |
|---|---|---|---|
| `main.py` (ويب/CLI/ماسح) | `main.py:26-191` | EXISTS | ثلاث مسارات حقيقية تعمل |
| خط الأنابيب `hunter_ai` | `main.py:116-158` | EXISTS | شُغّل فعليًا وانتهى `completed` |
| `cli/hunter_cli.py` (68 أمرًا) | `cli/hunter_cli.py:50` | **MISSING (معطوب)** | يفشل عند الاستيراد: `CoverageStatus` غير موجود → كل الأوامر الـ68 ميتة |
| واجهة الويب FastAPI | `ui/web/app.py` (1908 سطرًا، ~40 مسارًا) | EXISTS | مسارات حقيقية |
| TUI | `ui/tui/hunter_os.py` | EXISTS | Textual، 4 تبويبات |
| `certify.py` | `certify.py:90-771` | PARTIAL | 15 بوابة تمر في 7 ثوانٍ — فحص بنيوي لا تشغيل حقيقي |

### 4.2 طبقة الوكلاء والفرق

| المكوّن | المسار | الحكم | الدليل |
|---|---|---|---|
| العقود `ToolExecutionResult`/`TaskContract` | `core/contracts/task_contracts.py:76-210` | EXISTS | dataclasses حقيقية + آلة حالة مفروضة |
| `core/teams/*` (18 وكيلًا) | `core/teams/recon_team.py:46-58` وأمثاله | **MOCKED** | بيانات ثابتة (`api./auth./admin.`، `93.184.216.34`، منافذ `[80,443,8443]`، `nginx/1.24.0`، `pk_live_****`) ولا يوجد أي استيراد شبكة أو subprocess في الحزمة كلها |
| مراجعو الفرق | `core/teams/recon_team.py:128-151` | PARTIAL | يقبلون تلقائيًا ويكتبون بيانات مُختلقة في `CoverageLedger` |
| `core/teams` كحزمة | `core/teams/__init__.py:12` | **MISSING (كود ميت)** | لا مستدعي إنتاجي؛ الوحيد هو `tests/test_agent_teams_benchmark.py:27` |
| `agents/` (الطبقة القديمة) | `agents/recon_agent.py:33` · `agents/web_agent.py:45-58` | EXISTS | تُشغّل nmap/gobuster/nuclei/sqlmap/dalfox وتُحلّل stdout الحقيقي |
| `agents/skills/*` (14 مهارة) | `agents/skills/ssrf_skill.py:44-63` · `idor_skill.py:178-219` | EXISTS | httpx فعلي وتفاضل استجابات حقيقي |
| `agents/autonomous_mission_agent.py` | `:312` | PARTIAL | `Path` مستخدم وغير مستورد → `NameError` مبلوع في `:362` → إدخال قاعدة المعرفة ميت |
| `hunter_ai/agents/*_contract_agent.py` | `web_contract_agent.py:81-141` | **MOCKED** | نصوص استجابة ثابتة + finding SQLi بثقة 0.98 بغض النظر عن الهدف |
| `core/multi_agent/specialists.py` | `:47-317` | MOCKED | منافذ/مستأجرون ثابتون + فرق مُختلق 1420 بايت |
| `core/swarm/swarm_coordinator.py` | `:105-206` | MOCKED | قوائم ثابتة، و`boundary_isolation_verified` مُختلق |
| `core/subagent_manager_v2.py` | `:87-141` | MOCKED | `launch_subagent` يضيف dataclass فقط بحالة RUNNING |
| `core/system/task_scheduler.py` | `:216-291` | PARTIAL | آلة حالة حقيقية، لكن المراجعة الذاتية مكسورة (§5.4) |
| `core/blackboard/agent_blackboard.py` | `:42-80` | EXISTS (غير موصول) | لا مستدعي إنتاجي |

### 4.3 طبقة الأدوات والتنفيذ

| المكوّن | المسار | الحكم | الدليل |
|---|---|---|---|
| `ToolManager` (المنفّذ الحقيقي الوحيد) | `tools/tool_manager.py:224` | EXISTS | `asyncio.create_subprocess_shell` مع timeout وحفظ مخرجات |
| `MasterToolRegistry.execute_artifact` | `hunter_ai/pipeline/tool_specs.py:712-790` | EXISTS | `await self.tm.execute(...)` في `:741` |
| مُحلّل مخرجات الأدوات | `tool_specs.py:62,129,162,196,230,377,487,563` | PARTIAL | ترشيح نصوص فرعية لا تحليل بنيوي؛ مواصفة ffuf تطلب JSON ثم يُقرأ سطرًا سطرًا |
| `crtsh` adapter | `tool_specs.py:109` → `:730` → `:764-770` | **MOCKED** | `command_template=""` → يُنفّذ الاسم كأمر → exit 127 → ومع ذلك `status="success"` |
| `BurpRepeaterController` | `core/controllers/burp_controller.py:80-84` | **MOCKED** | `status = 200` و`body` مُختلق محليًا، ثم يُحفظ في `burp_repeater_experiments.json` |
| `hunter_ai/tools/tool_router.py` | `:96-104` | MOCKED | لا يسجّل أي معالج → لا يمكنه التنفيذ أبدًا |
| `core/gateway/tool_gateway.py` | `:55-165` | EXISTS | تنفيذ حقيقي + EvidenceItem — لكن **غير مستخدم** في خط الأنابيب |
| `PlaywrightBrowserController` | `core/browser/playwright_controller.py:111-119` | EXISTS | موصول في `pipeline_orchestrator.py:990-1003` |
| التوافق مع عقد `ToolExecutionResult` | — | **MISSING** | خط الأنابيب **لا يستورد** `core.contracts.task_contracts`؛ العقد المُستخدم فعليًا هو `ToolExecutionMeta` (`hunter_ai/pipeline/schemas.py:219-235`) |
| تسجيل فشل الأدوات | `pipeline_orchestrator.py` (15 موضعًا) | MISSING | كل استدعاء داخل `except Exception: logger.debug(...)` → الفشل لا يُسجَّل كفجوة تغطية ولا كدليل |

**أدوات تُنفَّذ فعليًا:** subfinder, assetfinder, gobuster_dns, amass, theharvester, subzy, nmap, waybackurls, katana, hakrawler, gau, ffuf, feroxbuster, gobuster, dirsearch, nuclei, dalfox, nikto, sqlmap (عبر المهارات).
**أدوات معلنة ولا تُنفَّذ:** httpx (يُنسب له الفضل زورًا — الفحص داخلي بـ Python)، wpscan, arjun, trufflehog, shodan, naabu, ssrfmap, burp_scanner.

### 4.4 طبقة النماذج المحلية والذكاء الاصطناعي

| المكوّن | المسار | الحكم | الدليل |
|---|---|---|---|
| غلاف Ollama + Triad | `models/local/*.py`, `hunter_ai/brain/local_triad_agent.py:228-275` | EXISTS | `POST /api/chat` حقيقي |
| AI Preflight Gate | `hunter_ai/brain/ai_preflight.py:132-357` | PARTIAL | يقبل أي نص غير فارغ كإثبات استدلال (`:226-227`)؛ ومستدعى في مسار واحد فقط |
| Cognitive Council | `hunter_ai/brain/cognitive_council.py:318-361` | PARTIAL | نداءات حقيقية، لكن عند انقطاع Ollama يُنتج تصويتًا وهميًا `HEURISTIC_PASS` (`:533-541`) يظهر في التقارير كأنه تصويت نماذج |
| Claude Thinking Protocol | `core/cognitive/claude_thinking_protocol.py:257-302` | **MOCKED** | نصوص "تفكير" مكتوبة سلفًا، بلا أي نداء نموذج؛ والوحدة غير موصولة بأي مدخل |
| `core/model_council.py` | `:132-182` | **MISSING (كود ميت)** | صفر مستدعين؛ مذكور في `WORKFLOW.md:96` فقط |
| Model Router (توجيه حسب المهمة) | `hunter_ai/brain/model_router.py:70-137` | MOCKED | دالة توجيه حقيقية، لكن مستهلكها الوحيد يسجّل الاسم في log ثم يستخدم نصوصًا ثابتة |
| ⚠️ **ادعاء البيئة المعزولة** | `core/ai_reasoning_core.py:24-30` · `core/smart_orchestrator.py:229-272` | **مخالف للواقع** | `.env` يحتوي `GEMINI_API_KEY` فعّالًا، والكود يجرّب السحابة **قبل** المحلي، ويرسل `html_source[:2500]` ومخرجات الأدوات إلى Google |

### 4.5 السكوب والسياسة والحوكمة (أخطر محور)

| المكوّن | المسار | الحكم | الدليل |
|---|---|---|---|
| الثوابت المقدّسة (loopback/metadata/RFC1918) | `core/scope_engine.py:31-66` | EXISTS | `INVIOLABLE_IPV4_SUBNETS` + `HARD_BLOCKED_HOSTS` |
| دالة تقييم الثوابت | `core/scope_engine.py:191-228` | EXISTS | ترفض الشبكات المقدّسة قبل أي قاعدة allowlist |
| `StrictScopeEngine` | `core/scope_engine.py:230-326` | PARTIAL | بلا allowlist ⇒ سماح شامل (`:311-312`) |
| `ScopeGuard` (تنفيذ ثانٍ) | `core/scope_guard.py:86-134` | PARTIAL | صفر كود لـ loopback/metadata |
| `NetworkScopeGuard` (جدار الحماية على مستوى النقل) | `core/network_scope_guard.py:30-159` | **MOCKED** | خطّافات httpx مُعرَّفة ولا تُثبَّت على أي عميل في الإنتاج؛ مستدعاة من الاختبارات فقط |
| `PolicyGate` | `core/control_plane/policy_gate.py:70-177` | PARTIAL | تخطي فحص السكوب لفئة الأوامر الطرفية (`:137-141`) |
| منع الأوامر المدمّرة | `policy_gate.py:88-91` · `core/system/terminal_bridge.py:24-31` | PARTIAL | قائمة نصوص فرعية (6 أنماط) |
| موافقة المشغّل على الطفرات | `core/policy/policy_as_code.py:91-140` | PARTIAL | منطق صحيح لكنه خارج مسار التنفيذ الفعلي |
| محدّد المعدّل (token bucket) | `core/rate_limiter.py:46-210` | EXISTS | تنفيذ حقيقي |
| تطبيق محدّد المعدّل | `pipeline_orchestrator.py:838,1095` | PARTIAL | موضعان فقط؛ غائب عن كل مسارات shell والأدوات |
| مفتاح الإيقاف الطارئ | `core/safety/kill_switch.py:33-81` | PARTIAL | يُفحص في موضع واحد فقط (`core/brain/autonomous_brain.py:1728`) |
| الطبقة الدستورية P0-P4 | `core/safety/constitutional_layer.py:31-77` | PARTIAL | بادئات نصية (`"169.254."`, `"127.0.0.1"`) |
| `hunter.yaml` (نطاق/حدود/موافقات) | `hunter.yaml:6-24` | **MISSING** | `--config` غير مقروء في أي مكان (`cli/hunter_cli.py:105`) |
| `config/settings.yaml` أذونات | `config/settings.yaml:28-33` | **MOCKED** | `unrestricted_scope: true` و`auto_approve_all: true` بلا أي قارئ في الكود |
| سجل تدقيق الأوامر المرفوضة | `core/control_plane/computer_control.py:88-95` | PARTIAL | الكاتب الوحيد لملف؛ ولا يوجد أي `*.jsonl` تدقيق في الشجرة |
| اختبارات الثوابت (loopback/metadata) | `tests/test_scope_and_false_positives.py` | **MISSING** | الملف يختبر ترشيح النطاقات فقط؛ اختبارات الثوابت في ملف آخر |

#### تجارب أمنية نُفّذت فعليًا (ليست استنتاجًا)

**تجربة 1 — بوابة السياسة تقبل استدعاء metadata السحابي عبر الأمر الطرفي:**

| الطلب | الفئة | النتيجة |
|---|---|---|
| `nmap -sV 8.8.8.8` (خارج النطاق، `target=local_terminal`) | `terminal_command` | ✅ **مسموح** |
| `curl http://169.254.169.254/latest/meta-data/` | `terminal_command` | ✅ **مسموح** |
| `rm -rf / --no-preserve-root` | `terminal_command` | ❌ مرفوض |
| `http://evil.example.net/` | `http_request` | ❌ مرفوض (خارج النطاق) |
| `http://example.com/` | `http_request` | ✅ مسموح |

السبب: `policy_gate.py:137-139` يعتبر أي أمر طرفي بـ`target` فارغ أو `local_terminal` تنفيذًا محليًا، فيتخطى فحص النطاق بالكامل — وفحص `169.254.169.254` موجود داخل الفرع المُتخطّى. أي أن **الحظر "المقدّس" للميتاداتا مُتجاوَز عبر مسار الأوامر الطرفية**، وهو نفس ما تدّعي بوابة التصديق GATE-11 التحقق منه.

**تجربة 2 — `--scope-file` يُسقط خط الأنابيب بالكامل:**
```
AttributeError: type object 'StrictScopeEngine' has no attribute 'from_file'.
  at hunter_ai/pipeline/pipeline_orchestrator.py:178
```
`from_file` غير موجودة (الموجود `from_yaml:129` و`from_dict:145`)، و`max_rate_limit_rps` المُمرَّر في `:183` حقل غير موجود في `ScopePolicy` فيُسقَط صامتًا (مُتحقَّق منه بالتشغيل).

#### فجوات أمنية مؤكدة

| # | الفجوة | الدليل |
|---|---|---|
| S1 | **كل تنفيذ الأدوات في خط الأنابيب بلا أي بوابة سياسة أو سكوب أو حدّ معدّل** | `hunter_ai/pipeline/tool_specs.py:741,766` → `tools/tool_manager.py:224` |
| S2 | **بوابة السكوب مُتجاوَزة لفئة الأوامر الطرفية** (تجربة 1) | `core/control_plane/policy_gate.py:137-141` + `computer_control.py:121,220` |
| S3 | **تخطي الثوابت عبر صيغ IP بديلة** (`localhost.`، `127.1`، `2130706433`، `0x7f000001`) — لا يوجد تحليل DNS | `core/scope_engine.py:196-222` ثم `:311-312` (سماح افتراضي) |
| S4 | **تسريب خارج النطاق عبر وسوم `<script src>`** — الترشيح مُطبَّق على الروابط لا على السكربتات، و`googletagmanager.com` يُمثّل الحالة الاختبارية في المستودع نفسه | `pipeline_orchestrator.py:1040-1042, 1102, 1105-1108, 1305` |
| S5 | **مرحلة السكوب نفسها تُجري اتصالًا شبكيًا قبل أن ترفض** | `pipeline_orchestrator.py:552` ثم الرفض في `:582` |
| S6 | **أربع تطبيقات نطاق متباعدة واثنان بنفس الاسم `PolicyEngine`** — أحدهما افتراضيًا مفتوح بالكامل | `core/gateway/policy_engine.py:33,36,40` (`full_permissions=True`, `target="*"`, `max_repeated_actions=99999`) |
| S7 | **بوابة الـToolRouter معطّلة صامتًا** — kwargs غير صحيحة ثم `except: pass` | `hunter_ai/tools/tool_router.py:151-162` |
| S8 | **واجهتا قدرات بلا أي فحص سياسة** (تنفيذ argv عشوائي + httpx GET بـ`verify=False`) | `core/capabilities/computer_skill.py:77,104` |

### 4.6 الذاكرة والحالة المشتركة · Event Bus

| المكوّن | المسار | الحكم | الدليل |
|---|---|---|---|
| **حالة تحقيق مشتركة واحدة** | — | **MISSING** | أربع فئات blackboard غير مترابطة (انظر أدناه)؛ `main.py:117` لا يستورد أياً من مخازن الذاكرة الخمسة |
| `ThreeTierBlackboardMemory` | `hunter_ai/brain/agent_manager.py:64` | EXISTS | كتابة `:108,152,180` وقراءة `:137,172,188` |
| `MemoryHierarchy` | `hunter_ai/brain/memory_hierarchy.py:22` | PARTIAL | 4 أدلة حقيقية، لكن الجذر الافتراضي `tempfile.mkdtemp` (`:32`) ⇒ لا استرجاع بعد إعادة التشغيل |
| `MemoryManager` v2 | `core/system/memory_manager_v2.py:188` | PARTIAL | `ProjectMemory.storage_path` لا يُستخدم للحفظ (`:88-90`) |
| ذاكرة SI (4 ملفات) | `agents/security_intelligence/memory_manager.py:21` | MOCKED | `persist=False` افتراضيًا، ولا يوجد أي `persist=True` في المستودع ⇒ كل دوال `_save` تُرجع فورًا |
| `FailureMemory` (مضاد التكرار) | `core/memory/failure_memory.py:37` | EXISTS | تحميل عند البدء `:50-65`، كتابة `:104`، قراءة `:117-129`، موصول في `pipeline_orchestrator.py:207` |
| نصف مضاد التكرار الفعّال | `core/decision_core.py:84-153` | PARTIAL | `record_failure` يُستدعى من `certify.py:510` فقط؛ الإنتاج يستدعي `record_rejected_hypothesis` فقط ⇒ المنع لا يتحقق أبدًا |
| `BrowserEventBus` | `core/browser/browser_event_bus.py:51` | PARTIAL | المُنتِج موصول (`core/browser/session.py:220-224`)، والمستهلك الوحيد فئة تُبنى في الاختبارات فقط ⇒ **صفر مستهلكين حقيقيين** |
| `BurpEventBus` + `SecurityEventBus` | `agents/burp_agent/pipeline/event_bus.py:26` · `agents/security_intelligence/events.py:64` | EXISTS | مُنتِجون ومستهلكون حقيقيون + محوّل في `core/integration/security_intelligence_adapter.py:54-60` |
| استرجاع بعد الانقطاع | — | PARTIAL | فقط `MissionState` و`failure_memory.json`؛ كل تشغيل يبني دليلًا بطابع زمني جديد (`engagement_manager.py:84-87`) |
| تنقيح الأسرار قبل الكتابة | `core/secret_sanitizer.py:12` | PARTIAL | مُطبَّق في `pipeline_orchestrator.py:422-423` فقط، ومُتجاوَز في `save_tool_artifact` |
| `BlackboardState` (مزعوم "مصدر الحقيقة الواحد") | `hunter_ai/brain/orchestrator_workers.py:73` | MOCKED | في الذاكرة؛ `save_json:143` لا يُستدعى؛ محتواه قيم ثابتة (`:500-501,511-512,521,525,550-552`) |
| blackboard الـOrchestrator | `core/orchestrator.py:250,273-275` | **MOCKED (معطوب)** | يستدعي `create_job()` غير الموجودة، و`add_evidence(url=)` بمخالفة التوقيع ⇒ استثناء؛ والفئة بلا أي موضع إنشاء |

#### فجوات الذاكرة المؤكدة

| # | الفجوة | الدليل |
|---|---|---|
| M1 | **لا توجد حالة تحقيق مشتركة** — ست مخازن متوازية لا يقرأ أحدها الآخر، ومسار الفحص الحقيقي لا يستورد أيًا منها | `pipeline_orchestrator.py:29-84` |
| M2 | **`core/brain/autonomous_brain.py` — الدماغ نفسه — بلا أي مرجع لـblackboard أو ذاكرة** | صفر نتائج لـ`blackboard|Memory(` في الملف |
| M3 | **ذاكرة الخبرة اصطناعية**: تسجّل `SUCCESS_CONFIRMED` بغض النظر عن الاستجابة الفعلية | `core/orchestration/investigation_loop.py:133-134,138,160,183-186` |
| M4 | **تسريب أسرار بنص صريح إلى artifacts التحقيق**: القيمة الخام تُمرَّر إلى `record_lineage` ثم إلى `timeline.json` و`run.log` و`lineage_graph.json` بدون تنقيح | `pipeline_orchestrator.py:1320` → `engagement_manager.py:229,201,174` |
| M5 | **مخرجات الأدوات الخام غير منقّحة** في `*.raw.txt` و`data/tool_outputs/*.txt` | `tool_specs.py:782` · `tools/tool_manager.py:135-151` |
| M6 | **ترويسات HTTP وكوكيز محفوظة خامة في SQLite** | `core/browser/traffic_bridge.py:131,170-179` |
| M7 | **ملفات `data/memory/*.json` بلا كاتب يمكن الوصول إليه** — ملفات قديمة من إصدار سابق | `agents/security_intelligence/config.py:30-33` |
| M8 | **آثار جانبية عند الاستيراد**: 6 وحدات تُنشئ أدلة/قواعد بيانات بمجرد الاستيراد | `experience_store.py:17` وأمثاله |

### 4.7 المحكمة والرسوم البيانية — التفصيل

| المكوّن | المسار | الحكم | الدليل |
|---|---|---|---|
| `EvidenceCourt` v1 (المرجع) | `core/evidence_court.py:151-389` | EXISTS | بوابات مرتبة: سكوب `:187` → WAF `:198` → أدلة سلبية `:212` → تناقض `:252` → انعكاس `:267` → فرق طول/حالة `:300` → triad `:314`؛ التأكيد في `:345` فقط |
| بوابة التأكيد الصلبة في خط الأنابيب | `hunter_ai/pipeline/qualification_gate.py:125` | EXISTS | `if judgment.verdict != CourtVerdict.CONFIRMED: return False, …` |
| **معيار "الإثبات القطعي"** | `core/evidence_court.py:331-343` | **MOCKED** | `has_deterministic_proof` = أي قيمة صحيحة يمررها المستدعي؛ لا يُستدعى أي محرك إثبات |
| `ProofOfExecutionEngine` | `core/poe_engine.py:19-52` | EXISTS | regex حقيقي يرفض انعكاس `$((53+19))` ويشترط `72` معزولة |
| **وصل PoE بالمحكمة/خط الأنابيب** | — | **MISSING** | يُستورد فقط في `run_unified_live_session.py:65` والاختبارات؛ لا وحدة في `hunter_ai/` تستورده |
| `EvidenceCourtV2` | `core/court/evidence_court_v2.py:62-147` | MOCKED | كل المدخلات Booleans من المستدعي `:70-74`، وصوت FINDER ثابت `VOTE_CONFIRM` `:79-84` |
| `EvidenceOS.rule_verdict` | `core/evidence_os/unified_model.py:242` | MOCKED | القيمة الافتراضية `decision="CONFIRMED"`؛ وبالتنفيذ: `has_execution_proof=False` ⇒ **CONFIRMED** |
| `ArbitrationEngine` | `core/arbitration_engine.py:75-99` | PARTIAL | `is_verified = tool_output.get("verified", False)` ⇒ `CONFIRMED` |
| `ConfidenceChecker` | `core/confidence_checker.py:474-522` | MOCKED | تصويت نموذجين مُختلقين ≥0.65 ⇒ `CONFIRMED 0.9` (نُفِّذ) |
| `HunterFinding` — القيمة الافتراضية | `hunter_ai/pipeline/schemas.py:199-202` | MOCKED | `status = FindingStatus.CONFIRMED` و`tier = VERIFIED_FINDING` كقيم افتراضية للمخطط |
| `EvidenceGraph` (v1) | `core/evidence_graph.py:190` | PARTIAL | يُكتب في `13_evidence/evidence_graph.json` (`pipeline_orchestrator.py:2139`) و**لا يُقرأ أبدًا** |
| `AttackSurfaceGraph` | `core/attack_surface_graph.py:76-122` | MOCKED | في الذاكرة فقط (`self.nodes`) |
| `AttackSurfaceGraph` (الاستدلالي) | `core/reasoning/attack_surface_graph.py` | MISSING | لا حفظ ولا JSON ولا SQLite |
| `EvidenceLedger` | `core/evidence_ledger.py:29-61` | PARTIAL | سلسلة في الذاكرة، والتجزئة تشمل `time.time()` (`:47`) ⇒ غير قابلة للتحقق |
| اختبارات الانعكاس/التشويش/WAF | متعددة | PARTIAL | تنجح كلها، لكنها تختبر تركيبات أعلام يمررها الاختبار لا استجابات حية؛ وفرع `BLOCKED` **غير مُختبَر إطلاقًا** |

#### فجوات المحكمة المؤكدة

| # | الفجوة | الدليل |
|---|---|---|
| C1 | **الحكم في النهاية حقل قابل للتحديد من المستدعي** — `{"reproduced":True,"deterministic_proof":"anything"}` ⇒ CONFIRMED (نُفِّذ) | `core/evidence_court.py:333-342` |
| C2 | **محكمتان بمسلّمتين متضادتين**: v1 يرفض "فرق الطول فقط"، وV2 يقبله لأن المستدعي يحوّل فرق البايت إلى `proof_nonce_proven=True` | `core/evidence_court.py:300` مقابل `core/brain/autonomous_brain.py:2297` |
| C3 | **"إثبات" بنص حر**: `"72" in reason` و`"reflection" in reason` كأدلة | `core/brain/autonomous_brain.py:2263-2267` |
| C4 | **إشارات الحساسات افتراضية `True`** ⇒ `agreement_ratio=1.0` ⇒ تأكيد فارغ | `core/brain/autonomous_brain.py:2459-2460` → `core/scoring/tool_agreement.py:59-61` |
| C5 | **الانعكاس يمكنه تأكيد XSS**: `has_xss_exec = … and probe in probe_resp.text` (مجرد صدى) | `core/smart_probe_engine.py:370,381`؛ ومثله `core/independent_verifier.py:69-72` |
| C6 | **`EvidenceOS.rule_verdict` افتراضيه CONFIRMED** ولا يستدعي مدقّق النسب | `core/evidence_os/unified_model.py:242,251` |
| C7 | **كتابة CONFIRMED مباشرة تتجاوز كل البوابات** | `investigation_controller.py:638` (مسار حيّ) و`pipeline_orchestrator.py:1810…2087` (ميت) و`schemas.py:199` |
| C8 | **خطأ منطقي (tautology)**: `x.lower() in x.lower()` يجعل فرق الطول وحده كافيًا | `core/evidence_graph.py:267` |

### 4.8 الاختبارات

| المكوّن | المسار | الحكم | الدليل |
|---|---|---|---|
| حجم مجموعة الاختبارات | `tests/` | EXISTS | **186 ملفًا**، **1129 دالة اختبار** |
| التشغيل الكامل | `python -m pytest tests` | PARTIAL | 1052 نجح / 12 فشل / 5 ملفات لا تُحمَّل (7:52 د) |
| **بوابة التأكيد الصلبة** | `hunter_ai/pipeline/qualification_gate.py` | **MISSING** | **صفر** ملفات اختبار تشير إليها — أخطر بوابة في النظام بلا اختبار |
| **العقود P0** | `core/contracts/task_contracts.py` | **MISSING** | **صفر** ملفات اختبار تشير إليها |
| `core/poe_engine.py` | — | PARTIAL | ملف اختبار واحد فقط، ولا اختبار يتحقق من وصوله لمسار إنتاجي |
| `core/teams/*` | `tests/test_agent_teams_benchmark.py` | MOCKED | الملف الوحيد، وهو **غير قابل للجمع بـpytest** (لا `test_*`) ويفشل 3/10 عند تشغيله |
| تأكيد عدد النتائج | `tests/test_hunter_master_pipeline.py:306,342` | MISSING | يفحص `status == "completed"` ووجود الملفات فقط، **ولا يفحص `findings_count`** ⇒ لا اختبار يمكنه كشف انعدام النتائج |
| اختبار فرع WAF/`BLOCKED` | `core/evidence_court.py:198` | MISSING | لا اختبار يضبط `is_blocked_by_waf` أو `waf_blocked` |
| اختبارات الانعكاس/التشويش | `tests/test_evidence_driven_system.py:44-59` وأمثاله | PARTIAL | تنجح، لكنها تختبر تركيبات أعلام يمررها الاختبار لا استجابات حية |
| اختبار ثوابت النطاق | `tests/test_scope_and_false_positives.py` | MISSING | يختبر ترشيح النطاقات فقط؛ لا loopback/metadata/RFC1918 |

#### تفصيل الأعطال الـ12 (مصنّفة بالسبب الجذري)

| السبب | العدد | الملفات | الدلالة |
|---|---|---|---|
| `ImportError: CoverageStatus` (من `core/brain/autonomous_brain.py:1734`) | 5 | `test_autonomous_brain_state`, `test_integration_pipeline`, `test_program_intelligence_and_triad`, `test_v19_epistemic_security_os` (2) | انحدار الكوميت `af1af9c` يعطّل مسار `AutonomousBrain` بالكامل |
| `'aborted' == 'completed'` | 5 | `test_artifact_based_recon`, `test_enterprise_casm` (2), `test_hunter_master_pipeline` (2) | توقف بسبب فشل AI Preflight (لا Ollama على هذا الجهاز) — **بيئي** |
| `'ai_preflight_failed' == 'out_of_scope'` | 2 | `test_enterprise_casm::test_orchestrator_invariant_abort_on_loopback`, `test_hunter_workflow_pipeline::test_orchestrator_scope_rejection` | **ليس بيئيًا**: الاختبار يكشف انقلاب ترتيب البوابات. مع وجود Ollama سيمرّ الاختبار **بالمصادفة** ويخفي العيب |

**ملاحظة حاكمة:** مصفوفة الاختبارات ضخمة (1129 دالة) لكنها **لا تحرس الثوابت المعمارية**: أخطر بوابتين جديدتين (`qualification_gate`, `task_contracts`) بصفر تغطية، ولا اختبار واحد يتحقق من أن النظام يكتشف ثغرة فعلًا. لذلك تمرّ 15/15 بوابة تصديق بينما التشغيل الحقيقي ينتج صفر نتائج.

---

## 5. الفجوات المؤكدة مرتّبة (قائمة موحّدة)

### P0 — تمنع النظام من العمل كمنظومة موثوقة

| # | الفجوة | الدليل | المصدر |
|---|---|---|---|
| 1 | **المحكمة تثق بأعلام المستدعي** — ادعاء مُختلق بالكامل يُؤكَّد | تجربة موثّقة §1؛ `core/evidence_court.py:331-343` | C1 |
| 2 | **مسار تأكيد يتجاوز المحكمة تمامًا** (`_promote_to_evidence_court` لا تستدعي المحكمة) | `hunter_ai/pipeline/investigation_controller.py:632-668` | C7 |
| 3 | **خط الأنابيب لا ينتج finding مؤكَّدًا أبدًا** (6 مواضع تمرر `reproduced` فقط) | `pipeline_orchestrator.py:711,1283,1613,1641,1667,1782` | §1 |
| 4 | **كتلة التحقق كلها كود ميت** (340 سطرًا) | `pipeline_orchestrator.py:1558` مقابل `:1793` | §1 |
| 5 | **محرك PoE غير موصول بأي مسار إنتاجي** | يُستورد فقط في `run_unified_live_session.py:65` | §4.7 |
| 6 | **محكمتان بمسلّمتين متضادتين** — V2 تقبل ما ترفضه V1 | `autonomous_brain.py:2297` مقابل `evidence_court.py:300` | C2 |
| 7 | **الحماية الأمنية مُتجاوَزة عبر الأوامر الطرفية** — `curl 169.254.169.254` مسموح (نُفِّذ) | `core/control_plane/policy_gate.py:137-141` | S2 |
| 8 | **كل تنفيذ أدوات في خط الأنابيب بلا سياسة/سكوب/حدّ معدّل** | `tool_specs.py:741,766` → `tool_manager.py:224` | S1 |
| 9 | **البوابة الأمنية بعد بوابة الذكاء الاصطناعي** — هدف خارج النطاق يرجع `ai_preflight_failed` | `pipeline_orchestrator.py:2359-2371` | §1 |
| 10 | **البيئة ليست معزولة**: مفتاح Gemini فعّال، والسحابة تُجرَّب قبل المحلي، وتُرسل بيانات الهدف | `core/ai_reasoning_core.py:24-30` · `.env` | §4.4 |
| 11 | **CLI معطوب بالكامل** — 68 أمرًا لا تعمل | `cli/hunter_cli.py:50` | §3 |
| 12 | **`--scope-file` يُسقط خط الأنابيب** بـAttributeError (نُفِّذ) | `pipeline_orchestrator.py:178` | تجربة 2 |
| 13 | **العقد الموحّد غير موصول بخط الأنابيب** — ثلاثة عقود متوازية | `pipeline_orchestrator.py:29-84` · `schemas.py:219-235` | §4.3 |
| 14 | **لا توجد حالة تحقيق مشتركة** — ست مخازن منفصلة لا يقرأ أحدها الآخر | `pipeline_orchestrator.py:29-84` | M1 |
| 15 | **تسريب أسرار بنص صريح إلى artifacts التحقيق** بدون تنقيح | `pipeline_orchestrator.py:1320` → `engagement_manager.py:229,201,174` | M4 |
| 16 | **فشل الأدوات يُبتلع صامتًا** في 15 موضعًا ولا يُسجَّل كفجوة تغطية | `pipeline_orchestrator.py:613…1707` | §4.3 |
| 17 | **قيم افتراضية خطيرة**: `HunterFinding.status=CONFIRMED` افتراضيًا، و`EvidenceOS.rule_verdict` افتراضيه CONFIRMED | `schemas.py:199` · `evidence_os/unified_model.py:242` | C6, C7 |

### P1 — تمنع التعاون الحقيقي بين الوكلاء

| # | الفجوة | الدليل |
|---|---|---|
| 18 | **`core/teams` كود ميت بالكامل** — الوحيد الذي يستوردها ملف بنشمارك | `core/teams/__init__.py:12` + فحص شامل: صفر مستدعٍ إنتاجي |
| 19 | **18 وكيل فريق لا يستطيع أي منهم العمل** — صفر استيراد شبكة/subprocess، والبيانات ثابتة | `recon_team.py:46-58` وأمثاله |
| 20 | **مراجعو الفرق يصدّقون على بيانات فرقهم نفسها ويكتبونها في سجل التغطية** | `recon_team.py:134,142-148` |
| 21 | **المراجعة المستقلة مكسورة في الجدولة** (تجاوز حارس منع المراجعة الذاتية) | `core/system/task_scheduler.py:275-277` مقابل `:168-170` |
| 22 | **`EvidenceCourtReviewer` يصدّق على UNVERIFIED** — نُفِّذ: `review()` ترجع True وملاحظتها "Verdict: UNVERIFIED" | `core/teams/verification_team.py:181,188` |
| 23 | **`TaskScheduler.add_task()` بلا `parameters`** ⇒ كل مهمة تحقق تتحول إلى IDOR صامتًا | `task_scheduler.py:84-95` · `verification_team.py:105,178,179` |
| 24 | **`subagent_manager_v2.launch_subagent` لا يُشغّل شيئًا** | `core/system/subagent_manager_v2.py:87-141` |
| 25 | **مخرجات مُختلقة تظهر للمستخدم** في `hunter swarm` وواجهة الويب | `cli/hunter_cli.py:630-632` · `ui/web/app.py:1636-1640` |
| 26 | **`hunter_ai/brain/orchestrator_workers.py` يحقن حالة مُختلقة** (نصوص ونتائج ثابتة) | `:500-512,521,525,550-552` |
| 27 | **`CognitiveCouncil` يُنتج تصويتًا وهميًا `HEURISTIC_PASS` عند انقطاع Ollama** ويُكتب في التقارير | `cognitive_council.py:533-541` → `pipeline_orchestrator.py:1520` |
| 28 | **`BrowserEventBus` بلا مستهلك إنتاجي** | `browser_event_bus.py:51` · `browser_brain_loop.py:91` (اختبارات فقط) |
| 29 | **`EvidenceGraph` يُكتب ولا يُقرأ أبدًا**؛ ورسوم سطح الهجوم في الذاكرة فقط | `pipeline_orchestrator.py:2139`; `attack_surface_graph.py:76-122` |
| 30 | **ذاكرة الخبرة اصطناعية** — تسجّل نجاحًا دائمًا | `core/orchestration/investigation_loop.py:133-186` |
| 31 | **لا سجل تغطية في خط الأنابيب** — صفر استخدام لـ`CoverageLedger` | `pipeline_orchestrator.py` |
| 32 | **`BurpRepeaterController` يُختلق الاستجابات محليًا** ثم تُحفظ كتجارب تفاضلية | `core/controllers/burp_controller.py:80-84` → `pipeline_orchestrator.py:1535-1550` |
| 33 | **`crtsh` adapter يبلّغ عن نجاح كاذب** (exit 127 مع `status="success"`) | `tool_specs.py:109,730,764-770` |
| 34 | **`httpx` يُنسب إليه الفضل كأداة ولم يُنفَّذ قط** | `pipeline_orchestrator.py:890,933` |
| 35 | **أربع تطبيقات نطاق واثنان بنفس اسم `PolicyEngine`**، أحدهما مفتوح افتراضيًا | `core/gateway/policy_engine.py:33,36,40` |
| 36 | **تخطي الثوابت عبر صيغ IP بديلة** (`127.1`, `2130706433`, `0x7f000001`) | `core/scope_engine.py:196-222` ثم `:311-312` |

### P2 — النظافة والاتساق

| # | الفجوة | الدليل |
|---|---|---|
| 37 | تشغيل الاختبارات و`certify.py` يعدّلان ملفات متتبَّعة (لا عزلة) | `PRE_KALI_CERTIFICATION.md` + 6 قواعد بيانات |
| 38 | `docs/IMPLEMENTATION_STATUS.md` متأخر عن الكود | يقول المراحل 2-17 لم تبدأ وهي موجودة |
| 39 | `config/models.yaml` و`model_manifest.json` و`hunter.yaml` بلا قارئ | صفر مستدعين |
| 40 | `config/settings.yaml` يُعلن `unrestricted_scope: true` و`auto_approve_all: true` بلا أي قارئ | `config/settings.yaml:28-33` |
| 41 | مضيف Ollama ثابت `192.168.1.3` في 6 مواضع رغم ادعاء 127.0.0.1 | `orchestrator_workers.py:155` وأمثاله |
| 42 | اختبارات خط الأنابيب تفحص البنية فقط ولا تفحص عدد النتائج | `tests/test_hunter_master_pipeline.py:306,342` |
| 43 | ملفات مهملة/مكررة: صفر بايت `python nvidia_test.py`، وإعادة تصدير `core/terminal_bridge.py` | — |
| 44 | `core/tool_registry.py:211` يستخدم `Tuple` غير المستوردة ⇒ NameError عند الاستدعاء | `core/tool_registry.py:12,211` |

---

## 6. ما هو حقيقي ويجب الحفاظ عليه (لا يُعاد بناؤه)

1. **`ToolManager`** — التنفيذ عبر subprocess مع timeout وحفظ مخرجات: `tools/tool_manager.py:224-259`.
2. **منطق `EvidenceCourt` v1 نفسه** — بوابات مرتبة وسليمة منطقيًا: `core/evidence_court.py:186-389`. الخلل في *مدخلاتها* لا في تسلسل قرارها.
3. **`core/poe_engine.py:19-92`** — محرك إثبات حسابي حقيقي يرفض الانعكاس. المشكلة أنه غير موصول.
4. **`agents/skills/*`** — 14 مهارة تستخدم httpx فعليًا مع منطق تحوّل ومقارنة حقيقي.
5. **`agents/recon_agent.py` + `web_agent.py`** — تشغيل أدوات حقيقي مع تحليل stdout وترشيح حسب توفر الأداة.
6. **`CoverageLedger`** — بنية محاسبة حقيقية مع حفظ JSON: `core/coverage/coverage_ledger.py:86-271`.
7. **العقود `ToolExecutionResult`/`TaskContract`** — تصميم سليم ومنفَّذ: `core/contracts/task_contracts.py:76-210`.
8. **`run_unified_live_session.py`** — هارنس E2E حقيقي يعمل وينتج حكمًا مؤكدًا عبر triad تحوّلي كامل.
9. **`core/detectors/{sqli,xss}_detector.py`** — تمرير أعلام الإثبات من ملاحظة فعلية (`sqli_detector.py:100-104`).
10. **`CounterexampleAgent` و`ReproductionAgent`** — منطق دحض حقيقي وإعادة تنفيذ فعلية (`verification_team.py:40-95`).
11. **`core/rate_limiter.py:46-210`** — token bucket حقيقي مع backoff وcircuit breaker.
12. **`core/scope_engine.py:31-66,191-228`** — الثوابت المقدّسة وتقييمها سليم — ينقصه التطبيق في كل المسارات.
13. **طبقة Burp الحقيقية**: `CaptureStore` + `SecurityEventBus` + `UnifiedEvidenceStore` لها مُنتِجون ومستهلكون فعليون.

---

---

## 8. مصفوفة التصنيف الموسّع (تحديث الجلسة الثانية)

الخطة الرسمية للمشروع تستخدم **7 حالات**. التدقيق الأصلي استخدم 5؛ هذا القسم يضيف `DISCONNECTED` و`BLOCKED` ويسجّل تغيّر خط الأساس.

### 8.1 حالة خط الأساس (أُعيد قياسها فعليًا)

| المقياس | الجولة الأولى | الجلسة الحالية | السبب |
|---|---|---|---|
| متجمّع بـpytest | 1064 | **1129** | إصلاح انحدار `CoverageStatus` |
| أخطاء تحميل | 5 ملفات | **0** | نفس الإصلاح |
| أعطال | 12 | **5** ثم **0** | 5 كانت انحدار الكود، و7 كانت مرتبطة بتوفر Ollama |
| Ollama | غير متاح وقت القياس | **متاح: 5 موديلات** | `qwen3:8b`, `qwen2.5-coder:14b`, `qwen2.5-coder:14b-tools`, `xploiter/pentester:latest`, `WhiteRabbitNeo/Llama-3.1-...` |
| AI Preflight | — | **`online=True, inference_ok=True, 3/3 أدوار`** | تم التحقق المباشر |
| أدوات خارجية مثبتة | nmap فقط | nmap فقط | الباقي مفقود |

> **تصحيح مسجّل:** التصنيف السابق لخمسة أعطال بـ"بيئي" صحيح بالنسبة لتلك اللحظة، لكنه **لم يكن السبب الجذري الكامل**. بعد توفّر Ollama بقي 5 أعطال حقيقية كلها من انحدار واحد. القاعدة المطبَّقة: أعد القياس، ولا تعتمد على سرد سابق.

### 8.2 `DISCONNECTED` — التنفيذ موجود لكنه غير موصول بمسار العمل

| المكوّن | المسار | لماذا غير موصول |
|---|---|---|
| `core/teams` (18 وكيلًا) | `core/teams/__init__.py:12` | صفر مستدعٍ إنتاجي؛ الوحيد ملف بنشمارك. الأجسام نفسها `MOCKED` |
| `ProofOfExecutionEngine` | `core/poe_engine.py:19-92` | يُستورد فقط في `run_unified_live_session.py:65` والاختبارات |
| `core/gateway/tool_gateway.py` | `:55-165` | تنفيذ حقيقي محكوم + EvidenceItem، لا يستدعيه خط الأنابيب |
| `core/network_scope_guard.py` | `:30-159` | خطّافات httpx لا تُثبَّت على أي عميل إنتاجي |
| `core/blackboard/agent_blackboard.py` | `:42-80` | فضاءات معرفية حقيقية بلا مستدعٍ إنتاجي |
| `core/normalizer/tool_normalizer.py` | `:62-120` | محلّل JSON حقيقي، يُستدعى فقط من CLI الميت سابقًا و`autonomous_brain` |
| `core/ai_bridge/*` | `hybrid_ai_router.py:83-159` | موجّه سحابي كامل غير موصول بأي مدخل |
| `core/cognitive/claude_thinking_protocol.py` | `:257-302` | نصوص مُعدّة سلفًا + غير موصولة |
| `core/model_council.py` | `:132-182` | صفر مستدعين |
| `hunter_ai/tools/tool_router.py` | `:96-104` | يسجّل صفر معالجات ⇒ لا يستطيع التنفيذ، وبوابته معطّلة صامتًا |
| `core/policy/policy_as_code.py` · `core/safety/constitutional_layer.py` | `:91-140` · `:31-77` | منطق صحيح لكنه خارج مسار التنفيذ الفعلي |
| `core/reasoning/attack_surface_graph.py` | — | في الذاكرة فقط بلا حفظ |
| `BrowserEventBus` | `core/browser/browser_event_bus.py:51` | المُنتِج موصول، والمستهلك الوحيد فئة تُبنى في الاختبارات |
| رسوم `EvidenceGraph` | `pipeline_orchestrator.py:2139` | تُكتب في `13_evidence/evidence_graph.json` ولا تُقرأ أبدًا |
| مواصفة `httpx` في سجل الأدوات | `hunter_ai/pipeline/tool_specs.py:136-149` | الفحص الفعلي داخلي بـPython، والأداة لا تُنفَّذ |
| `ToolExecutionResult` | `core/contracts/task_contracts.py:76-117` | لا يستورده خط الأنابيب (يستخدم `ToolExecutionMeta`) |

### 8.3 `BLOCKED` — التحقق/التنفيذ متوقف على اعتمادية غير متاحة

| المكوّن | الاعتمادية الغائبة | التحقق المنفّذ |
|---|---|---|
| `subfinder`, `httpx`, `nuclei`, `ffuf`, `gobuster`, `katana`, `sqlmap`, `dalfox`, `amass` | غير مثبتة على هذا الجهاز (`Get-Command` = missing) | مسار الـfallback يعمل، و7 فجوات تغطية سُجّلت الآن |
| وكيل Burp الحيّ عبر بروكسي | لا شيء يستمع على `127.0.0.1:8080` | فحص TCP مباشر ⇒ NOT LISTENING |
| بوابات التصديق المعتمدة على أدوات Kali | نفس الأدوات أعلاه | `certify.py` يمر بـ15/15 لأنه لا يشغّل الأدوات فعليًا |

> ملاحظة: `nmap` هو الأداة الخارجية الوحيدة المثبتة. أما مسارات المتصفح فتعمل: شُغِّل `firefox` و`chromium` عبر Playwright بنجاح (`LAUNCH OK` لكليهما)، و`run_unified_live_session.py` يمر من البداية للنهاية — أي أن أتمتة المتصفح `EXISTS` وليست `BLOCKED`.

### 8.4 ما تغيّر من `MISSING` إلى `EXISTS` في هذه الجلسة

`CoverageStatus` · `StrictScopeEngine.from_file` · ترتيب بوابات السكوب · تصنيف فشل الأدوات · تسجيل فجوات التغطية.

التفاصيل والأدلة في `docs/IMPLEMENTATION_LEDGER.md`.

---

## 7. الربط بخطة المرحلة الأولى

| أولوية الخطة | ما يجب فعله بناءً على هذا التدقيق |
|---|---|
| **P0 — تدقيق التنفيذ** | ✅ أُنجز بهذا التقرير |
| **P0 — توحيد العقود** | إزالة العقدين المتوازيين: تثبيت `ToolExecutionResult` وجعل `ToolExecutionMeta` adapterًا يرجع إليه؛ ثم توصيله بـ`MasterToolRegistry` وكل وكيل |
| **P0 — Task Scheduler** | إصلاح المراجعة الذاتية (`task_scheduler.py:275`)، إضافة `parameters`، ومنع `Simulated noop` من المرور كنجاح |
| **P0 — قياس التغطية** | توصيل `CoverageLedger` بـ`HunterPipelineOrchestrator`، وتسجيل كل فشل أداة كـblindspot بدل بلعه |
| **P0 — إغلاق ثغرة التحقق** | جعل الإثبات **مُشتقًّا** لا **مُعلَنًا**: تمرير الطلب/الاستجابة الفعليين إلى `ProofOfExecutionEngine` بدل الاعتماد على أعلام المستدعي. هذه أهم بند في القائمة كلها |
| **P1 — Recon/Web Teams** | إعادة بناء `core/teams` كوكلاء يستهلكون `MasterToolRegistry` الحقيقي، أو حذفها وبناء الفرق على `agents/` الحقيقي |
| **P1 — Adaptive Planner** | ربط `InformationGainPlanner` بالـ`hypotheses` الحقيقية بدل الثوابت |
| **P1 — Independent Verification** | جعل `EvidenceCourt` بوابة إلزامية على **كل** مسار يكتب `CONFIRMED`، وإزالة الكتابة المباشرة |
| **P1 — Persistent State** | اختيار مخزن واحد للحالة المشتركة وتوصيله بمسار `main.py` |
| **قبل كل ذلك** | إصلاح الانحدار: `CoverageStatus` (يُعيد CLI و5 ملفات اختبار)، وترتيب بوابات السكوب قبل الـAI |


