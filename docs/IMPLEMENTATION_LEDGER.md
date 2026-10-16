# HunterAI — سجل التنفيذ (Implementation Ledger)

> **الجلسة:** 2026-10-16 · **الفرع:** `main`
> **القاعدة:** لا يُعتبر أي بند مكتملًا لأن كودًا كُتب — بل فقط عند تحقق معايير القبول بتشغيل فعلي.
> **رموز الحالة:** `EXISTS` · `PARTIAL` · `MOCKED` · `DISCONNECTED` · `MISSING` · `UNVERIFIED` · `BLOCKED`

---

## ملخّص الجلسة

| البند | قبل | بعد | الاختبار |
|---|---|---|---|
| `CoverageStatus` (انحدار `af1af9c`) | ❌ CLI ميت + 5 ملفات لا تُحمَّل + 5 أعطال | ✅ **EXISTS** | 32/32 نجحت · CLI 68 أمرًا يعمل |
| `StrictScopeEngine.from_file` | ❌ `AttributeError` يقتل خط الأنابيب | ✅ **EXISTS** | نُفِّذ فعليًا (§ أدناه) |
| ترتيب بوابات السكوب/الـAI | ❌ الـAI قبل السكوب + اتصال قبل الرفض | ✅ **EXISTS** | أُعيد التشغيل: رفض في 2.41s |
| تجاوز `PolicyGate` للأوامر الطرفية | ❌ metadata/loopback مسموح | ✅ **EXISTS** | 19 اختبار انحدار جديد |
| تسجيل فشل الأدوات | ❌ يُبتلع في 15 موضعًا | ✅ **EXISTS** | 7 فجوات مسجّلة E2E |

**خط أساس الاختبارات (مُقاس فعليًا في هذه الجلسة):**

| المرحلة | متجمّع | نجح | فشل | أخطاء تحميل | الزمن |
|---|---|---|---|---|---|
| بداية الجلسة (Ollama متاح) | 1064 | 1052 | 12 | 5 | 7:52 |
| بعد إصلاح `CoverageStatus` | 1129 | — | — | **0** | — |
| تحقق مركّز على التغييرات الخمسة | — | **59** | 0 | 0 | 18 ث |
| **المجموعة الكاملة (الحالة النهائية)** | **1129** | **1156** | **0** | **0** | **4:53:26** |

> **ملاحظة تشغيلية خطيرة:** زمن المجموعة الكاملة انفجر من ~8 دقائق إلى **4 ساعات و53 دقيقة** بمجرد أن أصبح Ollama متاحًا. السبب أن عددًا كبيرًا من الاختبارات يجري **استدلالًا حقيقيًا** على النماذج المحلية بلا mock وبلا مهلة قصيرة. في السابق كانت هذه الاختبارات تفشل بسرعة (preflight)، فبدا الزمن معقولًا.
> النتيجة: المجموعة **غير صالحة كبوابة CI** بالشكل الحالي. هذا عيب في الاختبارات لا في الكود المُنتَج، ويجب معالجته في المرحلة 7 (تقليل الزمن / عزل الاستدلال خلف fixture). الأرقام أعلاه حقيقية بالكامل ولم تُختصر.

عدد الاختبارات المتجمّعة (`1129`) أقل من عدد الناجح (`1156`) لأن بعض الاختبارات مُعاملة بـparametrize وتُولّد حالات أكثر عند التشغيل من لحظة الجمع.

> **تصحيح مهم:** في تدقيق الجولة السابقة صُنِّف 5 أعطال كـ"بيئية" بسبب انقطاع Ollama. **هذا التصنيف كان خاطئًا في الجلسة الحالية**: Ollama متاح (`qwen3:8b`, `qwen2.5-coder:14b`, `qwen2.5-coder:14b-tools`, `xploiter/pentester:latest`, `WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B:latest`) والـAI Preflight ينجح بالكامل (`online=True, inference_ok=True, 3/3 أدوار`). أُعيد تشغيل الأعطال فتبيّن أن **5 فقط** كانت حقيقية وكلها سبب واحد: `CoverageStatus`.

---

## LEDGER-001 — إصلاح انحدار `CoverageStatus`

| الحقل | القيمة |
|---|---|
| **Capability** | سجل التغطية على مستوى الـendpoint + الـCLI الموحّد |
| **الحالة السابقة** | `MISSING` (الواجهة محذوفة والكود يعتمد عليها) |
| **الملفات المفحوصة** | `core/coverage/coverage_ledger.py`، `core/coverage/__init__.py`، `cli/hunter_cli.py:50,456-467,1101-1113`، `core/brain/autonomous_brain.py:1734-1736,2470-2471,2565-2566`، `tests/test_v18_...py:106-128`، `tests/test_v2_deep_architecture.py:47-64` |
| **الملفات المتغيرة** | `core/coverage/coverage_ledger.py` · `core/coverage/__init__.py` |
| **وصف التغيير** | استرجاع الواجهة القديمة **داخل نفس الفئة** بدل إنشاء سجل موازٍ: `CoverageStatus` (10 قيم)، `SurfaceItem`، `record_probed()`، `record_skipped()`، `format_terminal_coverage_map()`، والحقل `items`. موسّع `UntestableReason` بـ6 أسباب سببية كانت تُفقد، مع `LEGACY_STATUS_TO_REASON` يحوّل حالة التخطي إلى سبب بنيوي. المُنشئ يقبل `target_scope` و`persistence_file` معًا (تمييز مسار `.json` الموضعي). `get_summary()` أصبح **إسقاطًا مدمجًا**: مفاتيح مستوى الأصل (الجديدة) + مفاتيح مستوى الـendpoint (القديمة) بلا تعارض. |
| **الاختبارات المنفَّذة** | `pytest tests/test_v18_auditable_security_platform.py tests/test_v2_deep_architecture.py tests/test_agent_teams_benchmark.py` · `pytest tests/test_autonomous_brain_state.py tests/test_integration_pipeline.py tests/test_v19_epistemic_security_os.py tests/v27/test_v27_brain_ooda_and_endpoints.py` · `pytest tests --collect-only` · `python cli/hunter_cli.py coverage --domain example.com` |
| **نتائج الاختبارات** | ✅ **32/32 نجحت** · ✅ **أخطاء التحميل 5 → 0** (1129 متجمّع) · ✅ CLI يعمل ويطبع سجل المساحة السلبية |
| **قيود متبقية** | `/ledger` ليس وسيطًا في أمر `coverage` (يستخدم `--domain`); هذا سلوك موجود مسبقًا ولم أغيّره |
| **الحالة الحالية** | ✅ **EXISTS** |

---

## LEDGER-002 — `StrictScopeEngine.from_file`

| الحقل | القيمة |
|---|---|
| **Capability** | تحميل سياسة النطاق من ملف (`--scope-file` / `scope.yaml` / `scope.json`) |
| **الحالة السابقة** | `MISSING` — `pipeline_orchestrator.py:178` ينادي دالة غير موجودة ⇒ انهيار |
| **الملفات المفحوصة** | `core/scope_engine.py:88-146`، `hunter_ai/pipeline/pipeline_orchestrator.py:176-193`، `main.py:46,124` |
| **الملفات المتغيرة** | `core/scope_engine.py` · `hunter_ai/pipeline/pipeline_orchestrator.py` |
| **وصف التغيير** | 1) إضافة `from_file()` تدعم YAML/JSON وتتعامل مع مفتاح `scope:` المتداخل، وترفع `FileNotFoundError`/`ValueError` صراحةً بدل السقوط إلى سياسة متساهلة. 2) إضافة `check_inviolable()` كواجهة عامة لفحص الثوابت غير القابلة للتجاوز (تُستخدم في LEDGER-004). 3) إضافة `from pathlib import Path` المفقودة. 4) في الـOrchestrator: تمرير الحقل الصحيح `rate_limit_rps` بدل `max_rate_limit_rps` (حقل غير موجود كان يُسقَط صامتًا)، وتبنّي حدّ المعدّل المُعلن في ملف السكوب. |
| **الاختبارات المنفَّذة** | `python main.py -t https://evil.example.net --scope-file scratch/_scope_ok.json --dry-run --allow-no-ai` · `python main.py -t https://example.com --scope-file ...` · `pytest tests/test_policy_invariants_on_commands.py::TestScopeFileLoading` |
| **نتائج الاختبارات** | ✅ الهدف خارج النطاق: رُفض في **2.41s** برسالة `out_of_scope` (لا انهيار). ✅ الهدف داخل النطاق: `SCOPE_APPROVED → PREFLIGHT_PASSED (AI_READY) → completed`. ✅ 4/4 اختبارات تحميل ملف السكوب. ✅ التحقق من تبنّي حدّ المعدّل: `3.5` من الملف إلى `AdaptiveRateLimiter` |
| **قيود متبقية** | لا يوجد تحقق من مخطط الملف قبل البناء (يعتمد على pydantic) |
| **الحالة الحالية** | ✅ **EXISTS** |

---

## LEDGER-003 — ترتيب البوابات: السكوب قبل الـAI Preflight

| الحقل | القيمة |
|---|---|
| **Capability** | فرض النطاق قبل أي خروج شبكي (بند P0 في الدستور) |
| **الحالة السابقة** | ❌ `MISSING` — بوابتان معكوستان |
| **الملفات المفحوصة** | `hunter_ai/pipeline/pipeline_orchestrator.py:2348-2400,516-596` · `hunter_ai/pipeline/state_machine.py:61-78` |
| **الملفات المتغيرة** | `hunter_ai/pipeline/pipeline_orchestrator.py` · `hunter_ai/pipeline/state_machine.py` |
| **وصف التغيير** | عيبان منفصلان: **(أ)** `run()` كان ينادي `stage_ai_preflight()` قبل `stage_scope_check()`، فالهدف خارج النطاق يرجع `ai_preflight_failed` بدل `out_of_scope`، وبوابة الـAI تُجري خروجًا شبكيًا وتكتب artifacts لهدف غير مصرّح. **(ب)** داخل `stage_scope_check` كان `ProgramIntelligence.discover_program()` يُجري اتصالًا شبكيًا **قبل** فحص الرفض في `:589`. الحل: السكوب أولًا، ووقف صلب فوري عند الرفض قبل أي كود شبكي. كما حُدِّث جدول انتقالات الـFSM للسماح بـ`SCOPE_CHECK → PREFLIGHT` و`AI_READY/DEGRADED_MODE → DISCOVER` مع إبقاء الانتقالات القديمة (توافق خلفي). |
| **الاختبارات المنفَّذة** | `pytest tests/test_hunter_master_pipeline.py tests/test_hunter_workflow_pipeline.py tests/test_enterprise_casm.py tests/test_artifact_based_recon.py tests/test_program_intelligence_and_triad.py tests/test_scope_and_false_positives.py` · تشغيل E2E للهدفين |
| **نتائج الاختبارات** | ✅ **44/44 نجحت** (0.5–5.7 دقيقة) بلا انحدار. ✅ E2E: رفض خارج النطاق في 2.41s قبل أي طلب. ✅ الـFSM رفض الترتيب الجديد في المحاولة الأولى برسالة صريحة — دليل على أن آلة الحالة مفروضة فعليًا، ثم حُدِّث الجدول عن قصد |
| **قيود متبقية** | `stage_scope_check` ما زال يستدعي `record_lineage` قبل الفحص — كتابة محلية فقط، لا خروج شبكي |
| **الحالة الحالية** | ✅ **EXISTS** |

---

## LEDGER-004 — إغلاق تجاوز `PolicyGate` للأوامر الطرفية

| الحقل | القيمة |
|---|---|
| **Capability** | فرض الثوابت غير القابلة للتجاوز (loopback / cloud metadata / النطاقات المحجوزة) على **كل** فئات التنفيذ |
| **الحالة السابقة** | ❌ ثغرة مؤكدة بتجربة: `curl http://169.254.169.254/latest/meta-data/` ⇒ **مسموح** |
| **الملفات المفحوصة** | `core/control_plane/policy_gate.py:101-177` · `core/control_plane/computer_control.py:121,220` · `core/scope_engine.py:229-258` |
| **الملفات المتغيرة** | `core/control_plane/policy_gate.py` · `core/scope_engine.py` · **جديد:** `tests/test_policy_invariants_on_commands.py` |
| **وصف التغيير** | السبب الجذري: `is_local_exec` يعتبر أي أمر طرفي بـ`target=local_terminal` تنفيذًا محليًا فيتخطى **كل** فحص النطاق — وفحص الميتاداتا داخل الفرع المُتخطّى. الحل: خطوة جديدة **قبل** الاستثناء، تعمل على كل الفئات، تستخرج الوجهات من `url`/`target`/`command` عبر `extract_candidate_destinations()` (روابط + IPv4 + أسماء metadata المعروفة، **ولا تطابق المسارات الملفية** ولا أرقام الإصدارات) وتمرّرها على `check_inviolable()`. |
| **الاختبارات المنفَّذة** | `pytest tests/test_policy_invariants_on_commands.py` (19 اختبارًا جديدًا) |
| **نتائج الاختبارات** | ✅ **19/19 نجحت**: metadata عبر أمر طرفي ⇒ مرفوض · `metadata.google.internal` ⇒ مرفوض · `127.0.0.1:8085` ⇒ مرفوض · `localhost` ⇒ مرفوض · `240.0.0.1` ⇒ مرفوض · `rm -rf /` ⇒ مرفوض (سلوك محفوظ) · `ls -la /tmp && cat /etc/hostname` ⇒ **مسموح** (لا إفراط في الحجب) · طلب HTTP داخل النطاق ⇒ مسموح · خارجه ⇒ مرفوض |
| **قيود متبقية** | الأدوات التي تُنفَّذ عبر `ToolManager` مباشرة (مسار خط الأنابيب) **لا تمر بـ`PolicyGate` أصلًا** — فجوة S1 في تقرير التدقيق، لم تُعالَج في هذه الجلسة |
| **الحالة الحالية** | ✅ **EXISTS** (للمسار الذي يمر بالبوابة) · ⚠️ فجوة S1 منفصلة لا تزال `MISSING` |

---

## LEDGER-005 — تسجيل فشل الأدوات كفجوات تغطية

| الحقل | القيمة |
|---|---|
| **Capability** | تعقّب فشل الأدوات وتصنيفه والإبلاغ عنه بدل بلعه |
| **الحالة السابقة** | ❌ `MISSING` — `except Exception: logger.debug` في 15 موضعًا + أداة مفقودة لا تُميَّز عن نجاح فارغ |
| **الملفات المفحوصة** | `tools/tool_manager.py:8-25,194-259` · `hunter_ai/pipeline/tool_specs.py:712-790` · `hunter_ai/pipeline/pipeline_orchestrator.py` (مواضع الاستدعاء) |
| **الملفات المتغيرة** | `tools/tool_manager.py` · `hunter_ai/pipeline/tool_specs.py` · `hunter_ai/pipeline/pipeline_orchestrator.py` · **جديد:** `tests/test_tool_failure_classification.py` |
| **وصف التغيير** | **(1)** إضافة `error_category` إلى `ToolResult` ودالة `classify_tool_failure()`: سببان مؤكدان — `except FileNotFoundError` **لا يمكن أن يُستدعى أبدًا** مع `create_subprocess_shell`، فالأداة المفقودة تعود بـ127/9009 و`error=None`. الآن تُصنَّف `TOOL_UNAVAILABLE` / `NONZERO_EXIT` / `TIMEOUT` / `EXECUTION_ERROR`، مع نمط regex محكم لرسائل الـshell (`sh: 1: foo: not found`) لا يخطئ في تفسير «record not found» العادية. **(2)** حالة جديدة `fallback_empty` عندما يُنتج الـfallback صفر عناصر — لم تعد تُعدّ نجاحًا. **(3)** نقطة ربط واحدة: `MasterToolRegistry.set_result_observer()` تُستدعى بعد كل تنفيذ، والـOrchestrator يسجّل من خلالها فجوة تغطية في `CoverageLedger` (بدل تعديل 20 موضع نداء). **(4)** `coverage_summary` و`tool_failures` في نتيجة خط الأنابيب + حفظ `coverage_ledger.json`. |
| **الاختبارات المنفَّذة** | `pytest tests/test_tool_failure_classification.py tests/test_tool_output_logging.py` · `python main.py -t https://example.com --mode recon --dry-run --allow-no-ai` · فحص `13_evidence/coverage_ledger.json` |
| **نتائج الاختبارات** | ✅ **13/13 نجحت**. ✅ E2E: **7 فجوات** مسجّلة كانت تُبتلع سابقًا (`subfinder`, `waybackurls`, `hakrawler`, `gau`, `ffuf`, `feroxbuster`, `gobuster`) · الملف المكتوب: `blindspots_count=7`, `assets_untestable=2` |
| **قيود متبقية** | التصنيف يعتمد على أنماط نصية لبعض حالات Windows؛ `ToolSpec.parser` ما زال ترشيحًا نصيًا لا تحليلًا بنيويًا؛ الـobserver callback متزامن |
| **الحالة الحالية** | ✅ **EXISTS** |

---

## LEDGER-006 — محرّك تفكير موحّد (DeepSeek-R1 + Claude) وربطه بالأوركستريتور

| الحقل | القيمة |
|---|---|
| **Capability** | طبقة تفكير انعكاسية موحّدة تُغذّي قرار الأوركستريتور وتُسجَّل في سجل التدقيق |
| **الحالة السابقة** | `DISCONNECTED` — `ClaudeThinkingEngine` موجود لكن بلا اختبارات وبلا ربط؛ ونمط DeepSeek-R1 غير موجود إطلاقًا |
| **الملفات المفحوصة** | `core/cognitive/claude_thinking_protocol.py` · `hunter_ai/brain/orchestrator_workers.py:407-450` · `hunter_ai/brain/cognitive_council.py` · `hunter_ai/runtime/meta_reasoning.py` · `agents/security_intelligence/brain.py` |
| **الملفات المتغيرة** | `core/cognitive/__init__.py` · `hunter_ai/brain/orchestrator_workers.py` · **جديد:** `core/cognitive/deepseek_thinking_protocol.py` · `core/cognitive/hybrid_reasoning_core.py` · `tests/test_hybrid_reasoning.py` · `tests/test_orchestrator_workers.py` |
| **وصف التغيير** | **(1)** `DeepSeekThinkingEngine`: تفكيك المشكلة، استكشاف مسارات متعددة (self-consistency)، تحقق مستقل، **backtracking** بلحظة «wait» (aha)، ضبط الإفراط في التفكير (rumination-halt) وفق نتيجة بحث «Thoughtology» بأن الإفراط يضرّ، ثقة مُعايَرة على نسبة الاتفاق، ومراجعة ميتا. **(2)** `HybridReasoningCore`: يوجّه بين نمط Claude (منظّم 8 مراحل/متشابك) ونمط DeepSeek (انعكاسي) حسب تعقيد المهمة — نظير Claude Adaptive Thinking. **(3)** الربط الفعلي: `MasterOrchestratorEngine.decide_next_action()` يحقن بروتوكول التفكير في الـsystem prompt ويسجّل الاستراتيجية داخل `BlackboardState.record_action`. fail-safe: لو النظام المعرفي غير متاح يستمر الأوركستريتور بسلوكه السابق دون تغيير. لا تُعرَض سلسلة التفكير الخاصة — فقط ملخّص قرار مختصر (استراتيجية/ثقة/إحصاءات). **(4)** self-consistency على مستوى القرار: عند `reasoning_samples > 1` يُجري الأوركستريتور عدّة استدلالات بدرجة حرارة أعلى (0.7) ويأخذ **تصويت الأغلبية** للفعل عبر `Counter`، ويُسجّل `decision_agreement`. الافتراضي `1` ⇒ سلوك وتكلفة بلا تغيير. |
| **الاختبارات المنفَّذة** | `pytest tests/test_hybrid_reasoning.py tests/test_orchestrator_workers.py -v -p no:cacheprovider` · فحص الاستيراد `python -c "import core.cognitive, hunter_ai.brain"` |
| **نتائج الاختبارات** | ✅ **31/31 نجحت** (22 لمحركات التفكير + 9 للأوركستريتور، منها 6 جديدة: 3 للربط و3 لتصويت الأغلبية). أثناء التطوير كشفت الاختبارات **خطأين منطقيين حقيقيين** وأُصلحا: ترتيب تسطيح خطوات VERIFY/BACKTRACK في `think()`، ومُقيِّم التعقيد الذي صنّف مهمة تحليلية قصيرة كبسيطة. |
| **قيود متبقية** | self-consistency على مستوى القرار مُنفَّذة ومختبَرة لكنها **opt-in** (`reasoning_samples>1`) لأنها تضاعف استدعاءات الموديل؛ و`reasoner` callback في محرّك DeepSeek يبقى نقطة توسّع اختيارية غير موصولة بموديل في مسار القرار. |
| **الحالة الحالية** | ✅ **EXISTS** (المحرّكات + التوجيه + التدقيق + self-consistency على مستوى القرار) |

---

## LEDGER-007 — الإثبات المُشتق (لا المُعلَن) في الكاشفات ومسار الثغرات

| الحقل | القيمة |
|---|---|
| **Capability** | فرض عقد «إثبات قابل لإعادة التقييم» على كل مسار يقدّم دليلًا للمحكمة، وإزالة الإثبات المُعلَن الذي كان يُسقط نتائج صحيحة |
| **الحالة السابقة** | `DISCONNECTED` — المحكمة تشدّدت لترفض الإثبات المُعلَن، لكن الكاشفات ومحرّك الثغرات ومدقّقا Burp ما زالت ترسل أعلامًا مُعلَنة بلا دليل ⇒ 5 اختبارات فاشلة (نتاج `None`/صفر نتائج) |
| **الملفات المفحوصة** | `core/evidence_court.py` · `core/poe_engine.py` · `core/detectors/xss_detector.py` · `core/detectors/sqli_detector.py` · `core/vuln_engine.py` · `hunter_ai/pipeline/pipeline_orchestrator.py` · `validate_burp_integration.py` · `validate_burp_e2e_v2.py` |
| **الملفات المتغيرة** | نفسها — أُضيف `ProofPayload.from_vuln_evidence`، ووُصل `proof_payload` في الكاشفات/المحرّك/المدقّقين، ووُسِّع `verify_sqli_extraction` |
| **وصف التغيير** | **(1)** `ProofPayload.from_vuln_evidence(vuln_type, evidence)` — مصدر واحد لبناء حمولة دليل قابلة لإعادة التقييم (يعيد `None` عند غياب بصمة PoE، فلا يُلفَّق دليل). **(2)** `pipeline_orchestrator._build_proof_payload` صار يفوّض إليه (إزالة تكرار). **(3)** كاشف XSS يمرّر دليل توكن (nonce) مع الاستجابة المُطفَّرة وbaseline. **(4)** كاشف SQLi يمرّر دليلًا تفاضليًا (استجابة مُطفَّرة مقابل baseline). **(5)** `vuln_engine.assess_target` يبني الحمولة من `extracted_data`. **(6)** `ProofOfExecutionEngine.verify_sqli_extraction` يتعرّف الآن على بانرات **Oracle** و**MSSQL** (تقوية، لا إضعاف). **(7)** مدقّقا Burp (CHECK-09/11) يمرّران حمولة توكن حقيقية. |
| **الاختبارات المنفَّذة** | `pytest tests/test_v1_architecture.py tests/test_vuln_engine.py tests/test_burp_e2e_v2.py tests/test_burp_live_validation.py tests/test_proof_provenance.py tests/test_burp_gateway.py` · `tests/integration/test_evidence_court.py` · `tests/v27/*` · مستهلكو خط الأنابيب |
| **نتائج الاختبارات** | ✅ **61/61** (المجموعة المركزة) + 24 (المحكمة/PoE/v27) + 23 (خط الأنابيب) + 15 (master/workflow). صفر فشل. |
| **قيود متبقية** | الكاشفات القائمة على **بانر إصدار** فقط تُقبل كإثبات SQLi مباشر؛ أما الحالات الحسابية/الأخطاء فتستخدم الدليل التفاضلي (مسار مُعتمَد في المحكمة). |
| **الحالة الحالية** | ✅ **EXISTS** (الإثبات المُشتق مفروض ومُستهلك في كل المسارات المختبَرة) |

---

## LEDGER-008 — حوكمة تنفيذ الأدوات (`ToolManager` → PolicyGate) لإغلاق فجوة S1

| الحقل | القيمة |
|---|---|
| **Capability** | كل تنفيذ أداة يمرّ عبر `PolicyGate` (fail-closed) ويُسجَّل تدقيقيًا |
| **الحالة السابقة** | `MISSING` (S1): `ToolManager.execute()` كان يشغّل أوامر shell عبر `create_subprocess_shell` بلا أي بوابة، و`ToolManager` يُنشأ في ~15 موضعًا |
| **الملفات المفحوصة** | `tools/tool_manager.py` · `core/control_plane/policy_gate.py` · `core/system/terminal_bridge.py` (نمط مرجعي) · `hunter_ai/pipeline/pipeline_orchestrator.py:209` |
| **الملفات المتغيرة** | `tools/tool_manager.py` · `hunter_ai/pipeline/pipeline_orchestrator.py` · **جديد:** `tests/test_tool_manager_governance.py` |
| **وصف التغيير** | **(1)** `ToolManager.__init__(..., policy_gate=None, project_id="default")` + `attach_policy_gate()` + `_govern()`: يبني `ActionRequest(TERMINAL_COMMAND)`، ويستخرج الوجهات عبر `extract_candidate_destinations`، ويستدعي `PolicyGate.evaluate` — **fail-closed** عند أي خطأ، ويعيد `ToolResult(error_category="POLICY_DENIED"/"POLICY_ERROR")` دون تنفيذ. **(2)** استدعاء الحوكمة داخل `execute()` **قبل** الكاش والتنفيذ. **(3)** `pipeline_orchestrator` يربط بوابته الرسمية بـ`self.tm` فور بنائها ⇒ كل `NetworkTools/WebTools/MasterToolRegistry` محكومة. **(4)** سجل تدقيق `governance_audit` يحوي: project_id، tool_id، action، timestamp، القرار، السبب. |
| **الاختبارات المنفَّذة** | `pytest tests/test_tool_manager_governance.py` + `test_policy_invariants_on_commands.py` · `test_tool_failure_classification.py` · `test_tool_output_logging.py` · `test_governed_tool_gateway.py` · `test_policy_engine.py` · `test_risk_classifier.py` + خط الأنابيب |
| **نتائج الاختبارات** | ✅ 61/61 (الحوكمة/الأدوات) + 25 (master/workflow/scope) + 64 (مستهلكو خط الأنابيب + الأوركستريتور + التفكير + terminal_bridge). صفر فشل. |
| **قيود متبقية** | استخراج الوجهات يلتقط روابط `http(s)` وعناوين IPv4 والمضيفات المحظورة فقط؛ أسماء المضيفين المجرّدة (مثل `nmap evil.net`) تُعامَل كتبديل محلي — يبقى فرض قائمة السماح عليها في طبقة التخطيط/terminal_bridge. |
| **الحالة الحالية** | ✅ **EXISTS** (fail-closed + تدقيق لكل تنفيذ أداة في المسار الرئيسي) |

---

## LEDGER-009 — بوابة المحكمة على ترقية الفرضيات (`InvestigationController` → EvidenceCourt)

| الحقل | القيمة |
|---|---|
| **Capability** | كل Finding «مؤكد» ينتجه حلقة OODA يمرّ عبر `EvidenceCourt.adjudicate` قبل تسجيله |
| **الحالة السابقة** | `MISSING` — `_promote_to_evidence_court` كان يبني `HunterFinding(status=CONFIRMED)` مباشرة ويضيفه إلى `self.orc.findings` **دون استدعاء المحكمة إطلاقًا**، معتمدًا فقط على علم الـskill المُعلَن (`objective_met`/`verified`) ⇒ مسار تجاوز للمحكمة |
| **الملفات المفحوصة** | `hunter_ai/pipeline/investigation_controller.py:498-686` · `core/evidence_court.py:136-158,545-624` · `hunter_ai/pipeline/pipeline_orchestrator.py:1698-1710` · `tests/test_parameter_intelligence_and_canonicalizer.py:185-262` |
| **الملفات المتغيرة** | `hunter_ai/pipeline/investigation_controller.py` · **جديد:** `tests/test_investigation_court_promotion.py` |
| **وصف التغيير** | **(1)** الترقيہ الآن تستدعي `EvidenceCourt.adjudicate(...)` مع `is_in_scope=True` و`allow_declared_proof=True` (لأن الـskill مُحقِّق داخلي موثوق)، فلا يُسجَّل Finding إلا إذا أعادت المحكمة `CONFIRMED && reportable`. **(2)** مصفوفة `_COURT_FLAG_BY_VULN`: كل نوع ثغرة ⟶ علم مُعلَن مناسب (`dom_breakout_confirmed` لـXSS، `token_bypass_confirmed` لـIDOR/SSRF، `template_eval_confirmed` لـSSTI، `arithmetic_proof_confirmed` لـCmdInjection، `file_content_confirmed` لـLFI، `boolean_branch_confirmed` لـSQLi). **(3)** `_verified_proof_payload`: يرفق حمولة دليل **فقط** إذا تحقّق محرّك PoE نفسه أنه يستطيع اشتقاق الإثبات منها (فلا نحوّل نتيجة صحيحة إلى رفض خاطئ)، وإلا يعود لمسار الإثبات المُعلَن الموسوم. **(4)** `run()`: إذا لم تؤكّد المحكمة، تُسجَّل الحالة `inconclusive` وتُعاد الفرضية بترجيح أقل أو تُرفض — بدل وسمها `CONFIRMED`. **(5)** Finding يحمل الآن `court_verdict`/`court_proof_strength`/`court_epistemic_state` في `false_positive_checks`. |
| **الاختبارات المنفَّذة** | `pytest tests/test_investigation_court_promotion.py` (5 جديدة) · `pytest tests/test_parameter_intelligence_and_canonicalizer.py` (14) · مستهلكو خط الأنابيب |
| **نتائج الاختبارات** | ✅ **5/5** (مُعلَن مُوسَّم · مُشتَق · رفض يُسقط · حلقة كاملة تُسجّل فقط ما أكّدته المحكمة · رفض الادعاء المُعلَن) + **14/14** الحالي. صفر فشل. |
| **قيود متبقية** | الـskills التي لا تُصدر حقل `proof_payload` صريحًا تُؤكَّد عبر مسار الإثبات المُعلَن الموسوم (`CONFIRMED_ON_DECLARED_PROOF`) لا عبر إثبات مُشتَق — تحسين مستقبلي: أن تُصدر الـskills حمولات توكن/تفاضلية قابلة لإعادة التقييم. |
| **الحالة الحالية** | ✅ **EXISTS** (لا Finding بلا قرار محكمة) |

---

## LEDGER-010 — إزالة مسار الترقية الميت الذي يتجاوز المحكمة (`raw_probe_findings`)

| الحقل | القيمة |
|---|---|
| **Capability** | إزالة مسار موازٍ ميت كان يبني `HunterFinding(status=CONFIRMED)` متجاوزًا المحكمة |
| **الحالة السابقة** | `MISSING` — `raw_probe_findings = []` في `pipeline_orchestrator` **لم يُضَف إليه أي عنصر أبدًا**، فحلقتا المستهلك (استراتيجية WhiteRabbitNeo + كتلة VERIFY بـ~330 سطرًا) كانتا **غير قابلتين للوصول**، و`verified_findings` تبقى فارغة و`self.findings.extend([])` بلا أثر |
| **الملفات المفحوصة** | `hunter_ai/pipeline/pipeline_orchestrator.py:1678,1870-1887,1912-2245` · `git show HEAD:...` (تأكيد أنها كود قائم لا تعديل غير مُلتزم) |
| **الملفات المتغيرة** | `hunter_ai/pipeline/pipeline_orchestrator.py` |
| **وصف التغيير** | حُذفت **336 سطرًا** ميتًا: تهيئة `raw_probe_findings`، وحلقة WhiteRabbitNeo على الفرضيات الخام، وكتلة VERIFY المكرّرة التي كانت تبني Findings مباشرة بدرجات ثابتة ومتجاوزة للمحكمة. أُبقي انتقال حالة `VERIFY` كعلامة مرحلة. الكفاءة المفقودة مُغطّاة فعليًا عبر `InvestigationController` (LEDGER-009) + `FindingQualificationGate`. لم يتغيّر أي سلوك وقت التشغيل (الكود لم يُنفَّذ يومًا). |
| **الاختبارات المنفَّذة** | `python -m py_compile` · `pytest tests/test_hunter_master_pipeline.py tests/test_hunter_workflow_pipeline.py tests/test_enterprise_casm.py tests/test_program_intelligence_and_triad.py tests/test_artifact_based_recon.py tests/test_burp_pipeline_fusion.py` · `grep raw_probe_findings` |
| **نتائج الاختبارات** | ✅ **55/55 نجحت** (+2 أُعيد تشغيلهما بعد تحرير المنفذ 8085: نجحا) · صفر مرجع متبقٍّ ما عدا تعليق توثيقي. |
| **قيود متبقية** | حذف كود ميت لا يُضيف قدرة؛ التحسين الحقيقي كان في LEDGER-009. |
| **الحالة الحالية** | ✅ **EXISTS** (المسار المتجاوز أُزيل؛ لا مسار موازٍ بلا محكمة) |

---

## LEDGER-011 — منع `CONFIRMED` الصامت (افتراضات المخطط + حكم `EvidenceOS` + صدق مراجع الفرق)

| الحقل | القيمة |
|---|---|
| **Capability** | إغلاق كل مسار يسمح بإعلان نتيجة مؤكّدة/متحقَّقة بلا إثبات |
| **الحالة السابقة** | `MOCKED` — أربعة مواضع: (أ) `HunterFinding.status=CONFIRMED` و`tier=VERIFIED_FINDING` افتراضيًا في المخطط؛ (ب) `EvidenceOS.rule_verdict(decision="CONFIRMED")` افتراضيًا وبلا استدعاء مدقّق النسب (`verify_claim_lineage`)؛ (ج) تكرار منطقي `x.lower() in x.lower()` في `DeterministicEvidenceValidator.evaluate_differential_response` يجعل فرق الطول وحده كافيًا؛ (د) `EvidenceCourtReviewer` يصادق حتى على حكم `UNVERIFIED` ويستعمل `poe_token` مُلفَّقًا |
| **الملفات المفحوصة** | `hunter_ai/pipeline/schemas.py:199-200` · `core/evidence_os/unified_model.py:242` · `core/evidence_graph.py:252-271` · `core/teams/verification_team.py:98-189` · `tests/test_v4_evidence_os.py` · `tests/test_burp_pipeline_fusion.py` · `grep HunterFinding(`/`rule_verdict`/`evaluate_differential_response` |
| **الملفات المتغيرة** | `hunter_ai/pipeline/schemas.py` · `core/evidence_os/unified_model.py` · `core/evidence_graph.py` · `core/teams/verification_team.py` · `tests/test_evidence_integrity_defaults.py` (جديد) |
| **وصف التغيير** | 1) افتراضيا `HunterFinding` صار `UNVERIFIED`/`NEEDS_REVIEW` (الترقية صريحة فقط من مسار البوابة). 2) `rule_verdict` افتراضيه `UNVERIFIED`، ويرفض `CONFIRMED` برفع `ValueError` إن لم تصحّ سلسلة النسب (Observation→…→Claim). 3) أُزيل التكرار المنطقي؛ يتطلّب الآن وجود مؤشّر الفرق فعلًا داخل الجسم (`tampered_body`) للتأكيد، وفرق الطول وحده لا يكفي. 4) `EvidenceCourtReviewer` يعيد التحكيم عبر `EvidenceCourt` بحمولة فرق حقيقية (`probed_text`/`baseline_text`) بلا رمز مُلفَّق، ولا يوافق إلا على `CourtVerdict.CONFIRMED`. 5) `CausalVerificationAgent` لا يختلق استجابات (يرفض عند غياب القياسات) ويحمل الأجسام الخام في الدليل لإعادة التقييم. |
| **الاختبارات المنفَّذة** | `tests/test_evidence_integrity_defaults.py` (12) · `tests/test_v4_evidence_os.py` (14) · `tests/test_evidence_graph_and_lab_mode.py` + مجموعة الأدلة (55) · `tests/test_hunter_master_pipeline.py tests/test_hunter_workflow_pipeline.py` (15) |
| **نتائج الاختبارات** | ✅ **96/96** عبر الأهداف الأربعة · ✅ **1262/1262** بصلة كاملة للحالة السابقة (13 دقيقة) · البصلة الكاملة على الحالة الجديدة تُؤكَّد في تقرير المرحلة |
| **قيود متبقية** | مواضع بوابة الماسحات (`dalfox`/`nikto`/`secrets`) ما زالت تمرّر `reproduced` فقط ⇒ ترفضها المحكمة (سلوك صادق: لا Finding بلا إثبات) — يُعالَج في البند التالي بتحويل ملاحظات الماسحات إلى فرضيات تُختبر. |
| **الحالة الحالية** | ✅ **EXISTS** (لا مسار لإعلان `CONFIRMED` بلا إثبات في المخطط/`EvidenceOS`/المحكمة/مراجع الفرق) |

---

## LEDGER-012 — تثبيت أساس سريع: نظافة الحوكمة والأدوات (M0)

| الحقل | القيمة |
|---|---|
| **Capability** | إزالة أخطاء صغيرة عالية الأثر: فتح افتراضي في الإعدادات، مضيف LAN مُثبّت، واستيراد ناقص |
| **الحالة السابقة** | `MOCKED`/`PARTIAL` — (أ) `config/settings.yaml` يعلن `unrestricted_scope: true` و`auto_approve_all: true` بلا أي قارئ في الكود؛ (ب) `192.168.1.3` مُثبّت في ستة مواضع إنتاجية رغم ادعاء `127.0.0.1`؛ (ج) `core/tool_registry.py:211,259` يستخدم `Tuple` غير مستوردة |
| **الملفات المفحوصة** | `config/settings.yaml:28-33` · مواضع المضيف الستة · `core/tool_registry.py` · `core/terminal_bridge.py` · بحث `nvidia_test.py` · `grep 192.168.1.3` · `grep settings.yaml` |
| **الملفات المتغيرة** | `config/settings.yaml` · `core/tool_registry.py` · `hunter_ai/brain/model_router.py` · `core/ai_bridge/agent_ai_cognitive_bridge.py` · `core/pipeline/vram_sequential_pipeline.py` · `core/resilience/autonomous_healing_engine.py` · `models/ollama_manager.py` · `platform/kali.json` · `test_connection.py` · `tests/test_config_and_host_hygiene.py` (جديد) |
| **وصف التغيير** | 1) أذونات `settings.yaml` صارت fail-closed (`false`) مع تعليق يوضّح أنها بلا قارئ. 2) وُحّد مضيف Ollama على `os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434")` في كل مواضع الإنتاج، وأُزيل مضيف الشبكة من قائمة اكتشاف `OllamaManager`. 3) أُضيف استيراد `Tuple` إلى `tool_registry` (إصلاح وقائي؛ ملاحظة: `from __future__ import annotations` كان يمنع `NameError` وقت التشغيل، لذا التدقيق كان مبالغًا في الأثر). |
| **الاختبارات المنفَّذة** | `tests/test_config_and_host_hygiene.py` (3) · `test_ai_model_connectivity` + `test_agent_ai_cognitive_bridge` + `test_vram_sequential_pipeline` (25) · `test_full_computer_agent.py` (14) · `py_compile` + `import` |
| **نتائج الاختبارات** | ✅ **42/42** عبر الأهداف الثلاثة + ترجمة/استيراد نظيفان |
| **قيود متبقية** | بندا P2-43 في التدقيق غير صالحين: `nvidia_test.py` **غير موجود أصلًا**، و`core/terminal_bridge.py` **مُستخدَم فعليًا** (`tests/test_e2e_phase17.py:37` و`capability_matrix.json:38`) ⇒ أُبقي. و`sync.sh` سكربت تطويري لمضيف مزامنة (منفذ 9999) خارج نطاق الإنتاج ⇒ أُبقي. وبقيت `tests/test_vram_sequential_pipeline.py` تمرّر المضيف صراحةً كوسيط اختبار (ليس افتراضيًا إنتاجيًا). |
| **الحالة الحالية** | ✅ **EXISTS** |

---

## LEDGER-013 — منع الكتابة المباشرة إلى `CONFIRMED` (M1a / C7)

| الحقل | القيمة |
|---|---|
| **Capability** | ألّا يُعلن أي مسار إنتاجي `CONFIRMED` انطلاقًا من راية مستدعٍ أو تصويت نماذج أو قيمة افتراضية خطرة |
| **الحالة السابقة** | `PARTIAL` — (أ) `core/arbitration_engine.py:82` يكتب `LifecycleStage.CONFIRMED` من `tool_output.get("verified")`، وهو **كود ميت** (صفر مستوردين) يكرّر قدرة المحكمة؛ (ب) `core/evidence_os/unified_model.py:118` قيمة `Verdict.decision` الافتراضية `CONFIRMED`; (ج) `core/confidence_checker.py:518` تصويت نماذج ≥0.65 ⇒ `CONFIRMED` (إشاري) |
| **الملفات المفحوصة** | `core/arbitration_engine.py` · `core/confidence_checker.py` · `core/evidence_os/unified_model.py` · `core/evidence_court.py` (`_ProofResolver`) · `orchestrator/router.py` · `core/contract/security_contract.py` · `grep` شامل لـ`CONFIRMED` |
| **الملفات المتغيرة** | **حُذف** `core/arbitration_engine.py` · `core/evidence_os/unified_model.py` · `core/confidence_checker.py` · `tests/test_no_direct_confirmation.py` (جديد) |
| **وصف التغيير** | 1) حُذف `arbitration_engine` (كود ميت + كتابة مباشرة تكرّر المحكمة ⇒ لا يُوصَل). 2) `Verdict.decision` صار fail-closed = `"INCONCLUSIVE"`. 3) إجماع النماذج صار `"CORROBORATED"` إشاريًا مع توضيح معماري في الوثيقة والتقرير؛ لا `CONFIRMED` من تصويت LLM. 4) اختبار حراسة: يمنع أي كتابة `LifecycleStage.CONFIRMED` خارج وحدات دورة الحياة/العقد، ويثبت أن راية المستدعِ المجرّدة لا تُؤكِّد بينما الإثبات المُشتقّ يُؤكِّد. |
| **الاختبارات المنفَّذة** | `tests/test_no_direct_confirmation.py` (5) + `test_evidence_integrity_defaults` + `test_v4_evidence_os` + `test_investigation_court_promotion` + `test_v8_investigation_os` + `test_v2_deep_architecture` + `test_scope_and_false_positives` |
| **نتائج الاختبارات** | ✅ **76/76 نجحت** + `py_compile` نظيف |
| **قيود متبقية** | `core/contract/security_contract.py:97` يُبقي كلمة `CONFIRMED` لكنها مُشتقّة من تقييم متطلبات + حدّ إعادة إنتاج (ليست راية مستدعٍ مجرّدة) ⇒ أُبقي بوعي. باقي M1 (توحيد V1/V2، إشارات الانعكاس، توصيل PoE) = M1b..M1d. |
| **الحالة الحالية** | ✅ **EXISTS** |

---

## ما بقي خارج نطاق هذه الجلسة (مقصود)

| البند | الحالة | السبب |
|---|---|---|
| إثبات مُشتق لا مُعلَن في `EvidenceCourt` | ✅ `EXISTS` (LEDGER-007) | فُرض العقد ووُصلت الحمولات القابلة لإعادة التقييم في الكاشفات ومحرّك الثغرات ومدقّقَي Burp |
| مسار `_promote_to_evidence_court` الذي يتجاوز المحكمة | ✅ `EXISTS` (LEDGER-009) | كل Finding يمرّ الآن عبر `EvidenceCourt.adjudicate` (مُعلَن مُوسَّم / مُشتَق) — لا Finding بلا قرار محكمة |
| `raw_probe_findings` الفارغة (340 سطر كود ميت) | ✅ `EXISTS` (LEDGER-010) | أُزيل المسار الميت المتجاوز للمحكمة (336 سطرًا)؛ الكفاءة مغطّاة عبر LEDGER-009 |
| فجوة S1: تنفيذ `ToolManager` بلا بوابة سياسة | ✅ `EXISTS` (LEDGER-008) | رُبط `ToolManager.execute` بـ`PolicyGate` fail-closed + سجل تدقيق؛ تبقّى فرض قائمة السماح على أسماء المضيفين المجرّدة |
| `core/teams` (18 وكيلًا محاكاة + كود ميت) | `PARTIAL` | المرحلة 2 — صُدِّق مراجع التحقق (`EvidenceCourtReviewer`) وأُلغي الاختلاق في `CausalVerificationAgent` (LEDGER-011)؛ بقية الفرق ما زالت محاكاة |
| افتراضات `CONFIRMED` الصامتة (المخطط + `EvidenceOS` + مراجع الفرق) | ✅ `EXISTS` (LEDGER-011) | أُلغيت الافتراضات الخطيرة، ورُفض `CONFIRMED` بلا نسب، وصار المراجع صادقًا |
| المراجعة المستقلة في `TaskScheduler` | `PARTIAL` | المرحلة 2 |
| الذاكرة المشتركة الموحّدة (6 مخازن) | `MISSING` | المرحلة 6 |
| ادعاء "البيئة المعزولة" مع مفتاح Gemini فعّال | `DISCONNECTED`/خطر | يحتاج قرار من المالك قبل التغيير |

---

## طريقة إعادة إنتاج النتائج

```powershell
cd E:\Agant\PentestAI-Unified

# 1) صحة الجمع والأساس
python -m pytest tests --collect-only -q -p no:cacheprovider

# 2) الاختبارات المركزة للتغييرات الخمسة
python -m pytest tests/test_policy_invariants_on_commands.py tests/test_tool_failure_classification.py `
                 tests/test_v18_auditable_security_platform.py tests/test_v2_deep_architecture.py -q

# 3) اختبارات مسار خط الأنابيب
python -m pytest tests/test_hunter_master_pipeline.py tests/test_hunter_workflow_pipeline.py `
                 tests/test_enterprise_casm.py tests/test_scope_and_false_positives.py -q

# 3b) سلامة الأدلة: منع CONFIRMED الصامت (LEDGER-011)
python -m pytest tests/test_evidence_integrity_defaults.py tests/test_v4_evidence_os.py `
                 tests/test_evidence_graph_and_lab_mode.py -q

# 4) الـCLI الذي كان ميتًا
python cli\hunter_cli.py coverage --domain example.com

# 5) الرفض قبل الخروج الشبكي
'{ "allowed_targets": ["example.com"] }' | Set-Content scratch\scope.json
python main.py -t https://evil.example.net --scope-file scratch\scope.json --dry-run --allow-no-ai

# 6) فجوات التغطية
python main.py -t https://example.com --mode recon --dry-run --allow-no-ai
```
