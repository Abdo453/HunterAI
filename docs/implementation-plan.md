# خطة التنفيذ — Multi-Agent Security Automation Platform

**المستودع:** `E:\Agant\PentestAI-Unified`
**البنية المرجعية:** inspiraция من Muteki (بنية موثقة علنًا) —executed بأصلية كود MIT، لا نسخ من AGPL.
**حالة البداية:** الأنظمة السبعة مضمنة بالفعل واختباراتها ناجحة (راجع `docs/architecture-audit.md`).
**مبدأ التنفيذ:** إضافي فقط (additive) — لا يُحذف ولا يُستبدل أي كود قائم يعمل.

---

## المراحل ومحتواها

### Phase A — التدقيق والخط الأساس (مكتمل)

| البند | الحالة | الملف |
|---|---|---|
| تدقيق المستودع والبنية | ✅ | `docs/architecture-audit.md` |
| تسجيل اختبارات الخط الأساس (1709 gathered) | ✅ | نتائج الـ pytest في المحادثة |
| خطّة التنفيذ هذه | ✅ | هذا الملف |

### Phase B — واجهات مشتركة + Configuration + سجل الأدوات + سياسة الإذن (التالي)

**الأهداف:**
- واجهة `AgentProvider` موحدة للموفري LLM (capabilities / health_check / execute / stream / cancel).
- سجل أدوات مركب (`ToolRegistry`) مع تعريفات أداة منظمة (schema، إذن، مخاطرة، مهلة، حد إخراج).
- سياسة إذن مركزية (Permission Policy) تفحص قبل أي تنفيذ أداة.

| القدرة | استخدام موجود | ملفات يجب إنشاؤها/تعديلها | التبعيات | الآثار الأمنية | الاختبارات | معايير القبول |
|---|---|---|---|---|---|---|
| واجهة موفري LLM | `core/llm_router.py` موجود (توجيه نماذج) | `core/agent_provider.py` (واجهة + 어댑ترات) | SDKs موجودة (لا protocoles مملوكة جديدة) | لا أسرار في السجلات | اختبارات واجهة + مزودي اختبار وهميين | health_check يرد، execute يُرجع تنسيقًا مشتركًا، cancel يُلغي |
| سجل أدوات مركب | `tools/tool_manager.py` موجود (يُستخدم من base_agent) | `core/tool_registry.py` (`Tool` describe/validate_input/authorize/execute/cancel/health_check) | Pydantic للكشف عن المخططات | رفض الأدوات غير المعروفة، schema validation | اختبارات سجل الأدوات، validation، إذن | أداة غير معروفة تُرفض، وسيطات غير صالحة تُرفض |
| سياسة إذن | `core/scope_guard.py` يُستخدم جزئيًا من engines_api | `core/permission_policy.py` (فحص عامل، نطاق، سياسة مخاطرة) | لا تبعات جديدة | fail-closed: أي فحص فاشل = رفض | اختبارات إذن، تجاوز نطاق، أداة عالية المخاطرة | لا أداة تُنفذ بدون إذن صريح |

### Phase C — منسق المهام + سجل العمال + دورة الحياة + إلغاء

**الأهداف:**
- منسق (Coordinator) يقبل مهمة avec نطاق صريح، ينشئ سجل مهمة مع run ID فريد.
- حالات المهام: PENDING → READY → RUNNING → WAITING_FOR_APPROVAL → BLOCKED → SUCCEEDED / FAILED / CANCELLED مع تحولات صالحة.
- سجل عمال مع بيانات وصفية (ID، دور، أدوات، حالة، صحة).
- تخصيص مهام متوازٍ مع حدود توازي، قفل موارد، تتبع تبعيات، كشف حلقات غير منتجة.
- إلغاء متكرر النشر (duplicate dispatch) من إعادة المحاولات أو طلبات واجهة مكررة.
- استمرار حالة التشغيل (inspect/resume).

| القدرة | استخدام موجود | ملفات يجب إنشاؤها/تعديلها | التبعيات | الآثار الأمنية | الاختبارات | معايير القبول |
|---|---|---|---|---|---|---|
| سجل عمال + بيانات وصفية | `engines/worker.py` (عامل محرك واحد)، `agents/base_agent.py` | `core/worker_registry.py` (`Worker` metadata + status + health) | لا تبعات جديدة | عامل لا يحصل تلقائيًا على كل الأدوات | اختبارات تسجيل، توصيف क्षमता، فحص صحة | كل عامل يُبلغ عن قدراته وأدواته المصرح بها فقط |
| حالات المهام والتحولات | `core/run_control.py` (حالات تشغيل بسيطة) | `core/task_lifecycle.py` (آلة حالات المهام + run ID) | لا تبعات جديدة | منع نشر مكرر لنفس المهمة | اختبارات حالات، تحولات غير صالحة تُرفض | حالة كل مهمة محددة ومتاحة عبر API |
| منسق مهام | `orchestrator/router.py` (خفيف) | `core/coordinator.py` (تنظيم المهام إلى عمال) | asyncio، `RunController` موجود | حدود توازي، انتهاء مهلة | اختبارات تخصيص، توازي، إلغاء، uncover duplicate dispatch | المهام المستقلة تُنفذ متوازيًا، الإلغاء يوقف العمل |
| استمرار حالة التشغيل | الذاكرة فقط حاليًا | `core/run_persistence.py` (اختياري JSON/SQLite) | لا تبعات جديدة | لا أسرار في السجل المستمر | اختبارات حفظ/استعادة حالة | تشغيل متقطع يمكن فحصه أو استئنافه |

### Phase D — اللوحة السوداء المشتركة + الإثباتات + سجل الأحداث

**الأهداف:**
- استمرارية `SharedEvidenceGraph` (حاليًا في الذاكرة فقط) — استخدام existing DB إن وجد، وإلا minimal storage.
- كيانات: Run، Worker، Task، Evidence، Hypothesis، DeadEnd، ToolExecution، Event (كما في المواصفة).
- أحداث bus مع تاريخ دائم، أحداث لكل run، إعادة تشغيل، إعادة اتصال، احتفاظ محدود.
- لا overwriting صامت لإثباتات عامل آخر. تاريخ الأحداث غير قابل للتغيير (immutable).
- لا بيانات اعتماد خام في اللوحة.

| القدرة | استخدام موجود | ملفات يجب إنشاؤها/تعديلها | التبعيات | الآثار الأمنية | الاختبارات | معايير القبول |
|---|---|---|---|---|---|---|
| Evidence persistence | `core/shared_evidence.py` (في الذاكرة) | `core/evidence_store.py` (تغليف storage دائم) | SQLite أو الملف الحالي | لا أسرار خام | اختبارات إضافة/قراءة إثبات، مصدر، مصداقية | الإثبات يحتفظ بمصدر ومصداقية ورابط تشغيل |
| حدث 버스 دائم | `BaseAgent.emit()` بسيط | `core/event_bus.py` (أحداث مرتبة لكل run، مستمر) | asyncio | تنقية الأحداث قبل النشر | اختبارات ترتيب الأحداث، إعادة تشغيل، حد الاحتفاظ | أحداث run مرتبة ومتاحة عبر API |
| Dead-end / Hypothesis tracking | غير موجود | `core/evidence_store.py` (كيانات Hypothesis/DeadEnd) | لا تبعات جديدة | لا تدّعي تأكيدًا बिना أدلة | اختبارات ربط إثبات بفرضية، تسجيل طريق مسدود | الفرضية تتطلب إثباتات داعمة |

### Phase E — محولات الأدوات الآمنة (CLI / MCP / وكلاء برمجة) ✅ مكتمل (هذه الجلسة)
- `core/mcp_config.py` — schema إعداد خوادم MCP (Pydantic: server_id، النقل، الأمر، المصادقة، الصلاحيات لكل أداة).
- `core/mcp_client.py` — عميل MCP حقيقي (stdio عبر asyncio subprocess، JSON-RPC 2.0، initialize، tools/list، tools/call، الإلغاء، إعادة اتصال bounded retry، سجل تدقيق) + `MCPClientManager` لعدة خوادم مع namespaces.
- `core/coding_agent_adapter.py` — واجهة `CodingAgentAdapter` مجردة + `CLICodingAgentAdapter` ( CodeX/Claude/OpenCode عبر argv فقط، مساحة عمل مصرح بها، مراجعة diff قبل التطبيق، إلغاء، مهلة) + `CodingAgentRegistry` مع مصفوفة قدرات.
- `core/tool_registry.py` — `MCPTool` wrapper + `register_mcp_tools()` لربط أدوات MCP بالسجل المركب.
- `config/mcp.example.json` — مثال إعداد (بدون أسرار).
- `docs/mcp-setup.md`، `docs/coding-agent-setup.md` — توثيق الإعداد والأمان.
- `tests/test_mcp_client.py` (11)، `tests/test_coding_agent_adapter.py` (19) — جميعها ناجحة.

### Phase G — صندوق رمل + فرض نطاق الشبكة ✅ مكتمل (جلسة سابقة)
- `core/sandbox.py` (`LocalSandbox` + `DockerSandbox` موثق).
- `core/scope_enforcer.py` (`ScopeEnforcer`: حظر metadata/loopback/RFC1918، التحقق من re
directs، حدود المعدل، سجل تدقيق).
- ربط `CliTool.execute` بـ `LocalSandbox` + `CliTool.authorize` بـ `ScopeEnforcer`.

### Phase H — واجهة API / واجهة أمامية + رصد ✅ جزئيًا (جلسة سابقة)
- `core/global_state.py`، `ui/web/runs_api.py`، `/api/runs/{id}/events\|evidence\|findings`.

**الأهداف:**
- محول CLI آمن: مصفوفات وسيطات (argument arrays)، validation لمسار الملف التنفيذي، رفض أسماء غير متوقعة، مهلة، إ截اق الإخراج، json output.parser، لا shell strings.
- عميل MCP رسمي باستخدام SDK معتمد: خوادم متعددة، اكتشاف الأدوات، استدعاء مرخص، إلغاء، كشف انقطاع الاتصال، إعادة اتصال محدودة، أسماءmispaces منفصلة.
- محولات وكلاء برمجة (Codex/Claude Code/Cursor/OpenCode): واجهة عامة، فحص وجود الملف التنفيذي، مصادقة، دليل عمل مصرح به، مهلة، إخراج محدود، إلغاء، مصفوفة قدرات.
- مراجعة diff قبل التعديلات عالية التأثير. لا الوصول لملفات خارج مساحة العمل المسموح بها.

| القدرة | استخدام موجود | ملفات يجب إنشاؤها/تعديلها | التبعيات | الآثار الأمنية | الاختبارات | معايير القبول |
|---|---|---|---|---|---|---|
| محول CLI آمن | `agents/nmap_agent.py` إلخ (أدوات فردية) | `core/cli_adapter.py` (تنفيذ آمن، allowlist executables) | لا تبعات جديدة | لا shell strings،allowlist، مسار آلي | اختبارات مصفوفة وسيطات، رفض اسم غير مسموح، مهلة | كل أمر CLI يُنفذ كمصفوفة، لا Strings shell |
| عميل MCP | `core/mcp_server.py` (خادم فقط) | `core/mcp_client.py` (عميل رسمي، اكتشاف، استدعاء) | SDK MCP معتمد | تفويض مستقل عن ادعاءات الخادم، لا تعديلات سياسة من الخادم | اختبارات اكتشاف، استدعاء، خطأ خادم، إعادة اتصال | خوادم MCP تُكتشف وتُستدعى عبر الواجهة الموحدة |
| محول وكيل برمجة | `engines/drivers/` (claude/codex/opencode) | `core/coding_agent_adapter.py` (واجهة عامة + مراجعة diff) | ملفات تنفذية موجودة للمراجعة | مساحة عمل مصرح بها فقط، لا أسرار/SSH | اختبارات فحص أداة، قدرة مبلغ عنها بدقة | كل وكيل يبلغ عن क्षमतاته الحقيقية فقط |

### Phase F — تكامل Burp + محررات

**الأهداف:**
- محول Burp بناءً على واجهة توثيق حقيقية للنسخة المختارة (ليس استخراج GUI كافتراضي).
- عمليات: health_check، retrieve_authorized_http_history، retrieve_request/response، submit analysis job، import/export findings.
- تنقية 쿠كيز / Authorization / توكنز قبل إرسال للنماذج. تسجيل المنشأ لكل Finding. تدهور لطيف إذا Burp غير متاح.
- محولات محررات اختيارية فقط عندما تدعم API المحرر العمليات المطلوبة.

| القدرة | استخدام موجود | ملفات يجب إنشاؤها/تعديلها | التبعيات | الآثار الأمنية | الاختبارات | معايير القبول |
|---|---|---|---|---|---|---|
| محول Burp | `agents/burp_agent/` + `validate_burp_*.py` | `core/burp_adapter.py` + إعداد + توثيق إعداد بدون أسرار | واجهة Burp reales | تنقية بيانات حساسة، لا ادعاء تأكيد बिना دليل | اختبارات محول (Mock للوحدات، اختبار بيئة معزولة للتكامل) | ميزات Burp المطبقة تستخدم واجهة موثقة فعلاً |
| محولات محررات | غير موجود | `core/editor_adapter.py` (اختياري) | API المحرر المدعوم | لا ادعاء تحكم GUI لمجرد أوامر طرفية | اختبارات قدرة مبلغ عنها | الميزات اختيارية ومُوثقة بوضوح |

### Phase G — صندوق رمل + فرض نطاق + موافقات بشرية + إخفاء أسرار

**الأهداف:**
- تنفيذ في حاوية/آلة افتراضية مخصصة للكود غير الموثوق والأدوات الهجومية.
- دليل عمل مقيد، مهلة عمليات، حدود موارد، سياسة شبكة، Mounts للقراءة فقط، متغيرات بيئة محدودة، تنفيذ غير root إن أمكن، حدود artefact، تنظيف مؤقت، إيقاف شجرة العمليات، سجل تدقيق.
- سياسة نطاق نهائية: أسماء مضيفين، عناوين IP/Nطاقات، منافذ، بروتوكولات، استثناءات، نافذة زمنية، حدود معدل. إعادة التحقق عند إعادة التوجيه. منع وصول خدمات metadata المحلية / loopback / شبكات خاصة بدون إذن صريح.
- موافقات بشرية على العمليات عالية المخاطرة (Approve/Reject/Pause/Resume/Cancel)، مرتبطة بعملية محددة ومعلماتها وسياق السياسة. لا موافقة ذاتية للوكيل على المخاطر العالية.
- إخفاء الأسرار في السجلات، المحفزات، اللوحة، أحداث، تقارير الأخطاء. تنقية رؤوس HTTP والكوكيز.

| القدرة | استخدام موجود | ملفات يجب إنشاؤها/تعديلها | التبعيات | الآثار الأمنية | الاختبارات | معايير القبول |
|---|---|---|---|---|---|---|
| صندوق رمل | `docker/worker*.Dockerfile` موجود | `core/sandbox.py` (تنسيق حاوية/فصل) | Docker إن أمثل | لا مضيف كامل في عامل غير موثوق | اختبارات حاجز، حدود موارد | العامل يُنفذ في حاوية محدودة بشكل قابل للتحقق |
| فرض نطاق الشبكة | `core/scope_guard.py` (جزئي) | `core/scope_enforcer.py` (فحص وقت التنفيذ، إعادة توجيه) | لا تبعات جديدة | رفض خارج النطاق، لا تجاوز DNS/إعادة توجيه | اختبارات نطاق، رفض خارج النطاق، إعادة توجيه | كل عملية شبكية تُتحقق من النطاق عند التنفيذ |
| موافقات بشرية | `run_control.py` pause/resume/stop موجود | `core/approvals.py` (طلب موافقة مرتبط بالعملية) | لا تبعات جديدة | لا موافقة ذاتية، مهلة لا تُحول غير المصرح به إلى مصرح به | اختبارات approve/reject/timeout | операция عالية المخاطرة تنتظر موافقة |
| إخفاء الأسرار | `credential_env` عبر env (لا argv) | `core/secret_redactor.py` (تنقية السجلات/الأحداث/الأخطاء) | لا تبعات جديدة | لا أسرار في أي مخرج | اختبارات تنقية رؤوس/كوكيز/توكنز | لا سر يظهر في سجل أو حدث أو إثبات |

### Phase H — واجهة API / واجهة أمامية + رصد + توثيق

**الأهداف:**
- نقاط نهاية運：POST /runs، GET /runs، GET /runs/{id}، POST pause/resume/cancel، GET /events، GET /evidence، GET /findings.
- مصادقة، تفويض، التحقق من المدخلات، حدود معدل، استجابات خطأ، ترقيم، بث الأحداث، دلالات الإلغاء.
- لا واجهة إدارية غير مصادقة. لاbinding على واجهات عامة بدون تأمين.
- شاشات تكوين للموفري، العمال، الأدوات، خوادم MCP، Burp، صندوق الرمل، النطاق والسياسة. عرض واضح للحالة (مهيأ / متصل / منفصل / غير مدعوم / في انتظار بيانات اعتماد).

| القدرة | استخدام موجود | ملفات يجب إنشاؤها/تعديلها | التبعيات | الآثار الأمنية | الاختبارات | معايير القبول |
|---|---|---|---|---|---|---|
| نقاط نهاية التشغيل | `/api/runs/*` موجود في control_api.py | `ui/web/runs_api.py` (توسيع)، أحداث | FastAPI | مصادقة/تفويض على كل نقطة | اختبارات API، ترقيم، إلغاء | كل نقطة نهاية تُطبق التحكم في الوصول |
| بث الأحداث | غير موجود | `core/event_bus.py` → WebSocket في app.py | asyncio | تنقية قبل النشر | اختبارات بث، إعادة اتصال | واجهة أمامية تتلقى أحداث run مباشرة |
| شاشات تكوين | تبويبات موجودة في index.html | `ui/web/templates/` (توسيع) | لا تبعات جديدة | عرض حالة الصدق، لا afirmar صحي لمجرد وجود قيم Config | اختبارات واجهة (إن وجد) | كل تكامل يظهر حالة حقيقية |
| توثيق | غير موجود | `docs/architecture.md`, `docs/agent-runtime.md`, إلخ | لا تبعات جديدة | لا أسرار في التوثيق | مراجعة يدوية | التوثيق يطابق التنفيذ |

### Phase I — suite اختبار كامل + مراجعة أمنية + تقرير نهائي

| البند | المعيار |
|---|---|
| جميع الاختبارات الحالية تجتاز | لا رجعية في 1709+ اختبار |
| اختبارات جديدة لكل ميزة | تغطية للسجل، الإذن، الحالات، الأحداث، الإخفاء |
| اختبارات التكامل 외부 تحمل علامة environment blocker | لا تُدّعي اختبارات خارجية ناجحة بمزيفات فقط |
| مراجعة أمنية للكود الحساس | إذن، نطاق، أسرار، sandbox |
| تقرير نهائي | distinguishing implemented / tested / partially / blocked |

---

## dependencies المضافة المقترحة (فقط إذا لزم التشغيل الفعلي)

| الحزمة | الغرض | مرحلة |
|---|---|---|
| `pydantic` (إذا لم تكن موجودة) | تعريف مخططات الأدوات | B |
| `mcp` (官方 SDK) | عميل MCP | E |
| `httpx` | عملاء HTTP لـ Burp/MCP | E/F |
| `docker` (Python SDK، اختياري) | تحكم في حاوية الساندبوكس | G |

لا تُثبت أي أداة أمان تلقائيًا؛ todas las integraciones de CLI opcionales y configuradas por el operador.

---

## قبول "منجز" (Definition of Done) لهذا المشروع

1. التطبيق يبدأ دون أخطاء.
2. الوظائف الحالية تظل تعمل (لا رجعية).
3. البنية الجديدة مدمجة في التطبيق الفعلي (ليس تطبيق منفصل).
4. يمكن تسجيل العمال وتخصيص مهام لهم.
5. المنسق يتبع حالة المهمة والعامل.
6. استدعاءات الأدوات تُتحقق وتُفوض قبل التنفيذ.
7. تنفيذ CLI يستخدم مصفوفات وسيطات.
8. خوادم MCP يمكن تكوينها واكتشافها عبر البروتوكول المدعوم.
9. محول Burp يستخدم إمكانيات توثيق فعلية لميزاته المطبقة.
10. تكاملات وكلاء البرمجة تبلغ عن إمكانياتها بدقة.
11. الإثباتات تُخزن مع مصدر.
12. الإيجابيات الكاذبة والفرضيات غير المؤكدة تُمثَّل بشكل صحيح.
13. المهام الطويلة يمكن مراقبتها وإلغاؤها.
14. الإجراءات عالية المخاطر تحترم متطلبات الموافقة.
15. فرض النطاق ينطبق على العمليات الشبكية.
16. الأسرار لا تُكشف في السجلات أو الإثباتات.
17. الاختبارات الآلية تجتاز (باستثناء وثائق blocking بيئي واضح).
18. التوثيق يطابق التنفيذ الفعلي.
19. لا تكامل حاسم يُمثَّل بـ placeholder بينما يُوصف بأنه مكتمل.
20. التقرير النهائي يفرق بين منجز / مختبر / جزئي / محظور.

---

## تنفيذ تم (مُحدّث — حالة فعلية بتاريخ الجلسة الحالية)

### Phase A — التدقيق والخط الأساس ✅ مكتمل
- `docs/architecture-audit.md` — تدقيق كامل للبنية القائمة والفجوات.
- `docs/implementation-plan.md` — هذه الخطة.
- baseline: 1709 اختبارًا جمّعت (1701 ناجح، 7 فشل مسبق الوجود في ملفات `*_pilot.py` غير مرتبطة بهذا العمل، 1 skipped).

### Phase B — واجهات مشتركة + Configuration + سجل الأدوات + إذن ✅ مكتمل
- `core/agent_provider.py` — واجهة `AgentProvider` موحدة (capabilities / health_check / execute / stream / cancel) + `StubProvider` + سجل مزوّدين. لا أسرار في الأخطاء.
- `core/tool_registry.py` — سجل أدوات مركب (`ToolDefinition`, `Tool`, `CliTool`, `ToolRegistry`) مع التسلسل الإلزامي: التحقق من المخطط → إذن العامل → نطاق → سياسة مخاطرة → موافقة بشرية → تنفيذ عبر مصفوفات وسيطات → حد إخراج → تدقيق → إخفاء أسرار.
- `tests/test_agent_provider.py` (10)، `tests/test_tool_registry.py` (18) — جميعها ناجحة.

### Phase C — منسق المهام + سجل العمال + دورة الحياة + إلغاء ✅ مكتمل
- `core/planner/interface.py` — واجهة `Planner`/`DefaultPlanner` مضافة إلى حزمة `core/planner` القائمة (بدون تصادم مع `StateSpacePlanner`).
- `core/task_lifecycle.py` — آلة حالات المهام (PENDING→READY→RUNNING→WAITING_FOR_APPROVAL→BLOCKED→SUCCEEDED/FAILED/CANCELLED) مع تحولات صالحة ومنع النشر المكرر.
- `core/worker_registry.py` — سجل عمال مع بيانات وصفية، تخصيص/إكمال مهام، فحوصات صحة، عمال متاحون لكل دور.
- `core/coordinator.py` — منسق مهام: submit_run، planner، تخصيص عمال، تنفيذ متزامن مع semaphore، أقفال موارد عبر `SharedEvidenceGraph`، إعادة محاولة bounded، موافقة بشرية، إلغاء، سجل أحداث دائم لكل run، ملخص نهائي.
- `tests/test_coordinator_phase_c.py` (14) — جميعها ناجحة.

### Phase D — اللوحة السوداء المشتركة الدائمة + سجل أحداث ✅ مكتمل
- `core/evidence_store.py` — متجر أدلة دائم thread-safe (JSONL في `data/evidence_store/`) مع كيانات Evidence/Hypothesis/DeadEnd/ToolExecution/Event/Run، إخفاء أسرار، content hash (تغيير يُكتشف)، append-only (آخرtid يربح)، `get_events` لإعادة تشغيل التاريخ.
- `engines/worker.py` — `EngineWorker` يُخزّن الآن نتيجة كل تشغيل في `SharedEvidenceGraph` **و** `EvidenceStore` (إضافي اختياري، لا يكسر التشغيل بدونها).
- `tests/test_evidence_store.py` (12) — جميعها ناجحة.

### tổng kết الاختبارات الجديدة (الحديثة)
| المجموعة | الاختبارات | الحالة |
|---|---|---|
| agent_provider | 10 | ✅ |
| tool_registry | 18 | ✅ |
| coordinator_phase_c | 14 | ✅ |
| evidence_store | 12 | ✅ |
| engines_cli_workers (incl. evidence wiring) | 24 | ✅ |
| flags_pipeline | 18 | ✅ |
| run_control_and_budget | 17 | ✅ |
| ctf_platforms | 14 | ✅ |
| ctf_flag_bridge | 10 | ✅ |
| extensions_system | 22 | ✅ |
| shared_evidence_graph | 18 | ✅ |
| new_api_smoke | 6 | ✅ |
| runs_api | 2 | ✅ |
| sandbox | 6 | ✅ |
| scope_enforcer | 11 | ✅ |
| mcp_client | 11 | ✅ |
| coding_agent_adapter | 19 | ✅ |
| burp_adapter | 16 | ✅ |
| action_evaluator_and_policy (pre-existing) | 4 | ✅ |
| **المجموع** | **252** | ✅ **كلها ناجحة** |

### Phase F — تكامل بورب ✅ مكتمل (هذه الجلسة)
- `core/burp_adapter.py` — محول بورب ثابت مع 9 عمليات موثقة (`health_check`、`get_available_capabilities`、`retrieve_authorized_http_history`、`retrieve_request`、`retrieve_response`、`submit_supported_analysis_job`、`retrieve_analysis_results`、`import_supported_findings`、`export_supported_findings`).
- يُحلق فوق البنية القائمة (`core/burp_gateway/`): البوابة المحلية، مخزن الحركات، مصدّر النتائج (`BurpIssueExporter`)، محرك المصدر.
- يكشف بصراحة: بورب لا توفر REST API رسمية عامة؛ التكامل عبر إضافة Burp (BApp) ترسل الترافيك إلى البوابة المحلية.
- ضوابط أمنية: إخفاء كوكيز/Authorization/توكنز، تسجيل المنشأ لكل نتيجة، لا يُدعى تأكيدًا بدون أداة حقيقية، تدهور لطيف إذا بورب غير متاح.
- `config/burp.example.json` — مثال إعداد (بدون أسرار).
- `docs/burp-setup.md` — دليل الإعداد والأمان.
- `tests/test_burp_adapter.py` (16) — جميعها ناجحة (محاكاة، لا أنظمة خارجية).

### Phase G — صندوق رمل + فرض نطاق الشبكة ✅ مكتمل (جلسة سابقة)
- `core/sandbox.py` — واجهة `Sandbox` مجردة + `LocalSandbox` (تنفيذ محلي عبر `create_subprocess_exec` بلا shell string، cwd مقيد، env محدود، timeout مع process termination، حد إخراج) + `DockerSandbox` موثق لتشغيل Kali/خادم.
- `core/scope_enforcer.py` — `ScopeEnforcer` يغلف `core/scope_guard.py` القائمة: حظر خدمات metadata (169.254.169.254، metadata.google.internal)، منع loopback/RFC1918 ما لم يُصرح، التحقق من إعادة التوجيه (redirects) ضد النطاق، حدود معدل لكل هدف، سجل تدقيق لكل قرار نطاق.
- `core/tool_registry.py` — `CliTool` يُنفذ الآن عبر `LocalSandbox.run` بدلاً من `create_subprocess_exec` المباشر؛ `CliTool.authorize` يستدعي `ScopeEnforcer.enforce_target` عندما يتوفر.
- `tests/test_sandbox.py` (6)، `tests/test_scope_enforcer.py` (11) — جميعها ناجحة.

### Phase H — واجهة API / واجهة أمامية + رصد ✅ جزئيًا (مُنجز في جلسة سابقة)
- `core/global_state.py` — سواقل مشتركة `GLOBAL_COORDINATOR` و `GLOBAL_EVIDENCE_STORE` (مثل `GLOBAL_RUN_CONTROLLER`).
- `ui/web/runs_api.py` — نقاط نهاية:
  - `GET /api/runs/{run_id}/events` — تاريخ الأحداث runway لتشغيل.
  - `GET /api/runs/{run_id}/evidence` — الأدلة المرتبطة بتشغيل.
  - `GET /api/runs/{run_id}/findings` — النتائج المؤكدة (proof/anomaly/contradicted).
- تم تركيب `runs_api_router` في `ui/web/app.py` (بعد control/budget).
- `tests/test_runs_api.py` (2) — erfolg.
- المتبقٍ من Phase H: شاشات واجهة أمامية للعرض + توثيق مفصل.

### Phase I — suite اختبار كامل + مراجعة أمنية + تقرير نهائي ✅ قيد التنفيذ
- 206 اختبارًا جديدًا كلها ناجحة (incl. sandbox + scope_enforcer).
- 7 فشل مسبق الوجود في `*_pilot.py` موثقة وغير مرتبطة بهذا العمل.

