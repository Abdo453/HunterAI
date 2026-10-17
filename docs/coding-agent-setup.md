# إعداد الوكلاء البرمجيين (Coding Agent Adapters) — مرحلة E

## نظرة عامة

يُنفّذ HunterAI واجهة عامة للوكلاء البرمجيين عبر سطر الأوامر (Codex CLI / Claude Code / Cursor Agent / OpenCode / ...) مدمجة مع المنسق وسجل الأدوات. كل وكيل يعمل ضمن مساحة عمل مصرح بها فقط، والتعديلات عالية التأثير تتطلب مراجعة diff وموافقة بشرية.

## الملفات

| الملف | الدور |
|---|---|
| `core/coding_agent_adapter.py` | واجهة `CodingAgentAdapter` مجردة + تطبيق `CLICodingAgentAdapter` + `CodingAgentRegistry` |
| `tests/test_coding_agent_adapter.py` | اختبارات وحدة (محاكاة subprocess، لا أنظمة خارجية) |
| `docs/mcp-setup.md` | إعداد عميل MCP (مرتبطة) |

## المصفوفة المدعومة (Capabilities Matrix)

| الوكيل | الملف التنفيذي | قراءة ملفات | بحث | فحص依赖يات | اقتراح diff | تطبيق diff | تنفيذ اختبارات | إلغاء |
|---|---|---|---|---|---|---|---|---|
| Claude Code | `claude` | ✅ | ✅ | – | ✅ | ✅ | ✅ | ✅ |
| Codex CLI | `codex` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| OpenCode | `opencode` | ✅ | ✅ | – | ✅ | – | – | ✅ |

> القدرات تُبلغ ديناميكيًا من كل وكيل؛ لا تُفترض قدرات غير مدعومة.

## التشغيل

يتم تسجيل الوكلاء افتراضيًا عند استيراد `core/coding_agent_adapter`:

```python
from core.coding_agent_adapter import GLOBAL_CODING_AGENT_REGISTRY

agents = GLOBAL_CODING_AGENT_REGISTRY.list_agents()
for a in agents:
    print(a.agent_id, a.display_name, a.executable)
```

لإضافة وكيل مخصص:

```python
from core.coding_agent_adapter import (
    CLICodingAgentAdapter, CodingAgentCapabilities, AgentCapability,
    GLOBAL_CODING_AGENT_REGISTRY,
)

agent = CLICodingAgentAdapter(
    agent_id="my-agent",
    executable="my-cli",
    args_template=["run", "{prompt}"],
    capabilities=CodingAgentCapabilities(
        agent_id="my-agent", display_name="My Agent",
        executable="my-cli",
        supports_file_read=True,
        supports_patch_suggestion=True,
        supports_cancellation=True,
    ),
    auth_check_cmd=["my-cli", "--version"],
)
GLOBAL_CODING_AGENT_REGISTRY.register(agent)
```

## الأمان

- **مساحة عمل مصرح بها فقط**: كل طلب يُنفذ داخل `workspace` محدد؛ لا وصول لملفات خارجه (لا traversal).
- **لا أسرار**: لا مفاتيح API / SSH / توكنز تُعرض على الوكيل.
- **مراجعة diff**: التعديلات التي تنتج diff تُعلّم بـ `needs_human_review = True` وتتطلب موافقة بشرية قبل التطبيق عبر `ToolRegistry.approval_handler`.
- **الإلغاء**: يدعم الإلغاء حيث يدعمه الوكيل؛ المهلة محترمة.

## التكامل مع المنسق

يُحقن سجل الوكلاء البرمجيين في `core/coordinator.py` كمنفّذ مهام (`executor`) بحيث يمكن للمخطط تعيين مهام ترميز لوكلاء محددين مع تتبع الحالة والأحداث.

## المتطلبات الخارجية

- ملفات تنفيذية للوكلاء (claude / codex / opencode) يجب أن تكون مثبتة في PATH أو طريقها محدد صريحًا.
- مصادقة كل وكيل تُدار بشكل مستقل (تسجيل دخول عبر أداة الوكيل نفسها).
