# إعداد عميل MCP (Model Context Protocol) — مرحلة E

## نظرة عامة

يُنفّذ HunterAI عميل MCP حقيقي باستخدام مكتبة Python 표준 فقط (بدون تبعات خارجية)، عبر النقل **stdio** (عملية محلية تتواصل عبر stdin/stdout) وبروتوكول **JSON-RPC 2.0**.

العميل مدمج مع سجل الأدوات المركب (`core/tool_registry.py`) والمنسق (`core/coordinator.py`) بحيث تظهر أدوات خوادم MCP كأدوات منفذة محكومة بالإذن والنطاق.

## الملفات

| الملف | الدور |
|---|---|
| `core/mcp_config.py` | schema إعداد خوادم MCP (Pydantic) |
| `core/mcp_client.py` | عميل MCP (stdio، initialize، tools/list، tools/call، الإلغاء، إعادة اتصال) |
| `core/mcp_manager.py` (داخل mcp_client) | `MCPClientManager` لإدارة خوادم متعددة مع namespaces |
| `config/mcp.example.json` | مثال إعداد (بدون أسرار حقيقية) |
| `tests/test_mcp_client.py` | اختبارات وحدة (محاكاة، لا أنظمة خارجية) |

##架构

```
تكوين خادم MCP  →  MCPClientManager  →  MCPClient (ل_each خادم)
                                                        ↓
                                              tools/list  (اكتشاف الأدوات)
                                                        ↓
                                              tools/call  (تنفيذ أداة مع نطاق + إذن)
                                                        ↓
                                              سجل تدقيق + ToolRegistry
```

## التشغيل (إعداد محلي)

1. ثبت خادم MCP مرغوب، مثال نظام ملفات محلي:
   ```bash
   npm install -g @modelcontextprotocol/server-filesystem
   ```
2. عدل `config/mcp.example.json` وحدد `command` و `args` للخادم.
3. للمصادقة، ضع التوكن في متغير بيئة وأشر إليه عبر `auth_token_env` (لا تُكتب التوكن في ملف الإعداد):
   ```json
   { "auth_token_env": "GITHUB_PERSONAL_ACCESS_TOKEN" }
   ```
   ثم:
   ```bash
   export GITHUB_PERSONAL_ACCESS_TOKEN=ghp_...
   ```
4. حمّل الإعداد في التطبيق:
   ```python
   from core.mcp_config import load_mcp_config_from_file
   from core.mcp_client import MCPClientManager

   config = load_mcp_config_from_file("config/mcp.example.json")
   manager = MCPClientManager(config.servers)
   await manager.connect_all()
   ```

## الأمان

- مخرجات خوادم MCP تُعامل كبيانات غير موثوقة (لا تُقيّم ككود).
- الأدوات عالية المخاطرة (`risk_level: high/critical`) تتطلب موافقة بشرية عبر `ToolRegistry.approval_handler`.
- الخوادم الشبكية تخضع لسياسة النطاق (`ScopeEnforcer`) قبل أي استدعاء.
- لا أسرار خام في ملفات الإعداد أو السجلات.

## القيود

- النقل الشبكي (HTTP/SSE) موثق في الإعداد ولكن تنفيذه يُترك للإنتاج عند توفر `mcp` SDK الرسمي.
- اختبارات الوحدة تستخدم محاكاة؛ للاختبار ضد خادم حقيقي استخدم بيئة معزولة.
