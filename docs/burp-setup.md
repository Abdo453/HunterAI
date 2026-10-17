# إعداد تكامل بورب (Burp Adapter) — مرحلة F

## نظرة عامة

يُوفّر `core/burp_adapter.py` محولاً ثابتاً (stable interface) للتكامل مع **Burp Suite Professional/Community**، يُحلق فوق البنية القائمة في `core/burp_gateway/` (البوابة المحلية على `127.0.0.1:8085`، مخزن الحركات، مصدّر النتائج، محرك المصدر).

## معمار التكامل (موثق بصراحة)

> **بورب سوبرليغ لا توفر واجهة برمجية REST عامة رسمية** يمكن استدعاءها مباشرة من بايثون. واجهة البرمجة الرسمية لبورب هي **Java Extension API (BApp / `IBurpExtenderCallbacks`)**.

لذا يعتمد التكامل على هذه الآلية:
1. تُثبّت إضافة Burp Suite (BApp) في بورب (انظر `agents/burp_agent/integrations/burp_extension/`).
2. تُرسل الإضافة حركة HTTP الملتقطة (Proxy / Repeater) إلى بوابة HunterAI المحلية (`BurpGateway` على `127.0.0.1:8085`).
3. يقرأ `BurpAdapter` من البوابة عبر HTTP محلي ويقدّم واجهة مستقرة للمنسيق.

## الملفات

| الملف | الدور |
|---|---|
| `core/burp_adapter.py` | محول بورب (9 عمليات مستقرة) + نسخة مشتركة `GLOBAL_BURP_ADAPTER` |
| `core/burp_gateway/` | البنية القائمة: البوابة، مخزن الحركات، مصدّر النتائج، محرك المصدر |
| `config/burp.example.json` | مثال إعداد (بدون أسرار حقيقية) |
| `docs/burp-setup.md` | هذا الملف |
| `tests/test_burp_adapter.py` | اختبارات وحدة (محاكاة، لا أنظمة خارجية) |

## العمليات المدعومة

| العملية | الوصف |
|---|---|
| `health_check` | فحص وصول بوابة بورب والاستجابة |
| `get_available_capabilities` | اكتشاف القدرات المدعومة (بدون ادعاء قدرات غير مدعومة) |
| `retrieve_authorized_http_history` | استرجاع حركة HTTP مرخصة (بعد فحص النطاق) |
| `retrieve_request` / `retrieve_response` | استرجاع حركة معينة (مُنَظَّقة) |
| `submit_supported_analysis_job` | إرسال مهمة تحليل مدعومة (مثل فحص سلبي) |
| `retrieve_analysis_results` | استرجاع نتائج مهمة تحليل |
| `import_supported_findings` | استيراد نتائج مع تسجيل المنشأ |
| `export_supported_findings` | تصدير نتائج إلى تنسيق Burp `IScanIssue` JSON |

## التشغيل (إعداد محلي)

1. ثبّت إضافة Burp Suite (BApp) hunter في بورب.
2. شغّل بوابة HunterAI المحلية (`BurpGateway` على `127.0.0.1:8085`).
3. عدل `config/burp.example.json` وحدّد `gateway_base_url` والنطاق المصرح به.
4. حمّل الإعداد في التطبيق:
   ```python
   from core.burp_adapter import BurpAdapter, BurpAdapterConfig

   cfg = BurpAdapterConfig(gateway_base_url="http://127.0.0.1:8085")
   adapter = BurpAdapter(config=cfg)
   await adapter.health_check()
   ```

## الأمان

- تُنشق كوكيز ورؤوس `Authorization` والتوكنز قبل إرسال أي حركة إلى نموذج خارجي.
- تُسجل المنشأ (provenance) لكل نتيجة مستوردة من بورب.
- لا يُدعى أن نتيجة "مؤكدة" إلا إذا أكدت أداة بورب فعلاً (`verified_by_burp`).
- جميع العمليات تخضع لفحص النطاق (`ScopeEnforcer`) قبل استرجاع أي حركة خارجية.
- حظر خدمات metadata السحابية و loopback / RFC1918 ما لم تُصرح صراحةً.

## التدهور اللطيف (Degraded Mode)

إذا لم تكن إضافة بورب مثبتة أو البورب غير متاح، يعمل المحول بوضع تدهور لطيف:
- كل عملية ترجع خطأ `"غير متاح"` دون انهيار.
- `health_check` تُعيد `available: false`.
- يمكن للمستخدم المتابعة في مهام أخرى دون تأثر النظام.

## القيود

- التكامل يتم عبر إضافة بورب (BApp) التي ترسل الترافيك إلى البوابة المحلية، لا عبر واجهة برمجية REST رسمية من بورب.
- لا يُستخدم استخراج واجهة المستخدم (GUI scraping) كآلية تكامل افتراضية.
- للاختبار ضد بورب حقيقي، استخدم بيئة معزولة مع إضافة معتمدة.
