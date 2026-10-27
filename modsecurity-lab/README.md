# إعدادات مختبر ModSecurity + OWASP CRS

ضع هنا ملفات إعدادات OWASP CRS إذا كنت تريد تخصيصها.
بالإعدادات الافتراضية من الصورة `owasp/modsecurity-crs:nginx`، سيعمل WAF على البورت 8080 ويحول الطلبات إلى `victim-app` على البورت 8081.

## كيفية التشغيل

```bash
docker-compose -f docker-compose.waf-lab.yml up -d
```

## كيفية الاختبار عبر PentestAI

```bash
python pentest.py waf-bypass http://localhost:8080/search --payload "<svg onload=alert(1)>"
```

## ملاحظات

- هذا المختبر للتجريب المحلي فقط وعلى أنظمة تملكها.
- لا تستهدف أنظمة خارج نطاق إذنك الكتابي.
