# syntax=docker/dockerfile:1
# ============================================================
# HunterAI / PentestAI-Unified — صورة الويب
# تبني الواجهة وتشغّل FastAPI على المنفذ 7070.
# ملاحظة: صورة "العامل" (Workers بأدوات Kali) منفصلة — انظر docker/worker.Dockerfile
# ============================================================

FROM python:3.11-slim AS base

# متغيّرات البناء لتقليل الحجم
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# حزم نظام لأدوات الشبكة/المتصفح (يبقى خفيفًا؛ الأدوات الثقيلة في صورة العامل)
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        ca-certificates \
        git \
        nmap \
    && rm -rf /var/lib/apt/lists/*

# اعتماديات بايثون أولاً (تُخزَّن بين الطبقات)
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# تثبيت متصفح Playwright (اختياري لكن مطلوب للطبقة الحسّية)
RUN python -m playwright install --with-deps chromium || true

# نسخ الشيفرة
COPY . .

# منفذ الويب
EXPOSE 7070

# فحص صحة
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -fsS http://127.0.0.1:7070/api/status || exit 1

# تشغيل الويب (يربط على 0.0.0.0 داخل الحاوية)
CMD ["python", "main.py", "--web", "--host", "0.0.0.0", "--port", "7070"]
