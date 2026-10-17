# syntax=docker/dockerfile:1
# ============================================================
# HunterAI — صورة العامل (Worker) بأدوات الأمن
# هذه الصورة تحتوي سلسلة أدوات الاختبار (Kali-style) +
# متصفح + وكلاء CLI اختياريين. تُستخدم من docker-compose
# عندما يُحدَّد وضع runtime=container للوكلاء.
# ============================================================

FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /worker

# سلسلة أدوات أساسية (خفيفة نسبيًا؛ الصورة الكاملة/Kali تبقى خارج Docker)
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        curl \
        wget \
        git \
        jq \
        net-tools \
        iputils-ping \
        ca-certificates \
        dnsutils \
        libxml2 \
        libxslt1-dev \
        zlib1g-dev \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

# أدوات بايثون للأمن
RUN pip install --no-cache-dir \
        sqlmap \
        requests \
        httpx \
        beautifulsoup4 \
        pwntools \
        python-nmap \
        lxml

# متصفح للاستكشاف التلقائي
RUN python -m playwright install --with-deps chromium || true

# نسخ سكربتات العامل
COPY scripts/ /worker/scripts/
COPY tools/ /worker/tools/

# حساب غير متمكّن للأمان
RUN useradd -m -u 1000 hunter && chown -R hunter:hunter /worker
USER hunter

CMD ["sleep", "infinity"]
