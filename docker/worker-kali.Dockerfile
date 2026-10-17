# syntax=docker/dockerfile:1
# ============================================================
# HunterAI — صورة العامل الكاملة (Kali-based Worker)
# تستخدم قاعدة Kali Rolling لسلسلة أدوات اختبار الاختراق الحقيقية.
# هذه "الصورة الثقيلة" لوضع container للوكلاء — بديل الصورة الخفيفة
# في docker/worker.Dockerfile.
#
# البناء (يستغرق وقتًا ومساحة):
#   docker build -f docker/worker-kali.Dockerfile -t hunterai-worker:kali .
# ============================================================

FROM kalilinux/kali-rolling AS base

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /worker

# تحديث + سلسلة الأدوات الأساسية (نترك ما هو ثقيل اختياريًا)
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        python3-venv \
        curl \
        wget \
        git \
        jq \
        ca-certificates \
        nmap \
        masscan \
        whatweb \
        nikto \
        sqlmap \
        gobuster \
        ffuf \
        seclists \
        wordlists \
    && rm -rf /var/lib/apt/lists/*

# أدوات بايثون إضافية
RUN pip3 install --no-cache-dir --break-system-packages \
        requests \
        httpx \
        beautifulsoup4 \
        python-nmap \
        pwntools \
        lxml || \
    pip3 install --no-cache-dir \
        requests httpx beautifulsoup4 python-nmap lxml

# أدوات subfinder/httpx/katana (Go) — تُبنى أو تُنزَّل حسب الحاجة
# (تُترك للتشغيل الخارجي لتفادي تصغير الصورة أكثر من اللازم)

# حساب غير متمكّن للأمان
RUN useradd -m -u 1000 hunter && chown -R hunter:hunter /worker
USER hunter

CMD ["sleep", "infinity"]
