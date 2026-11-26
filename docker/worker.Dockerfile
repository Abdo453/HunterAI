# syntax=docker/dockerfile:1
# ============================================================
# HunterAI — Hardened Lightweight Security Worker Image
# Multi-stage build keeps build toolchains out of the runtime image.
# Runs as non-root user `hunter` (UID/GID 10001) with cap_drop ALL.
# ============================================================

FROM python:3.11.18-slim-bookworm@sha256:ef56ae98435cc40d8a27020b0b32a9941515acd5840f0fba34858bb34dd362d1 AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libxml2-dev \
        libxslt1-dev \
        zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN pip install --no-cache-dir \
        sqlmap \
        requests \
        httpx \
        beautifulsoup4 \
        pwntools \
        python-nmap \
        lxml

# ------------------------------------------------------------
# Final hardened runtime stage (no compilers, non-root)
# ------------------------------------------------------------
FROM python:3.11.18-slim-bookworm@sha256:ef56ae98435cc40d8a27020b0b32a9941515acd5840f0fba34858bb34dd362d1 AS runtime

ARG INSTALL_PLAYWRIGHT=0

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    PATH="/opt/venv/bin:$PATH"

WORKDIR /worker

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
        libxslt1.1 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/venv /opt/venv

RUN if [ "$INSTALL_PLAYWRIGHT" = "1" ]; then \
        pip install --no-cache-dir playwright \
        && python -m playwright install --with-deps chromium \
        && chmod -R a+rX /ms-playwright; \
    fi

RUN groupadd --gid 10001 hunter \
    && useradd --uid 10001 --gid 10001 --create-home --shell /bin/sh hunter \
    && mkdir -p /worker/data \
    && chown -R hunter:hunter /worker

COPY --chown=hunter:hunter scripts/ /worker/scripts/
COPY --chown=hunter:hunter tools/ /worker/tools/

HEALTHCHECK --interval=60s --timeout=5s --start-period=10s --retries=3 \
    CMD test -d /worker/data && command -v nmap >/dev/null

USER hunter

CMD ["sleep", "infinity"]
