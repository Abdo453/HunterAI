# syntax=docker/dockerfile:1
# ============================================================
# HunterAI — Hardened Kali-Based Security Worker Image
# Pinned to an immutable multi-arch quarterly Kali snapshot digest
# (`kalilinux/kali-last-release`, backed by `kali-last-snapshot`).
# Runs as non-root user `hunter` (UID/GID 10001) on isolated egress network.
#
# Build:
#   docker build -f docker/worker-kali.Dockerfile -t hunterai-worker:kali .
# ============================================================

FROM kalilinux/kali-last-release@sha256:20c8d1ad4390a533be1649b7532a9cd77a3caeb719ca39d23d809295d67a2aec AS base

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PATH="/opt/venv/bin:$PATH"

WORKDIR /worker

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
        whatweb \
        nikto \
        sqlmap \
        gobuster \
        ffuf \
        seclists \
        wordlists \
    && rm -rf /var/lib/apt/lists/*

# Isolated virtual environment avoids mutating system Python packages
RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir \
        requests \
        httpx \
        beautifulsoup4 \
        python-nmap \
        pwntools \
        lxml

RUN groupadd --gid 10001 hunter \
    && useradd --uid 10001 --gid 10001 --create-home --shell /bin/sh hunter \
    && mkdir -p /worker/data \
    && chown -R hunter:hunter /worker

COPY --chown=hunter:hunter scripts/ /worker/scripts/
COPY --chown=hunter:hunter tools/ /worker/tools/

HEALTHCHECK --interval=60s --timeout=5s --start-period=10s --retries=3 \
    CMD test -d /worker/data && command -v nmap >/dev/null && command -v ffuf >/dev/null

USER hunter

CMD ["sleep", "infinity"]
