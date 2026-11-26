# syntax=docker/dockerfile:1
# ============================================================
# HunterAI / ARTEX-Pro Unified Platform — Multi-Stage Dockerfile
# Targets:
#   - artex    : Go ARTEX-Pro Concurrency Core (:7071)
#   - frontend : Next.js 15 Obsidian Sentinel UI (:3000)
#   - web      : Django 5.2 + DRF Pure ASGI Backend (:8000, default)
#
# Worker images live separately in:
#   - docker/worker.Dockerfile
#   - docker/worker-kali.Dockerfile
# ============================================================

# ------------------------------------------------------------
# Stage 1a: Go ARTEX-Pro Builder
# ------------------------------------------------------------
FROM golang:1.26.11-alpine3.24@sha256:ecb67f987aa1a57794c91d19ade7ae0209f2f0f5496aaef9e6ae85ddf92d02ab AS artex-builder

ENV CGO_ENABLED=0 \
    GOOS=linux \
    GOTOOLCHAIN=auto

WORKDIR /src/backend

COPY backend/go.mod backend/go.sum ./
RUN go mod download

COPY backend/cmd/ ./cmd/
COPY backend/internal/ ./internal/

RUN go build -trimpath -ldflags="-s -w" -o /out/artex-server ./cmd/server

# ------------------------------------------------------------
# Stage 1b: Go ARTEX-Pro Runtime (:7071, non-root)
# ------------------------------------------------------------
FROM alpine:3.21.10@sha256:bc21487101ae47172509130ee1092cc273a831968d64b617776d1f69c81e42ab AS artex

RUN apk add --no-cache ca-certificates wget \
    && addgroup -S -g 10001 artex \
    && adduser -S -u 10001 -G artex -h /app -s /sbin/nologin artex

WORKDIR /app

COPY --from=artex-builder --chown=artex:artex /out/artex-server /usr/local/bin/artex-server

ENV ARTEX_PORT=7071 \
    ARTEX_BIND_ADDR=0.0.0.0:7071

EXPOSE 7071

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD wget -qO- http://127.0.0.1:7071/api/v1/health >/dev/null 2>&1 || exit 1

USER artex

ENTRYPOINT ["/usr/local/bin/artex-server"]
CMD ["-server", "-port", "7071"]

# ------------------------------------------------------------
# Stage 2a: Next.js Frontend Builder (Node 22)
# ------------------------------------------------------------
FROM node:22.23.5-alpine3.24@sha256:1314fb30ec37592d5845e5a160d522c0e680972aa534549940b8d73bde88481a AS frontend-builder

ARG HUNTER_API_BASE=http://web:8000
ENV NEXT_TELEMETRY_DISABLED=1 \
    HUNTER_API_BASE=${HUNTER_API_BASE}

WORKDIR /app

COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

COPY frontend/ ./
RUN npm run build

# ------------------------------------------------------------
# Stage 2b: Next.js Frontend Runtime (:3000, non-root)
# ------------------------------------------------------------
FROM node:22.23.5-alpine3.24@sha256:1314fb30ec37592d5845e5a160d522c0e680972aa534549940b8d73bde88481a AS frontend

ARG HUNTER_API_BASE=http://web:8000
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    HOSTNAME=0.0.0.0 \
    PORT=3000 \
    HUNTER_API_BASE=${HUNTER_API_BASE} \
    NEXT_PUBLIC_HUNTER_STREAM_SAME_ORIGIN=1

WORKDIR /app

COPY --from=frontend-builder --chown=node:node /app/package.json /app/package-lock.json /app/next.config.ts ./
COPY --from=frontend-builder --chown=node:node /app/node_modules ./node_modules
COPY --from=frontend-builder --chown=node:node /app/public ./public
COPY --from=frontend-builder --chown=node:node /app/.next ./.next

RUN mkdir -p /app/.next/cache && chown -R node:node /app/.next/cache

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD node -e "fetch('http://127.0.0.1:3000/').then(r=>process.exit(r.ok||r.status<500?0:1)).catch(()=>process.exit(1))"

USER node

CMD ["./node_modules/.bin/next", "start", "-H", "0.0.0.0", "-p", "3000"]

# ------------------------------------------------------------
# Stage 3: Django 5.2 + DRF Pure ASGI Web Backend (:8000, default, non-root)
# ------------------------------------------------------------
FROM python:3.11.18-slim-bookworm@sha256:ef56ae98435cc40d8a27020b0b32a9941515acd5840f0fba34858bb34dd362d1 AS web

ARG INSTALL_PLAYWRIGHT=0

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    DJANGO_SETTINGS_MODULE=hunter_backend.settings \
    WEB_HOST=0.0.0.0 \
    WEB_PORT=8000 \
    HUNTER_UNRESTRICTED=0

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        ca-certificates \
        git \
        nmap \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
    && if [ "$INSTALL_PLAYWRIGHT" = "1" ]; then \
        python -m playwright install --with-deps chromium \
        && chmod -R a+rX /ms-playwright; \
       fi

RUN groupadd --gid 10001 hunter \
    && useradd --uid 10001 --gid 10001 --create-home --shell /bin/sh hunter \
    && mkdir -p /app/data /app/artifacts /app/reports /app/logs \
    && chown -R hunter:hunter /app

# Unified Python platform packages & manifests (core/, hunter_ai/, hunter_backend/ + supporting runtime)
COPY --chown=hunter:hunter core/ ./core/
COPY --chown=hunter:hunter hunter_ai/ ./hunter_ai/
COPY --chown=hunter:hunter hunter_backend/ ./hunter_backend/
COPY --chown=hunter:hunter agents/ ./agents/
COPY --chown=hunter:hunter bughunter/ ./bughunter/
COPY --chown=hunter:hunter cli/ ./cli/
COPY --chown=hunter:hunter config/ ./config/
COPY --chown=hunter:hunter ctf/ ./ctf/
COPY --chown=hunter:hunter engines/ ./engines/
COPY --chown=hunter:hunter flags/ ./flags/
COPY --chown=hunter:hunter memory/ ./memory/
COPY --chown=hunter:hunter models/ ./models/
COPY --chown=hunter:hunter orchestrator/ ./orchestrator/
COPY --chown=hunter:hunter platform/ ./platform/
COPY --chown=hunter:hunter profiles/ ./profiles/
COPY --chown=hunter:hunter scripts/ ./scripts/
COPY --chown=hunter:hunter skills/ ./skills/
COPY --chown=hunter:hunter tools/ ./tools/
COPY --chown=hunter:hunter ui/ ./ui/
COPY --chown=hunter:hunter wordlists/ ./wordlists/
COPY --chown=hunter:hunter .opencode/ ./.opencode/
COPY --chown=hunter:hunter .agents/ ./.agents/
COPY --chown=hunter:hunter pentest.py main.py master.py agent_core.py bugbounty_agent.py \
    opencode.json agent_config.json model_manifest.json capability_matrix.json \
    hierarchy.json permissions.json hunter.yaml version.txt pyproject.toml \
    system_prompt.md rules.txt ./

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/api/health >/dev/null || exit 1

USER hunter

CMD ["python", "-m", "uvicorn", "hunter_backend.asgi:application", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--log-level", "info"]
