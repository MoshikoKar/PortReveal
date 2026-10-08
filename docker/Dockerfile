# Production image: built frontend + FastAPI backend + nmap, served by uvicorn on one port.
# Build context is the repository root:  docker compose build

# ---- 1. frontend build ---------------------------------------------------------
FROM node:22-alpine AS frontend
WORKDIR /src
COPY package.json package-lock.json ./
COPY frontend/package.json frontend/
RUN npm ci --no-audit --no-fund
COPY frontend/ frontend/
RUN npx tsc -p frontend && npx vite build frontend

# ---- 2. runtime ------------------------------------------------------------------
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    APP_ENV=production \
    DATA_DIR=/data \
    FRONTEND_DIST=/app/frontend/dist \
    SCANNER_MODE=nmap \
    NMAP_PRIVILEGED=true \
    APP_PORT=8080 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

# nmap is installed here; file capabilities let the non-root app user send raw
# packets (ARP/ICMP/SYN) when the container is granted NET_RAW/NET_ADMIN.
RUN apt-get update \
 && apt-get install -y --no-install-recommends nmap ffmpeg libcap2-bin tzdata ca-certificates \
 && setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip "$(readlink -f /usr/bin/nmap)" \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY backend/requirements.txt backend/requirements.txt
RUN pip install -r backend/requirements.txt \
 && playwright install --with-deps chromium

COPY backend/ backend/
COPY --from=frontend /src/frontend/dist frontend/dist

RUN useradd --system --uid 10001 --home /app netfinder \
 && mkdir -p /data \
 && chown -R netfinder:netfinder /data /app \
 && chmod -R a+rX /ms-playwright

USER netfinder
WORKDIR /app/backend
VOLUME ["/data"]
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
  CMD python -c "import os,urllib.request; urllib.request.urlopen(f'http://127.0.0.1:{os.environ.get(\"APP_PORT\",\"8080\")}/api/health', timeout=4)" || exit 1

# Single process on purpose: the scan queue and scheduler run inside it.
CMD ["sh", "-c", "exec uvicorn app.main:app --host ${APP_HOST:-0.0.0.0} --port ${APP_PORT:-8080} --proxy-headers --forwarded-allow-ips ${FORWARDED_ALLOW_IPS:-127.0.0.1} --log-level warning"]
