# ==============================================================================
# Dunex — LLM Guardrails & Data Leakage Prevention Engine
# Multi-stage production Dockerfile: Builder -> Non-root Runtime
# ==============================================================================

# ── Stage 1: Build & Dependencies ─────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

# Install build tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies to dedicated wheels/prefix
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Stage 2: Final Minimal Non-Root Runtime ───────────────────────────────────
FROM python:3.11-slim AS runner

WORKDIR /app

# Create non-root system user (UID 10001)
RUN groupadd -g 10001 dunexgroup && \
    useradd -u 10001 -g dunexgroup -s /bin/bash -m dunexuser

# Copy installed site-packages from builder
COPY --from=builder /install /usr/local

# Copy application code
COPY --chown=dunexuser:dunexgroup . /app

# Switch to non-root user
USER 10001

# Environment flags
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8000 \
    HOST=0.0.0.0 \
    DUNEX_ENV=production

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

# Start FastAPI service
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
