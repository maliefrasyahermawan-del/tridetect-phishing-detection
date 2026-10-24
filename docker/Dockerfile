# ── Stage 1: Builder ─────────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential gcc libssl-dev && \
    rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
COPY tridetect/ tridetect/
COPY scripts/ scripts/

RUN pip install --upgrade pip && \
    pip install --no-cache-dir -e ".[dev]"

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
FROM python:3.11-slim AS runtime

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl-dev curl && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/lib/python3.11 /usr/local/lib/python3.11
COPY --from=builder /usr/local/bin /usr/local/bin
COPY --from=builder /build /app

# Seed data
RUN python scripts/generate_synthetic_sms.py && \
    python scripts/seed_brands.py

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s \
  CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "tridetect.gateway.main:app", "--host", "0.0.0.0", "--port", "8000"]
