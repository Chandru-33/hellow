FROM python:3.12-slim AS base

LABEL maintainer="DevSecOps Team"
LABEL description="Enterprise DevSecOps Pre-Commit Guardian"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY src/ ./src/

RUN pip install --upgrade pip && pip install .

# Optional external security tools
RUN pip install semgrep || true

FROM base AS runtime

COPY .env.example ./.env.example
COPY client_patterns.yaml ./client_patterns.yaml

ENTRYPOINT ["devsecops"]
CMD ["--help"]
