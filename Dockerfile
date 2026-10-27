# Base image is digest-pinned (multi-arch index); bump deliberately and rebuild.
FROM python:3.12-slim@sha256:dddfd7e07f9d15aeeca61529320492139d21cac7f0070c00609243e51e4e0016

LABEL org.opencontainers.image.title="honeypot-auditor" \
      org.opencontainers.image.description="Multi-protocol CLI that fingerprints whether an authorized target behaves like a low-interaction honeypot" \
      org.opencontainers.image.source="https://github.com/mziqudhd92/honeypot-auditor" \
      org.opencontainers.image.licenses="MIT"

# uv binary from the official image (digest-pinned); installs from uv.lock.
COPY --from=ghcr.io/astral-sh/uv:0.9.5@sha256:f459f6f73a8c4ef5d69f4e6fbbdb8af751d6fa40ec34b39a1ab469acd6e289b7 \
     /uv /usr/local/bin/uv

WORKDIR /app
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY src ./src

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/app/.venv \
    PATH="/app/.venv/bin:$PATH"

RUN uv sync --frozen --extra full --no-dev --no-editable \
    && useradd --create-home --shell /usr/sbin/nologin auditor \
    && chown -R auditor:auditor /app

# Reports default to the CWD; /app is writable by the runtime user.
USER auditor

ENTRYPOINT ["honeypot-auditor"]
CMD ["--help"]
